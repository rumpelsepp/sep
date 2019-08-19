package sep

import (
	"context"
	"fmt"
	"sort"
	"time"

	"golang.org/x/xerrors"
)

type Connector struct {
	Config     Config
	Relay      *Fingerprint
	DirClient  DirectoryClient
	ListenAddr string

	resultCh chan internalConn
	errCh    chan error
}

type internalConn struct {
	conn Conn
	prio int
}

func (c *Connector) listenAndAccept(ctx context.Context) {
	defer logger.Debugln("listener terminated")

	ln, err := Listen("tcp", c.ListenAddr, c.Config)
	if err != nil {
		c.errCh <- xerrors.Errorf("listener Listen(): %w", err)
		return
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				c.errCh <- xerrors.Errorf("listener Accept(): %w", err)
			} else {
				c.resultCh <- internalConn{conn, 0}
				break
			}
		}
	}()

	<-ctx.Done()
	ln.Close()
}

func (c Connector) dial(ctx context.Context, target *Fingerprint) {
	defer logger.Debugln("dialer terminated")

	dialer, err := NewDialer("tcp", c.Config)
	if err != nil {
		c.errCh <- err
	}

	var conn Conn

	for conn == nil {
		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(5 * time.Second)

		conn, err = dialer.DialTimeout("tcp", target.String(), 5*time.Second)
		if err != nil {
			c.errCh <- err
		}
	}

	c.resultCh <- internalConn{conn, 0}
}

func (c *Connector) dialRelay(ctx context.Context, target *Fingerprint) {
	defer logger.Debugln("relay dialer terminated")

	var conn Conn
	for conn == nil {
		time.Sleep(5 * time.Second)

		select {
		case <-ctx.Done():
			return
		default:
		}

		relays, err := c.DirClient.DiscoverRelays(target)
		if err != nil {
			c.errCh <- err
			continue
		}

		if len(relays) != 1 {
			c.errCh <- fmt.Errorf("only one relay supported right now…")
			return
		}

		relayFP, err := FingerprintFromNIString(relays[0])
		if err != nil {
			c.errCh <- err
			return
		}

		// TODO: remove pointers, because of pain. Copy the config!!!
		conf := c.Config
		conf.AllowedPeers = append(conf.AllowedPeers, relayFP)

		// TODO: Make this guy persistent. Needs SEP changes.
		dialer, err := NewRelayClient(relayFP, conf)
		if err != nil {
			c.errCh <- err
		}

		conn, err = dialer.Dial(target)
		if err != nil {
			c.errCh <- err
		}
	}

	c.resultCh <- internalConn{conn, 1}
}

func (c *Connector) listenAndAcceptRelay(ctx context.Context) {
	defer logger.Debugln("relay listener terminated")

	// TODO: remove pointers, because of pain. Copy the config!!!
	conf := c.Config
	conf.AllowedPeers = append(conf.AllowedPeers, c.Relay)

	ln, err := NewRelayClient(c.Relay, conf)
	if err != nil {
		c.errCh <- err
		return
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			logger.Debugf("relayAccept failed: %s", err)
			return
		}

		c.resultCh <- internalConn{conn, 1}
	}()

	<-ctx.Done()
	ln.Close()
}

func (c *Connector) Connect(target *Fingerprint, timeout time.Duration) (Conn, error) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	c.errCh = make(chan error, 8)
	c.resultCh = make(chan internalConn)

	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
	} else {
		ctx = context.Background()
	}

	go c.listenAndAccept(ctx)
	go c.listenAndAcceptRelay(ctx)
	go c.dial(ctx, target)
	go c.dialRelay(ctx, target)

	var conns []internalConn

	for {
		select {
		case conn := <-c.resultCh:
			// Fast path when a direct connection comes.
			if conn.prio == 0 {
				return conn.conn, nil
			}
			conns = append(conns, conn)

		case err := <-c.errCh:
			logger.Debugln(err)

		case <-ctx.Done():
			if len(conns) == 0 {
				return nil, ctx.Err()
			}

			sort.Slice(conns, func(i, j int) bool {
				return conns[i].prio < conns[j].prio
			})

			return conns[0].conn, nil
		}
	}
}