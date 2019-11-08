package sep

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

type TCPConn struct {
	rawConn           *net.TCPConn
	tlsConn           *tls.Conn
	config            *Config
	localFingerprint  *Fingerprint
	remoteFingerprint *Fingerprint
}

func initTCP(conn *tls.Conn, config *Config) (*TCPConn, error) {
	if config.TLSConfig.VerifyPeerCertificate == nil {
		// We do verifying ourselves.
		config.TLSConfig.InsecureSkipVerify = true
		config.TLSConfig.VerifyPeerCertificate = MakeDefaultVerifier(config.AllowedPeers, config.TrustDB)
	}

	err := conn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("tls handshake: %s", err)
	}

	state := conn.ConnectionState()

	localFingerprint, err := FingerprintFromCertificate(config.TLSConfig.Certificates[0].Certificate[0])
	if err != nil {
		return nil, err
	}

	remoteFingerprint, err := FingerprintFromCertificate(state.PeerCertificates[0].Raw)
	if err != nil {
		return nil, err
	}

	Logger.Debugf(
		"connected %s: %s [%s] <-> %s [%s]",
		tlsCipherSuiteNames[state.CipherSuite],
		conn.LocalAddr(),
		localFingerprint.Short(),
		conn.RemoteAddr(),
		remoteFingerprint.Short(),
	)

	return &TCPConn{
		tlsConn:           conn,
		config:            config,
		localFingerprint:  localFingerprint,
		remoteFingerprint: remoteFingerprint,
	}, nil
}

func tcpServer(conn *net.TCPConn, config *Config) (*TCPConn, error) {
	tlsConn := tls.Server(conn, config.TLSConfig)
	sepConn, err := initTCP(tlsConn, config)
	if err != nil {
		return nil, err
	}
	sepConn.rawConn = conn

	return sepConn, nil
}

func tcpClient(conn *net.TCPConn, config *Config) (*TCPConn, error) {
	tlsConn := tls.Client(conn, config.TLSConfig)
	sepConn, err := initTCP(tlsConn, config)
	if err != nil {
		return nil, err
	}
	sepConn.rawConn = conn

	return sepConn, nil
}

func (c *TCPConn) RawConnection() net.Conn {
	return c.rawConn
}

func (c *TCPConn) Read(b []byte) (int, error) {
	return c.tlsConn.Read(b)
}

func (c *TCPConn) Write(b []byte) (int, error) {
	return c.tlsConn.Write(b)
}

func (c *TCPConn) Close() error {
	return c.tlsConn.Close()
}

func (c *TCPConn) RemoteAddr() net.Addr {
	return c.tlsConn.RemoteAddr()
}

func (c *TCPConn) LocalAddr() net.Addr {
	return c.tlsConn.LocalAddr()
}

func (c *TCPConn) SetDeadline(t time.Time) error {
	return c.tlsConn.SetDeadline(t)
}

func (c *TCPConn) SetReadDeadline(t time.Time) error {
	return c.tlsConn.SetReadDeadline(t)
}

func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	return c.tlsConn.SetWriteDeadline(t)
}

func (c *TCPConn) RemoteFingerprint() *Fingerprint {
	return c.remoteFingerprint
}

func (c *TCPConn) LocalFingerprint() *Fingerprint {
	return c.localFingerprint
}

type tcpListener struct {
	net.Listener
	config *Config
}

func tcpListen(network, address string, config *Config) (*tcpListener, error) {
	var (
		ln  net.Listener
		err error
	)

	switch network {
	case "tcp", "tcp4", "tcp6":
		if config.TCPFastOpen {
			lc := net.ListenConfig{
				Control: setTCPFastOpenCallback,
			}

			ln, err = lc.Listen(context.Background(), network, address)
		} else {
			ln, err = net.Listen(network, address)
		}

		if err != nil {
			return nil, err
		}

	default:
		panic("network is not supported")
	}

	return &tcpListener{
		Listener: ln,
		config:   config,
	}, nil
}

func (ln *tcpListener) Accept() (Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// This won't panic, otherwise it's a bug.
	tcpConn := conn.(*net.TCPConn)

	tunnel, err := tcpServer(tcpConn, ln.config)
	if err != nil {
		return nil, err
	}

	return tunnel, nil
}

type tcpDialer struct {
	dialer *net.Dialer
	config *Config
}

func newTCPDialer(config Config) Dialer {
	var dialer *net.Dialer

	if config.TCPFastOpen {
		dialer = &net.Dialer{
			Control: setTCPFastOpenConnectCallback,
		}
	} else {
		dialer = &net.Dialer{}
	}

	return &tcpDialer{
		dialer: dialer,
		config: &config,
	}
}

func (d *tcpDialer) DialTimeout(network, target string, timeout time.Duration) (Conn, error) {
	var c Conn

	d.dialer.Timeout = timeout

	fingerprint, err := FingerprintFromNIString(target)
	if err != nil {
		return nil, err
	}

	addrs, err := d.config.Directory.DiscoverAddresses(fingerprint)
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		parsedAddr, err := url.Parse(addr)
		if err != nil {
			Logger.Debugln(err)
			continue
		}

		network := parsedAddr.Scheme
		if network == "" {
			network = "tcp"
		}

		if !strings.Contains(network, "tcp") {
			Logger.Debugf("wrong network: %s", network)
			continue
		}

		tcpConnIntf, err := d.dialer.Dial(network, parsedAddr.Host)
		if err != nil {
			Logger.Debugln(err)
			continue
		}

		// This won't panic, otherwise it's a bug.
		tcpConn := tcpConnIntf.(*net.TCPConn)

		c, err = tcpClient(tcpConn, d.config)
		if err != nil {
			// This can happen, because TCP-FO is in use. connect(2)
			// returns immediately and fails on the first read(2) if
			// the connection cannot be established. In this case,
			// we must clean the connection in order to avoid a nil
			// pointer dereference.
			c = nil
			Logger.Debugln(err)
			continue
		}

		return c, nil
	}

	return nil, fmt.Errorf("could not connect to: %s", target)
}
