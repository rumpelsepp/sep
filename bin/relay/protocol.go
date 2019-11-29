package main

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"git.sr.ht/~rumpelsepp/helpers"
	"git.sr.ht/~rumpelsepp/sep"
)

const (
	sessionIDLE = iota
	sessionHANDSHAKE
	sessionTRANSFER
	// for later when sessions can resume
	// sessionWait
)

type relayConn struct {
	keypair    tls.Certificate
	initiator  *sep.RelayNode
	target     *sep.RelayNode
	pingActive bool
	mutex      sync.Mutex
	state      int
}

func (c *relayConn) handshake(req sep.RelayMessage) error {
	if c.initiator == nil || c.target == nil {
		panic("BUG: relayConn not properly initialized")
	}

	err := c.target.SendRaw(req)
	if err != nil {
		return err
	}

	resp, err := c.target.RecvRaw()
	if err != nil {
		return err
	}

	if resp.Type != sep.RelayMsgTypeAck {
		return fmt.Errorf("connection denied by target")
	}

	err = c.initiator.SendRaw(resp)
	if err != nil {
		return err
	}

	return nil
}

func (c *relayConn) serve() error {
	_, _, err := helpers.BidirectCopy(c.initiator.Conn.RawConnection(), c.target.Conn.RawConnection())
	return err
}

func (c *relayConn) close() {
	// TODO: return both errors or so
	c.initiator.Conn.Close()
	c.target.Conn.Close()
}

func (c *relayConn) stopPing() {
	c.mutex.Lock()
	c.pingActive = false
	c.mutex.Unlock()
}

func (c *relayConn) ping() error {
	// TODO: timeouts
	defer logger.Debug("keep alive stopped")

	for c.pingActive {
		c.mutex.Lock()

		req := sep.RelayMessage{
			Type: sep.RelayMsgTypePing,
		}

		logger.Debugf("[%s]: Exchanging ping message", c.target.Conn.RemoteFingerprint().Short())

		err := c.target.Send(req)
		if err != nil {
			c.mutex.Unlock()
			return err
		}

		resp, err := c.target.RecvFrom(c.target.Conn.RemoteFingerprint())
		if err != nil {
			c.mutex.Unlock()
			return err
		}

		if resp.Type != sep.RelayMsgTypePong {
			c.mutex.Unlock()
			return fmt.Errorf("unexpected message type")
		}

		logger.Debugf("[%s]: Received pong message", c.target.Conn.RemoteFingerprint().Short())

		c.mutex.Unlock()
		time.Sleep(5 * time.Second)
	}

	return nil
}
