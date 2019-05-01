package sep

import (
	"errors"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

var (
	ErrNotSupported = errors.New("method is not supported")
)

type quicConn struct {
	session           quic.Session
	config            *Config
	localFingerprint  *Fingerprint
	remoteFingerprint *Fingerprint

	isServer  bool
	isSession bool
}

func (c *quicConn) Read(b []byte) (int, error) {
	return 0, ErrNotSupported
}

func (c *quicConn) Write(b []byte) (int, error) {
	return 0, ErrNotSupported
}

func (c *quicConn) Close() error {
	return c.session.Close()
}

func (c *quicConn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

func (c *quicConn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

func (c *quicConn) SetDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *quicConn) SetReadDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *quicConn) SetWriteDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *quicConn) AcceptStream() (Stream, error) {
	stream, err := c.session.AcceptStream()
	if err != nil {
		return nil, err
	}

	return &quicStream{stream}, nil
}

func (c *quicConn) OpenStream() (Stream, error) {
	stream, err := c.session.OpenStreamSync()
	if err != nil {
		return nil, err
	}

	return &quicStream{stream}, nil
}

func (c *quicConn) RemoteFingerprint() *Fingerprint {
	return c.remoteFingerprint
}

func (c *quicConn) LocalFingerprint() *Fingerprint {
	return c.localFingerprint
}

// TODO: quic does not yet support this
func (c *quicConn) ALP() string {
	return ""
}

type quicStream struct {
	quic.Stream
}

func (s *quicStream) StreamID() uint64 {
	return uint64(s.StreamID())
}
