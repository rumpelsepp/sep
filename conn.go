package sep

import (
	"crypto/tls"
	"io"
	"net"
	"time"
)

type Config struct {
	TLSConfig    *tls.Config
	ResolveFlags int
	AllowedPeers []*Fingerprint
	TCPFastOpen  bool
	Database     TrustDatabase
}

type Conn interface {
	net.Conn
	RawConnection() net.Conn
	RemoteFingerprint() *Fingerprint
	LocalFingerprint() *Fingerprint
	AcceptStream() (Stream, error)
	OpenStream() (Stream, error)
}

type Multiplexer interface {
	io.Closer
	AcceptStream() (Stream, error)
	OpenStream() (Stream, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type Stream interface {
	io.ReadWriteCloser
	StreamID() uint64
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
