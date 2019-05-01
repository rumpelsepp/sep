package sep

import (
	"crypto/tls"
	"io"
	"net"
	"time"
)

const (
	RelayFlagEnabled = 1 << iota
	RelayFlagAcceptFromRelay
	RelayFlagRelayOnly
)

type Config struct {
	TLSConfig     *tls.Config
	ResolveFlags  int
	AllowedPeers  []Peer
	TCPFastOpen   bool
	TLSFalseStart bool
	TLSBackend    string
}

type Conn interface {
	net.Conn
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
