package sep

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

var ErrIsSession = errors.New("connection is a session")

type TCPConn struct {
	tlsConn           *tls.Conn
	transport         *net.TCPConn
	network           string
	multiplexer       Multiplexer
	config            *Config
	localFingerprint  *Fingerprint
	remoteFingerprint *Fingerprint
	alp               string

	isServer  bool
	isSession bool
}

func initSEP(conn *tls.Conn, config *Config) (*TCPConn, error) {
	err := conn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("tls handshake: %s", err)
	}

	state := conn.ConnectionState()
	alp := state.NegotiatedProtocol

	localFingerprint, err := CertificateToFingerprint(config.TLSConfig.Certificates[0].Certificate[0], DefaultFingerprintSuite)
	if err != nil {
		return nil, err
	}

	remoteFingerprint, err := CertificateToFingerprint(state.PeerCertificates[0].Raw, DefaultFingerprintSuite)
	if err != nil {
		return nil, err
	}

	tlsLogger.Debugf("%+v", state)
	tlsLogger.Debugf("connected to: %s", conn.RemoteAddr())
	tlsLogger.Debugf("ALPN: %s", state.NegotiatedProtocol)
	tlsLogger.Debugf("local fingerprint : %s", localFingerprint.String())
	tlsLogger.Debugf("remote fingerprint: %s", remoteFingerprint.String())
	tlsLogger.Debugf("TLS connection established: %s", tlsCipherSuiteNames[state.CipherSuite])

	if alp != AlpSEP {
		return nil, fmt.Errorf("unsupported ALP: %s", state.NegotiatedProtocol)
	}

	return &TCPConn{
		tlsConn:           conn,
		alp:               alp,
		config:            config,
		localFingerprint:  localFingerprint,
		remoteFingerprint: remoteFingerprint,
	}, nil
}

func tcpServer(conn *net.TCPConn, config *Config) (*TCPConn, error) {
	// TODO: Move to better location
	if config.TLSConfig.VerifyPeerCertificate == nil {
		config.TLSConfig.VerifyPeerCertificate = makeVerifyCallback(config.AllowedPeers, config.Database)
	}

	tlsConn := tls.Server(conn, config.TLSConfig)
	sepConn, err := initSEP(tlsConn, config)
	if err != nil {
		return nil, err
	}

	sepConn.transport = conn
	sepConn.isServer = true
	sepConn.network = "tcp"

	return sepConn, nil
}

func tcpClient(conn *net.TCPConn, config *Config) (*TCPConn, error) {
	if config.TLSConfig.NextProtos == nil {
		return nil, fmt.Errorf("NextProtos is not set")
	}

	// TODO: Move to better location
	if config.TLSConfig.VerifyPeerCertificate == nil {
		config.TLSConfig.VerifyPeerCertificate = makeVerifyCallback(config.AllowedPeers, config.Database)
	}

	tlsConn := tls.Client(conn, config.TLSConfig)
	sepConn, err := initSEP(tlsConn, config)
	if err != nil {
		return nil, err
	}

	sepConn.transport = conn
	sepConn.isServer = false
	sepConn.network = "tcp"

	return sepConn, nil
}

func (c *TCPConn) Read(b []byte) (int, error) {
	if c.isSession {
		return 0, ErrIsSession
	}

	return c.tlsConn.Read(b)
}

func (c *TCPConn) Write(b []byte) (int, error) {
	if c.isSession {
		return 0, ErrIsSession
	}

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

func (c *TCPConn) ALP() string {
	return c.alp
}

type sepMuxer struct {
	*yamux.Session
}

func (m *sepMuxer) AcceptStream() (Stream, error) {
	stream, err := m.Session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &tcpStream{stream}, nil
}

func (m *sepMuxer) OpenStream() (Stream, error) {
	stream, err := m.Session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &tcpStream{stream}, nil
}

func (c *TCPConn) initMuxer() error {
	muxLogger.Debugln("initializing multiplexer...")

	var (
		err   error
		muxer *yamux.Session
	)

	if c.isServer {
		muxer, err = yamux.Server(c.tlsConn, nil)
	} else {
		muxer, err = yamux.Client(c.tlsConn, nil)
	}

	if err != nil {
		return err
	}

	c.multiplexer = &sepMuxer{muxer}
	c.isSession = true

	return nil
}

type tcpStream struct {
	*yamux.Stream
}

func (s *tcpStream) StreamID() uint64 {
	return uint64(s.Stream.StreamID())
}

// TODO: Mutex
func (c *TCPConn) AcceptStream() (Stream, error) {
	if !c.isSession {
		c.initMuxer()
	}

	muxLogger.Debugln("accepting stream...")

	stream, err := c.multiplexer.AcceptStream()
	if err != nil {
		return nil, err
	}

	muxLogger.Debugf("got stream: %+v", stream)

	return stream, nil
}

func (c *TCPConn) OpenStream() (Stream, error) {
	if !c.isSession {
		c.initMuxer()
	}

	muxLogger.Debugln("opening stream...")

	stream, err := c.multiplexer.OpenStream()
	if err != nil {
		return nil, err
	}

	muxLogger.Debugf("got stream: %+v", stream)

	return stream, nil
}
