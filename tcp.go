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
	tlsConn           *tls.Conn
	transport         *net.TCPConn
	network           string
	config            *Config
	localFingerprint  *Fingerprint
	remoteFingerprint *Fingerprint
	alp               string

	isServer bool
}

func initSEP(conn *tls.Conn, config *Config) (*TCPConn, error) {
	if config.TLSConfig.VerifyPeerCertificate == nil {
		config.TLSConfig.VerifyPeerCertificate = MakeDefaultVerifier(config.AllowedPeers, config.Database)
	}

	err := conn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("tls handshake: %s", err)
	}

	state := conn.ConnectionState()
	alp := state.NegotiatedProtocol

	localFingerprint, err := FingerprintFromCertificate(config.TLSConfig.Certificates[0].Certificate[0], DefaultFingerprintSuite, DefaultResolveDomain)
	if err != nil {
		return nil, err
	}

	remoteFingerprint, err := FingerprintFromCertificate(state.PeerCertificates[0].Raw, DefaultFingerprintSuite, DefaultResolveDomain)
	if err != nil {
		return nil, err
	}

	Logger.Debugf("%+v", state)
	Logger.Debugf("connected to: %s", conn.RemoteAddr())
	Logger.Debugf("local fingerprint : %s", localFingerprint.String())
	Logger.Debugf("remote fingerprint: %s", remoteFingerprint.String())
	Logger.Debugf("TLS connection established: %s", tlsCipherSuiteNames[state.CipherSuite])

	return &TCPConn{
		tlsConn:           conn,
		alp:               alp,
		config:            config,
		localFingerprint:  localFingerprint,
		remoteFingerprint: remoteFingerprint,
	}, nil
}

func tcpServer(conn *net.TCPConn, config *Config) (*TCPConn, error) {
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
	// We do verifying ourselves.
	config.TLSConfig.InsecureSkipVerify = true

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

func (c *TCPConn) RawConnection() net.Conn {
	return c.transport
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

func (c *TCPConn) ALP() string {
	return c.alp
}

type tcpListener struct {
	net.Listener
	Config *Config
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
		Config:   config,
	}, nil
}

func (ln *tcpListener) Accept() (Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// This won't panic, otherwise it's a bug.
	tcpConn := conn.(*net.TCPConn)

	tunnel, err := tcpServer(tcpConn, ln.Config)
	if err != nil {
		return nil, err
	}

	return tunnel, nil
}

type tcpDialer struct {
	dialer    *net.Dialer
	Config    *Config
	directory DirectoryClient
	visited   []string
}

// TODO: Add a resolver argument
func newTCPDialer(config Config) Dialer {
	var dialer *net.Dialer

	if config.TCPFastOpen {
		dialer = &net.Dialer{
			Control: setTCPFastOpenConnectCallback,
		}
	} else {
		dialer = &net.Dialer{}
	}

	dirClient := NewDirectoryClient(DefaultResolveDomain, &config.TLSConfig.Certificates[0], nil)

	return &tcpDialer{
		dialer:    dialer,
		Config:    &config,
		directory: dirClient,
	}
}

func (d *tcpDialer) DialTimeout(network, target string, timeout time.Duration) (Conn, error) {
	var c Conn

	d.Config.TLSConfig.NextProtos = []string{AlpSEP}
	d.dialer.Timeout = timeout

	fingerprint, err := FingerprintFromNIString(target)
	if err != nil {
		return nil, err
	}

	addrs, err := d.directory.DiscoverAddresses(fingerprint)
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

		c, err = tcpClient(tcpConn, d.Config)
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

		// When the loop reaches this point, there is a connection.
		Logger.Debugf("established SEP connection to: %s", c.RemoteAddr())

		return c, nil
	}

	return nil, fmt.Errorf("could not connect to: %s", target)
}
