package sep

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/pion/dtls"
)

type UDPConn struct {
	dtlsConn          *dtls.Conn
	config            *Config
	localFingerprint  *Fingerprint
	remoteFingerprint *Fingerprint
}

func initUDP(conn *dtls.Conn, config *Config) (*UDPConn, error) {
	localFingerprint, err := FingerprintFromCertificate(config.DTLSConfig.Certificate.Raw)
	if err != nil {
		return nil, err
	}

	remoteFingerprint, err := FingerprintFromCertificate(conn.RemoteCertificate().Raw)
	if err != nil {
		return nil, err
	}

	Logger.Debugf(
		"dtls connected %s: [%s] <-> %s [%s]",
		conn.LocalAddr(),
		localFingerprint.Short(),
		conn.RemoteAddr(),
		remoteFingerprint.Short(),
	)

	return &UDPConn{
		dtlsConn:          conn,
		config:            config,
		localFingerprint:  localFingerprint,
		remoteFingerprint: remoteFingerprint,
	}, nil
}

func udpClient(conn *net.UDPConn, config *Config) (*UDPConn, error) {
	if config.DTLSConfig.VerifyPeerCertificate == nil {
		// We do verifying ourselves.
		config.DTLSConfig.InsecureSkipVerify = true
		config.DTLSConfig.VerifyPeerCertificate = MakeDefaultVerifierUDP(config.AllowedPeers, config.TrustDB)
		// config.DTLSConfig.VerifyPeerCertificate = VerifierAllowAllUDP
	}

	dtlsConn, err := dtls.Client(conn, config.DTLSConfig)
	if err != nil {
		return nil, err
	}

	sepConn, err := initUDP(dtlsConn, config)
	if err != nil {
		return nil, err
	}
	return sepConn, nil
}

func (c *UDPConn) RawConnection() net.Conn {
	return nil
}

func (c *UDPConn) Read(b []byte) (int, error) {
	return c.dtlsConn.Read(b)
}

func (c *UDPConn) Write(b []byte) (int, error) {
	return c.dtlsConn.Write(b)
}

func (c *UDPConn) Close() error {
	return c.dtlsConn.Close()
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.dtlsConn.RemoteAddr()
}

func (c *UDPConn) LocalAddr() net.Addr {
	return c.dtlsConn.LocalAddr()
}

func (c *UDPConn) SetDeadline(t time.Time) error {
	return c.dtlsConn.SetDeadline(t)
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	return c.dtlsConn.SetReadDeadline(t)
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	return c.dtlsConn.SetWriteDeadline(t)
}

func (c *UDPConn) RemoteFingerprint() *Fingerprint {
	return c.remoteFingerprint
}

func (c *UDPConn) LocalFingerprint() *Fingerprint {
	return c.localFingerprint
}

type udpListener struct {
	*dtls.Listener
	config *Config
}

func udpListen(network, address string, config *Config) (*udpListener, error) {
	var ln *dtls.Listener

	switch network {
	case "udp", "udp4", "udp6":
		addr, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, err
		}

		if config.DTLSConfig.VerifyPeerCertificate == nil {
			// We do verifying ourselves.
			config.DTLSConfig.InsecureSkipVerify = true
			config.DTLSConfig.VerifyPeerCertificate = MakeDefaultVerifierUDP(config.AllowedPeers, config.TrustDB)
			// config.DTLSConfig.VerifyPeerCertificate = VerifierAllowAllUDP
		}

		ln, err = dtls.Listen(network, addr, config.DTLSConfig)
		if err != nil {
			return nil, err
		}

	default:
		panic("network is not supported")
	}

	return &udpListener{
		Listener: ln,
		config:   config,
	}, nil
}

func (ln *udpListener) Accept() (Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	dtlsConn := conn.(*dtls.Conn)
	return initUDP(dtlsConn, ln.config)
}

func (ln *udpListener) Close() error {
	return ln.Listener.Close(5 * time.Second)
}

type udpDialer struct {
	dialer *net.Dialer
	config *Config
}

func newUDPDialer(config Config) Dialer {
	return &udpDialer{
		dialer: &net.Dialer{},
		config: &config,
	}
}

func (d *udpDialer) DialTimeout(network, target string, timeout time.Duration) (Conn, error) {
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

		if !strings.Contains(network, "udp") {
			Logger.Debugf("wrong network: %s", network)
			continue
		}

		udpConnIntf, err := d.dialer.Dial(network, parsedAddr.Host)
		if err != nil {
			Logger.Debugln(err)
			continue
		}

		// This won't panic, otherwise it's a bug.
		udpConn := udpConnIntf.(*net.UDPConn)

		c, err = udpClient(udpConn, d.config)
		if err != nil {
			Logger.Debugln(err)
			continue
		}

		return c, nil
	}

	return nil, fmt.Errorf("could not connect to: %s", target)
}
