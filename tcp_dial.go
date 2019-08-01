package sep

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

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
			logger.Debugln(err)
			continue
		}

		network := parsedAddr.Scheme
		if network == "" {
			network = "tcp"
		}

		if !strings.Contains(network, "tcp") {
			logger.Debugf("wrong network: %s", network)
			continue
		}

		tcpConnIntf, err := d.dialer.Dial(network, parsedAddr.Host)
		if err != nil {
			logger.Debugln(err)
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
			logger.Debugln(err)
			continue
		}

		// When the loop reaches this point, there is a connection.
		logger.Debugf("established SEP connection to: %s", c.RemoteAddr())

		return c, nil
	}

	return nil, fmt.Errorf("could not connect to: %s", target)
}
