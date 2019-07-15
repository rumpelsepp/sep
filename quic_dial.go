package sep

import (
	"fmt"
	"time"

	"git.sr.ht/~rumpelsepp/rlog"
	quic "github.com/lucas-clemente/quic-go"
)

type quicDialer struct {
	Config   *Config
	Resolver Resolver
}

// TODO: Add a resolver argument
func newQuicDialer(config Config) Dialer {
	privKey := config.TLSConfig.Certificates[0].PrivateKey

	return &quicDialer{
		Config:   &config,
		Resolver: NewResolver(config.ResolveFlags, privKey),
	}
}

func (d *quicDialer) DialTimeout(network, target string, timeout time.Duration) (Conn, error) {
	var session quic.Session

	// TODO: better location
	tlsConfig := d.Config.TLSConfig.Clone()
	if tlsConfig.VerifyPeerCertificate == nil {
		tlsConfig.VerifyPeerCertificate = makeVerifyCallback(d.Config.AllowedPeers, d.Config.Database)
	}

	addrs, err := d.Resolver.Resolve(target)
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		s, err := quic.DialAddr(addr, tlsConfig, nil)
		if err != nil {
			rlog.Debugln(err)
			continue
		}

		session = s
		break
	}

	if session == nil {
		return nil, fmt.Errorf("could not connect to: %s", target)
	}

	rlog.Debugf("established quic connection to: %s", session.RemoteAddr())

	return &quicConn{
		session:  session,
		isServer: false,
	}, nil
}

func (d *quicDialer) DialToNextHop(network, relay, target string, timeout time.Duration) (Conn, error) {
	return nil, ErrNotSupported
}

func (d *quicDialer) DialWithRelay(network, relay, target string, timeout time.Duration) (Conn, error) {
	return nil, ErrNotSupported
}
