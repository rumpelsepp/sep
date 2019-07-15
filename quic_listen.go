package sep

import (
	"net"

	quic "github.com/lucas-clemente/quic-go"
)

type quicListener struct {
	listener quic.Listener
	Config   *Config
}

func quicListen(address string, config *Config) (*quicListener, error) {
	// TODO: better location
	tlsConfig := config.TLSConfig.Clone()

	if tlsConfig.VerifyPeerCertificate == nil {
		tlsConfig.VerifyPeerCertificate = makeVerifyCallback(config.AllowedPeers, config.Database)
	}

	ln, err := quic.ListenAddr(address, config.TLSConfig, nil)
	if err != nil {
		return nil, err
	}

	return &quicListener{
		listener: ln,
		Config:   config,
	}, nil
}

func (ln *quicListener) Accept() (Conn, error) {
	session, err := ln.listener.Accept()
	if err != nil {
		return nil, err
	}

	return &quicConn{
		session:   session,
		isServer:  true,
		isSession: true,
	}, nil
}

func (ln *quicListener) AcceptRelay() (*RelayConn, error) {
	return nil, ErrNotSupported
}

func (ln *quicListener) AcceptAndServeRelay() (Conn, error) {
	return nil, ErrNotSupported
}

func (ln *quicListener) Addr() net.Addr {
	return ln.listener.Addr()
}

func (ln *quicListener) Close() error {
	return ln.listener.Close()
}
