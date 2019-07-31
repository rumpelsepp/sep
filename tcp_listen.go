package sep

import (
	"context"
	"net"
)

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
