package sep

import "net"

type Listener interface {
	Accept() (Conn, error)
	AcceptRelay() (*RelayConn, error)
	AcceptAndServeRelay() (Conn, error)
	Close() error
	Addr() net.Addr
}

func Listen(network, address string, config Config) (Listener, error) {
	var (
		err      error
		listener Listener
	)

	switch network {
	case "tcp", "tcp4", "tcp6":
		listener, err = tcpListen(network, address, &config)

	case "quic":
		listener, err = quicListen(address, &config)

	default:
		panic("transport is not supported")
	}

	if err != nil {
		return nil, err
	}

	return listener, nil
}
