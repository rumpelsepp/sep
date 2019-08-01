package sep

import (
	"fmt"
	"time"
)

type Dialer interface {
	DialTimeout(network, target string, timeout time.Duration) (Conn, error)
}

func NewDialer(transport string, config Config) (Dialer, error) {
	var dialer Dialer

	switch transport {
	case "tcp":
		dialer = newTCPDialer(config)

	// TODO: reintroduce this when stable
	// case "quic":
	// 	dialer = newQuicDialer(config)

	default:
		return nil, fmt.Errorf("transport is not supported")
	}

	return dialer, nil
}
