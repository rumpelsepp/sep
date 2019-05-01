package sep

import (
	"errors"
	"net"
	"time"
)

var (
	ErrRelayIsTarget = errors.New("cannot forward traffic; relay is target")
	ErrRelayDisabled = errors.New("relay handler is disabled")
	ErrRelayNACK     = errors.New("relay connection denied")
)

const (
	RelayMaxHop = 5
)

type RelayConn struct {
	Left          net.Conn
	Right         net.Conn
	DialTimeout   time.Duration
	PrevHop       *Fingerprint
	NextHop       *Fingerprint
	NextHopDialer Dialer
	TransportType string
}

// func RequestRelay(conn net.Conn, req *RelayRequest) (*RelayResponse, error) {
// 	log.Debugln("send RelayRequest")
//
// 	if err := writeRelayRequest(conn, req); err != nil {
// 		return nil, err
// 	}
//
// 	resp, err := readRelayResponse(conn)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	log.Tracef("response from relay: %+v", resp)
//
// 	return resp, nil
// }

func (r *RelayConn) Serve() (int, int, error, error) {
	return BidirectCopy(r.Left, r.Right)
}
