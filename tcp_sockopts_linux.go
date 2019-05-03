package sep

import (
	"syscall"

	"git.sr.ht/~rumpelsepp/rlog"
	"golang.org/x/sys/unix"
)

func setTCPFastOpenCallback(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 5); err != nil {
			rlog.Debugf("TCP FastOpen error: %s", err)
		}
	})
}

func setTCPFastOpenConnectCallback(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1); err != nil {
			rlog.Debugf("TCP FastOpen error: %s", err)
		}
	})
}
