// +build !linux

package sep

import (
	"syscall"
)

func setTCPFastOpenCallback(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {})
}

func setTCPFastOpenConnectCallback(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {})
}
