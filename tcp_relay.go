package sep

import (
	"net"
)

func (conn *TCPConn) reAccept() (*TCPConn, error) {
	tlsConfig := conn.config.TLSConfig.Clone()
	tlsConfig.NextProtos = []string{AlpSEP}
	sepConfig := &Config{
		AllowedPeers: conn.config.AllowedPeers,
		TLSConfig:    tlsConfig,
	}

	relayLogger.Tracef("drop SEP-RELAY handler and listen for SEP...")

	c, err := tcpServer(conn.downgrade(), sepConfig)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (conn *TCPConn) downgrade() *net.TCPConn {
	relayLogger.Tracef("dropping TLS connection")

	conn.tlsConn = nil

	return conn.transport
}
