package sep

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"git.sr.ht/~rumpelsepp/rlog"
)

const (
	DefaultPort             = "33000"
	DefaultFingerprintSuite = "sha3-256"
	DefaultResolveDomain    = "ace-sep.de"
	AlpSEP                  = "SEP/0"
	AlpSEPRelay             = "SEP-RELAY/0"
)

var (
	MNDIPv4MulticastAddress = net.ParseIP("224.0.0.251")
	MNDIPv6MulticastAddress = net.ParseIP("ff02::114") // TODO
	MNDPort                 = 7868                     // ASCII: MD (Multicast Discovery)
)

var logger = rlog.NewLogger()

func init() {
	logger.SetModule("[sep]")
}

// NewDefaultTLSConfig returns type tls.Config with default settings utilized in
// SEP. This means TLS1.2 is required at minimum, client certificates are
// mandatory, session tickets are disabled, certificate checks are enforced,
// dynamic record sizing is disabled and environmental variable `SSLKEYLOGFILE`
// is respected.
func NewDefaultTLSConfig(cert tls.Certificate) *tls.Config {
	var (
		err          error
		keyLogWriter *os.File
	)

	if sslKeyLogFile, ok := os.LookupEnv("SSLKEYLOGFILE"); ok {
		keyLogWriter, err = os.OpenFile(sslKeyLogFile, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}
		keyLogWriter.Seek(0, os.SEEK_END)
	}

	return &tls.Config{
		Certificates:                []tls.Certificate{cert},
		ClientAuth:                  tls.RequireAnyClientCert,
		SessionTicketsDisabled:      true,  // We don't want this.
		InsecureSkipVerify:          false, // Disable this explicitely!!
		DynamicRecordSizingDisabled: false,
		MinVersion:                  tls.VersionTLS12,
		KeyLogWriter:                keyLogWriter,
	}
}

type Listener interface {
	Accept() (Conn, error)
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

	// TODO: reintroduce this when stable
	// case "quic":
	// 	listener, err = quicListen(address, &config)

	default:
		panic("transport is not supported")
	}

	if err != nil {
		return nil, err
	}

	return listener, nil
}

type Config struct {
	TLSConfig    *tls.Config
	ResolveFlags int
	AllowedPeers []*Fingerprint
	TCPFastOpen  bool
	Database     TrustDatabase
}

type Conn interface {
	net.Conn
	RawConnection() net.Conn
	RemoteFingerprint() *Fingerprint
	LocalFingerprint() *Fingerprint
}

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
