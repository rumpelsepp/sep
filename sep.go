package sep

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"git.sr.ht/~rumpelsepp/rlog"
	"golang.org/x/crypto/sha3"
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

// From go/src/crypto/tls/cipher_suites.go
var tlsCipherSuiteNames = map[uint16]string{
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
	0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
}

type SepVerifier func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

func VerifierAllowAll(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return nil
}

func MakeDefaultVerifier(allowed []*Fingerprint, database TrustDatabase) SepVerifier {
	allowedDigests := make([][]byte, len(allowed))

	for i, peer := range allowed {
		// TODO
		allowedDigests[i] = peer.Bytes()[1:]
	}

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, cert := range rawCerts {
			parsedCert, err := x509.ParseCertificate(cert)
			if err != nil {
				return err
			}

			// FIXME: MUST NOT panic
			pubkey := parsedCert.PublicKey.(*ecdsa.PublicKey)
			pubkeyDer, err := x509.MarshalPKIXPublicKey(pubkey)
			if err != nil {
				return err
			}

			remoteDigest := sha3.Sum256(pubkeyDer)

			for _, allowedDigest := range allowedDigests {
				if bytes.Equal(remoteDigest[:], allowedDigest) {
					return nil
				}
			}

			fingerprint, err := FingerprintFromCertificate(cert, DefaultFingerprintSuite, DefaultResolveDomain)
			if err != nil {
				return err
			}

			if database != nil {
				if database.IsTrusted(fingerprint) {
					return nil
				}
			}
		}

		return fmt.Errorf("peer is not trusted")
	}
}
