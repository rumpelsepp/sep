package sep

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"time"

	"git.sr.ht/~rumpelsepp/rlog"
	"github.com/fxamacker/cbor"
)

const (
	DefaultPort             = "33000"
	DefaultFingerprintSuite = "sha3-256"
	DefaultResolveDomain    = "ace-sep.de"
	DefaultDoHURI           = "https://cloudflare-dns.com/dns-query?name=%s&type=TXT"

	// DefaultMNDDiscoverPort is where packets are sent to during MND Discovery
	DefaultMNDDiscoverPort = "7868"
	// DefaultMNDResponsePort is where a response is expected during MND Discovery
	DefaultMNDResponsePort = "7869"
)

// At the moment, those variables are not needed for broadcast discovery!
// var (
// 	MNDIPv4MulticastAddress = net.ParseIP("224.0.0.251")
// 	MNDIPv6MulticastAddress = net.ParseIP("ff02::114") // TODO
// 	MNDPort                 = 7868                     // ASCII: MD (Multicast Discovery)
// )

var (
	cborEncodingOpts = cbor.EncOptions{Canonical: true, TimeRFC3339: true}
	Logger           = rlog.NewLogger(ioutil.Discard)
	ErrInvalidKey    = errors.New("invalid key: only ed25519 keys are supported")
)

func init() {
	Logger.SetModule("[sep]")
}

// NewDefaultTLSConfig returns type tls.Config with default settings utilized in
// SEP. This means TLS1.2 is required at minimum, client certificates are
// mandatory, session tickets are disabled, certificate checks are enforced,
// dynamic record sizing is disabled and environmental variable `SSLKEYLOGFILE`
// is respected.
func NewDefaultTLSConfig(cert tls.Certificate) *tls.Config {
	var (
		err          error
		keyLogWriter io.Writer
	)

	if sslKeyLogFile, ok := os.LookupEnv("SSLKEYLOGFILE"); ok {
		keyLogWriter, err = os.OpenFile(sslKeyLogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			panic(err)
		}
	}

	return &tls.Config{
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,  // We don't want this.
		InsecureSkipVerify:     false, // Disable this explicitely!!
		MinVersion:             tls.VersionTLS13,
		KeyLogWriter:           keyLogWriter,
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
	AllowedPeers []*Fingerprint
	TrustDB      TrustDatabase
	Directory    *DirectoryClient
	TCPFastOpen  bool
}

func (c *Config) Clone() Config {
	allowed := make([]*Fingerprint, len(c.AllowedPeers))
	copy(allowed, c.AllowedPeers)

	return Config{
		TLSConfig:    c.TLSConfig.Clone(),
		AllowedPeers: allowed,
		TrustDB:      c.TrustDB,
		Directory:    c.Directory,
		TCPFastOpen:  c.TCPFastOpen,
	}
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

type SEPVerifier func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

func VerifierAllowAll(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return nil
}

func MakeDefaultVerifier(allowed []*Fingerprint, database TrustDatabase) SEPVerifier {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, cert := range rawCerts {
			remoteFP, err := FingerprintFromCertificate(cert, DefaultFingerprintSuite, "")
			if err != nil {
				return err
			}

			for _, fp := range allowed {
				if FingerprintIsEqual(remoteFP, fp) {
					return nil
				}
			}
			if database != nil {
				if database.IsTrusted(remoteFP) {
					return nil
				}
			}
		}

		return fmt.Errorf("peer is not trusted")
	}
}
