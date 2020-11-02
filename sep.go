package sep

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"git.sr.ht/~rumpelsepp/rlog"
	"github.com/pion/dtls"
)

const DefaultFingerprintSuite = "sha3-256"

var (
	Logger        = rlog.NewLogger(ioutil.Discard)
	ErrInvalidKey = errors.New("invalid key: only ed25519 keys are supported")
)

func init() {
	Logger.SetModule("[sep]")
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

	case "udp", "udp4", "udp6":
		listener, err = udpListen(network, address, &config)

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
	DTLSConfig   *dtls.Config
	AllowedPeers []*Fingerprint
	TrustDB      TrustDatabase
	Directory    *DirectoryClient
}

func (c *Config) Clone() Config {
	allowed := make([]*Fingerprint, len(c.AllowedPeers))
	copy(allowed, c.AllowedPeers)

	var dtlsConfig dtls.Config
	if c.DTLSConfig != nil {
		dtlsConfig = *c.DTLSConfig
	}
	return Config{
		TLSConfig:    c.TLSConfig.Clone(),
		DTLSConfig:   &dtlsConfig,
		AllowedPeers: allowed,
		TrustDB:      c.TrustDB,
		Directory:    c.Directory,
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

	case "udp":
		dialer = newUDPDialer(config)

	default:
		return nil, fmt.Errorf("transport is not supported")
	}

	return dialer, nil
}

type SEPVerifier func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

func VerifierAllowAll(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return nil
}

func MakeDefaultVerifier(allowed []*Fingerprint, database TrustDatabase) SEPVerifier {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, cert := range rawCerts {
			remoteFP, err := FingerprintFromCertificate(cert)
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

// XXX: The prototypes are different, that's why these guys are needed…
func VerifierAllowAllUDP(cert *x509.Certificate, verified bool) error {
	return nil
}

// XXX: The prototypes are different, that's why these guys are needed…
func MakeDefaultVerifierUDP(allowed []*Fingerprint, database TrustDatabase) func(*x509.Certificate, bool) error {
	return func(cert *x509.Certificate, verified bool) error {
		remoteFP, err := FingerprintFromCertificate(cert.Raw)
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

		return fmt.Errorf("peer is not trusted")
	}
}
