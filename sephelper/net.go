package sephelper

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"

	"github.com/pion/dtls"
)

// GatherAllAddresses gathers the IP addresses of all local interfaces and
// appends the specified port. If no port is provided (""), the default port is
// appended.
func GatherAllAddresses(transport, port string) ([]string, error) {
	addrs := []string{}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, intf := range interfaces {
		addresses, err := intf.Addrs()
		if err != nil {
			Logger.Warning(err)
			continue
		}

		for _, addr := range addresses {
			if n, ok := addr.(*net.IPNet); ok {
				if n.IP.IsGlobalUnicast() {
					addrStr := net.JoinHostPort(n.IP.String(), port)
					addrs = append(addrs, transport+"://"+addrStr)
				}
			}
		}
	}

	return addrs, nil
}

// NewDefaultTLSConfig returns type tls.Config with default settings utilized in
// SEP. This means TLS1.3 is required at minimum, client certificates are
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

func NewDefaultDTLSConfig(cert tls.Certificate) *dtls.Config {
	// XXX: fugly
	x509Cert, _ := x509.ParseCertificate(cert.Certificate[0])

	return &dtls.Config{
		Certificate:        x509Cert,
		PrivateKey:         cert.PrivateKey,
		ClientAuth:         dtls.RequireAnyClientCert,
		InsecureSkipVerify: false,
		MTU:                1200,
	}
}
