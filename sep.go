package sep

import (
	"crypto/tls"
	"io"
	"os"
)

const (
	DefaultPort             = "33000"
	DefaultFingerprintSuite = "sha3-256"
	DefaultResolveDomain    = "ace-sep.de"
	AlpSEP                  = "SEP/0"
	AlpSEPRelay             = "SEP-RELAY/0"
)

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
		keyLogWriter, err = os.OpenFile(sslKeyLogFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			panic(err)
		}
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
