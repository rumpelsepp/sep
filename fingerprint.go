package sep

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"strings"

	"git.sr.ht/~rumpelsepp/ni"
	"golang.org/x/crypto/sha3"
)

type Fingerprint struct {
	*ni.URL
}

func checkDigest(digest string) error {
	switch digest {
	case "sha-256", "sha-384", "sha-512", "sha3-224", "sha3-256", "sha3-384", "sha3-512":
		return nil

	case "sha-256-128", "sha-256-120", "sha-256-96", "sha-256-64", "sha-256-32":
		return fmt.Errorf("truncated suites are not supported")
	}

	return fmt.Errorf("suite %s is not implemented", digest)

}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		r[i] = b[len(b)-1-i]
	}

	return r
}

// FingerprintIsEqual checks whether two fingerprints are identical.
// The check is based on the hash of the public key and the used algorithm.
// This means two fingerprints based on the same public key but with different
// domains are considered identical.
// Different NI strings can also be identical due to Base64 encoding.
func FingerprintIsEqual(a, b *Fingerprint) bool {
	return bytes.Equal(a.Bytes(), b.Bytes())
}

// FingerprintFromCertificate transforms a TLS certificate to a DER-encoded public
// key and calls FingerprintFromPublicKey.
func FingerprintFromCertificate(cert []byte, suite string, domain string) (*Fingerprint, error) {
	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	pubkeyDer, err := x509.MarshalPKIXPublicKey(parsedCert.PublicKey)
	if err != nil {
		return nil, err
	}

	return FingerprintFromPublicKey(pubkeyDer, suite, domain)
}

// FingerprintFromNIString parses an NI string to type fingerprint.
func FingerprintFromNIString(rawFingerprint string) (*Fingerprint, error) {
	// TODO: ni.Parse
	niURL, err := ni.ParseNI(rawFingerprint)
	if err != nil {
		return nil, err
	}

	if err := checkDigest(niURL.Alg); err != nil {
		return nil, err
	}

	return &Fingerprint{niURL}, nil
}

// FingerprintFromPublicKey transforms a DER-encoded public key to a fingerprint.
// This is done by hashing the public key with the specified suite and inserting
// the given authority.
// These suites are supported:
// 		sha-256, sha-384 ,sha-512 ,sha3-224 ,sha3-256 ,sha3-384 ,sha3-512
func FingerprintFromPublicKey(pubKey []byte, suite string, domain string) (*Fingerprint, error) {
	var digest []byte

	switch suite {
	case "sha-256":
		d := sha256.Sum256(pubKey)
		digest = d[:]
	case "sha-384":
		d := sha512.Sum384(pubKey)
		digest = d[:]
	case "sha-512":
		d := sha512.Sum512(pubKey)
		digest = d[:]
	case "sha3-224":
		d := sha3.Sum224(pubKey)
		digest = d[:]
	case "sha3-256":
		d := sha3.Sum256(pubKey)
		digest = d[:]
	case "sha3-384":
		d := sha3.Sum384(pubKey)
		digest = d[:]
	case "sha3-512":
		d := sha3.Sum512(pubKey)
		digest = d[:]
	default:
		return nil, ni.ErrSuiteNotSupported
	}

	if domain == "" {
		domain = DefaultResolveDomain
	}

	niURL, err := ni.DigestToNI(digest[:], suite, domain)
	if err != nil {
		return nil, err
	}

	return FingerprintFromRawNI(niURL)
}

// FingerprintFromRawNI transforms an NI URL to type fingerprint.
func FingerprintFromRawNI(niURL *ni.URL) (*Fingerprint, error) {
	if err := checkDigest(niURL.Alg); err != nil {
		return nil, err
	}

	return &Fingerprint{niURL}, nil
}

// FQDN returns the Fully Qualified Domain Name representation of a fingerprint.
// For this purpose the byte representation of the fingerprint is reversed and
// prepended to the authority.
func (fp *Fingerprint) FQDN() string {
	var (
		fqdn       strings.Builder
		bin        = fp.Bytes()
		suiteID    = bin[0]
		digest     = bin[1:]
		labelBytes = 16
		fullLabels = len(digest) / labelBytes
	)

	digest = reverseBytes(digest)

	for i := 0; i < fullLabels; i++ {
		s := fmt.Sprintf("%x", digest[i*labelBytes:((i+1)*labelBytes)])
		fqdn.WriteString(s)
		fqdn.WriteString(".")
	}

	if len(digest) > fullLabels*labelBytes {
		s := fmt.Sprintf("%x", digest[fullLabels*labelBytes:])
		fqdn.WriteString(s)
		fqdn.WriteString(".")
	}

	fqdn.WriteString(fmt.Sprintf("%02x", suiteID))
	fqdn.WriteString(".")
	fqdn.WriteString(fp.URL.Authority)

	return fqdn.String()
}

// WellKnownURI returns the WellKnown representation of a fingerprint.
// This translates to the representation given in RCF6920, Section 4, with
// the addition that https is used instead of http.
func (fp *Fingerprint) WellKnownURI() string {
	// The RFC specifies an HTTP scheme (without s). ni-go implements the RFC
	// but in SEP we explicitely rely on HTTPS (with s). So this has to stay
	// here rather than in ni-go.
	return strings.Replace(fp.URL.WellKnownURI(), "http://", "https://", 1)
}
