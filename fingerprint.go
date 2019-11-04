package sep

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"strings"

	"git.sr.ht/~rumpelsepp/ni"
)

type Fingerprint struct {
	*ni.URL
}

func checkDigest(digest string) error {
	if digest == "sha3-256" {
		return nil
	}
	return fmt.Errorf("suite '%s' is not implemented", digest)
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
func FingerprintFromCertificate(cert []byte) (*Fingerprint, error) {
	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	pubkeyDer, err := x509.MarshalPKIXPublicKey(parsedCert.PublicKey)
	if err != nil {
		return nil, err
	}

	return FingerprintFromPublicKey(pubkeyDer)
}

// FingerprintFromNIString parses an NI string to type fingerprint.
func FingerprintFromNIString(rawFingerprint string) (*Fingerprint, error) {
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
func FingerprintFromPublicKey(pubKey []byte) (*Fingerprint, error) {
	if parsedPubKey, err := x509.ParsePKIXPublicKey(pubKey); err == nil {
		if _, ok := parsedPubKey.(ed25519.PublicKey); !ok {
			return nil, ErrInvalidKey
		}
	} else {
		return nil, fmt.Errorf("PublicKey: invalid der-encoding")
	}

	d := internalDigest(pubKey)
	niURL, err := ni.DigestToNI(d, DefaultFingerprintSuite, "")
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

// Canonical returns a string representation of the Fingerprint with an
// empty authority. This form is intended to be used internally e.g. for
// map or database keys, since the authority carries no relevant information
// for authentication.
func (fp *Fingerprint) Canonical() string {
	newFP, _ := ni.ParseNI(fmt.Sprintf("ni:///%s;%s", fp.URL.Alg, fp.URL.Val))
	return newFP.String()
}

// Short returns a short string describing the node. Useful for logs.
func (fp *Fingerprint) Short() string {
	return fmt.Sprintf("%s", fp.URL.Val[:8])
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
