package sep

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"git.sr.ht/~rumpelsepp/ni"
	"git.sr.ht/~rumpelsepp/rlog"
	"golang.org/x/crypto/sha3"
)

// TODO: error
func BidirectCopy(left io.ReadWriteCloser, right io.ReadWriteCloser) (int, int, error, error) {
	var (
		n1   = 0
		n2   = 0
		err1 error
		err2 error
		wg   sync.WaitGroup
	)

	wg.Add(2)

	go func() {
		if n, err := io.Copy(right, left); err != nil {
			rlog.Debugln(err)
			err1 = err
		} else {
			n1 = int(n)
		}

		right.Close()
		wg.Done()
	}()

	go func() {
		if n, err := io.Copy(left, right); err != nil {
			rlog.Debugln(err)
			err2 = err
		} else {
			n2 = int(n)
		}

		left.Close()
		wg.Done()
	}()

	wg.Wait()

	return n1, n2, err1, err2
}

func GenKeypairPEM() ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %s", priv)
	}

	pubDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshall private key: %s", priv)
	}

	notBefore := time.Now()
	notAfter := time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)
	digest := sha3.Sum256(pubDer)

	niURL, err := ni.DigestToNI(digest[:], "sha3-256", DefaultResolveDomain)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing digest: %s", err)
	}

	fingerprint, err := FingerprintFromRawNI(niURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing digest: %s", err)
	}

	commonName := fingerprint.FQDN()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})

	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	return certPEM, keyPEM, nil
}

func GenKeypair() (tls.Certificate, error) {
	certPEM, keyPEM, err := GenKeypairPEM()
	if err != nil {
		return tls.Certificate{}, err
	}

	keypair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	return keypair, nil
}
