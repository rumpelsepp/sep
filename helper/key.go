package helper

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
)

// GenKeypairPEM generates a fresh new keypair and returns a
// the certificate and the key is pem encoded bytes.
func GenKeypairPEM() ([]byte, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %s", priv)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %s", err)
	}

	template := x509.Certificate{SerialNumber: serialNumber}

	derCert, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})

	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: b})

	return certPEM, keyPEM, nil
}

// GenKeypair generates a fresh keypair and returns a parsed tls.Certificate.
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

// GenKeypair generates a fresh keypair and stores the key and the corresponding
// certificate in the supplied paths. PEM encoding is used.
func GenKeypairFile(keyPath, certPath string) error {
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("private key already exists")
	}

	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf("certificate already exists")
	}

	certPEM, keyPEM, err := GenKeypairPEM()
	if err != nil {
		return err
	}

	certBase := filepath.Dir(certPath)
	keyBase := filepath.Dir(keyPath)

	err = os.MkdirAll(certBase, 0700)
	if err != nil {
		return err
	}
	if certBase != keyBase {
		err = os.MkdirAll(keyBase, 0700)
		if err != nil {
			return err
		}
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	_, err = io.Copy(certOut, bytes.NewBuffer(certPEM))
	if err != nil {
		return err
	}
	_, err = io.Copy(keyOut, bytes.NewBuffer(keyPEM))
	if err != nil {
		return err
	}

	return nil
}
