package sephelper

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
)

// GenKeypairPEM generates a fresh new keypair and returns a
// the certificate and the key is pem encoded bytes.
func GenKeyPEM() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", priv)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: privDER})

	return privPEM, nil
}

func GenCertificate(priv ed25519.PrivateKey) (tls.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial number: %s", err)
	}

	template := x509.Certificate{SerialNumber: serialNumber}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: privDER})

	return tls.X509KeyPair(certPEM, privPEM)
}

// GenKeypair generates a fresh keypair and returns a parsed tls.Certificate.
func GenTLSKeypair() (tls.Certificate, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate private key: %w", priv)
	}
	return GenCertificate(priv)
}

// GenKeypair generates a fresh keypair and stores the key and the corresponding
// certificate in the supplied paths. PEM encoding is used.
func GenKeyFile(keyPath string) error {
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("private key already exists")
	}

	privPEM, err := GenKeyPEM()
	if err != nil {
		return err
	}

	keyBase := filepath.Dir(keyPath)

	err = os.MkdirAll(keyBase, 0700)
	if err != nil {
		return err
	}

	privOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer privOut.Close()

	_, err = io.Copy(privOut, bytes.NewReader(privPEM))
	if err != nil {
		return err
	}

	return nil
}

func LoadKey(keyPath string) (ed25519.PrivateKey, error) {
	file, err := os.Open(keyPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	privPEM, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("PEM decoding error")
	}

	p, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing key failed")
	}

	priv, ok := p.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("wrong key type")
	}

	return priv, nil
}

func LoadKeyCert(keyPath string) (tls.Certificate, error) {
	priv, err := LoadKey(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	return GenCertificate(priv)
}
