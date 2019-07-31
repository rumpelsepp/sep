package sep

import (
	"bufio"
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
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"git.sr.ht/~rumpelsepp/ni"
	"git.sr.ht/~rumpelsepp/rlog"
	"golang.org/x/crypto/sha3"
	"golang.org/x/xerrors"
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

// GatherAllAddresses gathers the IP addresses of all local interfaces
func GatherAllAddresses(port string) ([]string, error) {
	if port == "" {
		port = DefaultPort
	}
	addrs := []string{}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, intf := range interfaces {
		addresses, err := intf.Addrs()
		if err != nil {
			rlog.Warning(err)
			continue
		}

		for _, addr := range addresses {
			if n, ok := addr.(*net.IPNet); ok {
				if n.IP.IsGlobalUnicast() {
					addrStr := net.JoinHostPort(n.IP.String(), port)
					addrs = append(addrs, "tcp://"+addrStr)
				}
			}
		}
	}

	return addrs, nil
}

// LoadAuthorizedFingerprints loads a file and returns a map of alias to
// fingerprint. Lines starting with "#" are ignored. The file needs to have one
// fingerprint and alias per line like so:
// 	ni://<authority>/<algorithm>;<value>		<alias>
//	ni://<authority>/<algorithm>;<value>		<alias>
//	ni://<authority>/<algorithm>;<value>		<alias>
func LoadAuthorizedFingerprints(path string) (map[string]*Fingerprint, error) {
	rlog.Debugf("Loading authorized fingerprints from %s\n", path)

	m := make(map[string]*Fingerprint)

	if _, err := os.Stat(path); err != nil {
		return nil, xerrors.Errorf("file does not exist: %w", err)
	}

	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, xerrors.Errorf("read error: %w", err)
		}

		// Ignore comments
		if strings.HasPrefix(scanner.Text(), "#") {
			rlog.Debugf("Ignoring comment:\t\"%s\"\n", scanner.Text())
			continue
		}
		// Ignore empty lines
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		// Ignore invalid lines
		fingerprint, err := FingerprintFromNIString(fields[0])
		if len(fields) != 2 || err != nil {
			rlog.Debugf("Could not parse:\t\"%s\"\n", scanner.Text())
			continue
		}

		m[fields[1]] = fingerprint
	}

	rlog.Debugln("Extracted these fingerprints:")
	for k, v := range m {
		rlog.Debugf("\t%s\t%s\n", v, k)
	}

	return m, nil
}

// AddAuthorizedFingerprint appends the given fingerprint and alias to the
// specified file such that LoadAuthorizedFingerprints() can understand.
func AddAuthorizedFingerprint(path string, fingerprint *Fingerprint, alias string) error {
	rlog.Debugf("Trying to add fingerprint %s as %s\n", fingerprint.String(), alias)

	// Create conf folder if not existing
	// Load file, if it is already there.
	if _, err := os.Stat(path); err != nil {
		basePath := filepath.Dir(path)
		err = os.MkdirAll(basePath, 0700)
		if err != nil {
			return err
		}
	} else {
		// Check whether fingerprint or alias already exist
		if authorizedFingerprints, err := LoadAuthorizedFingerprints(path); err == nil {
			for k, v := range authorizedFingerprints {
				if k == alias {
					return fmt.Errorf("alias '%s' exists", alias)
				}
				if FingerprintIsEqual(v, fingerprint) {
					return fmt.Errorf("fingerprint '%s' exists", fingerprint.String())
				}
			}
		}
	}

	// Append new fingerprint and alias
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	// Check if the last byte is a newline.
	// If not, then add to avoid corruption…
	if fileInfo, _ := file.Stat(); fileInfo.Size() > 0 {
		if _, err := file.Seek(-1, os.SEEK_END); err != nil {
			return err
		}

		buf := make([]byte, 1)
		if _, err := file.Read(buf); err != nil {
			return err
		}

		if buf[0] != '\n' {
			file.WriteString("\n")
		}
	}

	file.WriteString(fmt.Sprintf("%s\t%s\n", fingerprint.String(), alias))

	return nil
}
