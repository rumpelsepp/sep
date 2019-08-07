package sep

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/sha3"
)

// BidirectCopy is a helper which spawns two goroutines.
// Each goroutine copies data from left to right and right to
// left respectively.
func BidirectCopy(left io.ReadWriteCloser, right io.ReadWriteCloser) (int, int, error) {
	var (
		n1   = 0
		n2   = 0
		err  error
		err1 error
		err2 error
		wg   sync.WaitGroup
	)

	wg.Add(2)

	go func() {
		if n, err := io.Copy(right, left); err != nil {
			err1 = err
		} else {
			n1 = int(n)
		}

		right.Close()
		wg.Done()
	}()

	go func() {
		if n, err := io.Copy(left, right); err != nil {
			err2 = err
		} else {
			n2 = int(n)
		}

		left.Close()
		wg.Done()
	}()

	wg.Wait()

	if err1 != nil && err2 != nil {
		err = fmt.Errorf("both copier failed; left: %s; right: %s", err1, err2)
	} else {
		if err1 != nil {
			err = err1
		} else if err2 != nil {
			err = err2
		}
	}

	return n1, n2, err
}

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

// GatherAllAddresses gathers the IP addresses of all local interfaces and
// appends the specified port. If no port is provided (""), the default port is
// appended.
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
			Logger.Warning(err)
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

func gatherAllBroadcastAddresses() ([]string, error) {
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
				if n.IP.To4() == nil {
					continue
				}
				if n.IP.IsGlobalUnicast() {
					ip := n.IP.To4()
					tmp := binary.BigEndian.Uint32(ip) | ^binary.BigEndian.Uint32(n.Mask)
					binary.BigEndian.PutUint32(ip, tmp)
					addrs = append(addrs, ip.String())
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
	Logger.Debugf("Loading authorized fingerprints from %s", path)

	m := make(map[string]*Fingerprint)

	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("file does not exist: %w", err)
	}

	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read error: %w", err)
		}

		// Ignore comments
		if strings.HasPrefix(scanner.Text(), "#") {
			Logger.Debugf("Ignoring comment:\t\"%s\"", scanner.Text())
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
			Logger.Debugf("Could not parse:\t\"%s\"", scanner.Text())
			continue
		}

		m[fields[1]] = fingerprint
	}

	Logger.Debugln("Extracted these fingerprints:")
	for k, v := range m {
		Logger.Debugf("\t%s\t%s", v, k)
	}

	return m, nil
}

// AddAuthorizedFingerprint appends the given fingerprint and alias to the
// specified file such that LoadAuthorizedFingerprints() can understand.
func AddAuthorizedFingerprint(path string, fingerprint *Fingerprint, alias string) error {
	Logger.Debugf("Trying to add fingerprint %s as %s", fingerprint.String(), alias)

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

func internalDigest(p []byte) []byte {
	digest := sha3.Sum256(p)
	return digest[:]
}
