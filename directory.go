package sep

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"text/template"
	"time"
)

type DirectoryRecordSet struct {
	Addresses []string  `json:"addresses,omitempty"`
	Relays    []string  `json:"relay,omitempty"`
	Blob      []byte    `json:"blob,omitempty"`
	PubKey    []byte    `json:"pubkey"`
	TTL       uint      `json:"ttl"`
	Timestamp time.Time `json:"timestamp"`
	Signature []byte    `json:"signature"`
	Version   uint      `json:"version"`
}

func (a *DirectoryRecordSet) concat() []byte {
	var res []byte

	sort.Strings(a.Addresses)
	sort.Strings(a.Relays)

	if len(a.Addresses) > 0 {
		res = append(res, []byte(strings.Join(a.Addresses, ""))...)
	}
	if len(a.Relays) > 0 {
		res = append(res, []byte(strings.Join(a.Relays, ""))...)
	}
	if len(a.Blob) != 0 {
		res = append(res, a.Blob...)
	}

	ttlBin := make([]byte, 8)
	binary.LittleEndian.PutUint64(ttlBin, uint64(a.TTL))

	res = append(res, ttlBin...)
	res = append(res, []byte(a.Timestamp.Format(time.RFC3339))...)
	res = append(res, a.PubKey...)

	return res
}

// Sign appends a base64-encoded signature, current timestamp and public key to
// the DirectoryPayload. The signature consists of the following data; | means
// concatenation, binary data must be converted to base64 strings first.
//
//  SHA3-256(Addresses | Delegators | Relays | Blob | TTL | Timestamp | PubKey)
func (a *DirectoryRecordSet) Sign(privateKey crypto.PrivateKey) error {
	var err error

	privKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return ErrInvalidKey
	}

	a.PubKey, err = x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return err
	}

	a.Timestamp = time.Now()
	a.Signature = ed25519.Sign(privKey, a.concat())

	return nil
}

// CheckSignature verifies the integrity and authenticity of a DirectoryPayload
// by validating the signature of the payload and checking whether the key used
// for signing matches the given fingerprint.
func (a *DirectoryRecordSet) CheckSignature(fingerprint *Fingerprint) (bool, error) {
	pk, err := x509.ParsePKIXPublicKey(a.PubKey)
	if err != nil {
		return false, err
	}
	pubKey, ok := pk.(ed25519.PublicKey)
	if !ok {
		return false, ErrInvalidKey
	}

	digestKey := internalDigest(pubKey)

	// Verify hash of public key against fingerprint
	if !bytes.Equal(digestKey, fingerprint.Bytes()[1:]) {
		return false, fmt.Errorf("unexpected public key")
	}
	if ok := ed25519.Verify(pubKey, a.concat(), a.Signature); !ok {
		return false, nil
	}
	if dur := time.Since(a.Timestamp); dur > time.Duration(a.TTL)*time.Second {
		return false, fmt.Errorf("recordSet expired")
	}
	return true, nil
}

// Pretty generates a nice, human readable representation of the RecordSet.
// This is useful for debugging.
func (a *DirectoryRecordSet) Pretty() string {
	tpl := `Addresses : {{range $i, $v := .Addresses}}{{$v}} {{end}}
Relays    : {{range $i, $v := .Relays}}{{$v}}{{end}}
Blob      : {{if .Blob}}{{.Blob | printf "%.33x…"}}{{end}}
Timestamp : {{.Timestamp}}
TTL       : {{.TTL}}
PubKey    : {{.PubKey | printf "%.33x…"}}
Signature : {{.Signature | printf "%.33x…"}}`
	var builder strings.Builder
	t := template.Must(template.New("pretty").Parse(tpl))
	if err := t.Execute(&builder, a); err != nil {
		panic(err)
	}
	return builder.String()
}

// Fingerprint returns the canonical fingerprint which is associated with
// this RecordSet instance. It errors out if the PubKey record is empty or invalid.
// The returned fingerprint is always canonical.
func (rs *DirectoryRecordSet) Fingerprint() (*Fingerprint, error) {
	pubKey, err := x509.ParsePKIXPublicKey(rs.PubKey)
	if err != nil {
		return nil, err
	}
	return FingerprintFromPublicKey(pubKey)
}

type DirectoryClient struct {
	AnnounceEndpoint string

	httpClient *http.Client
	privateKey crypto.PrivateKey
}

// NewDirectoryClient creates a new type DirectoryClient with default settings
func NewDirectoryClient(addr string, config *tls.Config) *DirectoryClient {
	return &DirectoryClient{
		AnnounceEndpoint: addr,
		privateKey:       config.Certificates[0].PrivateKey,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: config,
			},
			Timeout: 10 * time.Second,
		},
	}
}

// Announce serves as universal function call for announcing a given record set.
// Depending on the AnnounceFlags set different schemes are executed simultaneously.
func (a *DirectoryClient) Announce(payload *DirectoryRecordSet) error {
	if err := payload.Sign(a.privateKey); err != nil {
		return err
	}

	u := url.URL{}
	u.Scheme = "https"
	u.Host = a.AnnounceEndpoint
	payload.Version = 0

	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	Logger.Debugf("PUT request to: %s", u.String())
	Logger.Debugf("JSON payload: %s", b)

	req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(b))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		// The server responds with an error message.
		// Read it if available and log it.
		defer resp.Body.Close()
		if body, err := ioutil.ReadAll(resp.Body); err != nil {
			Logger.Warningln(string(body))
		}
		return fmt.Errorf("Status Code %d", resp.StatusCode)
	}

	Logger.Debugf("answer: %+v", resp)

	return nil
}

// AnnounceAddresses is a helper function that wraps the more generic Announce()
func (a *DirectoryClient) AnnounceAddresses(addresses []string, ttl uint) error {
	return a.Announce(&DirectoryRecordSet{
		Addresses: addresses,
		TTL:       ttl,
	})
}

// AnnounceBlob is a helper function that wraps the more generic Announce()
func (a *DirectoryClient) AnnounceBlob(data []byte, ttl uint) error {
	return a.Announce(&DirectoryRecordSet{
		Blob: data,
		TTL:  ttl,
	})
}

func (a *DirectoryClient) Discover(fingerprint *Fingerprint) (*DirectoryRecordSet, error) {
	Logger.Debugf("discovering '%s'", fingerprint.String())

	payload, err := a.discoverViaHTTPS(fingerprint)
	if err == nil {
		Logger.Debugf("got RecordSet via HTTP: %s", payload.Pretty())
		return payload, nil
	}
	Logger.Debugf("discover via HTTPS failed: %s", err)
	return nil, fmt.Errorf("fingerprint '%s' not found", fingerprint.String())
}

// discoverViaHTTPS queries a record set of the given fingerprint from the directory
// via HTTP GET and verifies its signature.
func (a *DirectoryClient) discoverViaHTTPS(fingerprint *Fingerprint) (*DirectoryRecordSet, error) {
	req, err := http.NewRequest(http.MethodGet, fingerprint.WellKnownURI(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", fingerprint.WellKnownURI(), resp.Status)
	}

	rawData, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	var payload DirectoryRecordSet
	err = json.Unmarshal(rawData, &payload)
	if err != nil {
		return nil, err
	}

	if payload.Version != 0 {
		return nil, fmt.Errorf("unsupported api version")
	}

	ok, err := payload.CheckSignature(fingerprint)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("signature check failed")
	}

	return &payload, nil
}

// DiscoverAddresses is a helper function that wraps the more generic
// Discover().
func (a *DirectoryClient) DiscoverAddresses(fingerprint *Fingerprint) ([]string, error) {
	payload, err := a.Discover(fingerprint)
	if err != nil {
		return nil, err
	}
	sortByRFC6724(payload.Addresses)
	return payload.Addresses, nil
}

// DiscoverBlob is a helper function that wraps the more generic discoverViaHTTPS().
func (a *DirectoryClient) DiscoverBlob(fingerprint *Fingerprint) ([]byte, error) {
	// We want this to be specifically via HTTP for size reasons
	payload, err := a.discoverViaHTTPS(fingerprint)
	if err != nil {
		return nil, err
	}
	if len(payload.Blob) == 0 {
		return nil, fmt.Errorf("no blob available for: %s", fingerprint.String())
	}
	return payload.Blob, nil
}

// DiscoverRelays is a helper function that wraps the more generic Discover().
func (a *DirectoryClient) DiscoverRelays(fingerprint *Fingerprint) ([]string, error) {
	payload, err := a.Discover(fingerprint)
	if err != nil {
		return nil, err
	}
	return payload.Relays, nil
}
