package sep

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/sha3"
)

type DirectoryOptions struct {
	DNSTTL    int    `json:"dns_ttl"`
	Suite     string `json:"suite"`
	WholeCert bool   `json:"wholecert"`
}

type DirectoryRecordSet struct {
	Addresses  []string          `json:"addresses,omitempty"`
	Delegators []string          `json:"delegator,omitempty"`
	Relays     []string          `json:"relay,omitempty"`
	Blob       []byte            `json:"blob,omitempty"`
	PubKey     []byte            `json:"pubkey"`
	TTL        uint              `json:"ttl"`
	Timestamp  time.Time         `json:"timestamp"`
	Signature  []byte            `json:"signature"`
	Version    uint              `json:"version"`
	Options    *DirectoryOptions `json:"options,omitempty"`
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (a *DirectoryRecordSet) digest() ([]byte, error) {
	var res []byte

	sort.Strings(a.Addresses)
	sort.Strings(a.Delegators)
	sort.Strings(a.Relays)

	if len(a.Addresses) > 0 {
		res = append(res, []byte(strings.Join(a.Addresses, ""))...)
	}
	if len(a.Delegators) > 0 {
		res = append(res, []byte(strings.Join(a.Delegators, ""))...)
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

	timeBin, err := a.Timestamp.MarshalBinary()
	if err != nil {
		return nil, err
	}

	res = append(res, timeBin...)
	res = append(res, a.PubKey...)
	digest := sha3.Sum256([]byte(res))

	return digest[:], nil
}

// Sign appends a base64-encoded signature, current timestamp and public key to
// the DirectoryPayload. The signature consists of the following data; | means
// concatenation, binary data must be converted to base64 strings first.
//
//  SHA3-256(Addresses | Delegators | Relays | Blob | TTL | Timestamp | PubKey)
func (a *DirectoryRecordSet) Sign(privateKey crypto.PrivateKey) error {
	// FIXME: Do not panic!!!
	var (
		err     error
		privKey = privateKey.(*ecdsa.PrivateKey)
	)

	a.Timestamp = time.Now()
	a.PubKey, err = x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return err
	}

	digest, err := a.digest()
	if err != nil {
		return err
	}

	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
	if err != nil {
		return err
	}

	a.Signature, err = asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return err
	}

	return nil
}

// CheckSignature verifies the integrity and authenticity of a DirectoryPayload
// by validating the signature of the payload and checking whether the key used
// for signing matches the given fingerprint.
func (a *DirectoryRecordSet) CheckSignature(fingerprint *Fingerprint) (bool, error) {
	// Verify hash of public key against fingerprint
	digestKey := sha3.Sum256(a.PubKey)
	if !bytes.Equal(digestKey[:], fingerprint.Bytes()[1:]) {
		return false, fmt.Errorf("unexpected public key")
	}

	var signature ecdsaSignature
	_, err := asn1.Unmarshal(a.Signature, &signature)
	if err != nil {
		return false, err
	}

	remotePK, err := x509.ParsePKIXPublicKey(a.PubKey)
	if err != nil {
		return false, err
	}

	// FIXME: don't panic
	remotePubKey := remotePK.(*ecdsa.PublicKey)
	digest, err := a.digest()
	if err != nil {
		return false, err
	}

	if ok := ecdsa.Verify(remotePubKey, digest, signature.R, signature.S); !ok {
		return false, nil
	}

	if dur := time.Since(a.Timestamp); dur > time.Duration(a.TTL)*time.Second {
		return false, fmt.Errorf("recordSet expired")
	}

	return true, nil
}

// Pretty generates a nice, human readable representation of the
// RecordSet. Is useful for debugging,
func (a *DirectoryRecordSet) Pretty() string {
	tpl := `Addresses : {{range $i, $v := .Addresses}}{{$v}} {{end}}
Delegators: {{range $i, $v := .Delegators}}{{$v}}{{end}}
Relays    : {{range $i, $v := .Relays}}{{$v}}{{end}}
Blob      : {{if .Blob}}{{.Blob | printf "%.33x…"}}{{end}}
Timestamp : {{.Timestamp}}
TTL       : {{.TTL}}
PubKey    : {{.PubKey | printf "%.33x…"}}
Signature : {{.Signature | printf "%.33x…"}}
`
	var builder strings.Builder
	t := template.Must(template.New("pretty").Parse(tpl))
	if err := t.Execute(&builder, a); err != nil {
		panic(err)
	}
	return builder.String()
}

type DirectoryResponse struct {
	Fingerprint *Fingerprint
	Location    *url.URL
}

func parseDirectoryResponse(header http.Header) (*DirectoryResponse, error) {
	rawLocation := header.Get("Content-Location")
	location, err := url.Parse(rawLocation)
	if err != nil {
		return nil, err
	}

	rawFingerprint := header.Get("Fingerprint")
	fingerprint, err := FingerprintFromNIString(rawFingerprint)
	if err != nil {
		return nil, err
	}

	response := &DirectoryResponse{
		Location:    location,
		Fingerprint: fingerprint,
	}

	return response, nil
}

const (
	DiscoverFlagUseSystemDNS = 1 << iota
	DiscoverFlagUseDoH
	DiscoverFlagUseHTTPs
	DiscoverFlagUseMND
)

type DirectoryClient struct {
	AnnounceEndpoint string
	DiscoverFlags    int
	DoHEndpoint      string

	httpClient *http.Client
	keypair    *tls.Certificate
	options    *DirectoryOptions
	// We need this for MND Discovery
	// MNDDiscover   *mnd.Node
}

// NewDirectoryClient creates a new type DirectoryClient with default settings
// TODO Add more details about those defaults, e.g. DiscoverFlags
func NewDirectoryClient(addr string, keypair *tls.Certificate, options *DirectoryOptions) DirectoryClient {
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			TLSClientConfig:    NewDefaultTLSConfig(*keypair),
		},
	}

	return DirectoryClient{
		AnnounceEndpoint: addr,
		DoHEndpoint:      DefaultDoHURI,
		keypair:          keypair,
		httpClient:       client,
		options:          options,
		DiscoverFlags:    DiscoverFlagUseDoH | DiscoverFlagUseHTTPs,
	}
}

// Announce signs the record set and sends it to the directory in a json-encoded
// HTTP PUT request.
func (a *DirectoryClient) Announce(payload DirectoryRecordSet) (*DirectoryResponse, error) {
	err := payload.Sign(a.keypair.PrivateKey)
	if err != nil {
		return nil, err
	}

	u := url.URL{}
	u.Scheme = "https"
	u.Host = a.AnnounceEndpoint
	payload.Version = 0

	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	logger.Debugf("PUT request to: %s", u.String())
	logger.Debugf("JSON payload: %s", b)

	reader := bytes.NewReader(b)
	req, err := http.NewRequest("PUT", u.String(), reader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		// The server responds with an error message.
		// Read it if available and log it.
		defer resp.Body.Close()
		if body, err := ioutil.ReadAll(resp.Body); err != nil {
			logger.Warningln(string(body))
		}

		return nil, fmt.Errorf("Status Code %d", resp.StatusCode)
	}

	logger.Debugf("answer: %+v", resp)

	response, err := parseDirectoryResponse(resp.Header)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// AnnounceAddresses is a helper function that wraps the more generic Announce()
func (a *DirectoryClient) AnnounceAddresses(addresses []string, ttl uint) (*DirectoryResponse, error) {
	payload := DirectoryRecordSet{
		Addresses: addresses,
		Options:   a.options,
		TTL:       ttl,
	}

	return a.Announce(payload)
}

// AnnounceBlob is a helper function that wraps the more generic Announce()
func (a *DirectoryClient) AnnounceBlob(data []byte, ttl uint) (*DirectoryResponse, error) {
	var (
		payload = DirectoryRecordSet{
			Blob:    data,
			TTL:     ttl,
			Options: a.options,
		}
	)

	return a.Announce(payload)
}

// Discover serves universal function call for discovering the record set of a
// fingerprint. Depending on the DiscoverFlags set different schemes are tried,
// but always in this order:
//  - MND     : Discover in local network with MND protocol
//  - DoH     : Discover via the DoH JSON flavor using HTTP GET.
//  - ni-URI  : Discover via DNS TXT records and validate signature
//  - HTTP    : Discover via HTTP GET and validate signature
func (a *DirectoryClient) Discover(fingerprint *Fingerprint) (*DirectoryRecordSet, error) {
	if a.DiscoverFlags == 0 {
		return nil, fmt.Errorf("no DiscoverFlags present")
	}

	logger.Debugf("discovering '%s'", fingerprint.String())

	// MND is not implemented by now
	//
	// if (r.Flags&DiscoverFlagUseMND) != 0 && r.MNDResolver != nil {
	// 	addrs, err = r.MNDResolver.Request(fingerprint.URL)
	// 	if err == nil {
	// 		found = true
	// 	}
	// }

	if (a.DiscoverFlags & DiscoverFlagUseDoH) != 0 {
		payload, err := a.discoverViaDoH(fingerprint)
		if err == nil {
			logger.Debugf("got RecordSet via DoH: %v", payload)
			return payload, nil
		} else {
			logger.Debug(err)
		}
	}

	if (a.DiscoverFlags & DiscoverFlagUseSystemDNS) != 0 {
		payload, err := a.discoverViaDNS(fingerprint)
		if err == nil {
			logger.Debugf("got RecordSet via DNS: %v", payload)
			return payload, nil
		} else {
			logger.Debug(err)
		}
		logger.Debugf("discover via system dns failed: %s", err)
	}

	if (a.DiscoverFlags & DiscoverFlagUseHTTPs) != 0 {
		payload, err := a.discoverViaHTTP(fingerprint)
		if err == nil {
			logger.Debugf("got RecordSet via HTTP: %v", payload)
			return payload, nil
		} else {
			logger.Debug(err)
		}
		logger.Debugf("discover via http failed: %s", err)
	}

	return nil, fmt.Errorf("fingerprint '%s' not found", fingerprint.String())
}

type dohJSON struct {
	Status   int
	TC       bool
	RD       bool
	RA       bool
	CD       bool
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	}
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int
		Data string `json:"data"`
	}
}

func parseDNSResponse(txts []string) (*DirectoryRecordSet, error) {
	var (
		err     error
		payload DirectoryRecordSet
	)

	for _, txt := range txts {
		parts := strings.SplitN(strings.Trim(txt, "\""), "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s entry is corrupt", txt)
		}

		switch parts[0] {
		case "address":
			parsedURL, err := url.Parse(parts[1])
			if err != nil {
				return nil, err
			}
			payload.Addresses = append(payload.Addresses, parsedURL.String())

		case "relay":
			parsedURL, err := url.Parse(parts[1])
			if err != nil {
				return nil, err
			}
			payload.Relays = append(payload.Relays, parsedURL.String())

		case "delegator":
			parsedURL, err := url.Parse(parts[1])
			if err != nil {
				return nil, err
			}
			payload.Delegators = append(payload.Delegators, parsedURL.String())

		case "signature":
			payload.Signature, err = base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				return nil, err
			}

		case "pubkey":
			payload.PubKey, err = base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				return nil, err
			}

		case "ttl":
			tmp, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				return nil, err
			}
			payload.TTL = uint(tmp)

		case "timestamp":
			var tmp time.Time
			if err := tmp.UnmarshalText([]byte(parts[1])); err != nil {
				return nil, err
			}
			payload.Timestamp = tmp
		}
	}

	return &payload, nil
}

func (a *DirectoryClient) discoverViaDoH(fingerprint *Fingerprint) (*DirectoryRecordSet, error) {
	u := fmt.Sprintf(a.DoHEndpoint, fingerprint.FQDN())

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-json")

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

	var rawPayload dohJSON
	err = json.Unmarshal(rawData, &rawPayload)
	if err != nil {
		return nil, err
	}

	// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
	if rawPayload.Status != 0 {
		return nil, fmt.Errorf("dns error: %d", rawPayload.Status)
	}

	var txts []string
	for _, record := range rawPayload.Answer {
		txts = append(txts, record.Data)
	}

	payload, err := parseDNSResponse(txts)
	if err != nil {
		return nil, err
	}

	ok, err := payload.CheckSignature(fingerprint)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("signature check failed")
	}

	return payload, nil
}

// DiscoverViaDNS queries a record set of the given fingerprint from the directory
// via DNS TXT records and verifies its signature.
func (a *DirectoryClient) discoverViaDNS(fingerprint *Fingerprint) (*DirectoryRecordSet, error) {
	txts, err := net.LookupTXT(fingerprint.FQDN())
	if err != nil {
		return nil, err
	}

	payload, err := parseDNSResponse(txts)
	if err != nil {
		return nil, err
	}

	ok, err := payload.CheckSignature(fingerprint)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("signature check failed")
	}

	return payload, nil
}

// DiscoverViaHTTP queries a record set of the given fingerprint from the directory
// via HTTP GET and verifies its signature.
func (a *DirectoryClient) discoverViaHTTP(fingerprint *Fingerprint) (*DirectoryRecordSet, error) {
	req, err := http.NewRequest("GET", fingerprint.WellKnownURI(), nil)
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

// DiscoverBlob is a helper function that wraps the more generic DiscoverViaHTTP().
func (a *DirectoryClient) DiscoverBlob(fingerprint *Fingerprint) ([]byte, error) {
	// We want this to be specifically via HTTP for size reasons
	payload, err := a.discoverViaHTTP(fingerprint)
	if err != nil {
		return nil, err
	}

	if len(payload.Blob) == 0 {
		return nil, fmt.Errorf("no blob available for: %s", fingerprint.String())
	}

	return payload.Blob, nil
}

// DiscoverDelegators is a helper function that wraps the more generic
// Discover().
func (a *DirectoryClient) DiscoverDelegators(fingerprint *Fingerprint) ([]string, error) {
	payload, err := a.Discover(fingerprint)
	if err != nil {
		return nil, err
	}

	return payload.Delegators, nil
}

// DiscoverRelays is a helper function that wraps the more generic Discover().
func (a *DirectoryClient) DiscoverRelays(fingerprint *Fingerprint) ([]string, error) {
	payload, err := a.Discover(fingerprint)
	if err != nil {
		return nil, err
	}

	return payload.Relays, nil
}
