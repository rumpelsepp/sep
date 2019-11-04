package sep

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
)

type DirectoryOptions struct {
	DNSTTL    int    `json:"dns_ttl"`
	Suite     string `json:"suite"`
	WholeCert bool   `json:"wholecert"`
}

type DirectoryRecordSet struct {
	Addresses []string          `json:"addresses,omitempty"`
	Relays    []string          `json:"relay,omitempty"`
	Blob      []byte            `json:"blob,omitempty"`
	PubKey    []byte            `json:"pubkey"`
	TTL       uint              `json:"ttl"`
	Timestamp time.Time         `json:"timestamp"`
	Signature []byte            `json:"signature"`
	Version   uint              `json:"version"`
	Options   *DirectoryOptions `json:"options,omitempty"`
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

	a.Timestamp = time.Now()

	privKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return ErrInvalidKey
	}

	a.PubKey, err = x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return err
	}

	a.Signature = ed25519.Sign(privKey, a.concat())
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
	digestKey := internalDigest(a.PubKey)

	if !bytes.Equal(digestKey, fingerprint.Bytes()[1:]) {
		return false, fmt.Errorf("unexpected public key")
	}

	remotePK, err := x509.ParsePKIXPublicKey(a.PubKey)
	if err != nil {
		return false, err
	}

	remotePubKey, ok := remotePK.(ed25519.PublicKey)
	if !ok {
		return false, ErrInvalidKey
	}

	if ok := ed25519.Verify(remotePubKey, a.concat(), a.Signature); !ok {
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
	return FingerprintFromPublicKey(rs.PubKey)
}

const (
	// DiscoverFlagUseDNS defines whether system DNS is used during discovery
	DiscoverFlagUseDNS = 1 << iota
	// DiscoverFlagUseDoH defines whether DNS over HTTPS is used during discovery
	DiscoverFlagUseDoH
	// DiscoverFlagUseHTTPS defines whether HTTPS GET is used during discovery
	DiscoverFlagUseHTTPS
	// DiscoverFlagUseMND defines whether local broadcast is used during discovery
	DiscoverFlagUseMND
)

const (
	AnnounceFlagUseHTTPS = 1 << iota
	AnnounceFlagUseMND
)

type DirectoryClient struct {
	AnnounceEndpoint string
	DiscoverFlags    int
	DoHEndpoint      string
	AnnounceFlags    int

	httpClient *http.Client
	keypair    *tls.Certificate
	options    *DirectoryOptions

	MNDListener *MNDListener
}

// NewDirectoryClient creates a new type DirectoryClient with default settings
// TODO Add more details about those defaults, e.g. DiscoverFlags
func NewDirectoryClient(addr string, keypair *tls.Certificate, options *DirectoryOptions) *DirectoryClient {
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			TLSClientConfig:    NewDefaultTLSConfig(*keypair),
		},
		Timeout: 10 * time.Second,
	}

	return &DirectoryClient{
		AnnounceEndpoint: addr,
		DoHEndpoint:      DefaultDoHURI,
		keypair:          keypair,
		httpClient:       client,
		options:          options,
		DiscoverFlags: DiscoverFlagUseDoH |
			DiscoverFlagUseHTTPS,
		AnnounceFlags: AnnounceFlagUseHTTPS,

		MNDListener: nil,
	}
}

// Announce serves as universal function call for announcing a given record set.
// Depending on the AnnounceFlags set different schemes are executed simultaneously.
// The record set is signed prior to sending.
//  - HTTPs : via HTTP PUT and validate signature
//  - MND   : Discover in local network with MND protocol
func (a *DirectoryClient) Announce(payload *DirectoryRecordSet) error {
	if a.AnnounceFlags == 0 {
		return fmt.Errorf("no AnnounceFlags set")
	}

	if (a.AnnounceFlags & AnnounceFlagUseMND) != 0 {
		err := a.announceViaMND(payload)
		if err != nil {
			Logger.Warningf("announce via MND failed: %s", err)
		} else {
			Logger.Debugf("announce via MND successful")
		}
	}

	// This just reimplements the old .Announce functionality for now.
	var (
		err error
	)
	if (a.AnnounceFlags & AnnounceFlagUseHTTPS) != 0 {
		err = a.announceViaHTTPS(payload)
		if err != nil {
			Logger.Warningf("announce via HTTPS failed: %w", err)
		} else {
			Logger.Debugf("announce via HTTPS successful")
		}
	}

	return err
}

// announceViaHTTPS signs the record set and sends it to the directory in a
// json-encoded HTTP PUT request.
func (a *DirectoryClient) announceViaHTTPS(payload *DirectoryRecordSet) error {
	if err := payload.Sign(a.keypair.PrivateKey); err != nil {
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

	reader := bytes.NewReader(b)
	req, err := http.NewRequest("PUT", u.String(), reader)
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

// announceViaMND checks for an attached MND listener and if present updates the
// RecordSet.
func (a *DirectoryClient) announceViaMND(payload *DirectoryRecordSet) error {
	if a.MNDListener == nil {
		return fmt.Errorf("no attached MNDListener ")
	}

	return a.MNDListener.ServeRecordSet(payload)
}

// AnnounceAddresses is a helper function that wraps the more generic Announce()
func (a *DirectoryClient) AnnounceAddresses(addresses []string, ttl uint) error {
	payload := &DirectoryRecordSet{
		Addresses: addresses,
		Options:   a.options,
		TTL:       ttl,
	}

	return a.Announce(payload)
}

// AnnounceBlob is a helper function that wraps the more generic Announce()
func (a *DirectoryClient) AnnounceBlob(data []byte, ttl uint) error {
	var (
		payload = &DirectoryRecordSet{
			Blob:    data,
			TTL:     ttl,
			Options: a.options,
		}
	)

	return a.Announce(payload)
}

// Discover serves as universal function call for discovering the record set of a
// fingerprint. Only record sets with valid signatures are returned. Depending
// on the DiscoverFlags set different schemes are tried, but always in this order:
//  - MND   : Discover in local network with UDP broadcasts
//  - DoH   : Discover via the DoH JSON flavor using HTTP GET.
//  - DNS   : Discover via DNS TXT records and validate signature
//  - HTTPS : Discover via HTTPS GET and validate signature
func (a *DirectoryClient) Discover(fingerprint *Fingerprint) (*DirectoryRecordSet, error) {
	if a.DiscoverFlags == 0 {
		return nil, fmt.Errorf("no DiscoverFlags present")
	}

	Logger.Debugf("discovering '%s'", fingerprint.String())

	if (a.DiscoverFlags & DiscoverFlagUseMND) != 0 {
		payload, err := a.discoverViaMND(fingerprint)
		if err == nil {
			// FIXME: This debug message is fugly!
			Logger.Debugf("got RecordSet via MND: %s", payload.Pretty())
			return payload, nil
		}
		Logger.Debugf("discover via MND failed: %s", err)
	}

	if (a.DiscoverFlags & DiscoverFlagUseDoH) != 0 {
		payload, err := a.discoverViaDoH(fingerprint)
		if err == nil {
			Logger.Debugf("got RecordSet via DoH: %s", payload.Pretty())
			return payload, nil
		}
		Logger.Debugf("discover via DoH failed: %s", err)
	}

	if (a.DiscoverFlags & DiscoverFlagUseDNS) != 0 {
		payload, err := a.discoverViaDNS(fingerprint)
		if err == nil {
			Logger.Debugf("got RecordSet via DNS: %s", payload.Pretty())
			return payload, nil
		}
		Logger.Debugf("discover via system dns failed: %s", err)
	}

	if (a.DiscoverFlags & DiscoverFlagUseHTTPS) != 0 {
		payload, err := a.discoverViaHTTPS(fingerprint)
		if err == nil {
			Logger.Debugf("got RecordSet via HTTP: %s", payload.Pretty())
			return payload, nil
		}
		Logger.Debugf("discover via HTTPS failed: %s", err)
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

// discoverViaDNS queries a record set of the given fingerprint from the directory
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

// discoverViaHTTPS queries a record set of the given fingerprint from the directory
// via HTTP GET and verifies its signature.
func (a *DirectoryClient) discoverViaHTTPS(fingerprint *Fingerprint) (*DirectoryRecordSet, error) {
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

// discoverViaMND sends a discovery packet via udp to a broadcast address and
// listens for the response of the queried node. If a response is received, the
// signature of the record set is verified.
func (a *DirectoryClient) discoverViaMND(fingerprint *Fingerprint) (*DirectoryRecordSet, error) {
	Logger.Debugf("Discovering via MND: %s", fingerprint.String())

	// Define request payload with target FP as bytes in blob entry
	req := &DirectoryRecordSet{
		TTL:  5,
		Blob: fingerprint.Bytes(),
	}

	if err := req.Sign(a.keypair.PrivateKey); err != nil {
		return nil, err
	}

	go mndBroadcastRequest(req)

	resp, err := mndListenForResponse(fingerprint, 2*time.Second)
	if err != nil {
		return nil, err
	}
	signatureOk, err := resp.CheckSignature(fingerprint)
	if err != nil {
		Logger.Debugf("signature check failed: %s", err)
		return nil, err
	}
	if !signatureOk {
		Logger.Debug("response has invalid signature")
		return nil, fmt.Errorf("signature check failed")
	}

	return resp, nil
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
