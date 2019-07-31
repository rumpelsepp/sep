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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"git.sr.ht/~rumpelsepp/mnd"
	"golang.org/x/crypto/sha3"
)

type DirectoryOptions struct {
	DNSTTL    int    `json:"dns_ttl"`
	Suite     string `json:"suite"`
	WholeCert bool   `json:"wholecert"`
}

type DirectoryPayload struct {
	Addresses  []string          `json:"addresses,omitempty"`
	Delegators []string          `json:"delegator,omitempty"`
	Relays     []string          `json:"relay,omitempty"`
	Blob       string            `json:"blob,omitempty"`
	PubKey     string            `json:"pubkey"`
	TTL        int               `json:"ttl"`
	Timestamp  string            `json:"timestamp"`
	Signature  string            `json:"signature"`
	Version    int               `json:"version"`
	Options    *DirectoryOptions `json:"options,omitempty"`
}

type DirectoryResponse struct {
	TTL         time.Duration
	Fingerprint *Fingerprint
	Location    *url.URL
}

type ecdsaSignature struct {
	R, S *big.Int
}

func concat(date []string) string {
	var res string
	for _, subStr := range date {
		res += subStr
	}
	return res
}

func (a *DirectoryPayload) digest() []byte {
	var res string

	if len(a.Addresses) > 0 {
		res += concat(a.Addresses)
	}
	if len(a.Delegators) > 0 {
		res += concat(a.Delegators)
	}
	if len(a.Relays) > 0 {
		res += concat(a.Relays)
	}
	if a.Blob != "" {
		res += a.Blob
	}

	res += string(a.TTL)
	res += a.Timestamp
	res += a.PubKey

	digest := sha3.Sum256([]byte(res))

	return digest[:]
}

// Sign appends a base64-encoded signature, current timestamp and public key to
// the DirectoryPayload. The signature consists of the following data; | means
// concatenation, binary data must be converted to base64 strings first.
//
//  SHA3-256(Addresses | Delegators | Relays | Blob | TTL | Timestamp | PubKey)
func (a *DirectoryPayload) Sign(privateKey crypto.PrivateKey) error {
	var (
		// FIXME: Do not panic!!!
		now     = time.Now()
		privKey = privateKey.(*ecdsa.PrivateKey)
	)

	textTimestamp, err := now.MarshalText()
	if err != nil {
		return err
	}

	a.Timestamp = string(textTimestamp)

	derPubKey, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return err
	}

	a.PubKey = base64.StdEncoding.EncodeToString(derPubKey)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, a.digest())
	if err != nil {
		return err
	}

	signature, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return err
	}

	a.Signature = base64.StdEncoding.EncodeToString(signature)

	return nil
}

// CheckSignature verifies the integrity and authenticity of a DirectoryPayload
// by validating the signature of the payload and checking whether the key used
// for signing matches the given fingerprint.
func (a *DirectoryPayload) CheckSignature(fingerprint *Fingerprint) (bool, error) {
	var timestamp time.Time
	if err := timestamp.UnmarshalText([]byte(a.Timestamp)); err != nil {
		return false, err
	}

	rawPubKey, err := base64.StdEncoding.DecodeString(a.PubKey)
	if err != nil {
		return false, err
	}

	// Verify hash of public key against fingerprint
	digest := sha3.Sum256(rawPubKey)
	if !bytes.Equal(digest[:], fingerprint.Bytes()[1:]) {
		return false, fmt.Errorf("unexpected public key")
	}

	rawSignature, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return false, err
	}

	var signature ecdsaSignature
	_, err = asn1.Unmarshal(rawSignature, &signature)
	if err != nil {
		return false, err
	}

	remotePK, err := x509.ParsePKIXPublicKey(rawPubKey)
	if err != nil {
		return false, err
	}

	// FIXME: don't panic
	remotePubKey := remotePK.(*ecdsa.PublicKey)

	if ok := ecdsa.Verify(remotePubKey, a.digest(), signature.R, signature.S); !ok {
		return false, nil
	}

	if dur := time.Since(timestamp); dur > time.Duration(a.TTL)*time.Second {
		return false, fmt.Errorf("recordSet expired")
	}

	return true, nil
}

type DirectoryClient struct {
	endpoint   string
	httpClient *http.Client
	keypair    *tls.Certificate
	options    *DirectoryOptions
}

func NewDirectoryClient(addr string, keypair *tls.Certificate, options *DirectoryOptions) DirectoryClient {
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			TLSClientConfig:    NewDefaultTLSConfig(*keypair),
		},
	}

	return DirectoryClient{
		endpoint:   addr,
		keypair:    keypair,
		httpClient: client,
		options:    options,
	}
}

func (a *DirectoryClient) Put(payload DirectoryPayload) (*http.Response, error) {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = a.endpoint
	payload.Version = 0

	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	announceLogger.Debugf("PUT request to: %s", u.String())
	announceLogger.Debugf("JSON payload: %s", b)

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
			announceLogger.Warningln(string(body))
		}

		return nil, fmt.Errorf("Status Code %d", resp.StatusCode)
	}

	announceLogger.Debugf("answer: %+v", resp)

	return resp, nil
}

func (a *DirectoryClient) Get(fingerprint *Fingerprint) (*DirectoryPayload, error) {
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

	var payload DirectoryPayload
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

func getResponse(header http.Header) (*DirectoryResponse, error) {
	rawTTL := header.Get("reannounce-after")
	TTL, err := time.ParseDuration(rawTTL)
	if err != nil {
		return nil, err
	}

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
		TTL:         TTL,
		Location:    location,
		Fingerprint: fingerprint,
	}

	return response, nil
}

func (a *DirectoryClient) PushAddresses(addresses []string, ttl int) (*DirectoryResponse, error) {
	payload := DirectoryPayload{
		Addresses: addresses,
		Options:   a.options,
		TTL:       ttl,
	}

	// Sign the RecordSet
	err := payload.Sign(a.keypair.PrivateKey)
	if err != nil {
		return nil, err
	}

	resp, err := a.Put(payload)
	if err != nil {
		return nil, err
	}

	response, err := getResponse(resp.Header)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (a *DirectoryClient) PushBlob(data []byte, ttl int) (*DirectoryResponse, error) {
	var (
		b64Data = base64.StdEncoding.EncodeToString(data)
		payload = DirectoryPayload{
			Blob:    b64Data,
			TTL:     ttl,
			Options: a.options,
		}
	)

	err := payload.Sign(a.keypair.PrivateKey)
	if err != nil {
		return nil, err
	}

	resp, err := a.Put(payload)
	if err != nil {
		return nil, err
	}

	response, err := getResponse(resp.Header)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (a *DirectoryClient) FetchBlob(fingerprint *Fingerprint) ([]byte, error) {
	payload, err := a.Get(fingerprint)
	if err != nil {
		return nil, err
	}

	if payload.Blob == "" {
		return nil, fmt.Errorf("no blob available for: %s", fingerprint.String())
	}

	blob, err := base64.StdEncoding.DecodeString(payload.Blob)
	if err != nil {
		return nil, err
	}

	return blob, nil
}

const (
	ResolveFlagUseSystemDNS = 1 << iota
	ResolveFlagUseHTTPs
	ResolveFlagUseMND
)

func makeURLs(ips []string, port string) []string {
	addrs := make([]string, len(ips))
	for i, addr := range ips {
		if port != "" {
			addrs[i] = fmt.Sprintf("//%s", net.JoinHostPort(addr, port))
		} else {
			addrs[i] = fmt.Sprintf("//%s:%s", addr, port)
		}
	}

	return addrs
}

type Resolver struct {
	Flags           int
	DirectoryClient *DirectoryClient
	MNDResolver     *mnd.Node
}

func NewResolver(dirClient *DirectoryClient, flags int) Resolver {
	var mndClient *mnd.Node

	if dirClient != nil && flags&ResolveFlagUseMND > 0 {
		// TODO: create v4 and v6 resolvers
		mndClient = &mnd.Node{
			Address:    "0.0.0.0:7868",
			Group:      MNDIPv4MulticastAddress,
			Port:       MNDPort,
			PrivateKey: dirClient.keypair.PrivateKey,
		}
	}

	return Resolver{
		Flags:           flags,
		DirectoryClient: dirClient,
		MNDResolver:     mndClient,
	}
}

func dnsLookup(fingerprint *Fingerprint) (*DirectoryPayload, error) {
	var payload DirectoryPayload

	txts, err := net.LookupTXT(fingerprint.FQDN())
	if err != nil {
		return nil, err
	}

	for _, txt := range txts {
		parts := strings.SplitN(txt, "=", 2)
		if len(parts) != 2 {
			resolveLogger.Warningf("%s entry is corrupt", txt)
			continue
		}

		switch parts[0] {
		case "address":
			parsedURL, err := url.Parse(parts[1])
			if err != nil {
				resolveLogger.Warningf("%s: %s", txt, err)
				continue
			}

			payload.Addresses = append(payload.Addresses, parsedURL.String())

		case "signature":
			payload.Signature = parts[1]

		case "pubkey":
			payload.PubKey = parts[1]

		case "ttl":
			tmp, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				return nil, err
			}

			payload.TTL = int(tmp)

		case "timestamp":
			payload.Timestamp = parts[1]
		}
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

func dnsLookupHost(host string) ([]string, error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
		port = DefaultPort
	}

	ips, err := net.LookupHost(hostname)
	if err != nil {
		return []string{}, err
	}

	return makeURLs(ips, port), nil
}

func (r *Resolver) Lookup(fingerprint *Fingerprint) (*DirectoryPayload, error) {
	var (
		err     error
		payload *DirectoryPayload
	)

	if (r.Flags & ResolveFlagUseSystemDNS) != 0 {
		payload, err := dnsLookup(fingerprint)
		if err == nil {
			return payload, nil
		}
	}

	if (r.Flags & ResolveFlagUseHTTPs) != 0 {
		payload, err = r.DirectoryClient.Get(fingerprint)
		if err == nil {
			return payload, nil
		}
	}

	return nil, fmt.Errorf("lookup %s: not found", fingerprint.String())
}

func (r *Resolver) LookupAddresses(fingerprint *Fingerprint) ([]string, error) {
	var (
		addrs []string
		err   error
		found = false
	)

	// These schemes are tried in this order:
	//  - MND     : Search in local network with MND protocol
	//  - ni-URI  : Check TXT records and validate signature
	//  - HTTP    : Fetch JSON and validate signature
	if (r.Flags&ResolveFlagUseMND) != 0 && r.MNDResolver != nil {
		addrs, err = r.MNDResolver.Request(fingerprint.URL)
		if err == nil {
			found = true
		}
	}

	if !found {
		payload, err := r.Lookup(fingerprint)
		if err == nil {
			found = true
			addrs = payload.Addresses[:]
		}
	}

	if found {
		sortByRFC6724(addrs)
		return addrs, nil
	}

	return nil, fmt.Errorf("fingerprint %s not present", fingerprint.String())
}

func (r *Resolver) LookupDelegators(fingerprint *Fingerprint) ([]string, error) {
	payload, err := r.Lookup(fingerprint)
	if err != nil {
		return nil, err
	}

	return payload.Delegators, nil
}
