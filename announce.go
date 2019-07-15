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
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/sha3"
)

type Announcer struct {
	mariaEndpoint string
	httpClient    *http.Client
	keypair       *tls.Certificate
	options       *AnnounceOptions
}

type AnnounceOptions struct {
	DNSTTL    int    `json:"dns_ttl"`
	Suite     string `json:"suite"`
	WholeCert bool   `json:"wholecert"`
}

type AnnouncePayload struct {
	Addresses  []string         `json:"addresses,omitempty"`
	Delegators []string         `json:"delegator,omitempty"`
	Relays     []string         `json:"relay,omitempty"`
	Blob       string           `json:"blob,omitempty"`
	PubKey     string           `json:"pubkey"`
	TTL        int              `json:"ttl"`
	Timestamp  string           `json:"timestamp"`
	Signature  string           `json:"signature"`
	Version    int              `json:"version"`
	Options    *AnnounceOptions `json:"options,omitempty"`
}

func concat(date []string) string {
	var res string
	for _, subStr := range date {
		res += subStr
	}
	return res
}

func (a *AnnouncePayload) digest() []byte {
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

// The signature is created over the following data;
// | means concatenation, binary data must be converted to
// base64 strings first.
//
//  SHA3-256(Addresses | Delegators | Relays | Blob | TTL | Timestamp | PubKey)
func (a *AnnouncePayload) Sign(privateKey crypto.PrivateKey) error {
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

func (a *AnnouncePayload) CheckSignature(fingerprint *Fingerprint) (bool, error) {
	var timestamp time.Time
	if err := timestamp.UnmarshalText([]byte(a.Timestamp)); err != nil {
		return false, err
	}

	rawPubKey, err := base64.StdEncoding.DecodeString(a.PubKey)
	if err != nil {
		return false, err
	}

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

	return true, nil
}

func NewAnnouncer(addr string, keypair *tls.Certificate, options *AnnounceOptions) Announcer {
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			TLSClientConfig:    DefaultTLSConfig(*keypair),
		},
	}

	return Announcer{
		mariaEndpoint: addr,
		keypair:       keypair,
		httpClient:    client,
		options:       options,
	}
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (a *Announcer) Put(payload AnnouncePayload) (*http.Response, error) {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = a.mariaEndpoint
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

// TODO: relays and delegators can coexists... :)
func (a *Announcer) PushAddresses(addresses []string, ttl int) (time.Duration, error) {
	var (
		payload = AnnouncePayload{
			Addresses: addresses,
			Options:   a.options,
			TTL:       ttl,
		}
	)

	// Sign the RecordSet
	err := payload.Sign(a.keypair.PrivateKey)
	if err != nil {
		return 0, err
	}

	resp, err := a.Put(payload)
	if err != nil {
		return 0, err
	}

	reannounce := resp.Header.Get("reannounce-after")
	reannounceDur, err := time.ParseDuration(reannounce)
	if err != nil {
		return 0, err
	}

	return reannounceDur, nil
}

func (a *Announcer) PushBlob(data []byte, ttl int) (time.Duration, error) {
	var (
		b64Data = base64.StdEncoding.EncodeToString(data)
		payload = AnnouncePayload{
			Blob:    b64Data,
			TTL:     ttl,
			Options: a.options,
		}
	)

	err := payload.Sign(a.keypair.PrivateKey)
	if err != nil {
		return 0, err
	}

	resp, err := a.Put(payload)
	if err != nil {
		return 0, err
	}

	reannounce := resp.Header.Get("reannounce-after")
	reannounceDur, err := time.ParseDuration(reannounce)
	if err != nil {
		return 0, err
	}

	return reannounceDur, nil
}
