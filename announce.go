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

// TODO: maybe with reflect?
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

func (a *AnnouncePayload) checkSignature(fingerprint *Fingerprint) (bool, error) {
	// TODO: Currently this interface supports only one data record at a time.
	//       It should be possible to combine them arbitrarily.
	var data interface{}
	switch {
	case a.Addresses != nil:
		data = a.Addresses
	case a.Delegators != nil:
		data = a.Delegators
	case a.Relays != nil:
		data = a.Relays
	case a.Blob != "":
		data = a.Blob
	default:
		return false, fmt.Errorf("no data to verify")
	}

	var timestamp time.Time
	if err := timestamp.UnmarshalText([]byte(a.Timestamp)); err != nil {
		return false, err
	}

	ser, err := serializeRecordSet(data, a.TTL, timestamp)
	if err != nil {
		return false, err
	}

	rawPubKey, err := base64.StdEncoding.DecodeString(a.PubKey)
	if err != nil {
		return false, err
	}

	// TODO: check if remote public key is equal to the expected publickey
	// Hash the key and compare digest with fingerprint

	digest := sha3.Sum256(rawPubKey)

	if !bytes.Equal(digest[:], fingerprint.Bytes()[1:]) {
		return false, fmt.Errorf("unexpected public key")
	}

	// Build data which is needed to compute the digest
	ser += base64.StdEncoding.EncodeToString(rawPubKey)
	digest = sha3.Sum256([]byte(ser))

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

	if ok := ecdsa.Verify(remotePubKey, digest[:], signature.R, signature.S); !ok {
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

func serializeRecordSet(data interface{}, ttl int, timestamp time.Time) (string, error) {
	res := ""

	switch t := data.(type) {
	case string:
		res += t
	case []string:
		for _, subStr := range t {
			res += subStr
		}
	default:
		return "", fmt.Errorf("type %T is not supported in serialize", t)
	}

	res += string(ttl)
	res += timestamp.String()

	return res, nil
}

// The signature is created over the following data;
// || means logical OR, | concatenation, binary data must be converted to
// base64 strings first. This function appends the PublicKey.
//
//  SHA3-256((Addresses || Delegators || Relays || Blob) | TTL | Timestamp | PubKey)
func signRecordSet(privateKey crypto.PrivateKey, data interface{}, ttl int, timestamp time.Time) ([]byte, error) {
	ser, err := serializeRecordSet(data, ttl, timestamp)
	if err != nil {
		return nil, err
	}

	// FIXME: Do not panic!!!
	privKey := privateKey.(*ecdsa.PrivateKey)

	derPubKey, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return nil, err
	}

	ser += base64.StdEncoding.EncodeToString(derPubKey)
	digest := sha3.Sum256([]byte(ser))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		return nil, err
	}

	signature, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (a *Announcer) doPut(payload AnnouncePayload, now time.Time) (*http.Response, error) {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = a.mariaEndpoint

	// FIXME: Do not panic!!!
	// Add public key on this shared location.
	privKey := a.keypair.PrivateKey.(*ecdsa.PrivateKey)

	derPubKey, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return nil, err
	}

	payload.PubKey = base64.StdEncoding.EncodeToString(derPubKey)
	payload.Version = 1

	// Add timestamp to payload
	textTimestamp, err := now.MarshalText()
	if err != nil {
		return nil, err
	}

	payload.Timestamp = string(textTimestamp)

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
		now = time.Now()
	)

	// Sign the RecordSet
	signature, err := signRecordSet(a.keypair.PrivateKey, addresses, ttl, now)
	if err != nil {
		return 0, err
	}

	payload.Signature = base64.StdEncoding.EncodeToString(signature)

	resp, err := a.doPut(payload, now)
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
		now     = time.Now()
		payload = AnnouncePayload{
			Blob:    b64Data,
			TTL:     ttl,
			Options: a.options,
		}
	)

	// Sign the RecordSet
	signature, err := signRecordSet(a.keypair.PrivateKey, data, ttl, now)
	if err != nil {
		return 0, err
	}

	payload.Signature = base64.StdEncoding.EncodeToString(signature)

	resp, err := a.doPut(payload, now)
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
