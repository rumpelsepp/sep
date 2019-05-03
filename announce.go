package sep

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type Announcer struct {
	mariaEndpoint string
	httpClient    *http.Client
	options       *AnnounceOptions
}

type AnnounceOptions struct {
	Expire    int    `json:"expire"`
	Suite     string `json:"suite"`
	TTL       int    `json:"ttl"`
	WholeCert bool   `json:"wholecert"`
}

type AnnouncePayload struct {
	Addresses []string         `json:"addresses"`
	Options   *AnnounceOptions `json:"options"`
}

func NewAnnouncer(addr string, keypair *tls.Certificate, options *AnnounceOptions) Announcer {
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			TLSClientConfig:    DefaultTLSConfig(*keypair),
		},
	}

	return Announcer{mariaEndpoint: addr, httpClient: client, options: options}
}

func (a *Announcer) Announce(addresses []string) (time.Duration, error) {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = a.mariaEndpoint
	payload := AnnouncePayload{Addresses: addresses, Options: a.options}

	b, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	announceLogger.Debugf("PUT request to: %s", u.String())
	announceLogger.Debugf("JSON payload: %s", b)

	reader := bytes.NewReader(b)
	req, err := http.NewRequest("PUT", u.String(), reader)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return 0, err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		// The server responds with an error message.
		// Read it if available and log it.
		defer resp.Body.Close()
		if body, err := ioutil.ReadAll(resp.Body); err != nil {
			announceLogger.Warningln(string(body))
		}

		return 0, fmt.Errorf("Status Code %d", resp.StatusCode)
	}

	announceLogger.Debugf("answer: %+v", resp)

	reannounce := resp.Header.Get("reannounce-after")
	reannounceDur, err := time.ParseDuration(reannounce)
	if err != nil {
		return 0, err
	}

	return reannounceDur, nil
}
