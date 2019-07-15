package sep

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"

	"git.sr.ht/~rumpelsepp/mnd"
)

var (
	DefaultResolveDomain = "ace-sep.de"
)

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
	Flags       int
	MNDResolver *mnd.Node
}

func NewResolver(flags int, privKey crypto.PrivateKey) Resolver {
	var resolver *mnd.Node

	if privKey != nil {
		// TODO: create v4 and v6 resolvers
		resolver = &mnd.Node{
			Address:    "0.0.0.0:7868",
			Group:      MNDIPv4MulticastAddress,
			Port:       MNDPort,
			PrivateKey: privKey,
		}
	}

	return Resolver{
		Flags:       flags,
		MNDResolver: resolver,
	}
}

func dnsLookupNode(fingerprint *Fingerprint) ([]string, error) {
	var addrs []string

	txts, err := net.LookupTXT(fingerprint.FQDN())
	if err != nil {
		// If there are no TXTs available, let's try the A and AAAA ones.
		ips, err := net.LookupHost(fingerprint.FQDN())
		if err != nil {
			return []string{}, err
		}

		return makeURLs(ips, DefaultPort), nil
	}

	addrs = make([]string, 0, len(txts))

	for _, txt := range txts {
		parts := strings.Split(txt, "=")
		if len(parts) != 2 {
			resolveLogger.Warningf("%s entry is corrupt", txt)
			continue
		}

		if parts[0] == "addr" {
			parsedURL, err := url.Parse(parts[1])
			if err != nil {
				resolveLogger.Warningf("%s: %s", txt, err)
				continue
			}

			addrs = append(addrs, parsedURL.String())
		}
	}

	return addrs, nil
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

func (r *Resolver) Resolve(node string) ([]string, error) {
	// These schemes are tried in this order:
	//  - MND (default off) : Search in local network with MND protocol
	//  - ni-URI            : Check TXT records
	//  - ni-URI            : Check A and AAAA records, use default port
	//  - hostname          : nothing special here

	if fingerprint, err := ParseFingerprint(node); err == nil {
		if (r.Flags&ResolveFlagUseMND) != 0 && r.MNDResolver != nil {
			addrs, err := r.MNDResolver.Request(fingerprint.URL)
			if err == nil {
				sortByRFC6724(addrs)
				resolveLogger.Debugf("Got addresses %s via MND", addrs)
				return addrs, nil
			}

			resolveLogger.Debug(err)
		}

		if (r.Flags & ResolveFlagUseSystemDNS) != 0 {
			addrs, err := dnsLookupNode(fingerprint)
			if err == nil {
				sortByRFC6724(addrs)
				resolveLogger.Debugf("Got addresses %s via DNS", addrs)
				return addrs, nil
			}

			resolveLogger.Debug(err)
		}

		if (r.Flags & ResolveFlagUseHTTPs) != 0 {
			addrs, err := httpsLookup(fingerprint)
			if err == nil {
				sortByRFC6724(addrs)
				resolveLogger.Debugf("Got addresses %s via HTTPs", addrs)
				return addrs, nil
			}

			resolveLogger.Debug(err)
		}

		return nil, fmt.Errorf("discover %s: not found", node)
	}

	// This is the looser trail; if fingerprint parsing fails,
	// a "few" fallbacks are tried to resolve the node.
	if (r.Flags & ResolveFlagUseSystemDNS) != 0 {
		addrs, err := dnsLookupHost(node)
		if err == nil {
			resolveLogger.Debugf("Got addresses %s via DNS", addrs)
			return addrs, nil
		}

		resolveLogger.Debug(err)
	}

	// If this is reached, nothing has been found.
	return nil, fmt.Errorf("discover %s: not found", node)
}

func httpsLookup(fingerprint *Fingerprint) ([]string, error) {
	resp, err := http.Get(fingerprint.WellKnownURI())
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

	var payload AnnouncePayload
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

	return payload.Addresses, nil
}
