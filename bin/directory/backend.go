package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"git.sr.ht/~rumpelsepp/rlog"
	"git.sr.ht/~rumpelsepp/sep"
	"github.com/go-redis/redis/v7"
)

const (
	recordTypeAddress   = "addr"
	recordTypeRelay     = "relay"
	recordTypeBlob      = "blob"
	recordTypeSignature = "signature"
	recordTypePubKey    = "pubkey"
	recordTypeTimestamp = "timestamp"
	recordTypeTTL       = "ttl"
)

var (
	errRsExists     = errors.New("recordset exists")
	errNotSupported = errors.New("operation is not supported by backend")
)

func parseURLs(rawURLs []string) []url.URL {
	urls := make([]url.URL, 0, len(rawURLs))
	for _, rawURL := range rawURLs {
		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			rlog.Warningf("url %s is broken: %s", rawURL, err)
			continue
		}

		urls = append(urls, *parsedURL)
	}

	return urls
}

type backend interface {
	addRecordSet(rs *sep.DirectoryRecordSet) error
	rmRecordSet(fp *sep.Fingerprint) error
	awaitExpireEvents() (<-chan *sep.Fingerprint, error)
	close() error
}

type redisBackend struct {
	client *redis.Client
}

func newRedisBackend(opts *redis.Options) (*redisBackend, error) {
	redisClient := redis.NewClient(opts)
	if _, err := redisClient.Ping().Result(); err != nil {
		return nil, err
	}

	// Enable redis expire stuff.
	if err := redisClient.ConfigSet("notify-keyspace-events", "Ex").Err(); err != nil {
		return nil, err
	}

	return &redisBackend{client: redisClient}, nil
}

func (b *redisBackend) addRecordSet(rs *sep.DirectoryRecordSet) error {
	fp, err := rs.Fingerprint()
	if err != nil {
		return err
	}

	key := fp.Canonical()

	var (
		blob      = base64.StdEncoding.EncodeToString(rs.Blob)
		pubkey    = base64.StdEncoding.EncodeToString(rs.PubKey)
		signature = base64.StdEncoding.EncodeToString(rs.Signature)
		timestamp = rs.Timestamp.Format(time.RFC3339)
	)

	if val, err := b.client.Exists(key).Result(); err != nil {
		return err
	} else {
		if val == 1 {
			return errRsExists
		}
	}

	for i := 0; i < len(rs.Addresses); i++ {
		err = b.client.RPush(key, recordTypeAddress+"="+rs.Addresses[i]).Err()
		if err != nil {
		}
	}

	for i := 0; i < len(rs.Relays); i++ {
		err = b.client.RPush(key, recordTypeRelay+"="+rs.Relays[i]).Err()
		if err != nil {
		}
	}

	err = b.client.RPush(key, recordTypeBlob+"="+blob).Err()
	if err != nil {
		return err
	}

	err = b.client.RPush(key, recordTypeSignature+"="+signature).Err()
	if err != nil {
		return err
	}

	err = b.client.RPush(key, recordTypeTimestamp+"="+timestamp).Err()
	if err != nil {
		return err
	}

	err = b.client.RPush(key, recordTypePubKey+"="+pubkey).Err()
	if err != nil {
		return err
	}

	err = b.client.RPush(key, fmt.Sprintf("%s=%d", recordTypeTTL, rs.TTL)).Err()
	if err != nil {
		return err
	}

	err = b.client.Expire(key, time.Duration(rs.TTL)*time.Second).Err()
	if err != nil {
		return err
	}

	rlog.Debugf("recordSet for '%s' added", key)

	return nil
}

func (b *redisBackend) rmRecordSet(fp *sep.Fingerprint) error {
	return b.client.Del(fp.Canonical()).Err()
}

func (b *redisBackend) awaitExpireEvents() (<-chan *sep.Fingerprint, error) {
	ch := make(chan *sep.Fingerprint, 32)

	go func() {
		pubsub := b.client.Subscribe("__keyevent@0__:expired")
		defer pubsub.Close()
		defer close(ch)

		for {
			msg, err := pubsub.ReceiveMessage()
			if err != nil {
				rlog.Warning(err)
				break
			}

			fingerprint, err := sep.FingerprintFromNIString(msg.Payload)
			if err != nil {
				rlog.Warning(err)
				break
			}

			ch <- fingerprint
		}
	}()

	return ch, nil
}

func (b *redisBackend) close() error {
	return b.client.Close()
}

type nsupdateManager struct {
	process   *exec.Cmd
	stdin     io.WriteCloser
	stderr    io.ReadCloser
	zone      string
	ttl       int
	dnsserver string
	cmdBuf    strings.Builder
}

func (m *nsupdateManager) spawn() error {
	var (
		err  error
		proc = exec.Command("nsupdate")
	)

	rlog.Debug("spawning nsupdate")

	m.stdin, err = proc.StdinPipe()
	if err != nil {
		return err
	}

	m.stderr, err = proc.StderrPipe()
	if err != nil {
		return err
	}

	if err := proc.Start(); err != nil {
		return err
	}

	go func() {
		scanner := bufio.NewScanner(m.stderr)
		for scanner.Scan() {
			rlog.Debugf("nsupdate: %s\n", scanner.Text())
		}

		err := proc.Wait()

		rlog.Errf("nsupdate: terminated with %s\n", err)
		rlog.Warning("restarting nsupdate")
		m.spawn()
	}()

	m.cmdBuf.Reset()
	cmd := fmt.Sprintf("server %s\n", m.dnsserver)
	_, err = m.cmdBuf.WriteString(cmd)
	if err != nil {
		return err
	}

	cmd = fmt.Sprintf("zone %s\n", m.zone)
	_, err = m.cmdBuf.WriteString(cmd)
	if err != nil {
		return err
	}

	// Flush it!
	if err := m.commit(); err != nil {
		return err
	}

	return nil
}

func (m *nsupdateManager) addARecord(fp *sep.Fingerprint, host string, ttl int) error {
	cmd := fmt.Sprintf("update add %s %d A %s\n", fp.FQDN(), ttl, host)
	_, err := m.cmdBuf.WriteString(cmd)
	return err
}

func (m *nsupdateManager) addAAAARecord(fp *sep.Fingerprint, host string, ttl int) error {
	cmd := fmt.Sprintf("update add %s %d AAAA %s\n", fp.FQDN(), ttl, host)
	_, err := m.cmdBuf.WriteString(cmd)
	return err
}

func (m *nsupdateManager) addTXTRecord(fp *sep.Fingerprint, rtype, val string, ttl int) error {
	cmd := fmt.Sprintf("update add %s %d TXT %s=%s\n", fp.FQDN(), ttl, rtype, val)
	_, err := m.cmdBuf.WriteString(cmd)
	return err
}

func (m *nsupdateManager) delEntry(key string) error {
	m.cmdBuf.Reset()

	cmd := fmt.Sprintf("update del %s\n", key)
	_, err := m.cmdBuf.WriteString(cmd)
	if err != nil {
		return err
	}

	if err := m.commit(); err != nil {
		return err
	}

	return nil
}

func (m *nsupdateManager) commit() error {
	defer m.cmdBuf.Reset()

	for _, l := range strings.Split(m.cmdBuf.String(), "\n") {
		rlog.Debugf("nsupdate: %s", strings.TrimSpace(l))
	}

	if _, err := io.Copy(m.stdin, strings.NewReader(m.cmdBuf.String())); err != nil {
		return err
	}

	rlog.Debug("nsupdate: send")
	_, err := fmt.Fprint(m.stdin, "send\n")
	if err != nil {
		return err
	}

	return nil
}

func (m *nsupdateManager) wait() error {
	return m.process.Wait()
}

func (m *nsupdateManager) kill() error {
	if err := m.process.Process.Kill(); err != nil {
		return err
	}
	return m.wait()
}

type nsupdateBackend struct {
	manager *nsupdateManager
	mutex   sync.Mutex
	zone    string
}

func newNsupdateBackend(host, zone string, ttl int) (*nsupdateBackend, error) {
	manager := &nsupdateManager{
		zone:      zone,
		dnsserver: host,
		ttl:       ttl,
	}
	if err := manager.spawn(); err != nil {
		return nil, err
	}
	return &nsupdateBackend{manager: manager}, nil
}

func (b *nsupdateBackend) addRecordSet(rs *sep.DirectoryRecordSet) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// If the blob is too big skip DNS entirely.
	if len(rs.Blob) >= 2*1024 {
		return errors.New("blob is too large")
	}

	var (
		blob      = base64.StdEncoding.EncodeToString(rs.Blob)
		pubkey    = base64.StdEncoding.EncodeToString(rs.PubKey)
		signature = base64.StdEncoding.EncodeToString(rs.Signature)
		timestamp = rs.Timestamp.Format(time.RFC3339)
		ttl       = 60
	)

	fp, err := rs.Fingerprint()
	if err != nil {
		return err
	}
	fp.Authority = b.manager.zone

	// Add addresses
	addrURLs := parseURLs(rs.Addresses)
	for _, addr := range addrURLs {
		host := addr.Hostname()
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() != nil {
				if err := b.manager.addARecord(fp, ip.String(), ttl); err != nil {
					return err
				}
			} else {
				if err := b.manager.addAAAARecord(fp, ip.String(), ttl); err != nil {
					return err
				}
			}
		} else {
			return fmt.Errorf("no valid ip address: %s", ip)
		}

		// Add TXT records, only if a port was specified.
		if err := b.manager.addTXTRecord(fp, recordTypeAddress, addr.String(), ttl); err != nil {
			return err
		}
	}

	// Add relays
	relayURLs := parseURLs(rs.Relays)
	for _, relay := range relayURLs {
		if err := b.manager.addTXTRecord(fp, recordTypeRelay, relay.String(), ttl); err != nil {
			return err
		}
	}

	// Add blob
	if blob != "" {
		if err := b.manager.addTXTRecord(fp, recordTypeBlob, blob, ttl); err != nil {
			return err
		}
	}

	// Add TTL
	rsTTL := fmt.Sprintf("%d", rs.TTL)
	if err := b.manager.addTXTRecord(fp, recordTypeTTL, rsTTL, ttl); err != nil {
		return err
	}

	// Add timestamp
	if err := b.manager.addTXTRecord(fp, recordTypeTimestamp, timestamp, ttl); err != nil {
		return err
	}

	// Add pubkey
	if err := b.manager.addTXTRecord(fp, recordTypePubKey, pubkey, ttl); err != nil {
		return err
	}

	// Add sig
	if err := b.manager.addTXTRecord(fp, recordTypeSignature, signature, ttl); err != nil {
		return err
	}

	// Flush it!
	return b.manager.commit()
}

func (b *nsupdateBackend) rmRecordSet(fp *sep.Fingerprint) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	fp.Authority = b.manager.zone
	return b.manager.delEntry(fp.FQDN())
}

func (b *nsupdateBackend) awaitExpireEvents() (<-chan *sep.Fingerprint, error) {
	return nil, errNotSupported
}

func (b *nsupdateBackend) close() error {
	return b.manager.kill()
}
