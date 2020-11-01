package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"git.sr.ht/~rumpelsepp/rlog"
	"git.sr.ht/~rumpelsepp/sep"
	"github.com/go-redis/redis/v8"
)

const (
	recordTypeAddress   = "address"
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
	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		return nil, err
	}

	// Enable redis expire stuff.
	if err := redisClient.ConfigSet(context.Background(), "notify-keyspace-events", "Ex").Err(); err != nil {
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

	if val, err := b.client.Exists(context.Background(), key).Result(); err != nil {
		return err
	} else {
		if val == 1 {
			return errRsExists
		}
	}

	for i := 0; i < len(rs.Addresses); i++ {
		err = b.client.RPush(context.Background(), key, recordTypeAddress+"="+rs.Addresses[i]).Err()
		if err != nil {
		}
	}

	for i := 0; i < len(rs.Relays); i++ {
		err = b.client.RPush(context.Background(), key, recordTypeRelay+"="+rs.Relays[i]).Err()
		if err != nil {
		}
	}

	err = b.client.RPush(context.Background(), key, recordTypeBlob+"="+blob).Err()
	if err != nil {
		return err
	}

	err = b.client.RPush(context.Background(), key, recordTypeSignature+"="+signature).Err()
	if err != nil {
		return err
	}

	err = b.client.RPush(context.Background(), key, recordTypeTimestamp+"="+timestamp).Err()
	if err != nil {
		return err
	}

	err = b.client.RPush(context.Background(), key, recordTypePubKey+"="+pubkey).Err()
	if err != nil {
		return err
	}

	err = b.client.RPush(context.Background(), key, fmt.Sprintf("%s=%d", recordTypeTTL, rs.TTL)).Err()
	if err != nil {
		return err
	}

	err = b.client.Expire(context.Background(), key, time.Duration(rs.TTL)*time.Second).Err()
	if err != nil {
		return err
	}

	rlog.Debugf("recordSet for '%s' added", key)

	return nil
}

func (b *redisBackend) rmRecordSet(fp *sep.Fingerprint) error {
	return b.client.Del(context.Background(), fp.Canonical()).Err()
}

func (b *redisBackend) awaitExpireEvents() (<-chan *sep.Fingerprint, error) {
	ch := make(chan *sep.Fingerprint, 32)

	go func() {
		pubsub := b.client.Subscribe(context.Background(), "__keyevent@0__:expired")
		defer pubsub.Close()
		defer close(ch)

		for {
			msg, err := pubsub.ReceiveMessage(context.Background())
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
