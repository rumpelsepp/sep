package sep

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/fxamacker/cbor"
	"golang.org/x/crypto/sha3"
)

const (
	RelayMsgTypeRequest = iota
	RelayMsgTypeExpose
	RelayMsgTypePing
	RelayMsgTypePong
	RelayMsgTypeAck
	RelayMsgTypeNack
)

type RelayMessage struct {
	Type      byte
	Version   byte
	Initiator string
	Target    string
	TTL       uint16
	Timestamp []byte
	PubKey    []byte
	Signature []byte
}

func (m *RelayMessage) digest() []byte {
	ttlBin := make([]byte, 2)
	binary.BigEndian.PutUint16(ttlBin, m.TTL)

	var res []byte
	res = append(res, m.Type)
	res = append(res, []byte(m.Initiator)...)
	res = append(res, []byte(m.Target)...)
	res = append(res, m.Timestamp...)
	res = append(res, ttlBin...)
	res = append(res, m.PubKey...)
	res = append(res, m.Version)

	digest := sha3.Sum256([]byte(res))

	return digest[:]
}

//  SHA3-256(Type | Initiator | Target | Timestamp | Nonce | PubKey)
func (m *RelayMessage) Sign(privateKey crypto.PrivateKey) error {
	var (
		// FIXME: Do not panic!!!
		now     = time.Now()
		privKey = privateKey.(*ecdsa.PrivateKey)
	)

	timestamp, err := now.MarshalBinary()
	if err != nil {
		return err
	}

	m.Timestamp = timestamp
	m.TTL = 10

	derPubKey, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return err
	}

	m.PubKey = derPubKey

	r, s, err := ecdsa.Sign(rand.Reader, privKey, m.digest())
	if err != nil {
		return err
	}

	signature, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return err
	}

	m.Signature = signature

	return nil
}

func (m *RelayMessage) CheckSignature(fingerprint *Fingerprint) (bool, error) {
	digest := sha3.Sum256(m.PubKey)

	if !bytes.Equal(digest[:], fingerprint.Bytes()[1:]) {
		return false, fmt.Errorf("unexpected public key")
	}

	remotePK, err := x509.ParsePKIXPublicKey(m.PubKey)
	if err != nil {
		return false, err
	}

	var signature ecdsaSignature
	if _, err := asn1.Unmarshal(m.Signature, &signature); err != nil {
		return false, err
	}

	// FIXME: don't panic
	remotePubKey := remotePK.(*ecdsa.PublicKey)

	if ok := ecdsa.Verify(remotePubKey, m.digest(), signature.R, signature.S); !ok {
		return false, nil
	}

	var timestamp time.Time
	if err := timestamp.UnmarshalBinary(m.Timestamp); err != nil {
		return false, err
	}

	if time.Since(timestamp) > time.Duration(m.TTL)*time.Second {
		return false, fmt.Errorf("ttl expired")
	}

	return true, nil
}

type RelayNode struct {
	Conn    Conn
	Encoder *cbor.Encoder
	Decoder *cbor.Decoder
	Keypair tls.Certificate
	Trusted []*Fingerprint
}

// DoRequest is a low level message primitive. It is used to implement relay clients.
func (r *RelayNode) Send(msg RelayMessage) error {
	if err := msg.Sign(r.Keypair.PrivateKey); err != nil {
		return err
	}
	return r.SendRaw(msg)
}

func (r *RelayNode) RecvFrom(from *Fingerprint) (RelayMessage, error) {
	resp, err := r.RecvRaw()
	if err != nil {
		return RelayMessage{}, err
	}
	if ok, err := resp.CheckSignature(from); err != nil || !ok {
		return RelayMessage{}, fmt.Errorf("signature check failed")
	}
	return resp, nil
}

func (r *RelayNode) Recv() (RelayMessage, error) {
	req, err := r.RecvRaw()
	if err != nil {
		return RelayMessage{}, err
	}
	for _, fp := range r.Trusted {
		if ok, err := req.CheckSignature(fp); ok && err == nil {
			return req, nil
		}
	}
	return RelayMessage{}, fmt.Errorf("signature check failed")
}

func (r *RelayNode) SendRaw(msg RelayMessage) error {
	return r.Encoder.Encode(msg)
}

func (r *RelayNode) RecvRaw() (RelayMessage, error) {
	var msg RelayMessage
	if err := r.Decoder.Decode(&msg); err != nil {
		return RelayMessage{}, err
	}
	return msg, nil
}

type RelayClient struct {
	config Config
	relay  *Fingerprint
	dialer Dialer
	node   *RelayNode
}

func NewRelayClient(relay *Fingerprint, config Config) (RelayClient, error) {
	dialer, err := NewDialer("tcp", config)
	if err != nil {
		return RelayClient{}, err
	}

	return RelayClient{
		config: config,
		relay:  relay,
		dialer: dialer,
	}, nil
}

func (c *RelayClient) Dial(target *Fingerprint) (Conn, error) {
	Logger.Debugf("dialing via relay %s to %s", c.relay, target)

	relayConn, err := c.dialer.DialTimeout("tcp", c.relay.String(), 5*time.Second)
	if err != nil {
		return nil, err
	}

	relay := RelayNode{
		Conn:    relayConn,
		Encoder: cbor.NewEncoder(relayConn, cbor.EncOptions{Canonical: true}),
		Decoder: cbor.NewDecoder(relayConn),
		Keypair: c.config.TLSConfig.Certificates[0],
		Trusted: append(c.config.AllowedPeers, c.relay),
	}
	c.node = &relay

	req := RelayMessage{
		Type:   RelayMsgTypeRequest,
		Target: target.String(),
	}

	if err := relay.Send(req); err != nil {
		return nil, err
	}

	if resp, err := relay.RecvFrom(target); err != nil {
		return nil, err
	} else if resp.Type != RelayMsgTypeAck {
		return nil, fmt.Errorf("access denied")
	}

	rawConn := relayConn.RawConnection().(*net.TCPConn)
	conn, err := tcpClient(rawConn, &c.config)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (c *RelayClient) Accept() (Conn, error) {
	relayConn, err := c.dialer.DialTimeout("tcp", c.relay.String(), 5*time.Second)
	if err != nil {
		return nil, err
	}

	relay := RelayNode{
		Conn:    relayConn,
		Encoder: cbor.NewEncoder(relayConn, cbor.EncOptions{Canonical: true}),
		Decoder: cbor.NewDecoder(relayConn),
		Keypair: c.config.TLSConfig.Certificates[0],
		Trusted: append(c.config.AllowedPeers, c.relay),
	}

	req := RelayMessage{
		Type:   RelayMsgTypeExpose,
		Target: relayConn.LocalFingerprint().String(),
	}

	if err := relay.Send(req); err != nil {
		return nil, err
	}

	if resp, err := relay.RecvFrom(c.relay); err != nil {
		return nil, err
	} else if resp.Type != RelayMsgTypeAck {
		return nil, fmt.Errorf("relay access denied")
	}

	var resp RelayMessage

	for {
		incoming := false

		// FIXME: This SigCheck fails. Why?
		req, err := relay.RecvRaw()
		if err != nil {
			return nil, err
		}

		switch req.Type {
		case RelayMsgTypeRequest:
			resp = RelayMessage{
				Type:   RelayMsgTypeAck,
				Target: relayConn.LocalFingerprint().String(),
			}
			incoming = true
		case RelayMsgTypePing:
			resp = RelayMessage{
				Type:   RelayMsgTypePong,
				Target: relayConn.LocalFingerprint().String(),
			}
		default:
			return nil, fmt.Errorf("unexpected message type")
		}

		if err := relay.Send(resp); err != nil {
			return nil, err
		}

		if incoming {
			rawConn := relayConn.RawConnection().(*net.TCPConn)
			conn, err := tcpServer(rawConn, &c.config)
			if err != nil {
				return nil, err
			}

			return conn, nil
		}
	}
}

func (c *RelayClient) Close() error {
	if c.node != nil {
		return c.node.Conn.Close()
	}
	return nil
}
