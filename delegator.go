package sep

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor"
)

const (
	DelegMsgTypeDelegate = iota
	DelegMsgTypeSubscribe
	DelegMsgTypeAddPeer
	DelegMsgTypeDelPeer
	DelegMsgTypeFinish
	DelegMsgTypeACK
	DelegMsgTypeNACK
	DelegMsgTypePing
)

type DelegatorMessage struct {
	Type       byte
	Peer       string
	ValidUntil string
}

type DelegatorNode struct {
	Conn    Conn
	Encoder *cbor.Encoder
	Decoder *cbor.Decoder
}

func NewDelegatorNode(conn Conn) *DelegatorNode {
	return &DelegatorNode{
		Conn:    conn,
		Encoder: cbor.NewEncoder(conn, cborEncodingOpts),
		Decoder: cbor.NewDecoder(conn),
	}
}

func (c *DelegatorNode) Delegate() error {
	req := DelegatorMessage{Type: DelegMsgTypeDelegate}
	if err := c.Encoder.Encode(req); err != nil {
		return nil
	}

	var resp DelegatorMessage
	if err := c.Decoder.Decode(&resp); err != nil {
		return nil
	}

	switch resp.Type {
	case DelegMsgTypeACK:
		return nil
	case DelegMsgTypeNACK:
		return fmt.Errorf("delegation denied by delegator")
	default:
		return fmt.Errorf("unexpected message type")
	}
}

func (c *DelegatorNode) AcceptDelegate() error {
	var req DelegatorMessage
	if err := c.Decoder.Decode(&req); err != nil {
		return err
	}
	if req.Type != DelegMsgTypeDelegate {
		return fmt.Errorf("unexpected message type")
	}

	resp := DelegatorMessage{Type: DelegMsgTypeACK}
	if err := c.Encoder.Encode(resp); err != nil {
		return err
	}
	return nil
}

func (c *DelegatorNode) PushFingerprint(fp *Fingerprint, valid time.Time) error {
	msg := DelegatorMessage{
		Type:       DelegMsgTypeAddPeer,
		Peer:       fp.String(),
		ValidUntil: valid.Format(time.RFC3339),
	}
	if err := c.Encoder.Encode(msg); err != nil {
		return err
	}

	return nil
}

func (c *DelegatorNode) Finish() error {
	msg := DelegatorMessage{Type: DelegMsgTypeFinish}
	if err := c.Encoder.Encode(msg); err != nil {
		return err
	}

	return nil
}

func (c *DelegatorNode) Fetch(db TrustDatabase) error {
	if err := c.Delegate(); err != nil {
		return err
	}

	for {
		var msg DelegatorMessage
		if err := c.Decoder.Decode(&msg); err != nil {
			return err
		}
		if msg.Type == DelegMsgTypeFinish {
			return nil
		}

		fp, err := FingerprintFromNIString(msg.Peer)
		if err != nil {
			Logger.Warning(err)
			continue
		}

		switch msg.Type {
		case DelegMsgTypeAddPeer:
			valid, err := time.Parse(time.RFC3339, msg.ValidUntil)
			if err != nil {
				Logger.Warning(err)
				continue
			}

			ttl := valid.Sub(time.Now())
			if ttl < 0 {
				Logger.Warning("DelegatorClient received timed out fingerprint")
				continue
			}

			if err := db.AddPeer(fp, ttl); err != nil {
				Logger.Warning(err)
				continue
			}

		case DelegMsgTypeDelPeer:
			if err := db.DelPeer(fp); err != nil {
				Logger.Warning(err)
				continue
			}

		default:
			Logger.Warning("DelegatorClient encountered unexpected message type")
			continue
		}
	}
}

func (c *DelegatorNode) Close() error {
	return c.Conn.Close()
}

type TrustManager struct {
	Delegator *Fingerprint
	Dialer    Dialer
	DB        TrustDatabase
}

func (m *TrustManager) UpdateTrust() error {
	conn, err := m.Dialer.DialTimeout("tcp", m.Delegator.String(), 5*time.Second)
	if err != nil {
		return err
	}
	delegNode := NewDelegatorNode(conn)
	return delegNode.Fetch(m.DB)
}
