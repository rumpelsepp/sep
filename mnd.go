package sep

import (
	"bufio"
	"bytes"
	"crypto"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func mndBroadcastRequest(payload *DirectoryRecordSet) {
	brdAddresses, err := gatherAllBroadcastAddresses()
	if err != nil {
		Logger.Warningf("MND discover failed while gathering broadcast addresses: %s", err)
		return
	}
	Logger.Debugf("MND discover requests are sent to these broadcast addresses: %+v", brdAddresses)

	for _, brdAddress := range brdAddresses {
		brd, err := net.ResolveUDPAddr("udp", net.JoinHostPort(brdAddress, DefaultMNDDiscoverPort))
		if err != nil {
			Logger.Warningf("%v", err)
			continue
		}

		conn, err := net.DialUDP("udp", nil, brd)
		if err != nil {
			Logger.Warningf("%v", err)
			continue
		}

		encoder := cbor.NewEncoder(conn)
		if err := encoder.Encode(payload); err != nil {
			Logger.Warningf("%v", err)
			continue
		}

		if err := conn.Close(); err != nil {
			Logger.Warningf("%v", err)
			continue
		}
	}
}

func mndListenForResponse(targetFp *Fingerprint, timeoutDuration time.Duration) (*DirectoryRecordSet, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("0.0.0.0", DefaultMNDResponsePort))
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	response := &DirectoryRecordSet{}
	decoder := cbor.NewDecoder(conn)
	gotResp := make(chan bool)

	decoding := true
	go func() {
		for decoding {
			if err := decoder.Decode(response); err != nil {
				Logger.Debugf("MND discovery encountered decoder error: %s", err)
				continue
			}

			respFp, err := FingerprintFromPublicKey(response.PubKey)
			if err != nil {
				Logger.Debugf("MND discovery got response with non-parsable public key: %s", err)
				continue
			}
			if !FingerprintIsEqual(respFp, targetFp) {
				Logger.Debugf("MND discovery got response from '%s', instead expected '%s'", respFp.String(), targetFp.String())
				continue
			}

			Logger.Debugf("MND discovery got valid response")
			gotResp <- true
			return
		}
	}()

	timeout := time.After(timeoutDuration)
	for {
		select {
		case <-timeout:
			Logger.Debug("MND discovery timed out")
			decoding = false
			return nil, fmt.Errorf("MND discovery timeout")
		case <-gotResp:
			Logger.Debug("MND discovery was successful")
			return response, nil
		}
	}
}

// MNDListener responds to MNDDiscoverRequests.
type MNDListener struct {
	privateKey crypto.PrivateKey
	payload    *DirectoryRecordSet
	listenAddr string

	running bool
	close   chan bool
	timeout *time.Timer

	ownFp      *Fingerprint
	trustedFPs []*Fingerprint
}

// NewMNDListener serves as constructor of the MNDListener type which responds
// to MNDDiscoverRequests.
func NewMNDListener(listenAddr string, ownFp *Fingerprint, privateKey crypto.PrivateKey, trustedFPs []*Fingerprint) *MNDListener {
	timer := time.NewTimer(5 * time.Second)
	timer.Stop()
	return &MNDListener{
		ownFp:      ownFp,
		privateKey: privateKey,
		listenAddr: listenAddr,
		payload:    &DirectoryRecordSet{},
		close:      make(chan bool, 1),
		running:    false,
		timeout:    timer,
		trustedFPs: trustedFPs,
	}
}

// Close stops the MNDListener.
func (m *MNDListener) Close() {
	m.close <- true
}

// ServeRecordSet updates the RecordSet that is served as a reply for valid Discovery
// requests.
// If not already running, it moreover starts a Listener on the given address and
// DefaultMNDDiscoveryPort which validates incoming MNDDiscoverRequests, signs the
// RecordSet and responds to the requester.
//
// The Listener terminates either when the Close() method is called or when the
// RecordSet expires (defined by the TTL).
func (m *MNDListener) ServeRecordSet(recordSet *DirectoryRecordSet) error {
	m.payload = recordSet
	m.payload.Sign(m.privateKey)

	// This is an length check of the resulting record, arbitrarily set to 500
	var b bytes.Buffer
	writer := bufio.NewWriter(&b)
	encoder := cbor.NewEncoder(writer)
	if err := encoder.Encode(m.payload); err != nil {
		return err
	}
	if writer.Buffered() > 500 || writer.Buffered() == 0 {
		Logger.Warning(writer.Buffered())
		return fmt.Errorf("RecordSet too large")
	}

	m.timeout.Reset(time.Duration(m.payload.TTL) * time.Second)

	if !m.running {
		Logger.Debugf("MNDListener is now listening on %s", m.listenAddr)
		m.running = true
		if err := m.listen(m.listenAddr); err != nil {
			return err
		}
	}

	return nil
}

// Listen starts a listener on the given address and DefaultMNDDiscoveryPort
// which validates incoming MNDDiscoverRequests, signs the RecordSet given by
// the ServeRecordSet() method and responds to the requester.
//
// The Listener terminates either when the Close() method is called or when the
// RecordSet given by the ServeRecordSet() method expires.
func (m *MNDListener) listen(listenAddr string) error {
	requestPayload := &DirectoryRecordSet{}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(listenAddr, DefaultMNDDiscoverPort))
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-m.timeout.C:
				Logger.Info("MNDListener timed out")
				m.running = false
				conn.Close()
				return
			case <-m.close:
				Logger.Info("MNDListener received close request")
				m.running = false
				conn.Close()
				return
			}
		}
	}()

	go func() {
		// It was checked before that the encoded RecordSet is smaller than 500
		buff := make([]byte, 500)

		for m.running {
			n, senderAddress, err := conn.ReadFromUDP(buff)
			if err != nil {
				Logger.Debugf("MNDListener encountered decoder error: %s", err)
				continue
			}
			Logger.Debugf("MNDListener received packet from %s", senderAddress.String())

			// Decode packet
			decoder := cbor.NewDecoder(bytes.NewReader(buff[:n]))
			if err := decoder.Decode(requestPayload); err != nil {
				Logger.Debugf("MNDListener could not parse payload: %s", err)
				continue
			}

			// Check target
			if !bytes.Equal(requestPayload.Blob, m.ownFp.Bytes()) {
				Logger.Debugf("MNDListener got request addressed to other node: '%X'", requestPayload.Blob)
				continue
			}
			Logger.Debugf("MND discover request is addressed to me")

			// Validate packet signature
			reqFp, err := FingerprintFromPublicKey(requestPayload.PubKey)
			if err != nil {
				Logger.Debugf("MND discover request has non-parsable public key: %s", err)
				continue
			}
			signatureOk, err := requestPayload.CheckSignature(reqFp)
			if err != nil {
				Logger.Debugf("MND discover request failed signature check: %s", err)
				continue
			}
			if !signatureOk {
				Logger.Infof("MND discover request has invalid signature: %s", err)
				continue
			}
			Logger.Debugf("MND discover request has valid signature")

			// Check whether sender is trusted
			trusted := false
			for _, fp := range m.trustedFPs {
				if FingerprintIsEqual(reqFp, fp) {
					trusted = true
					break
				}
			}
			if !trusted {
				Logger.Debug("MND discover request comes from untrusted node")
				continue
			}
			Logger.Debug("MND discover request comes from trusted node")

			// Prepare response address
			if senderAddress.Port, err = strconv.Atoi(DefaultMNDResponsePort); err != nil {
				Logger.Warningf("MNDListener could not parse DefaultMNDResponsePort")
				continue
			}

			// Send response
			respConn, err := net.DialUDP("udp", nil, senderAddress)
			if err != nil {
				Logger.Warning(err)
				continue
			}
			defer respConn.Close()

			// Hardcode TTL to 5 for low lifetimes on local networks
			m.payload.TTL = 5
			m.payload.Sign(m.privateKey)

			encoder := cbor.NewEncoder(respConn)
			if err := encoder.Encode(m.payload); err != nil {
				Logger.Warning(err)
				continue
			}
			Logger.Debugf("MND discover response sent to %s", senderAddress.String())
		}
	}()

	return nil
}
