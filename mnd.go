package sep

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"git.sr.ht/~rumpelsepp/ni"
	"git.sr.ht/~rumpelsepp/rlog"
	"github.com/fxamacker/cbor"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func mndBroadcastRequest(payload *DirectoryRecordSet) {
	brdAddresses, err := gatherAllBroadcastAddresses()
	if err != nil {
		logger.Warningf("gathering broadcast addresses failed: %s", err)
		return
	}
	logger.Debugf("Sending MND discover request to these broadcast addresses: %+v", brdAddresses)

	for _, brdAddress := range brdAddresses {
		brd, err := net.ResolveUDPAddr("udp", net.JoinHostPort(brdAddress, DefaultMNDDiscoverPort))
		if err != nil {
			logger.Warningf("%v", err)
			continue
		}

		conn, err := net.DialUDP("udp", nil, brd)
		if err != nil {
			logger.Warningf("%v", err)
			continue
		}

		encoder := cbor.NewEncoder(conn, cbor.EncOptions{Canonical: true})
		if err := encoder.Encode(payload); err != nil {
			logger.Warningf("%v", err)
			continue
		}

		if err := conn.Close(); err != nil {
			logger.Warningf("%v", err)
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
				logger.Debugf("error while decoding: %s", err)
				continue
			}

			respFp, err := FingerprintFromPublicKey(response.PubKey, DefaultFingerprintSuite, "")
			if err != nil {
				logger.Debugf("got response with non-parsable public key: %s", err)
				continue
			}
			if !FingerprintIsEqual(respFp, targetFp) {
				logger.Debugf("got response from '%s', expecting '%s'", respFp, targetFp)
				continue
			}

			logger.Debugf("got valid response")
			gotResp <- true
			return
		}
	}()

	timeout := time.After(timeoutDuration)
	for {
		select {
		case <-timeout:
			logger.Debug("MND discovery timed out")
			decoding = false
			return nil, fmt.Errorf("MND discovery timeout")
		case <-gotResp:
			logger.Debug("MND discovery was successful")
			return response, nil
		}
	}
}

// MNDListener responds to MNDDiscoverRequests.
type MNDListener struct {
	privateKey crypto.PrivateKey
	payload    *DirectoryRecordSet

	running bool
	close   chan bool
	timeout *time.Timer

	ownFp      *Fingerprint
	trustedFPs []*Fingerprint
}

// NewMNDListener serves as constructor of the MNDListener type which responds
// to MNDDiscoverRequests.
func NewMNDListener(ownFp *Fingerprint, privateKey crypto.PrivateKey, trustedFPs []*Fingerprint) MNDListener {
	timer := time.NewTimer(5 * time.Second)
	timer.Stop()
	return MNDListener{
		ownFp:      ownFp,
		privateKey: privateKey,
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
func (m *MNDListener) ServeRecordSet(recordSet *DirectoryRecordSet, listenAddr string) error {
	logger.Debug("Updating RecordSet of MND listener")
	m.payload = recordSet
	m.payload.Sign(m.privateKey)

	// This is an length check of the resulting record, arbitrarily set to 500
	var b bytes.Buffer
	writer := bufio.NewWriter(&b)
	encoder := cbor.NewEncoder(writer, cbor.EncOptions{Canonical: true})
	if err := encoder.Encode(m.payload); err != nil {
		return err
	}
	if writer.Buffered() > 500 || writer.Buffered() == 0 {
		logger.Warning(writer.Buffered())
		return fmt.Errorf("RecordSet too large")
	}

	m.timeout.Reset(time.Duration(m.payload.TTL) * time.Second)

	if !m.running {
		logger.Debug("Starting MND listener")
		m.running = true
		if err := m.listen(listenAddr); err != nil {
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
				logger.Info("MNDListener timed out")
				m.running = false
				conn.Close()
				return
			case <-m.close:
				logger.Info("MNDListener received close request")
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
				logger.Debugf("error while decoding: %s", err)
				continue
			}
			logger.Debugf("Received packet from %s", senderAddress.String())

			// Decode packet
			decoder := cbor.NewDecoder(bytes.NewReader(buff[:n]))
			if err := decoder.Decode(requestPayload); err != nil {
				logger.Debugf("could not parse payload: %s", err)
				continue
			}

			// Check target
			if !bytes.Equal(requestPayload.Blob, m.ownFp.Bytes()) {
				logger.Debugf("got request for '%s'; am '%s'", requestPayload.Blob, m.ownFp.Bytes())
				continue
			}
			logger.Debugf("Request is addressed to me")

			// Validate packet signature
			reqFp, err := FingerprintFromPublicKey(requestPayload.PubKey, DefaultFingerprintSuite, "")
			if err != nil {
				logger.Debugf("got response with non-parsable public key: %s", err)
				continue
			}
			signatureOk, err := requestPayload.CheckSignature(reqFp)
			if err != nil {
				logger.Debugf("signature check failed: %s", err)
				continue
			}
			if !signatureOk {
				logger.Infof("signature check failed: %s", err)
				continue
			}
			logger.Debugf("Request has valid signature")

			// Check whether sender is trusted
			trusted := false
			for _, fp := range m.trustedFPs {
				if FingerprintIsEqual(reqFp, fp) {
					trusted = true
					break
				}
			}
			if !trusted {
				logger.Debug("Request comes from untrusted node")
				continue
			}
			logger.Debug("Request comes from trusted node")

			// Prepare response address
			if senderAddress.Port, err = strconv.Atoi(DefaultMNDResponsePort); err != nil {
				logger.Warningf("could not parse DefaultMNDResponsePort")
				continue
			}

			// Send response
			respConn, err := net.DialUDP("udp", nil, senderAddress)
			if err != nil {
				logger.Warning(err)
				continue
			}
			defer respConn.Close()

			// Hardcode TTL to 5 for low lifetimes on local networks
			m.payload.TTL = 5
			m.payload.Sign(m.privateKey)

			encoder := cbor.NewEncoder(respConn, cbor.EncOptions{Canonical: true})
			if err := encoder.Encode(m.payload); err != nil {
				logger.Warning(err)
				continue
			}
			logger.Debugf("Sent response to %s", senderAddress.String())
		}
	}()

	return nil
}

// From here it's untouched legacy stuff

const (
	FlagQuery      = iota // Normal Query
	FlagQueryAll          // All Nodes should answer.
	FlagMCResponse        // The response should be a multicast.
)

const ReqTimeout = 1 * time.Second

type Request struct {
	Version   uint32
	Flags     uint32
	Query     string
	PubKey    []byte
	Nonce     []byte
	Timestamp []byte
}

type Response struct {
	Version   uint32
	Addresses []string
	PubKey    []byte
	Nonce     []byte
	Timestamp []byte
}

type Node struct {
	Interfaces     []net.Interface
	Address        string
	Group          net.IP
	Port           int
	GetAddresses   func() ([]string, error)
	PrivateKey     crypto.PrivateKey
	OwnFingerprint *ni.URL
	Trusted        []*ni.URL

	init  bool
	conn  net.PacketConn
	pconn interface{}
}

func gatherAddresses() ([]string, error) {
	addrs := []string{}

	interfaces, err := net.Interfaces()
	if err != nil {
		rlog.Critln(err)
	}

	for _, intf := range interfaces {
		addresses, err := intf.Addrs()
		if err != nil {
			rlog.Warning(err)
			continue
		}

		for _, addr := range addresses {
			if n, ok := addr.(*net.IPNet); ok {
				if n.IP.IsGlobalUnicast() {
					addrStr := net.JoinHostPort(n.IP.String(), "33000")
					addrs = append(addrs, "tcp://"+addrStr)
				}
			}
		}
	}

	return addrs, nil
}

func (n *Node) genNonce() []byte {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	return nonce
}

func (n *Node) deduceFingerprint() (*ni.URL, error) {
	// TODO: panics; don't panic!
	privKey := n.PrivateKey.(*ecdsa.PrivateKey)

	derPubKey, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return nil, err
	}

	digest := sha3.Sum256(derPubKey)

	fingerprint, err := ni.DigestToNI(digest[:], "sha3-256", "lddns.org")
	if err != nil {
		return nil, err
	}

	return fingerprint, nil
}

func (n *Node) initClient4() error {
	c, err := net.ListenPacket("udp4", n.Address)
	if err != nil {
		return err
	}

	p := ipv4.NewPacketConn(c)
	n.conn = c
	n.pconn = p

	if err := p.SetControlMessage(ipv4.FlagDst, true); err != nil {
		return err
	}

	return nil
}

func (n *Node) initClient6() error {
	c, err := net.ListenPacket("udp6", n.Address)
	if err != nil {
		return err
	}

	p := ipv6.NewPacketConn(c)
	n.conn = c
	n.pconn = p

	if err := p.SetControlMessage(ipv6.FlagDst, true); err != nil {
		return err
	}

	return nil
}

func (n *Node) initClient() error {
	var err error

	if n.Group.To4() != nil {
		err = n.initClient4()
	} else {
		err = n.initClient6()
	}

	if err != nil {
		return err
	}

	if len(n.Interfaces) == 0 {
		n.Interfaces, err = net.Interfaces()
		if err != nil {
			return err
		}
	}

	if n.OwnFingerprint == nil {
		n.OwnFingerprint, err = n.deduceFingerprint()
		if err != nil {
			return err
		}
	}

	n.init = true

	return nil
}

func (n *Node) initServer4() error {
	c, err := net.ListenPacket("udp4", n.Address)
	if err != nil {
		return err
	}

	p := ipv4.NewPacketConn(c)
	n.conn = c
	n.pconn = p

	if err := p.SetControlMessage(ipv4.FlagDst, true); err != nil {
		return err
	}

	for _, intf := range n.Interfaces {
		if (intf.Flags&net.FlagUp) == 0 || (intf.Flags&net.FlagMulticast) == 0 {
			continue
		}

		if err := p.JoinGroup(&intf, &net.UDPAddr{IP: n.Group}); err != nil {
			rlog.Warningf("JoinGroup: %+v %s", intf, err)
		}
	}

	return nil
}
func (n *Node) initServer6() error {
	c, err := net.ListenPacket("udp6", n.Address)
	if err != nil {
		return err
	}

	p := ipv6.NewPacketConn(c)
	n.conn = c
	n.pconn = p

	if err := p.SetControlMessage(ipv6.FlagDst, true); err != nil {
		return err
	}

	for _, intf := range n.Interfaces {
		if (intf.Flags&net.FlagUp) == 0 || (intf.Flags&net.FlagMulticast) == 0 {
			continue
		}

		if err := p.JoinGroup(&intf, &net.UDPAddr{IP: n.Group}); err != nil {
			rlog.Warningf("JoinGroup: %+v %s", intf, err)
		}
	}

	return nil
}

func (n *Node) initServer() error {
	var err error

	if n.Group.To4() != nil {
		err = n.initServer4()
	} else {
		err = n.initServer6()
	}

	if err != nil {
		return err
	}

	if len(n.Interfaces) == 0 {
		n.Interfaces, err = net.Interfaces()
		if err != nil {
			return err
		}
	}

	if n.GetAddresses == nil {
		n.GetAddresses = gatherAddresses
	}

	if n.OwnFingerprint == nil {
		n.OwnFingerprint, err = n.deduceFingerprint()
		if err != nil {
			return err
		}
	}

	n.init = true

	return nil
}

var errWrongAddr = errors.New("wrong destination address")

func (n *Node) readFromDualStack1(p []byte) (int, net.Addr, error) {
	var (
		src    net.Addr
		nBytes int
		err    error
	)

	switch c := n.pconn.(type) {
	case *ipv4.PacketConn:
		var rcm *ipv4.ControlMessage

		nBytes, rcm, src, err = c.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}

		if rcm.Dst.IsMulticast() {
			// Wrong packet; drop it and move on.
			return 0, nil, errWrongAddr
		}
	case *ipv6.PacketConn:
		var rcm *ipv6.ControlMessage

		nBytes, rcm, src, err = c.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}

		if rcm.Dst.IsMulticast() {
			// Wrong packet; drop it and move on.
			return 0, nil, errWrongAddr
		}
	default:
		panic("wrong PacketConn type")
	}

	return nBytes, src, nil
}

func (n *Node) readFromDualStack(p []byte) (int, net.Addr, error) {
	var (
		src    net.Addr
		nBytes int
		err    error
	)

	switch c := n.pconn.(type) {
	case *ipv4.PacketConn:
		var rcm *ipv4.ControlMessage

		nBytes, rcm, src, err = c.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}

		if !(rcm.Dst.IsMulticast() && rcm.Dst.Equal(n.Group)) {
			// Wrong packet; drop it and move on.
			return 0, nil, errWrongAddr
		}
	case *ipv6.PacketConn:
		var rcm *ipv6.ControlMessage

		nBytes, rcm, src, err = c.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}

		if !(rcm.Dst.IsMulticast() && rcm.Dst.Equal(n.Group)) {
			// Wrong packet; drop it and move on.
			return 0, nil, errWrongAddr
		}
	default:
		panic("wrong PacketConn type")
	}

	return nBytes, src, nil
}

func (n *Node) writeToDualStack(p []byte, dst net.Addr, index int) (int, error) {
	var (
		nBytes int
		err    error
	)

	switch c := n.pconn.(type) {
	case *ipv4.PacketConn:
		wcm := ipv4.ControlMessage{IfIndex: index}

		nBytes, err = c.WriteTo(p, &wcm, dst)
		if err != nil {
			return 0, err
		}

	case *ipv6.PacketConn:
		wcm := ipv6.ControlMessage{TrafficClass: 0xe0, HopLimit: 1, IfIndex: index}

		nBytes, err = c.WriteTo(p, &wcm, dst)
		if err != nil {
			return 0, err
		}

	default:
		panic("wrong PacketConn type")
	}

	return nBytes, nil
}

func (n *Node) Serve() error {
	if !n.init {
		if err := n.initServer(); err != nil {
			return err
		}
	}

	b := make([]byte, 1500)
	for {
		_, src, err := n.readFromDualStack(b)
		if err != nil {
			rlog.Debugln(err)
			continue
		}

		req, err := n.parseRequest(b)
		if err != nil {
			rlog.Warningln(err)
			continue
		}

		target, err := ni.ParseNI(req.Query)
		if err != nil {
			rlog.Warningln(err)
			continue
		}

		if ok := bytes.Equal(target.Bytes(), n.OwnFingerprint.Bytes()); !ok {
			rlog.Warningf("received query which is not for me: %s\n", target)
			continue
		}

		addresses, _ := n.GetAddresses()
		resp, err := n.makeResponse(addresses, req.Nonce)
		if err != nil {
			rlog.Warningln(err)
			continue
		}

		if _, err := n.conn.WriteTo(resp, src); err != nil {
			rlog.Warningln(err)
			continue
		}
	}

	return nil
}

func (n *Node) makeRequest(fingerprint *ni.URL, flags uint32) ([]byte, []byte, error) {
	// TODO: panics; handle error
	privKey := n.PrivateKey.(*ecdsa.PrivateKey)

	derPubKey, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return nil, nil, err
	}

	nonce := n.genNonce()
	timestamp, err := time.Now().MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	req := Request{
		Version:   1,
		Flags:     flags,
		Nonce:     nonce,
		PubKey:    derPubKey,
		Query:     fingerprint.String(),
		Timestamp: timestamp,
	}

	var reqBuf bytes.Buffer
	encoder := cbor.NewEncoder(&reqBuf, cbor.EncOptions{Canonical: true})
	err = encoder.Encode(&req)
	if err != nil {
		return nil, nil, err
	}

	buf := make([]byte, 2)
	// Length prefix covers the whole packet until the signature.
	binary.BigEndian.PutUint16(buf, uint16(reqBuf.Len()+2))
	buf = append(buf, reqBuf.Bytes()...)

	d := sha3.Sum256(buf)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, d[:])
	if err != nil {
		return nil, nil, err
	}

	signature, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return nil, nil, err
	}

	return append(buf, signature...), nonce, nil
}

func (n *Node) makeResponse(addresses []string, nonce []byte) ([]byte, error) {
	privKey := n.PrivateKey.(*ecdsa.PrivateKey)

	derPubKey, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return nil, err
	}

	timestamp, err := time.Now().MarshalBinary()
	if err != nil {
		return nil, err
	}

	resp := Response{
		Version:   1,
		Addresses: addresses,
		PubKey:    derPubKey,
		Nonce:     nonce,
		Timestamp: timestamp,
	}

	var respBuf bytes.Buffer
	encoder := cbor.NewEncoder(&respBuf, cbor.EncOptions{Canonical: true})
	encoder.Encode(&resp)

	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(respBuf.Len()+2))
	buf = append(buf, respBuf.Bytes()...)

	d := sha3.Sum256(buf)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, d[:])
	if err != nil {
		return nil, err
	}

	signature, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return nil, err
	}

	return append(buf, signature...), err
}

func (n *Node) checkTimestamp(timestamp []byte) error {
	var (
		parsedTime time.Time
		errInvalid = errors.New("invalid timestamp")
	)

	if err := parsedTime.UnmarshalBinary(timestamp); err != nil {
		return errInvalid
	}

	// TODO: Make more tests here; reinclude time.Now().After() check
	if time.Since(parsedTime) > ReqTimeout {
		return errInvalid
	}

	return nil
}

func (n *Node) parseRequest(rawRequest []byte) (Request, error) {
	sigOffset := binary.BigEndian.Uint16(rawRequest[:2])
	rawSignature := rawRequest[sigOffset:]

	req := Request{}
	buf := bytes.NewBuffer(rawRequest[2:sigOffset])
	decoder := cbor.NewDecoder(buf)
	if err := decoder.Decode(&req); err != nil {
		return Request{}, err
	}

	if err := n.checkTimestamp(req.Timestamp); err != nil {
		return Request{}, err
	}

	keyDigest := sha3.Sum256(req.PubKey)
	fromTrusted := false

	for i := 0; i < len(n.Trusted); i++ {
		// TODO: prefix from ni URL stuff
		if bytes.Equal(keyDigest[:], n.Trusted[i].Bytes()[1:]) {
			fromTrusted = true
			break
		}
	}

	if !fromTrusted {
		return Request{}, fmt.Errorf("received request from untrusted node")
	}

	pk, err := x509.ParsePKIXPublicKey(req.PubKey)
	if err != nil {
		return Request{}, err
	}

	signature := ecdsaSignature{}
	_, err = asn1.Unmarshal(rawSignature, &signature)
	if err != nil {
		return Request{}, err
	}

	pubKey := pk.(*ecdsa.PublicKey)
	d := sha3.Sum256(rawRequest[:sigOffset])

	if ok := ecdsa.Verify(pubKey, d[:], signature.R, signature.S); !ok {
		return Request{}, fmt.Errorf("signature verification failed")
	}

	return req, nil
}

func (n *Node) parseResponse(rawResp []byte, nonce []byte) (Response, error) {
	sigOffset := binary.BigEndian.Uint16(rawResp[:2])
	rawSignature := rawResp[sigOffset:]

	resp := Response{}
	buf := bytes.NewBuffer(rawResp[2:sigOffset])
	decoder := cbor.NewDecoder(buf)
	if err := decoder.Decode(&resp); err != nil {
		return Response{}, err
	}

	if err := n.checkTimestamp(resp.Timestamp); err != nil {
		return Response{}, err
	}

	keyDigest := sha3.Sum256(resp.PubKey)

	// TODO: prefix from ni URL stuff
	if !bytes.Equal(keyDigest[:], n.Trusted[0].Bytes()[1:]) {
		return Response{}, fmt.Errorf("received response from untrusted node")
	}

	pk, err := x509.ParsePKIXPublicKey(resp.PubKey)
	if err != nil {
		return Response{}, err
	}

	if !bytes.Equal(nonce, resp.Nonce) {
		return Response{}, fmt.Errorf("wrong nonce")
	}

	signature := ecdsaSignature{}
	_, err = asn1.Unmarshal(rawSignature, &signature)
	if err != nil {
		return Response{}, err
	}

	pubKey := pk.(*ecdsa.PublicKey)
	d := sha3.Sum256(rawResp[:sigOffset])

	if ok := ecdsa.Verify(pubKey, d[:], signature.R, signature.S); !ok {
		return Response{}, fmt.Errorf("signature verification failed")
	}

	return resp, nil
}

func (n *Node) Request(fingerprint *ni.URL) ([]string, error) {
	if !n.init {
		if err := n.initClient(); err != nil {
			return []string{}, err
		}
	}

	// TODO:
	n.Trusted = make([]*ni.URL, 1)
	n.Trusted[0] = fingerprint

	dst := &net.UDPAddr{IP: n.Group, Port: n.Port}
	// TODO: Is this safe to send to multiple interfaces with the same nonce?
	req, nonce, err := n.makeRequest(fingerprint, FlagQuery)
	if err != nil {
		return []string{}, err
	}

	for _, intf := range n.Interfaces {
		if (intf.Flags&net.FlagUp) == 0 || (intf.Flags&net.FlagMulticast) == 0 {
			continue
		}

		if _, err := n.writeToDualStack(req, dst, intf.Index); err != nil {
			rlog.Warningf("%s", err)
		}
	}

	b := make([]byte, 1500)
	var nBytes int
	errCounter := 0

	for errCounter < 3 {
		n.conn.SetReadDeadline(time.Now().Add(time.Second))
		nBytes, _, err = n.readFromDualStack1(b)
		n.conn.SetReadDeadline(time.Time{})

		if err != nil {
			rlog.Debug(err)
			errCounter++
		} else {
			break
		}
	}

	if err != nil {
		return []string{}, err
	}

	resp, err := n.parseResponse(b[:nBytes], nonce)
	if err != nil {
		return []string{}, err
	}

	return resp.Addresses, nil
}
