package main

import (
	"os"
	"path"

	"git.sr.ht/~rumpelsepp/rlog"
	"git.sr.ht/~rumpelsepp/sep"
	"git.sr.ht/~rumpelsepp/sep/sephelper"
	"git.sr.ht/~sircmpwn/getopt"
	"github.com/fxamacker/cbor/v2"
)

var logger = rlog.NewLogger(os.Stderr)

func handleRelayReq(req sep.RelayMessage, relay *sep.RelayNode, sessionDB *sessionDB) {
	targetFp, err := sep.FingerprintFromNIString(req.Target)
	if err != nil {
		logger.Warningln(err)
		return
	}

	session, ok := sessionDB.get(targetFp.String())
	if !ok {
		logger.Debug("target is not exposed")
		return
	}

	if session.state != sessionIDLE {
		logger.Debug("no available session")
		return
	}

	logger.Debug("target is there. Stopping keep alive.")
	session.stopPing()
	session.initiator = relay
	session.state = sessionHANDSHAKE

	logger.Debug("starting relay handshake")
	err = session.handshake(req)
	if err != nil {
		logger.Warningln(err)
		return
	}

	session.state = sessionTRANSFER

	logger.Debug("starting transfer phase")
	err = session.serve()
	if err != nil {
		logger.Warningln(err)
		return
	}
}

func handleExpose(req sep.RelayMessage, relay *sep.RelayNode, sessionDB *sessionDB) {
	targetFp, err := sep.FingerprintFromNIString(req.Target)
	if err != nil {
		logger.Warningln(err)
		return
	}

	logger.Infof("[%x]: got expose request", targetFp.Bytes()[:6])

	resp := sep.RelayMessage{
		Type: sep.RelayMsgTypeAck,
	}

	if err := relay.Send(resp); err != nil {
		return
	}

	session := relayConn{
		state:      sessionIDLE,
		target:     relay,
		pingActive: true,
	}
	sessionDB.put(targetFp.String(), &session)

	logger.Infof("[%s]: acknowledged. Starting keep alive.", targetFp.Short())

	err = session.ping()
	if err != nil {
		logger.Warning(err)
		sessionDB.del(targetFp.String())
	}
}

func getAddresses(proto, port string) func() ([]string, error) {
	return func() ([]string, error) {
		return sephelper.GatherAllAddresses(proto, port)
	}
}

type runtimeOptions struct {
	configDir  string
	directory  string
	listenAddr string
	help       bool
}

func main() {
	logger.SetModule("[sep-relay]")

	opts := runtimeOptions{}
	getopt.StringVar(&opts.configDir, "c", "/etc/sep-relay", "Config directory")
	getopt.StringVar(&opts.directory, "d", "ace-sep.de", "Announce to this directory")
	getopt.StringVar(&opts.listenAddr, "l", "[::]:33010", "Listen on this address")
	getopt.BoolVar(&opts.help, "h", false, "Show help and exit")
	getopt.Parse()

	keyPath := path.Join(opts.configDir, "key.pem")

	if opts.help {
		getopt.Usage()
		os.Exit(0)
	}

	keypair, err := sephelper.LoadKeyCert(keyPath)
	if err != nil {
		logger.Critln(err)
	}

	ownFp, err := sep.FingerprintFromCertificate(keypair.Certificate[0])
	if err != nil {
		logger.Critln(err)
	}

	logger.Infof("Your fingerprint is: %s\n", ownFp.String())

	tlsConfig := sephelper.NewDefaultTLSConfig(keypair)
	tlsConfig.VerifyPeerCertificate = sep.VerifierAllowAll
	config := sep.Config{
		TCPFastOpen: true,
		TLSConfig:   tlsConfig,
	}

	ln, err := sep.Listen("tcp", opts.listenAddr, config)
	if err != nil {
		logger.Critln(err)
	}

	sessionDB := newSessionDB()
	tlsConfigDir := sephelper.NewDefaultTLSConfig(keypair)
	dirClient := sep.NewDirectoryClient("api"+opts.directory, tlsConfigDir, nil)
	// TODO: get port from cli
	ann := sephelper.Announcer{
		DirClient:     dirClient,
		TTL:           1800,
		AddrsCallback: getAddresses("tcp", "33010"),
		Active:        true,
	}

	go ann.AnnounceAddresses()

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Warningln(err)
			continue
		}

		relay := sep.RelayNode{
			Conn:    conn,
			Keypair: keypair,
			Encoder: cbor.NewEncoder(conn),
			Decoder: cbor.NewDecoder(conn),
		}

		req, err := relay.RecvRaw()
		if err != nil {
			logger.Warningln(err)
			continue
		}

		switch req.Type {
		case sep.RelayMsgTypeExpose:
			go handleExpose(req, &relay, &sessionDB)
		case sep.RelayMsgTypeRequest:
			go handleRelayReq(req, &relay, &sessionDB)
		default:
			conn.Close()
		}
	}
}
