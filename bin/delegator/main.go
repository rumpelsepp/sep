package main

import (
	"fmt"
	"os"
	"path"
	"time"

	"git.sr.ht/~rumpelsepp/rlog"
	"git.sr.ht/~rumpelsepp/sep"
	"git.sr.ht/~rumpelsepp/sep/sephelper"
	"git.sr.ht/~sircmpwn/getopt"
)

var logger = rlog.NewLogger(os.Stderr)

func init() {
	logger.SetModule("[sep-deleg]")
}

func handleDelegate(conn sep.Conn, conf *config) {
	delegNode := sep.NewDelegatorNode(conn)
	defer delegNode.Close()
	defer delegNode.Finish()

	if err := delegNode.AcceptDelegate(); err != nil {
		logger.Warning(err)
		return
	}

	i, ok := conf.contains(conn.RemoteFingerprint())
	if !ok {
		logger.Info("peer is not known")
		return
	}

	for _, fpRaw := range conf.Peers[i].Trusted {
		fp, err := sep.FingerprintFromNIString(fpRaw)
		if err != nil {
			logger.Warningln(err)
			continue
		}
		// TODO: make the time configurable
		if err := delegNode.PushFingerprint(fp, time.Now().Add(1*time.Hour)); err != nil {
			logger.Warningln(err)
			return
		}
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
	genKey     bool
	show       bool
	help       bool
}

func main() {
	opts := runtimeOptions{}
	getopt.StringVar(&opts.configDir, "c", "/etc/sep-deleg", "Config directory")
	getopt.StringVar(&opts.listenAddr, "l", "[::]:33033", "Listen on this address")
	getopt.StringVar(&opts.directory, "d", "ace-sep.de", "Announce to this directory")
	getopt.BoolVar(&opts.genKey, "g", false, "Generate a new keypair")
	getopt.BoolVar(&opts.show, "s", false, "Show own fingerprint")
	getopt.BoolVar(&opts.help, "h", false, "Show help and exit")
	getopt.Parse()

	var (
		keyPath    = path.Join(opts.configDir, "key.pem")
		configPath = path.Join(opts.configDir, "config.toml")
	)

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

	if opts.show || opts.genKey {
		fmt.Println(ownFp.String())
		os.Exit(0)
	} else {
		logger.Infof("Your fingerprint is: %s\n", ownFp.String())
	}

	tlsConfig := sephelper.NewDefaultTLSConfig(keypair)
	tlsConfig.VerifyPeerCertificate = sep.VerifierAllowAll
	config := sep.Config{
		TLSConfig: tlsConfig,
	}

	ln, err := sep.Listen("tcp", opts.listenAddr, config)
	if err != nil {
		logger.Critln(err)
	}

	conf, err := readConfig(configPath)
	if err != nil {
		logger.Critln(err)
	}
	fmt.Printf("%+v\n", conf)

	tlsConfigDir := sephelper.NewDefaultTLSConfig(keypair)
	dirClient := sep.NewDirectoryClient("sep"+opts.directory, tlsConfigDir)
	// TODO: get port from cli
	ann := sephelper.Announcer{
		DirClient:     dirClient,
		TTL:           1800,
		AddrsCallback: getAddresses("tcp", "33033"),
		Active:        true,
	}

	go ann.AnnounceAddresses()

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Warningln(err)
			continue
		}

		go handleDelegate(conn, conf)
	}
}
