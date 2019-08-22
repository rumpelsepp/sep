package main

import (
	"crypto/tls"
	"os"
	"path"

	"git.sr.ht/~rumpelsepp/rlog"
	"git.sr.ht/~rumpelsepp/sep"
	"git.sr.ht/~sircmpwn/getopt"
)

type runtimeOptions struct {
	directory string
	delegator string
	debug     bool
	genKey    bool
	help      bool
}

func main() {
	homeDir, err := sep.UserConfigDir()
	if err != nil {
		rlog.Critln(err)
	}

	opts := runtimeOptions{}
	getopt.StringVar(&opts.directory, "d", "ace-sep.de", "Directory API server location")
	getopt.StringVar(&opts.delegator, "t", "ni://ace-sep.de/sha3-256;sreScqcsxsE-H_tRTkPg3PV79t0ZSxjiHUz0yRKXGHg", "Trust is managed by this guy")
	getopt.BoolVar(&opts.genKey, "g", false, "Generate a new keypair")
	getopt.BoolVar(&opts.debug, "v", false, "Print debug output")
	getopt.BoolVar(&opts.help, "h", false, "Show help page and exit")
	getopt.Parse()

	if opts.debug {
		rlog.SetLogLevel(rlog.DEBUG)
	}

	var (
		certPath = path.Join(homeDir, "sep", "cert.pem")
		keyPath  = path.Join(homeDir, "sep", "key.pem")
	)

	if opts.help {
		getopt.Usage()
		os.Exit(0)
	}

	if opts.genKey {
		err := sep.GenKeypairFile(keyPath, certPath)
		if err != nil {
			rlog.Critln(err)
		}
		os.Exit(0)
	}

	keypair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		rlog.Critln(err)
	}

	delegator, err := sep.FingerprintFromNIString(opts.delegator)
	if err != nil {
		rlog.Critln(err)
	}

	dirClient := sep.NewDirectoryClient("api."+opts.directory, &keypair, nil)
	tlsConfig := sep.NewDefaultTLSConfig(keypair)
	config := sep.Config{
		AllowedPeers: []*sep.Fingerprint{delegator},
		Directory:    &dirClient,
		TLSConfig:    tlsConfig,
	}
	dialer, err := sep.NewDialer("tcp", config)
	if err != nil {
		rlog.Critln(err)
	}

	manager := sep.TrustManager{
		Delegator: delegator,
		Dialer:    dialer,
		DB:        sep.NewMemoryDB(),
	}
	manager.UpdateTrust()
}
