package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"path"

	"git.sr.ht/~rumpelsepp/rlog"
	"git.sr.ht/~rumpelsepp/sep"
	"git.sr.ht/~sircmpwn/getopt"
)

type runtimeOptions struct {
	genKey bool
	show   bool
	help   bool
}

func main() {
	homeDir, err := os.UserConfigDir()
	if err != nil {
		rlog.Critln(err)
	}

	opts := runtimeOptions{}
	getopt.BoolVar(&opts.genKey, "g", false, "Generate a new keypair")
	getopt.BoolVar(&opts.show, "s", false, "Show own fingerprint")
	getopt.BoolVar(&opts.help, "h", false, "Show help page and exit")
	getopt.Parse()

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
	} else if opts.show {
		keypair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			rlog.Critln(err)
		}

		ownFp, err := sep.FingerprintFromCertificate(keypair.Certificate[0], sep.DefaultFingerprintSuite, sep.DefaultResolveDomain)
		if err != nil {
			rlog.Critln(err)
		}

		fmt.Println(ownFp.String())
	}
}
