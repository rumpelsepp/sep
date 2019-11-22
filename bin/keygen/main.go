package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"git.sr.ht/~rumpelsepp/rlog"
	"git.sr.ht/~rumpelsepp/sep"
	"git.sr.ht/~rumpelsepp/sep/sephelper"
	"git.sr.ht/~sircmpwn/getopt"
)

type runtimeOptions struct {
	genKey bool
	show   bool
	help   bool
}

func main() {
	opts := runtimeOptions{}
	getopt.BoolVar(&opts.genKey, "g", false, "Generate a new keypair")
	getopt.BoolVar(&opts.show, "s", false, "Show fingerprint, key from stdin")
	getopt.BoolVar(&opts.help, "h", false, "Show help page and exit")
	getopt.Parse()

	if opts.help {
		getopt.Usage()
		os.Exit(0)
	}

	if opts.genKey {
		privPEM, err := sephelper.GenKeyPEM()
		if err != nil {
			rlog.Critln(err)
		}

		fmt.Print(string(privPEM))
	} else if opts.show {
		privPEM, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			rlog.Critln(err)
		}

		block, _ := pem.Decode(privPEM)
		if block == nil || block.Type != "ED25519 PRIVATE KEY" {
			rlog.Critln("PEM decoding error")
		}

		p, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			rlog.Crit("parsing key failed")
		}

		priv, ok := p.(ed25519.PrivateKey)
		if !ok {
			rlog.Crit("wrong key type")
		}

		ownFp, err := sep.FingerprintFromPublicKey(priv.Public())
		if err != nil {
			rlog.Critln(err)
		}

		fmt.Println(ownFp.String())
	}
}
