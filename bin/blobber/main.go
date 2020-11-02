package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"git.sr.ht/~rumpelsepp/rlog"
	"git.sr.ht/~rumpelsepp/sep"
	"git.sr.ht/~rumpelsepp/sep/sephelper"
	"git.sr.ht/~sircmpwn/getopt"
)

type runtimeOptions struct {
	directory string
	fetch     string
	verbose   bool
}

func main() {
	opts := runtimeOptions{}
	getopt.StringVar(&opts.directory, "d", "ace-sep.de", "Domain of Directory")
	getopt.StringVar(&opts.fetch, "f", "", "Fetch this Blob and print to stdout")
	getopt.BoolVar(&opts.verbose, "v", false, "Enable debug log")
	getopt.Parse()

	if opts.verbose {
		rlog.SetLogLevel(rlog.DEBUG)
		sep.Logger.SetWriter(os.Stderr)
		sep.Logger.SetLogLevel(rlog.DEBUG)
	}

	keypair, err := sephelper.GenTLSKeypair()
	if err != nil {
		rlog.Crit(err)
	}

	config := sephelper.NewDefaultTLSConfig(keypair)
	dirClient := sep.NewDirectoryClient("sep."+opts.directory, config)

	if opts.fetch != "" {
		fingerprint, err := sep.FingerprintFromNIString(opts.fetch)
		if err != nil {
			rlog.Crit(err)
		}

		data, err := dirClient.DiscoverBlob(fingerprint)
		if err != nil {
			rlog.Crit(err)
		}

		_, err = io.Copy(os.Stdout, bytes.NewReader(data))
		if err != nil {
			rlog.Crit(err)
		}
	} else {
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			rlog.Crit(err)
		}

		if err := dirClient.AnnounceBlob(data, 1800); err != nil {
			rlog.Crit(err)
		}

		ownFp, err := sep.FingerprintFromCertificate(keypair.Certificate[0])
		if err != nil {
			fmt.Println(err)
		}
		ownFp.Authority = opts.directory

		fmt.Println(ownFp.String())
	}
}
