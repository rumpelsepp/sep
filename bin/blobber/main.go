package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"git.sr.ht/~rumpelsepp/rlog"
	"git.sr.ht/~rumpelsepp/sep"
	"git.sr.ht/~rumpelsepp/sep/helper"
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

	keypair, err := helper.GenTLSKeypair()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	config := helper.NewDefaultTLSConfig(keypair)
	dirClient := sep.NewDirectoryClient("api."+opts.directory, config, nil)

	if opts.fetch != "" {
		fingerprint, err := sep.FingerprintFromNIString(opts.fetch)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		data, err := dirClient.DiscoverBlob(fingerprint)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		_, err = os.Stdout.Write(data)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		os.Exit(0)
	}

	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := dirClient.AnnounceBlob(data, 1800); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	ownFp, err := sep.FingerprintFromCertificate(keypair.Certificate[0])
	if err != nil {
		fmt.Println(err)
	}
	ownFp.Authority = opts.directory

	fmt.Println(ownFp.String())
}
