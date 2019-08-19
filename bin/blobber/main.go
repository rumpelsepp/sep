package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"git.sr.ht/~rumpelsepp/sep"
	"git.sr.ht/~sircmpwn/getopt"
)

type runtimeOptions struct {
	directory string
	fetch     string
}

func main() {
	opts := runtimeOptions{}
	getopt.StringVar(&opts.directory, "d", "api.ace-sep.de", "Domain of Directory")
	getopt.StringVar(&opts.fetch, "f", "", "Fetch this Blob and print to stdout")
	getopt.Parse()

	keypair, err := sep.GenKeypair()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	dirClient := sep.NewDirectoryClient(opts.directory, &keypair, nil)

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

	resp, err := dirClient.AnnounceBlob(data, 1800)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(resp.Fingerprint)
}
