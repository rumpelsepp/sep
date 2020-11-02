package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path"

	"git.sr.ht/~rumpelsepp/rlog"
	"git.sr.ht/~rumpelsepp/sep"
	"git.sr.ht/~rumpelsepp/sep/sephelper"
	"git.sr.ht/~sircmpwn/getopt"
)

type runtimeOptions struct {
	directory string
	put       bool
	query     bool
	debug     bool
	json      bool
	help      bool
}

func main() {
	homeDir, err := os.UserConfigDir()
	if err != nil {
		rlog.Critln(err)
	}

	opts := runtimeOptions{}
	getopt.StringVar(&opts.directory, "d", "ace-sep.de", "Directory API server location")
	getopt.BoolVar(&opts.query, "q", false, "Query directory for record set of given fingerprint")
	getopt.BoolVar(&opts.put, "p", false, "Put record set to directory and exit")
	getopt.BoolVar(&opts.json, "j", false, "Print data as JSON")
	getopt.BoolVar(&opts.debug, "v", false, "Print debug output")
	getopt.BoolVar(&opts.help, "h", false, "Show help page and exit")
	getopt.Parse()

	if opts.debug {
		rlog.SetLogLevel(rlog.DEBUG)
		sep.Logger.SetWriter(os.Stderr)
		sep.Logger.SetLogLevel(rlog.DEBUG)
	}

	var (
		certPath = path.Join(homeDir, "sep", "cert.pem")
		keyPath  = path.Join(homeDir, "sep", "key.pem")
		args     = getopt.Args()
	)

	if opts.help {
		getopt.Usage()
		os.Exit(0)
	}

	keypair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		rlog.Critln(err)
	}

	tlsConfig := sephelper.NewDefaultTLSConfig(keypair)
	dirClient := sep.NewDirectoryClient(opts.directory, tlsConfig)

	if opts.put {
		addrs, err := sephelper.GatherAllAddresses("tcp", "33000")
		if err != nil {
			rlog.Critln(err)
		}

		req := sep.DirectoryRecordSet{
			Addresses: addrs,
			TTL:       1800,
		}
		if err := dirClient.Announce(&req); err != nil {
			rlog.Critln(err)
		}

		os.Exit(0)
	}

	if opts.query {
		fp, err := sep.FingerprintFromNIString(args[0])
		if err != nil {
			rlog.Critln(err)
		}

		if rs, err := dirClient.Discover(fp); err != nil {
			rlog.Critln(err)
		} else {
			if opts.json {
				d, _ := json.Marshal(rs)
				fmt.Println(string(d))
				os.Exit(0)
			} else {
				fmt.Println(rs.Pretty())
				os.Exit(0)
			}
		}
	}
}
