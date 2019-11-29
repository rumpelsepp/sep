package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"git.sr.ht/~rumpelsepp/sep"

	"github.com/pelletier/go-toml"
)

type config struct {
	Peers []peer
}

type peer struct {
	Fingerprint string
	Trusted     []string
}

func readConfig(path string) (*config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var conf config
	if err := toml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}
	return &conf, nil
}

func (c *config) contains(fp *sep.Fingerprint) (int, bool) {
	for i, v := range c.Peers {
		fp2, err := sep.FingerprintFromNIString(v.Fingerprint)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if sep.FingerprintIsEqual(fp, fp2) {
			return i, true
		}
	}
	return 0, false
}
