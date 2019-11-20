package helper

import (
	mathrand "math/rand"
	"time"

	"git.sr.ht/~rumpelsepp/sep"
)

type Announcer struct {
	DirClient     *sep.DirectoryClient
	TTL           uint
	Active        bool
	AddrsCallback func() ([]string, error)
}

func (a *Announcer) AnnounceAddresses() error {
	for a.Active {
		addrs, err := a.AddrsCallback()
		if err != nil {
			return err
		}
		if err := a.DirClient.AnnounceAddresses(addrs, a.TTL); err != nil {
			return err
		}
		random := uint(mathrand.Intn(60))
		time.Sleep(time.Duration(a.TTL-random) * time.Second)
	}

	return nil
}
