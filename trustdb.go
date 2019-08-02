package sep

import (
	"fmt"
	"sync"
)

type TrustDatabase interface {
	AddPeer(fingerprint *Fingerprint) error
	DelPeer(fingerprint *Fingerprint) error
	IsTrusted(fingerprint *Fingerprint) bool
}

type MemoryDB struct {
	data  map[string]bool
	mutex sync.Mutex
}

func NewMemoryDB() *MemoryDB {
	return &MemoryDB{
		data: make(map[string]bool),
	}
}

func (db *MemoryDB) AddPeer(fingerprint *Fingerprint) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if _, ok := db.data[fingerprint.String()]; ok {
		return fmt.Errorf("%s is already known", fingerprint.String())
	}

	db.data[fingerprint.String()] = true

	return nil
}

func (db *MemoryDB) DelPeer(fingerprint *Fingerprint) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	delete(db.data, fingerprint.String())

	return nil
}

func (db *MemoryDB) IsTrusted(fingerprint *Fingerprint) bool {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if _, ok := db.data[fingerprint.String()]; ok {
		return true
	}
	return false
}
