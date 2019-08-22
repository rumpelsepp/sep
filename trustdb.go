package sep

import (
	"fmt"
	"sync"
	"time"
)

type TrustDatabase interface {
	AddPeer(fingerprint *Fingerprint, ttl time.Duration) error
	DelPeer(fingerprint *Fingerprint) error
	IsTrusted(fingerprint *Fingerprint) bool
}

type MemoryDB struct {
	data  map[string]entry
	mutex sync.Mutex
}

type entry struct {
	timestamp time.Time
	ttl       time.Duration
}

func NewMemoryDB() *MemoryDB {
	return &MemoryDB{
		data: make(map[string]entry),
	}
}

func (db *MemoryDB) AddPeer(fingerprint *Fingerprint, ttl time.Duration) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if _, ok := db.data[fingerprint.String()]; ok {
		return fmt.Errorf("%s is already known", fingerprint.String())
	}

	db.data[fingerprint.String()] = entry{timestamp: time.Now(), ttl: ttl}
	Logger.Debugf("new dynamically trusted peer: %s", fingerprint.String())

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

	if val, ok := db.data[fingerprint.String()]; ok {
		if time.Since(val.timestamp) > val.ttl {
			delete(db.data, fingerprint.String())
			Logger.Debugf("trusted peer timed out: %s", fingerprint.String())
			return false
		}
		return true
	}
	return false
}
