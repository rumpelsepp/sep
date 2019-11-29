package main

import (
	"sync"
)

type sessionDB struct {
	data  map[string]*relayConn
	mutex sync.Mutex
}

func newSessionDB() sessionDB {
	return sessionDB{
		data:  make(map[string]*relayConn),
		mutex: sync.Mutex{},
	}
}

func (db *sessionDB) get(fingerprint string) (*relayConn, bool) {
	db.mutex.Lock()
	sess, ok := db.data[fingerprint]
	db.mutex.Unlock()
	return sess, ok
}

func (db *sessionDB) put(fingerprint string, sess *relayConn) {
	db.mutex.Lock()
	db.data[fingerprint] = sess
	db.mutex.Unlock()
}

func (db *sessionDB) del(fingerprint string) {
	db.mutex.Lock()
	if _, ok := db.data[fingerprint]; ok {
		delete(db.data, fingerprint)
	}
	db.mutex.Unlock()
}
