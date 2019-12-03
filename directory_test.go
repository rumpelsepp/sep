package sep

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rs := DirectoryRecordSet{TTL: 10}
	rs.Sign(privKey)

	fmt.Println(rs.Pretty())

	fp, err := FingerprintFromPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	if ok, err := rs.CheckSignature(fp); !ok || err != nil {
		t.Fatalf("ok: %v, err: %v", ok, err)
	}
}
