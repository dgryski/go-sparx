package sparx

import (
	"crypto/cipher"
	"reflect"
	"testing"
)

func TestSPARX(t *testing.T) {
	key := []uint16{0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xaabb, 0xccdd, 0xeeff}
	plain := []uint8{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	cipher := []uint8{0x2b, 0xbe, 0xf1, 0x52, 0x01, 0xf5, 0x5f, 0x98}

	c := New(key)

	d := make([]uint8, len(plain))
	copy(d, plain)

	c.Encrypt(d, d)
	if !reflect.DeepEqual(d, cipher) {
		t.Errorf("encrypt failed")
	}

	copy(d, cipher)
	c.Decrypt(d, d)
	if !reflect.DeepEqual(d, plain) {
		t.Errorf("decrypt failed")
	}
}

var _ cipher.Block = (*Cipher)(nil)
