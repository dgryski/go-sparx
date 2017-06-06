package sparx

import (
	"reflect"
	"testing"
)

func TestSPARX(t *testing.T) {
	key := []uint16{0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xaabb, 0xccdd, 0xeeff}
	plain := []uint16{0x0123, 0x4567, 0x89ab, 0xcdef}
	cipher := []uint16{0x2bbe, 0xf152, 0x01f5, 0x5f98}

	c := New(key)

	d := make([]uint16, len(plain))
	copy(d, plain)

	c.Encrypt(d)
	if !reflect.DeepEqual(d, cipher) {
		t.Errorf("encrypt failed")
	}

	copy(d, cipher)
	c.Decrypt(d)
	if !reflect.DeepEqual(d, plain) {
		t.Errorf("decrypt failed")
	}
}
