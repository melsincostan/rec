package rec

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/melsincostan/rec/types"
)

const nonexistentVersion = uint(0)

type testStruct struct {
	String string
}

var testStructInstance = testStruct{
	String: "test",
}
var key [32]byte // should all already be 0

var testStructEncrypted = types.EncryptedRecord{
	ID:        uuid.MustParse("75942bd1-d291-406c-9327-8eea821ea2dc"),
	Data:      []byte{0xb6, 0x8e, 0x13, 0x50, 0x78, 0xa2, 0xc2, 0x35, 0x8e, 0x13, 0x3d, 0xa3, 0x98, 0x52, 0xd7, 0x40, 0x7, 0xbd, 0xb9, 0x6c, 0x46, 0x99, 0x94, 0x22, 0xd4, 0xde, 0x6e, 0xd, 0x5a, 0x3f, 0x33, 0x9, 0xa, 0xd5, 0x18, 0x97, 0x5d, 0x88, 0x54, 0xd3, 0x41, 0x4, 0x49, 0x9e, 0x6f, 0x34, 0x4f, 0x5f, 0x3c, 0x38, 0x6, 0xe4, 0x22, 0x13, 0x8d, 0x1f, 0x31, 0x63, 0xff, 0xb2, 0x13, 0x78, 0x95, 0x4d, 0x28, 0x72, 0xcb, 0xcc, 0x0, 0x81, 0xac, 0x19, 0xe9},
	Integrity: []byte{0xb3, 0xa4, 0x2c, 0x9d, 0x44, 0xe1, 0x8d, 0xf4, 0x92, 0xa7, 0xe0, 0x67, 0x62, 0x9f, 0x43, 0xe0, 0x2f, 0x73, 0xd3, 0xfd, 0x9d, 0xc8, 0x71, 0x4, 0xf, 0x10, 0x9, 0x83, 0xb7, 0x8b, 0xd8, 0xc8},
	Version:   V1,
}

func TestEncryptBadVersion(t *testing.T) {
	t.Parallel()
	// test that a non-existent version returns an error
	res, err := Encrypt(nonexistentVersion, key[:], testStructInstance)
	if err == nil {
		t.Error("expected error, got none")
	} else if _, ok := err.(*types.ErrUnimplemented); !ok {
		t.Errorf("expected error of type types.ErrUnimplemented, got %#v", err)
	}

	if res != nil {
		t.Errorf("expected nil result, got %#v", res)
	}
}

func TestEncrypt(t *testing.T) {
	t.Parallel()
	// test that a proper version works fine
	enc, err := Encrypt(V1, key[:], testStructInstance)
	if err != nil {
		t.Errorf("expected no error, got %#v", err)
	}

	if enc == nil {
		t.Fatal("expected result when encrypting")
	}

	if enc.Version != V1 {
		t.Errorf("bad version, expected %d, got %d", V1, enc.Version)
	}
}

func TestDecrypt(t *testing.T) {
	t.Parallel()
	// test that a known good (hopefully?) version decrypts fine
	dec, err := Decrypt[testStruct](key[:], *&testStructEncrypted)
	if err != nil {
		t.Errorf("expected no error, got %#v", err)
	}

	if dec == nil {
		t.Fatal("expected result when decrypting")
	}

	if !reflect.DeepEqual(*dec, testStructInstance) {
		t.Errorf("expected %#v, got %#v", testStructInstance, *dec)
	}

}
