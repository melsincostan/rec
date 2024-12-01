package rec

import (
	"reflect"
	"testing"

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

func TestEncrypt(t *testing.T) {
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

	// test that the generated version decrypts fine
	dec, err := Decrypt[testStruct](key[:], *enc)
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
