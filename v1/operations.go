package v1

import (
	"bytes"
	"encoding/gob"

	"github.com/melsincostan/rec/types"
)

func Encrypt(key []byte, data any) (*types.EncryptedRecord, error) {
	if len(key) != 32 { // key size for AES256
		return nil, nil // TODO: proper error type later
	}

	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)

	if err := enc.Encode(data); err != nil {
		return nil, err
	}

	return nil, nil
}

func Decrypt[T any](key []byte, data types.EncryptedRecord) (*T, error) {
	return nil, nil
}
