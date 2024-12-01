package v1

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/google/uuid"
	"github.com/melsincostan/rec/types"
)

var VERSION = uint(1)

func Encrypt(key []byte, data any) (*types.EncryptedRecord, error) {
	if len(key) != 32 { // key size for AES256
		return nil, types.NewBadKeyErr(fmt.Sprintf("key size must be 32, got %d", len(key)))
	}

	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)

	if err := enc.Encode(data); err != nil {
		return nil, err
	}

	return &types.EncryptedRecord{
		ID:        uuid.New(),
		Data:      []byte{},
		Signature: []byte{},
		Version:   VERSION,
	}, nil
}

func Decrypt[T any](key []byte, data types.EncryptedRecord) (*T, error) {
	return nil, nil
}
