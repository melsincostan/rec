package v1

import (
	"bytes"
	"crypto/aes"
	"encoding/gob"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/melsincostan/rec/types"
)

const VERSION = uint(1)

func Encrypt(key []byte, data any) (*types.EncryptedRecord, error) {
	if len(key) != 32 { // key size for AES256
		return nil, types.NewBadKeyErr(fmt.Sprintf("key size must be 32, got %d", len(key)))
	}

	id := uuid.New()

	buf := new(bytes.Buffer)

	encoder := gob.NewEncoder(buf)

	if err := encoder.Encode(data); err != nil {
		return nil, err
	}

	encoded, err := io.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encrypted := []byte{}

	cipher.Encrypt(encrypted, encoded)

	integrity, err := NewIntegrity(key, id, encrypted)
	if err != nil {
		return nil, err
	}

	return &types.EncryptedRecord{
		ID:        id,
		Data:      encrypted,
		Integrity: integrity.Digest(),
		Version:   VERSION,
	}, nil
}

func Decrypt[T any](key []byte, data types.EncryptedRecord) (*T, error) {
	return nil, nil
}
