package v1

import (
	"bytes"
	"crypto/aes"
	"crypto/subtle"
	"encoding/gob"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/melsincostan/rec/types"
)

const VERSION = uint(1)
const KEY_SIZE = int(32)

func Encrypt(key []byte, data any) (*types.EncryptedRecord, error) {
	if len(key) != KEY_SIZE { // key size for AES256
		return nil, types.NewBadKeyErr(fmt.Sprintf("key size must be %d, got %d", KEY_SIZE, len(key)))
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
	if len(key) != KEY_SIZE { // key_size for AES256
		return nil, types.NewBadKeyErr(fmt.Sprintf("key size must be %d, got %d", KEY_SIZE, len(key)))
	}

	integrity, err := NewIntegrity(key, data.ID, data.Data)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(data.Integrity, integrity.Digest()) != 1 {
		return nil, types.NewBadIntegrityErr()
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encoded := []byte{}
	cipher.Decrypt(encoded, data.Data)
	decoder := gob.NewDecoder(bytes.NewBuffer(encoded))

	res := new(T)
	if err := decoder.Decode(res); err != nil {
		return nil, err
	}

	return res, nil
}
