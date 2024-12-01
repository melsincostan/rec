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

// VERSION defined the version uint number of these implementations.
// Since this is used to compute integrity, changing this will render existing records unusable.
// This shouldn't be changed anyways.
// A new version should be implemented instead, and records can be migrated to it using the Rotate function.
const VERSION = uint(1)

// KEY_SIZE expresses the number of bytes in a key.
// Since the plan is to use AES256, the key must be 32 bytes (32 * 8 = 256).
const KEY_SIZE = int(32)

// Encrypt takes a key and data in an arbitrary format, and returns an EnryptedRecord or an error.
// It uses gob to turn the data into a binary representation.
// This binary is then encrypted using AES256 with the provided key.
// For the ID, an uuid is generated.
// This also sets an integrity hash which bases on the id, the data itself, the version and the encryption key.
// Note: since gob is used under the hood, one might have to use gob.Register to avoid errors with some custom types.
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

// Decrypt takes an EncryptedRecord and, provided the integrity checksum matches with the provided data, tries to decrypt it.
// The generic type should be specified, as it cannot be inferred from the EncryptedRecord.
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
