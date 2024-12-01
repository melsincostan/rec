package rec

import (
	"fmt"

	"github.com/melsincostan/rec/types"
	v1 "github.com/melsincostan/rec/v1"
)

var V1 = v1.VERSION

// Encrypt encrypts data to an Encrypted record using the specified key and version.
func Encrypt(version uint, key []byte, data any) (*types.EncryptedRecord, error) {
	switch version {
	case V1:
		return v1.Encrypt(key, data)
	default:
		return nil, types.NewNotImplementedErr(fmt.Sprintf("encryption version: %d", version))
	}
}

// Decrypt decrypts data from an Encrypted record using the internal version field and provided key.
func Decrypt[T any](key []byte, data types.EncryptedRecord) (*T, error) {
	switch data.Version {
	case V1:
		return v1.Decrypt[T](key, data)
	default:
		return nil, types.NewNotImplementedErr(fmt.Sprintf("encryption version: %d", data.Version))
	}
}

// Rotate is able to rotate key and version for a record by decrypting it and re-encrypting it using the new key and version.
func Rotate[T any](oldKey []byte, newVersion uint, newKey []byte, data types.EncryptedRecord) (*types.EncryptedRecord, error) {
	if data.Version > newVersion {
		return nil, types.NewBadRotationErr(fmt.Sprintf("newVersion cannot be lower than the current version: %d < %d", newVersion, data.Version))
	}

	d, err := Decrypt[T](oldKey, data)
	if err != nil {
		return nil, err
	}

	return Encrypt(newVersion, newKey, d)
}
