package types

import "github.com/google/uuid"

type EncryptedRecord struct {
	ID        uuid.UUID
	Data      []byte
	Signature []byte
	Version   uint
}
