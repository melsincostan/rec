package types

import "github.com/google/uuid"

type EncryptedRecord struct {
	ID        uuid.UUID
	Data      []byte
	Integrity []byte
	Version   uint
}
