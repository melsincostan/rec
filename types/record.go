package types

type EncryptedRecord struct {
	ID        uint
	Data      []byte
	Signature []byte
	Version   uint
}
