package v1

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/google/uuid"
	"github.com/melsincostan/rec/types"
)

const KEY_EXTRACT_SIZE = int(4)

type Integrity struct {
	KeyExtract []byte // first 4 bytes of the key
	ID         []byte
	Version    []byte
	Data       []byte // full data, it's going to be hashed anyways
}

func NewIntegrity(key []byte, id uuid.UUID, data []byte) (*Integrity, error) {
	if len(key) < KEY_EXTRACT_SIZE { // should be redundant, key should be 32 bytes
		return nil, types.NewBadKeyErr(fmt.Sprintf("expected len >= %d, got %d", KEY_EXTRACT_SIZE, len(key)))
	}
	versionBin := []byte{}
	binary.LittleEndian.PutUint64(versionBin, uint64(VERSION)) // force into an uint64: uint might be 32 bits or 64 bits depending on platform
	uuidBin, err := id.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &Integrity{
		KeyExtract: key[:KEY_EXTRACT_SIZE],
		ID:         uuidBin,
		Version:    versionBin,
		Data:       data,
	}, nil
}

func (i Integrity) Digest() []byte {
	digest := sha256.Sum256(i.Bin())
	return digest[:]
}

func (i Integrity) Bin() []byte {
	res := []byte{}
	res = append(res, i.KeyExtract...)
	res = append(res, i.ID...)
	res = append(res, i.Version...)
	res = append(res, i.Data...)
	return res
}
