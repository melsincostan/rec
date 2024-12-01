package v1

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/google/uuid"
	"github.com/melsincostan/rec/types"
)

// KEY_EXTRACT_SIZE defined the number of bytes from the key that should be used as part of the integrity check
const KEY_EXTRACT_SIZE = int(4)

// Integrity holds the various components used to compute a SHA256 hash to fingerprint a record.
// It also offers a Digest function to generate said hash.
type Integrity struct {
	KeyExtract []byte // first 4 bytes of the key
	ID         []byte
	Version    []byte
	Data       []byte // full data, it's going to be hashed anyways
}

// NewIntegrity returns an Integrity struct with the internal fields filled using the provided informations.
func NewIntegrity(key []byte, id uuid.UUID, data []byte) (*Integrity, error) {
	if len(key) < KEY_EXTRACT_SIZE { // should be redundant, key should be 32 bytes
		return nil, types.NewBadKeyErr(fmt.Sprintf("expected len >= %d, got %d", KEY_EXTRACT_SIZE, len(key)))
	}
	versionBin := make([]byte, 4)
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

// Digest returns a byte array holding the SHA256 digest of the binary representation of the information.
// This binary representation is obtained using Bin().
func (i Integrity) Digest() []byte {
	digest := sha256.Sum256(i.Bin())
	return digest[:]
}

// Bin returns a representation of all of the information as a single byte array.
func (i Integrity) Bin() []byte {
	res := []byte{}
	res = append(res, i.KeyExtract...)
	res = append(res, i.ID...)
	res = append(res, i.Version...)
	res = append(res, i.Data...)
	return res
}
