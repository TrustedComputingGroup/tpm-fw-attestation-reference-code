// Package util implements utility functions needed for the rest of this module.
package util

import (
	"encoding/hex"
	"encoding/json"
)

// HexBytes is a byte array that encodes as a hex string when serializing to JSON.
type HexBytes []byte

func (m HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(m))
}
