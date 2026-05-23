package auth

import (
	"encoding/hex"
	"fmt"
)

// SecretFromHex parses a 64-character hex string into the 32-byte
// secret FromSecret expects. A wrong-length input fails up front with
// a clear "expected N bytes" message instead of half-zeroing a key
// and surfacing the mistake at HKDF time.
func SecretFromHex(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("hex decode secret: %w", err)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("secret must be 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
