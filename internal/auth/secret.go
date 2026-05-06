package auth

import (
	"encoding/hex"
	"fmt"
)

// devStubByte is the byte every position of DevStubSecret holds.
// 0xAA gives an obvious all-bits-alternating pattern in a hex dump
// so a stray dev-stub key in production logs is recognisable at a
// glance; the precise value otherwise has no significance.
const devStubByte = 0xAA

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

// DevStubSecret returns the deterministic 32-byte secret used by
// `--dev-stub-secret`. It exists so multiple binaries (cmd/bouncer
// and cmd/issue-token) hit the same key when running locally — a
// token issued offline by issue-token under the stub verifies in a
// stub-mode proxy without operator coordination.
func DevStubSecret() [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = devStubByte
	}
	return out
}
