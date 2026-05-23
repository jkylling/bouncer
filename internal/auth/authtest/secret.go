// Package authtest holds test-only helpers for the auth package. It
// exists so unit and integration tests can share a deterministic
// 32-byte secret without re-exposing that secret to production code:
// the previous in-package helper (DevStubSecret) was bound to a CLI
// flag, and a stray env-var could silently downgrade a prod boot to a
// well-known key. Anything in this package is reachable only from
// within the bouncer module; production binaries never import it.
package authtest

// secretByte is the byte every position of Secret holds. 0xAA gives
// an obvious all-bits-alternating pattern in a hex dump so a stray
// test secret in a log is recognisable at a glance.
const secretByte = 0xAA

// Secret returns a deterministic 32-byte secret for tests. Both sides
// of a round-trip (issue + verify) must derive their keys from the
// same secret; importing this from a test gives every caller the same
// bytes without coordinating a hex string. Never use in production —
// the value is public in this repo.
func Secret() [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = secretByte
	}
	return out
}
