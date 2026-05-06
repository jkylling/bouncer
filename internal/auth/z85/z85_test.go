package z85

import (
	"bytes"
	"testing"
)

// TestRoundtrip exercises a spread of input lengths so the pad-count
// framing is hit at every alignment (n%4 == 0..3) and an empty input.
func TestRoundtrip(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 5, 16, 28, 100} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*31 + 7)
		}
		s := Encode(data)
		out, err := Decode(s)
		if err != nil {
			t.Fatalf("len=%d decode: %v", n, err)
		}
		if !bytes.Equal(out, data) {
			t.Errorf("len=%d roundtrip mismatch", n)
		}
	}
}

func TestDecodeRejectsBadLength(t *testing.T) {
	// 4 chars is not a multiple of 5.
	if _, err := Decode("abcd"); err == nil {
		t.Fatal("expected length error")
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestDecodeRejectsBadCharacter(t *testing.T) {
	// `~` is not in the alphabet.
	if _, err := Decode("abc~e"); err == nil {
		t.Fatal("expected unknown-character error")
	}
}

// TestDecodeRejectsBadPadCount pins the pad>3 rejection. We bypass
// Encode (which only ever emits pad ∈ [0..3]) and hand-craft a Z85
// block whose first decoded byte is 4 — out of range.
func TestDecodeRejectsBadPadCount(t *testing.T) {
	bad := encodeBlockForTest([4]byte{4, 0, 0, 0})
	if _, err := Decode(bad); err == nil {
		t.Fatal("expected pad-count error")
	}
}

// encodeBlockForTest is the inner Z85 block encoder, exposed only so
// tests can construct illegal payloads.
func encodeBlockForTest(b [4]byte) string {
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	var out [5]byte
	for j := 4; j >= 0; j-- {
		out[j] = alphabet[v%85]
		v /= 85
	}
	return string(out[:])
}
