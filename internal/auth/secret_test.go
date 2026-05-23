package auth

import (
	"strings"
	"testing"
)

func TestSecretFromHex(t *testing.T) {
	hex64 := strings.Repeat("cd", 32)
	got, err := SecretFromHex(hex64)
	if err != nil {
		t.Fatalf("SecretFromHex: %v", err)
	}
	for i, b := range got {
		if b != 0xCD {
			t.Fatalf("byte[%d] = %#x, want 0xCD", i, b)
		}
	}
}

func TestSecretFromHexRejectsShort(t *testing.T) {
	_, err := SecretFromHex(strings.Repeat("aa", 16))
	if err == nil {
		t.Fatal("expected error for 16-byte secret")
	}
}

func TestSecretFromHexRejectsLong(t *testing.T) {
	_, err := SecretFromHex(strings.Repeat("aa", 33))
	if err == nil {
		t.Fatal("expected error for 33-byte secret")
	}
}

func TestSecretFromHexRejectsNonHex(t *testing.T) {
	_, err := SecretFromHex(strings.Repeat("zz", 32))
	if err == nil {
		t.Fatal("expected error for non-hex input")
	}
}
