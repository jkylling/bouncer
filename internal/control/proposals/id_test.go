package proposals

import (
	"strings"
	"testing"
	"time"
)

// TestNewProposalIDPrefix pins that issued IDs always start with the
// `prop_` prefix so a stray ID in a log line is recognisable.
func TestNewProposalIDPrefix(t *testing.T) {
	got := NewProposalID()
	if !strings.HasPrefix(got.String(), proposalIDPrefix) {
		t.Errorf("id %q does not start with %q", got, proposalIDPrefix)
	}
}

// TestNewProposalIDLength pins the encoded width: prefix + 32 hex
// chars (16 bytes hex-encoded). Stable shape so an API boundary can
// validate the format at parse time.
func TestNewProposalIDLength(t *testing.T) {
	got := NewProposalID().String()
	if want := len(proposalIDPrefix) + 32; len(got) != want {
		t.Errorf("len(%q) = %d, want %d", got, len(got), want)
	}
}

// TestNewProposalIDUniqueWithinMillisecond asserts that two IDs issued
// in tight succession differ — the time-prefix alone would collide,
// so the random suffix is what carries the uniqueness.
func TestNewProposalIDUniqueWithinMillisecond(t *testing.T) {
	a := NewProposalID()
	b := NewProposalID()
	if a == b {
		t.Errorf("two consecutive ids collided: %q", a)
	}
}

// TestProposalIDLexOrderMatchesTime asserts that the encoded form
// sorts in time order across millisecond boundaries — pagination by
// `id` then matches pagination by insertion time without an
// additional `(ts, id)` index.
func TestProposalIDLexOrderMatchesTime(t *testing.T) {
	a := NewProposalID()
	time.Sleep(2 * time.Millisecond)
	b := NewProposalID()
	if a >= b {
		t.Errorf("expected a < b after sleep; got a=%q b=%q", a, b)
	}
}
