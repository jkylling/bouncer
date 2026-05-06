package id_test

import (
	"encoding/json"
	"testing"

	"github.com/jkylling/bouncer/internal/id"
)

// fooKind / barKind are stand-ins for real domain markers. The two
// IDs declared here are the smallest possible reproduction of the
// "different IDs are different types" guarantee the package
// promises — they are never used outside this test file.
type fooKind struct{}
type barKind struct{}

type fooID = id.Type[fooKind]
type barID = id.Type[barKind]

func TestDistinctMarkersDoNotAssign(t *testing.T) {
	// Compilation guard: a fooID literal cannot be assigned to a
	// barID slot. We can't write the negative case without breaking
	// the build, so this test just pins the conversion path that's
	// allowed (explicit re-typing through string).
	a := fooID("x")
	b := barID(a)
	if string(b) != "x" {
		t.Errorf("re-typing dropped value: %q", b)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	in := struct {
		ID fooID `json:"id"`
	}{ID: "abc-123"}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != `{"id":"abc-123"}` {
		t.Errorf("emitted %s, want abc-123 in id field", raw)
	}
	var out struct {
		ID fooID `json:"id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ID != "abc-123" {
		t.Errorf("round-trip drift: %q", out.ID)
	}
}

func TestSQLScan(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  any
		want fooID
	}{
		{"string", "hello", "hello"},
		{"bytes", []byte("hello"), "hello"},
		{"nil", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got fooID
			if err := got.Scan(tc.src); err != nil {
				t.Fatalf("scan: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSQLScanRejectsUnknownType(t *testing.T) {
	var got fooID
	if err := got.Scan(42); err == nil {
		t.Fatal("scan(int) should error")
	}
}

func TestValueReturnsString(t *testing.T) {
	v, err := fooID("z").Value()
	if err != nil {
		t.Fatalf("value: %v", err)
	}
	if v != "z" {
		t.Errorf("got %v, want %q", v, "z")
	}
}

func TestIsZero(t *testing.T) {
	if !fooID("").IsZero() {
		t.Error("empty fooID should be zero")
	}
	if fooID("x").IsZero() {
		t.Error("non-empty fooID should not be zero")
	}
}
