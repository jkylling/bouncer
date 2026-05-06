// Package id provides a generic, type-safe identifier wrapper.
//
// Each domain (proposal, traffic event, …) declares a zero-size
// marker struct and aliases id.Type to it:
//
//	type proposalKind struct{}
//	type ProposalID = id.Type[proposalKind]
//
// Distinct markers produce distinct types, so the compiler refuses to
// assign a ProposalID to a slot expecting an EventID — even though
// both are strings under the hood. The marker is purely a phantom: it
// has no fields, no methods, and never appears at runtime.
//
// The shared method set (String, Marshal/UnmarshalText, Scan, Value)
// covers the wire formats every ID in this codebase uses — JSON,
// SQL TEXT columns, URL path params — so per-domain ID files only
// declare the marker and the constructor.
package id

import (
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding"
	"encoding/hex"
	"fmt"
	"time"
)

// Type is a string-backed identifier tagged with phantom marker K.
// Two instantiations with different K are distinct named types and
// will not assign or compare across class boundaries; both share the
// methods declared below.
//
// String backing was chosen because every ID surface this codebase
// crosses (JSON wire, SQL TEXT column, chi URL param) is already a
// string — so the methods reduce to one-liners and there is no
// hidden conversion when a value crosses a boundary.
type Type[K any] string

// String renders the canonical text representation. Satisfies
// fmt.Stringer so logging and `%s` formatting do the right thing.
func (id Type[K]) String() string { return string(id) }

// IsZero reports whether the ID is the zero value. Useful at API
// boundaries where an unset ID is the "create me a new one" signal.
func (id Type[K]) IsZero() bool { return id == "" }

// MarshalText implements encoding.TextMarshaler, which is also
// encoding/json's preferred path for non-string types — a single
// implementation covers JSON, query-string, and YAML emission.
func (id Type[K]) MarshalText() ([]byte, error) { return []byte(id), nil }

// UnmarshalText is the symmetric decoder. It accepts whatever bytes
// the wire carried; per-domain validators (e.g. uuid.Parse) should
// run separately when format guarantees matter.
func (id *Type[K]) UnmarshalText(text []byte) error {
	*id = Type[K](text)
	return nil
}

// Value implements driver.Valuer for SQL writes. SQLite (and most
// other drivers) want a concrete primitive — the wrapper is opaque
// to them.
func (id Type[K]) Value() (driver.Value, error) { return string(id), nil }

// Scan implements sql.Scanner for SQL reads. Accepts the two shapes
// the SQLite driver returns for TEXT columns (string and []byte) and
// rejects anything else with a clear error rather than silently
// dropping the value.
func (id *Type[K]) Scan(src any) error {
	switch v := src.(type) {
	case string:
		*id = Type[K](v)
	case []byte:
		*id = Type[K](v)
	case nil:
		*id = ""
	default:
		return fmt.Errorf("id: cannot scan %T into Type[K]", src)
	}
	return nil
}

// TimeBytes is the byte width of a time-prefixed ID before hex
// encoding: 6 bytes of millisecond timestamp + 10 bytes of randomness.
// Layout mirrors ULID but encodes as 32-char hex because hex is
// grep-friendly in the sqlite shell and sort-stable without needing
// a Crockford alphabet.
const TimeBytes = 16

// NewTimePrefixed returns a fresh ID whose lex sort matches insertion
// order at millisecond resolution. The leading 6 bytes are big-endian
// milliseconds since Unix epoch; the trailing 10 bytes are
// crypto/rand. The result is hex-encoded and optionally fronted with
// `prefix` so a stray ID in a log line is recognisable as belonging
// to its domain (e.g. "prop_..." for proposals).
//
// crypto/rand failure is unrecoverable: emitting a non-unique ID
// would confuse every downstream system, so the panic is the safer
// option.
func NewTimePrefixed[K any](t time.Time, prefix string) Type[K] {
	var b [TimeBytes]byte
	ms := uint64(t.UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	if _, err := rand.Read(b[6:]); err != nil {
		panic("id: rand.Read: " + err.Error())
	}
	return Type[K](prefix + hex.EncodeToString(b[:]))
}

// TimestampOf extracts the embedded millisecond timestamp from an ID
// produced by NewTimePrefixed. `prefix` must match what was passed at
// construction. Returns the zero time on malformed input — callers
// that care about correctness over leniency should sanity-check.
func TimestampOf[K any](id Type[K], prefix string) time.Time {
	s := string(id)
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
		return time.Time{}
	}
	b, err := hex.DecodeString(s[len(prefix):])
	if err != nil || len(b) != TimeBytes {
		return time.Time{}
	}
	ms := uint64(b[0])<<40 |
		uint64(b[1])<<32 |
		uint64(b[2])<<24 |
		uint64(b[3])<<16 |
		uint64(b[4])<<8 |
		uint64(b[5])
	return time.UnixMilli(int64(ms))
}

// Compile-time interface guards. Drift in the method set above
// surfaces here at build time rather than as a confused runtime
// failure inside encoding/json or database/sql.
var (
	_ fmt.Stringer             = Type[struct{}]("")
	_ encoding.TextMarshaler   = Type[struct{}]("")
	_ encoding.TextUnmarshaler = (*Type[struct{}])(nil)
	_ driver.Valuer            = Type[struct{}]("")
	_ sql.Scanner              = (*Type[struct{}])(nil)
)
