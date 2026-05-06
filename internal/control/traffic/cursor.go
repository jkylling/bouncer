package traffic

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// cursorPayload is the structured form of a Cursor. Stores compose
// one of these, then call EncodeCursor / DecodeCursor at the
// boundary so the wire form is uniform across backends.
type cursorPayload struct {
	TS time.Time `json:"ts"`
	ID EventID   `json:"id"`
}

// EncodeCursor serialises a (ts, id) pair into the opaque wire
// cursor returned by Store.List. Empty inputs produce the empty
// cursor — callers use that to signal "no further pages."
func EncodeCursor(ts time.Time, id EventID) Cursor {
	if id.IsZero() {
		return ""
	}
	b, err := json.Marshal(cursorPayload{TS: ts, ID: id})
	if err != nil {
		// json.Marshal on this struct cannot fail; surface as panic
		// so a regression in the encoding layout is caught loudly.
		panic("traffic: encode cursor: " + err.Error())
	}
	return Cursor(base64.RawURLEncoding.EncodeToString(b))
}

// DecodeCursor reverses EncodeCursor. Empty input yields the zero
// values without an error so handlers can pass through "no cursor".
// Malformed input yields ErrBadCursor — typically a 400 at the
// HTTP boundary.
func DecodeCursor(c Cursor) (time.Time, EventID, error) {
	if c == "" {
		return time.Time{}, "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(string(c))
	if err != nil {
		return time.Time{}, "", ErrBadCursor
	}
	var p cursorPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return time.Time{}, "", ErrBadCursor
	}
	return p.TS, p.ID, nil
}

// ErrBadCursor signals a decode failure on a List cursor — caller
// supplied an opaque token that did not round-trip through
// EncodeCursor.
var ErrBadCursor = errors.New("traffic: bad cursor")
