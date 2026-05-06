package traffic

import (
	"time"

	"github.com/jkylling/bouncer/internal/id"
)

// eventKind is the phantom marker that turns id.Type into EventID.
type eventKind struct{}

// EventID identifies one captured request. Tagged with eventKind so
// the compiler refuses to mix it with proposal ids or any future id
// class.
type EventID = id.Type[eventKind]

// NewEventID returns a fresh time-prefixed event ID.
func NewEventID() EventID { return newIDAt(time.Now()) }

func newIDAt(t time.Time) EventID {
	return id.NewTimePrefixed[eventKind](t, "")
}
