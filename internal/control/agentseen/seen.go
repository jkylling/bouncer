// Package agentseen tracks JWT subjects that have recently
// authenticated against the bouncer control plane. The dashboard's
// "Connected agents" card reads from List; the MCP handler feeds
// Touch on every Bearer-authenticated JSON-RPC call.
//
// In-memory by design: the data answers "who is here right now",
// and a restart resetting the view is correct semantics — an agent
// that hasn't reconnected since the restart isn't connected. If we
// ever need historical retention, swap the map for a SQLite-backed
// store behind the same surface.
package agentseen

import (
	"sort"
	"sync"
	"time"
)

// Tracker is the in-memory roll-up of subject sightings.
type Tracker struct {
	mu   sync.Mutex
	seen map[string]*entry
}

type entry struct {
	firstSeen time.Time
	lastSeen  time.Time
	count     int64
}

// New returns an empty Tracker.
func New() *Tracker {
	return &Tracker{seen: map[string]*entry{}}
}

// Touch records that subject was seen at at. First call for a
// subject inserts; subsequent calls advance LastSeen and increment
// the request count. Empty subject is a no-op so the caller can
// hand the anonymous Caller through without a guard.
func (t *Tracker) Touch(subject string, at time.Time) {
	if subject == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.seen[subject]
	if !ok {
		t.seen[subject] = &entry{firstSeen: at, lastSeen: at, count: 1}
		return
	}
	if at.After(e.lastSeen) {
		e.lastSeen = at
	}
	e.count++
}

// Sighting is one entry in the List response.
type Sighting struct {
	Subject      string    `json:"subject"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	RequestCount int64     `json:"request_count"`
}

// List returns every recorded sighting, most-recently-seen first.
func (t *Tracker) List() []Sighting {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Sighting, 0, len(t.seen))
	for subj, e := range t.seen {
		out = append(out, Sighting{
			Subject:      subj,
			FirstSeen:    e.firstSeen,
			LastSeen:     e.lastSeen,
			RequestCount: e.count,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}
