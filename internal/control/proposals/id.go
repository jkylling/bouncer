package proposals

import (
	"time"

	"github.com/jkylling/bouncer/internal/id"
)

// proposalKind is the phantom marker that turns id.Type into
// ProposalID. Never instantiated.
type proposalKind struct{}

// ProposalID identifies one proposal record. Tagged with proposalKind
// so the compiler refuses to mix it with EventID or any future id
// class.
type ProposalID = id.Type[proposalKind]

// proposalIDPrefix tags proposal ids in logs and the wire format so a
// stray id is recognisable as a proposal rather than an event id.
const proposalIDPrefix = "prop_"

// NewProposalID returns a fresh proposal ID. Same 6+10 byte layout as
// the traffic recorder, with a `prop_` prefix.
func NewProposalID() ProposalID {
	return id.NewTimePrefixed[proposalKind](time.Now(), proposalIDPrefix)
}
