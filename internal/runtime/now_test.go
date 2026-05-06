package runtime

import (
	"testing"
	"time"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// TestEvaluateInjectsNow checks that a policy condition referencing
// `now` evaluates against the runtime's clock. Pins the wiring: a
// stubbed `r.now` lets the test compare against an exact instant.
func TestEvaluateInjectsNow(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Actions: []models.Action{
			{Name: "ping", Method: "GET", Path: "/svc/ping"},
		},
	}
	rt := buildSingleAPI(t, api, models.Policy{
		API:       "svc",
		Name:      "after_cutoff",
		Action:    `action.name == "ping"`,
		Condition: `now > timestamp_seconds(1700000000)`,
		Result:    models.Permit,
	})
	rt.now = func() time.Time { return time.Unix(1700000001, 0).UTC() }

	got, err := rt.Evaluate(t.Context(), constantResolver(staticAPI{}),
		&pb.Request{Method: "GET", Path: "/svc/ping", PathSegments: []string{"svc", "ping"}},
		stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Permit {
		t.Fatalf("decision = %s, want Permit (now > cutoff)", got)
	}

	rt.now = func() time.Time { return time.Unix(1699999999, 0).UTC() }
	got, err = rt.Evaluate(t.Context(), constantResolver(staticAPI{}),
		&pb.Request{Method: "GET", Path: "/svc/ping", PathSegments: []string{"svc", "ping"}},
		stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Deny {
		t.Fatalf("decision = %s, want Deny (now < cutoff)", got)
	}
}

// TestEvaluateNowIsFixedPerRequest verifies the per-request capture
// guarantee: every policy on a single Evaluate call must see the same
// `now` value, even though the runtime evaluates principal/action/
// condition predicates in sequence. We assert this by stubbing `r.now`
// with a counter that increments on every call — if the runtime asked
// for `now` more than once per request, the two policies below would
// disagree about the cutoff and the test would flake.
//
// The runtime contract is "one `r.now()` per `APIRuntime.Evaluate`",
// so a counter greater than one calls = bug.
func TestEvaluateNowIsFixedPerRequest(t *testing.T) {
	api := &models.API{
		Name:         "svc",
		BaseURL:      "https://svc",
		PathPrefixes: []string{"/svc"},
		Actions: []models.Action{
			{Name: "ping", Method: "GET", Path: "/svc/ping"},
		},
	}
	// Two policies, both with conditions that read `now`. Each
	// principal/action/condition predicate would re-fetch `now` if the
	// runtime didn't cache.
	rt := buildSingleAPI(t, api,
		models.Policy{
			API:       "svc",
			Name:      "p1",
			Principal: `now > timestamp_seconds(0)`,
			Action:    `now > timestamp_seconds(0) && action.name == "ping"`,
			Condition: `now > timestamp_seconds(0)`,
			Result:    models.Permit,
		},
		models.Policy{
			API:       "svc",
			Name:      "p2",
			Principal: `now > timestamp_seconds(0)`,
			Action:    `now > timestamp_seconds(0) && action.name == "ping"`,
			Condition: `now > timestamp_seconds(0)`,
			Result:    models.Permit,
		},
	)

	calls := 0
	rt.now = func() time.Time {
		calls++
		return time.Unix(1700000000, 0).UTC()
	}

	_, err := rt.Evaluate(t.Context(), constantResolver(staticAPI{}),
		&pb.Request{Method: "GET", Path: "/svc/ping", PathSegments: []string{"svc", "ping"}},
		stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if calls != 1 {
		t.Fatalf("now() called %d times, want 1 (per-request capture)", calls)
	}
}
