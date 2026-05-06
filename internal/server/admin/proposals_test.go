package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/policies"
	"github.com/jkylling/bouncer/internal/control/proposals"
	"github.com/jkylling/bouncer/internal/runtime"
)

// proposalServer wires both /_api/policies and /_api/proposals onto
// one httptest server. Approve in particular needs the policy service
// to exist so the promotion side-effect lands; mounting both keeps the
// happy-path test honest.
func proposalServer(t *testing.T) (*httptest.Server, *policies.Service, *proposals.Service, string) {
	ts, pSvc, prSvc, bearer, _ := proposalServerWithKeys(t)
	return ts, pSvc, prSvc, bearer
}

// proposalServerWithKeys is the keys-aware variant. Subject-scoping
// tests need to issue non-admin bearers for arbitrary subjects.
func proposalServerWithKeys(t *testing.T) (*httptest.Server, *policies.Service, *proposals.Service, string, *auth.ServerKeys) {
	t.Helper()
	b := runtime.NewBuilder()
	if err := b.AddAPI(trivialAPI("svc")); err != nil {
		t.Fatalf("add api: %v", err)
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	pSvc := policies.New(rt, policies.NewMemoryStore())
	prSvc := proposals.New(proposals.NewMemoryStore(), pSvc)
	keys := mustKeys(t)
	r := testRouter(keys)
	MountPolicies(r, pSvc)
	MountProposals(r, prSvc)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, pSvc, prSvc, adminBearer(t, keys), keys
}

func goodCreateInput() proposals.CreateInput {
	return proposals.CreateInput{
		Policy:    goodPolicy(),
		Origin:    proposals.Origin{Kind: proposals.OriginAgent, Agent: "test"},
		Author:    "agent-1",
		Rationale: "auto-generated",
	}
}

func TestProposalsCreateRoundTrips(t *testing.T) {
	ts, _, _, bearer := proposalServer(t)
	resp := doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput())
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	got := decodeOK[proposals.Proposal](t, resp, http.StatusCreated)
	if loc, want := resp.Header.Get("Location"), ProposalsPath+"/"+got.ID.String(); loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
	if got.ID.IsZero() || got.Status != proposals.StatusProposed {
		t.Errorf("got %+v", got)
	}
	if got.Author != "agent-1" || got.Origin.Kind != proposals.OriginAgent {
		t.Errorf("metadata not preserved: %+v", got)
	}
}

func TestProposalsCreateInvalidPolicyReturns400(t *testing.T) {
	ts, _, _, bearer := proposalServer(t)
	in := goodCreateInput()
	in.Policy.Condition = "no_such_var"
	requireStatus(t, doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, in), http.StatusBadRequest).Body.Close()
}

// TestProposalsEmptyBodyHitsValidator pins the no-body shape: a
// POST without payload decodes as zero CreateInput and the validator
// then surfaces the first missing field (api), which is more useful
// than a raw "invalid JSON: EOF".
func TestProposalsEmptyBodyHitsValidator(t *testing.T) {
	ts, _, _, bearer := proposalServer(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+ProposalsPath, http.NoBody)
	req.Header.Set("Authorization", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestProposalsPatchRevalidates(t *testing.T) {
	ts, _, _, bearer := proposalServer(t)
	created := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput()),
		http.StatusCreated)

	// Bad edit: invalid CEL — must return 400 and leave the record
	// untouched.
	bad := goodPolicy()
	bad.Condition = "no_such_var"
	requireStatus(t,
		doJSON(t, bearer, http.MethodPatch, ts.URL+ProposalsPath+"/"+created.ID.String(), proposals.UpdateInput{Policy: &bad}),
		http.StatusBadRequest).Body.Close()

	// Good edit: a tightening of the condition — must succeed.
	good := goodPolicy()
	good.Condition = "1 == 1"
	got := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPatch, ts.URL+ProposalsPath+"/"+created.ID.String(), proposals.UpdateInput{Policy: &good}),
		http.StatusOK)
	if got.Policy.Condition != "1 == 1" {
		t.Errorf("policy not updated: %+v", got.Policy)
	}
}

func TestProposalsApprovePromotesPolicy(t *testing.T) {
	ts, pSvc, _, bearer := proposalServer(t)
	created := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput()),
		http.StatusCreated)

	got := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath+"/"+created.ID.String()+"/approve", approveBody{By: "reviewer-1"}),
		http.StatusOK)
	if got.Status != proposals.StatusApproved || got.DecidedBy != "reviewer-1" {
		t.Errorf("got %+v", got)
	}
	// And the policy is now live in the policies service.
	if _, err := pSvc.Get("svc", "p1"); err != nil {
		t.Errorf("approved policy missing: %v", err)
	}
}

func TestProposalsApproveOnDecidedReturns409(t *testing.T) {
	ts, _, _, bearer := proposalServer(t)
	created := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput()),
		http.StatusCreated)

	// First approval succeeds.
	doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath+"/"+created.ID.String()+"/approve", approveBody{By: "r"}).Body.Close()

	// Second approval is a transition error — proposal already decided.
	requireStatus(t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath+"/"+created.ID.String()+"/approve", approveBody{By: "r"}),
		http.StatusConflict).Body.Close()
}

func TestProposalsApproveCollidingPolicyReturns409(t *testing.T) {
	ts, pSvc, _, bearer := proposalServer(t)
	// Seed an existing live policy so approval needs overwrite=true.
	existing := goodPolicy()
	if err := pSvc.Create(t.Context(), &existing); err != nil {
		t.Fatalf("seed: %v", err)
	}

	created := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput()),
		http.StatusCreated)

	requireStatus(t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath+"/"+created.ID.String()+"/approve", approveBody{By: "r"}),
		http.StatusConflict).Body.Close()

	requireStatus(t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath+"/"+created.ID.String()+"/approve", approveBody{By: "r", Overwrite: true}),
		http.StatusOK).Body.Close()
}

// TestProposalsApproveAcceptsEmptyBody pins the documented contract
// that approve/reject accept an empty body and fall back to defaults
// (no `By`, no `Reason`).
func TestProposalsApproveAcceptsEmptyBody(t *testing.T) {
	ts, _, _, bearer := proposalServer(t)
	created := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput()),
		http.StatusCreated)

	requireStatus(t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath+"/"+created.ID.String()+"/approve", nil),
		http.StatusOK).Body.Close()
}

func TestProposalsRejectRecordsReason(t *testing.T) {
	ts, _, _, bearer := proposalServer(t)
	created := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput()),
		http.StatusCreated)

	got := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath+"/"+created.ID.String()+"/reject", rejectBody{By: "reviewer", Reason: "too permissive"}),
		http.StatusOK)
	if got.Status != proposals.StatusRejected || got.RejectionReason != "too permissive" {
		t.Errorf("got %+v", got)
	}
}

func TestProposalsListFilters(t *testing.T) {
	ts, _, _, bearer := proposalServer(t)
	for i := 0; i < 2; i++ {
		in := goodCreateInput()
		// Distinct names so create doesn't 409 against the runtime
		// (proposals don't dedupe on name; the policy validator does
		// during approve).
		if i == 1 {
			in.Policy.Name = "p2"
		}
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, in).Body.Close()
	}
	list := decodeOK[proposalsListResponse](t,
		doJSON(t, bearer, http.MethodGet, ts.URL+ProposalsPath+"?status=proposed", nil),
		http.StatusOK)
	if len(list.Proposals) != 2 {
		t.Errorf("got %d entries, want 2", len(list.Proposals))
	}
}

func TestProposalsUIServesHTML(t *testing.T) {
	// UI shell now redirects anonymous callers to the login page,
	// so we authenticate.
	ts, _, _, bearer := proposalServer(t)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+ProposalsUIPath, nil)
	req.Header.Set("Authorization", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Fatal("empty body")
	}
}

func TestProposalsDelete(t *testing.T) {
	ts, _, _, bearer := proposalServer(t)
	created := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput()),
		http.StatusCreated)
	requireStatus(t,
		doJSON(t, bearer, http.MethodDelete, ts.URL+ProposalsPath+"/"+created.ID.String(), nil),
		http.StatusNoContent).Body.Close()
	requireStatus(t,
		doJSON(t, bearer, http.MethodGet, ts.URL+ProposalsPath+"/"+created.ID.String(), nil),
		http.StatusNotFound).Body.Close()
}

// TestProposalsCreateStampsAuthorForNonAdmin pins that a non-admin
// caller's create body cannot impersonate another author — the
// handler overwrites Author with the JWT subject. Admins are
// trusted, so their explicit Author still wins (a separate sub-test
// exercises that path implicitly via the admin happy paths above).
func TestProposalsCreateStampsAuthorForNonAdmin(t *testing.T) {
	ts, _, _, _, keys := proposalServerWithKeys(t)
	bearer := userBearer(t, keys, "alice")
	in := goodCreateInput() // Author = "agent-1"
	got := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, in),
		http.StatusCreated)
	if got.Author != "alice" {
		t.Errorf("Author = %q, want alice (handler must overwrite for non-admin)", got.Author)
	}
}

// TestProposalsListScopedForNonAdmin pins that a non-admin sees only
// their own proposals in the listing — admin's drafts and other
// subjects' drafts are filtered out.
func TestProposalsListScopedForNonAdmin(t *testing.T) {
	ts, _, _, adminB, keys := proposalServerWithKeys(t)
	aliceB := userBearer(t, keys, "alice")
	bobB := userBearer(t, keys, "bob")

	// Alice and Bob each post; admin posts a third with a distinct
	// policy name to avoid the validator's name-clash check.
	doJSON(t, aliceB, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput()).Body.Close()
	in := goodCreateInput()
	in.Policy.Name = "p2"
	doJSON(t, bobB, http.MethodPost, ts.URL+ProposalsPath, in).Body.Close()
	in = goodCreateInput()
	in.Policy.Name = "p3"
	doJSON(t, adminB, http.MethodPost, ts.URL+ProposalsPath, in).Body.Close()

	// Alice sees one (her own).
	aliceList := decodeOK[proposalsListResponse](t,
		doJSON(t, aliceB, http.MethodGet, ts.URL+ProposalsPath, nil), http.StatusOK)
	if len(aliceList.Proposals) != 1 || aliceList.Proposals[0].Author != "alice" {
		t.Errorf("alice list = %+v, want 1 entry with author alice", aliceList.Proposals)
	}

	// Admin sees all three.
	adminList := decodeOK[proposalsListResponse](t,
		doJSON(t, adminB, http.MethodGet, ts.URL+ProposalsPath, nil), http.StatusOK)
	if len(adminList.Proposals) != 3 {
		t.Errorf("admin list = %d, want 3", len(adminList.Proposals))
	}
}

// TestProposalsCrossSubjectGet404 pins the cross-subject guard:
// asking for someone else's proposal as a non-admin returns 404,
// not 403, so an agent can't probe id namespaces.
func TestProposalsCrossSubjectGet404(t *testing.T) {
	ts, _, _, _, keys := proposalServerWithKeys(t)
	aliceB := userBearer(t, keys, "alice")
	bobB := userBearer(t, keys, "bob")

	created := decodeOK[proposals.Proposal](t,
		doJSON(t, aliceB, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput()),
		http.StatusCreated)

	// Bob can't see alice's proposal.
	requireStatus(t,
		doJSON(t, bobB, http.MethodGet, ts.URL+ProposalsPath+"/"+created.ID.String(), nil),
		http.StatusNotFound).Body.Close()

	// And can't update or delete it either.
	requireStatus(t,
		doJSON(t, bobB, http.MethodDelete, ts.URL+ProposalsPath+"/"+created.ID.String(), nil),
		http.StatusNotFound).Body.Close()
}

// TestProposalsApproveDefaultsByToTokenSubject pins that the
// approve handler infers `by` from the JWT subject when the body
// omits it. The proposals UI used to prompt the reviewer for a
// name; the server already knows it from the cookie/bearer.
func TestProposalsApproveDefaultsByToTokenSubject(t *testing.T) {
	// adminBearer uses subject "test-admin"; an approve POST with
	// no `by` should land that as the approver.
	ts, _, _, bearer := proposalServer(t)
	created := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput()),
		http.StatusCreated)
	got := decodeOK[proposals.Proposal](t,
		doJSON(t, bearer, http.MethodPost,
			ts.URL+ProposalsPath+"/"+created.ID.String()+"/approve",
			map[string]any{}), // no `by`
		http.StatusOK)
	if got.DecidedBy != "test-admin" {
		t.Errorf("DecidedBy = %q, want test-admin (from JWT subject)", got.DecidedBy)
	}
}

// TestProposalsApproveRequiresAdmin pins the route-gate distinction
// between authenticated (CRUD) and admin-only (approve/reject). A
// non-admin POSTing to .../approve gets 403, not 200.
func TestProposalsApproveRequiresAdmin(t *testing.T) {
	ts, _, _, adminB, keys := proposalServerWithKeys(t)
	aliceB := userBearer(t, keys, "alice")

	// Alice posts her own proposal — she's allowed to do that.
	created := decodeOK[proposals.Proposal](t,
		doJSON(t, aliceB, http.MethodPost, ts.URL+ProposalsPath, goodCreateInput()),
		http.StatusCreated)

	// But she can't approve it.
	requireStatus(t,
		doJSON(t, aliceB, http.MethodPost, ts.URL+ProposalsPath+"/"+created.ID.String()+"/approve", approveBody{By: "alice"}),
		http.StatusForbidden).Body.Close()

	// Admin can.
	requireStatus(t,
		doJSON(t, adminB, http.MethodPost, ts.URL+ProposalsPath+"/"+created.ID.String()+"/approve", approveBody{By: "admin"}),
		http.StatusOK).Body.Close()
}
