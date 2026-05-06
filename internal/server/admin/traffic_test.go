package admin_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jkylling/bouncer/internal/control/store"
	"github.com/jkylling/bouncer/internal/control/traffic"
	"github.com/jkylling/bouncer/internal/server/admin"
)

// newTrafficSrv mounts the four endpoints on a fresh chi router and
// returns the test server, the underlying store, and the bearer
// header value the tests should attach to every request. Traffic
// reads are admin-tier today; the bearer carries the admin claim
// against the package-shared dev keys.
func newTrafficSrv(t *testing.T, principal admin.PrincipalExtractor) (*httptest.Server, traffic.Store, string) {
	t.Helper()
	s, err := traffic.Open(store.Memory(), traffic.Options{})
	if err != nil {
		t.Fatalf("traffic.Open: %v", err)
	}
	keys := newTestKeys(t)
	r := authedRouter(keys)
	admin.MountTraffic(r, s, principal)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	t.Cleanup(func() { _ = s.Close() })
	return srv, s, adminBearer(t, keys)
}

func mustInsert(t *testing.T, s traffic.Store, ev traffic.Event) {
	t.Helper()
	if err := s.Insert(context.Background(), ev); err != nil {
		t.Fatalf("Insert: %v", err)
	}
}

func newEvent(api string, decision traffic.Decision, subject string, ts time.Time) traffic.Event {
	return traffic.Event{
		ID:        traffic.NewEventID(),
		Timestamp: ts,
		Subject:   subject,
		Method:    "GET",
		URL:       "/" + api + "/v1/things",
		API:       api,
		Decision:  decision,
		LatencyMS: 5,
	}
}

func TestTrafficListReturnsRows(t *testing.T) {
	srv, store, bearer := newTrafficSrv(t, nil)
	now := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	mustInsert(t, store, newEvent("gmail", traffic.DecisionPermit, "alice", now))
	mustInsert(t, store, newEvent("drive", traffic.DecisionDeny, "bob", now.Add(-time.Second)))

	resp, err := authedGet(t, srv.URL+admin.TrafficListPath, bearer)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var got struct {
		Rows       []traffic.Summary `json:"rows"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Errorf("rows = %d, want 2", len(got.Rows))
	}
}

func TestTrafficListAppliesFilters(t *testing.T) {
	srv, store, bearer := newTrafficSrv(t, nil)
	now := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	mustInsert(t, store, newEvent("gmail", traffic.DecisionPermit, "alice", now))
	mustInsert(t, store, newEvent("drive", traffic.DecisionPermit, "bob", now.Add(-time.Second)))

	resp, err := authedGet(t, srv.URL+admin.TrafficListPath+"?api=gmail", bearer)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var got struct {
		Rows []traffic.Summary `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Rows) != 1 || got.Rows[0].API != "gmail" {
		t.Errorf("filtered rows = %+v, want one gmail row", got.Rows)
	}
}

func TestTrafficListBadLimit400(t *testing.T) {
	srv, _, bearer := newTrafficSrv(t, nil)
	resp, err := authedGet(t, srv.URL+admin.TrafficListPath+"?limit=notanint", bearer)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTrafficListSubjectFilter(t *testing.T) {
	alice := "alice"
	srv, store, bearer := newTrafficSrv(t, func(_ *http.Request) *string { return &alice })
	now := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	mustInsert(t, store, newEvent("gmail", traffic.DecisionPermit, "alice", now))
	mustInsert(t, store, newEvent("gmail", traffic.DecisionPermit, "bob", now.Add(-time.Second)))

	resp, err := authedGet(t, srv.URL+admin.TrafficListPath, bearer)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var got struct {
		Rows []traffic.Summary `json:"rows"`
	}
	json.NewDecoder(resp.Body).Decode(&got)
	if len(got.Rows) != 1 || got.Rows[0].Subject != "alice" {
		t.Errorf("rows = %+v, want one alice row", got.Rows)
	}
}

func TestTrafficGetReturnsFullEvent(t *testing.T) {
	srv, store, bearer := newTrafficSrv(t, nil)
	now := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	ev := newEvent("gmail", traffic.DecisionPermit, "alice", now)
	ev.Policy = "read-only"
	mustInsert(t, store, ev)

	resp, err := authedGet(t, srv.URL+"/_api/traffic/"+ev.ID.String(), bearer)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got traffic.Event
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != ev.ID || got.Policy != "read-only" {
		t.Errorf("got %+v, want ID/policy match", got)
	}
}

func TestTrafficGetUnknown404(t *testing.T) {
	srv, _, bearer := newTrafficSrv(t, nil)
	resp, err := authedGet(t, srv.URL+"/_api/traffic/deadbeef", bearer)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestTrafficGetCrossSubject404(t *testing.T) {
	alice := "alice"
	srv, store, bearer := newTrafficSrv(t, func(_ *http.Request) *string { return &alice })
	now := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	bobEvent := newEvent("gmail", traffic.DecisionPermit, "bob", now)
	mustInsert(t, store, bobEvent)

	resp, err := authedGet(t, srv.URL+"/_api/traffic/"+bobEvent.ID.String(), bearer)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for cross-subject access", resp.StatusCode)
	}
}

func TestTrafficPinAndUnpin(t *testing.T) {
	srv, store, bearer := newTrafficSrv(t, nil)
	now := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	ev := newEvent("gmail", traffic.DecisionPermit, "alice", now)
	mustInsert(t, store, ev)

	req := authedRequest(t, "PUT", srv.URL+"/_api/traffic/"+ev.ID.String()+"/pin", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("pin status = %d, want 204", resp.StatusCode)
	}

	got, _ := store.Get(context.Background(), ev.ID)
	if !got.Pinned {
		t.Error("Pinned = false after PUT pin")
	}

	req = authedRequest(t, "DELETE", srv.URL+"/_api/traffic/"+ev.ID.String()+"/pin", bearer)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unpin: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("unpin status = %d, want 204", resp.StatusCode)
	}
}

func TestTrafficPinUnknown404(t *testing.T) {
	srv, _, bearer := newTrafficSrv(t, nil)
	req := authedRequest(t, "PUT", srv.URL+"/_api/traffic/deadbeef/pin", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestTrafficPagination(t *testing.T) {
	srv, store, bearer := newTrafficSrv(t, nil)
	base := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	for i := 0; i < 6; i++ {
		mustInsert(t, store, newEvent("gmail", traffic.DecisionPermit, "alice",
			base.Add(time.Duration(i)*time.Second)))
	}
	type page struct {
		Rows       []traffic.Summary `json:"rows"`
		NextCursor string            `json:"next_cursor"`
	}
	resp, _ := authedGet(t, srv.URL+admin.TrafficListPath+"?limit=4", bearer)
	var p1 page
	json.NewDecoder(resp.Body).Decode(&p1)
	resp.Body.Close()
	if len(p1.Rows) != 4 || p1.NextCursor == "" {
		t.Fatalf("page1 rows=%d cur=%q, want 4+cursor", len(p1.Rows), p1.NextCursor)
	}
	resp, _ = authedGet(t, srv.URL+admin.TrafficListPath+"?limit=4&cursor="+p1.NextCursor, bearer)
	var p2 page
	json.NewDecoder(resp.Body).Decode(&p2)
	resp.Body.Close()
	if len(p2.Rows) != 2 {
		t.Errorf("page2 rows=%d, want 2 (6 total = 4+2)", len(p2.Rows))
	}
	if p2.NextCursor != "" {
		t.Errorf("page2 cursor=%q, want empty (final)", p2.NextCursor)
	}
}

// TestTrafficUIServesHTML pins the embedded UI page: 200 OK, the
// expected content type, and that a sentinel string from the page
// shows up in the body so a future "wrong file embedded" regression
// fails here.
// TestTrafficProposeUIServesHTML pins the per-event propose page:
// it lives at /_admin/traffic/{id}/propose, serves the embedded
// HTML shell, and references the API endpoint it POSTs to so a
// future rewire surfaces here.
func TestTrafficProposeUIServesHTML(t *testing.T) {
	srv, _, bearer := newTrafficSrv(t, nil)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/_admin/traffic/evt_1/propose", nil)
	req.Header.Set("Authorization", bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "propose-policy") {
		t.Errorf("page does not reference /_api/.../propose-policy — JS won't post anywhere")
	}
}

func TestTrafficUIServesHTML(t *testing.T) {
	// UI shell now redirects anonymous callers to the login page,
	// so we authenticate.
	srv, _, bearer := newTrafficSrv(t, nil)
	for _, path := range []string{admin.TrafficUIPath, admin.TrafficUIPath + "/"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", bearer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s status = %d, want 200", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s content-type = %q, want text/html prefix", path, ct)
		}
		if !strings.Contains(string(body), "Traffic viewer") {
			t.Errorf("%s body missing the page heading", path)
		}
	}
}

// TestTrafficListNoConflictWithIssue verifies the new `/_api/traffic`
// routes coexist with the existing `/_api/issue/tokens` route under
// the same `_api` prefix on one chi router. Regression guard for a
// future route refactor.
func TestTrafficListNoConflictWithIssue(t *testing.T) {
	srv, _, bearer := newTrafficSrv(t, nil)
	resp, err := authedGet(t, srv.URL+admin.TrafficListPath, bearer)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Errorf("traffic list 404'd — route mounting regression")
	}
	// Spot check the chi 404 is the expected text, so a future
	// rewrite that swaps response-text formats fails here.
	resp, err = http.Get(srv.URL + "/no/such/route")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "404") {
		t.Errorf("unknown route body = %q, want chi 404 marker", body)
	}
}
