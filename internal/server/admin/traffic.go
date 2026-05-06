package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/control/traffic"
)

// Traffic path constants. The API endpoints share the `_api` prefix
// the rest of the admin family uses; the UI page sits under `_admin`
// alongside the issue form.
const (
	TrafficListPath = "/_api/traffic"
	// TrafficItemPath uses chi's `{id}` parameter syntax. Pinned-only
	// listing rides on the same path with `?pinned=true`, so we
	// don't need a dedicated `/pinned` route — that would conflict
	// with `{id}` anyway under chi's literal-vs-param rules.
	TrafficItemPath = "/_api/traffic/{id}"
	TrafficPinPath  = "/_api/traffic/{id}/pin"
	TrafficUIPath   = "/_admin/traffic"

	// TrafficProposeUIPath is the per-event "propose policy from
	// this request" page. Linked from each row's detail panel; the
	// page reads the {id} from window.location and POSTs to the
	// existing /_api/traffic/{id}/propose-policy endpoint.
	TrafficProposeUIPath = "/_admin/traffic/{id}/propose"
)

// PrincipalExtractor maps an inbound request to a principal subject
// the traffic store filters on. Returning a non-nil string narrows
// the visible rows to that subject; returning nil means "this
// principal sees every row" (admin/unauthenticated mode). The
// recorder's listener is unauthenticated today (REVIEW caveat in
// the README), so the default extractor returns nil — flip it on
// once the control-plane auth gate lands.
type PrincipalExtractor func(r *http.Request) *string

// AnonymousPrincipal is the default extractor: every caller sees
// every row. Mirrors the current trust model where the control-
// plane listener is expected to be on a trusted network.
func AnonymousPrincipal(_ *http.Request) *string { return nil }

// MountTraffic attaches the traffic-viewer endpoints (read API + UI
// page) to r, backed by store. Pass AnonymousPrincipal (or nil — same
// behaviour) until the control-plane auth gate exists.
//
// The endpoint family lives in admin rather than alongside the
// traffic package because the wire shape, route layout, and access-
// control hook all belong to the control plane, not the storage
// layer.
func MountTraffic(r chi.Router, store traffic.Store, principal PrincipalExtractor) {
	if principal == nil {
		principal = AnonymousPrincipal
	}
	// Reading other principals' recorded traffic is admin-only —
	// requests can carry sensitive paths (resource ids, query
	// parameters), and the existing `principal` extractor is the
	// per-subject filter for the eventual subject-scoped read path.
	// Today the proxy ships AnonymousPrincipal, so for now reads
	// are admin-tier full stop. If the subject-scoped reader lands
	// later, switch the GETs to RequireAuthenticated and let the
	// extractor narrow the rows.
	r.Get(TrafficListPath, RequireAdmin(listHandler(store, principal)))
	r.Get(TrafficItemPath, RequireAdmin(getHandler(store, principal)))
	r.Put(TrafficPinPath, RequireAdmin(pinHandler(store, principal)))
	r.Delete(TrafficPinPath, RequireAdmin(unpinHandler(store, principal)))
	mountUIPage(r, TrafficUIPath, "traffic")
	r.Get(TrafficProposeUIPath, RedirectAnonymousToLogin(pageHandler("traffic_propose")))
}

// listHandler serves GET /_api/traffic with structured filter and
// pagination query params:
//
//	api, action, method, decision, path_prefix, since, until, pinned,
//	limit, cursor.
//
// `since` / `until` accept RFC 3339; everything else is a literal
// string. `pinned=true` filters to pinned rows only.
func listHandler(store traffic.Store, principal PrincipalExtractor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opts, err := parseListOpts(r)
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		opts.Subject = principal(r)
		rows, next, err := store.List(r.Context(), opts)
		if err != nil {
			writeMappedError(r.Context(), w, "traffic list", err, []errMap{
				{sentinel: traffic.ErrBadCursor, status: http.StatusBadRequest, msg: "bad cursor"},
			})
			return
		}
		writeJSON(w, listResponse{Rows: rows, NextCursor: string(next)})
	}
}

// getHandler serves GET /_api/traffic/{id} with the full event
// payload. 404 on unknown id, 403 when the principal's subject
// filter rejects it (the row exists but does not belong to them).
func getHandler(store traffic.Store, principal PrincipalExtractor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := traffic.EventID(chi.URLParam(r, "id"))
		ev, err := store.Get(r.Context(), id)
		if err != nil {
			writeMappedError(r.Context(), w, "traffic get", err, []errMap{
				{sentinel: traffic.ErrNotFound, status: http.StatusNotFound, msg: "not found"},
			})
			return
		}
		if subj := principal(r); subj != nil && ev.Subject != *subj {
			// Row exists but principal cannot see it. 404 rather
			// than 403 so a hostile caller can't probe ids.
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, ev)
	}
}

// pinHandler / unpinHandler mark id pinned/unpinned. Idempotent;
// 404 on unknown id, 409 on pin-cap exhaustion. Subject scoping
// applies — a principal can only pin rows they can see.
func pinHandler(store traffic.Store, principal PrincipalExtractor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := traffic.EventID(chi.URLParam(r, "id"))
		if err := authorizeID(r, store, principal, id); err != nil {
			writeStoreError(r.Context(), w, err)
			return
		}
		if err := store.Pin(r.Context(), id); err != nil {
			writeStoreError(r.Context(), w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func unpinHandler(store traffic.Store, principal PrincipalExtractor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := traffic.EventID(chi.URLParam(r, "id"))
		if err := authorizeID(r, store, principal, id); err != nil {
			writeStoreError(r.Context(), w, err)
			return
		}
		if err := store.Unpin(r.Context(), id); err != nil {
			writeStoreError(r.Context(), w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// authorizeID looks up the row and returns ErrNotFound when the
// principal's subject filter rejects it. Centralised so pin/unpin
// share one trust check.
func authorizeID(r *http.Request, store traffic.Store, principal PrincipalExtractor, id traffic.EventID) error {
	subj := principal(r)
	if subj == nil {
		return nil // admin / anonymous-trust mode
	}
	ev, err := store.Get(r.Context(), id)
	if err != nil {
		return err
	}
	if ev.Subject != *subj {
		return traffic.ErrNotFound
	}
	return nil
}

// listResponse is the GET /_api/traffic body. Exported so callers
// can decode without restating the shape.
type listResponse struct {
	Rows       []traffic.Summary `json:"rows"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

// parseListOpts pulls structured filter values out of the URL query
// string. Empty values are treated as "filter not applied"; numeric
// and timestamp parses are strict so a malformed query fails closed
// with 400 rather than silently dropping a filter.
func parseListOpts(r *http.Request) (traffic.ListOpts, error) {
	q := r.URL.Query()
	opts := traffic.ListOpts{
		API:        q.Get("api"),
		Action:     q.Get("action"),
		Method:     q.Get("method"),
		Decision:   traffic.Decision(q.Get("decision")),
		PathPrefix: q.Get("path_prefix"),
		PinnedOnly: q.Get("pinned") == "true",
		Cursor:     traffic.Cursor(q.Get("cursor")),
	}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return traffic.ListOpts{}, errors.New("limit: not an integer")
		}
		opts.Limit = n
	}
	if s := q.Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return traffic.ListOpts{}, errors.New("since: expected RFC3339 timestamp")
		}
		opts.Since = t
	}
	if s := q.Get("until"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return traffic.ListOpts{}, errors.New("until: expected RFC3339 timestamp")
		}
		opts.Until = t
	}
	return opts, nil
}

func writeStoreError(ctx context.Context, w http.ResponseWriter, err error) {
	writeMappedError(ctx, w, "traffic", err, []errMap{
		{sentinel: traffic.ErrNotFound, status: http.StatusNotFound, msg: "not found"},
		{sentinel: traffic.ErrPinnedFull, status: http.StatusConflict, msg: "pinned cap reached"},
	})
}
