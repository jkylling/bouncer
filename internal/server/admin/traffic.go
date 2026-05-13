package admin

import (
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
	TrafficItemPath = "/_api/traffic/{id}"
	TrafficUIPath   = "/_admin/traffic"

	// TrafficSubjectsPath returns one row per JWT subject seen in
	// stored traffic. The Agents page reads this to show "agents that
	// have authenticated" without needing the agents.Store (which
	// nothing populates in the local-bouncer model).
	TrafficSubjectsPath = "/_api/traffic/subjects"
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
	// Per-route access tiers live in the embedded internal-policy
	// set (traffic_list / traffic_get / ui_traffic).
	// The default sets gate the JSON endpoints to admin and the UI
	// shell to authenticated callers (anonymous bounces to login).
	r.Get(TrafficListPath, listHandler(store, principal))
	r.Get(TrafficSubjectsPath, subjectsHandler(store))
	r.Get(TrafficItemPath, getHandler(store, principal))
	mountUIPage(r, TrafficUIPath, "traffic")
}

// listHandler serves GET /_api/traffic with structured filter and
// pagination query params:
//
//	api, action, method, decision, path_prefix, since, until, limit, cursor.
//
// `since` / `until` accept RFC 3339; everything else is a literal string.
//
// subjectsHandler serves GET /_api/traffic/subjects — a per-subject
// roll-up of stored traffic. Read-only by design; "revoke this
// subject" is intentionally a follow-up because it requires new
// state on the JWT-verify hot path.
func subjectsHandler(store traffic.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := store.Subjects(r.Context())
		if err != nil {
			writeJSONError(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"subjects": out})
	}
}

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
	// `api` can be repeated (?api=foo&api=bar) for per-service traffic
	// views that scope to the bundle's full API set. A single value
	// folds into the legacy API field; multiple values land in APIs.
	apis := q["api"]
	opts := traffic.ListOpts{
		Action:     q.Get("action"),
		Method:     q.Get("method"),
		Decision:   traffic.Decision(q.Get("decision")),
		PathPrefix: q.Get("path_prefix"),
		Cursor:     traffic.Cursor(q.Get("cursor")),
	}
	switch len(apis) {
	case 0:
		// no filter
	case 1:
		opts.API = apis[0]
	default:
		opts.APIs = apis
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
