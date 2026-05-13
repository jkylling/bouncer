package mcp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/traffic"
)

// trafficTools is the traffic-family slice contributed to the
// registry. Both entries are read-only — recorded events mutate
// only as new requests flow through the proxy.
//
// `list_traffic` is safe for non-admin callers: the Summary shape
// already excludes headers, bodies, binds, meta fetches, and the
// policy-evaluation trace. `get_traffic_event` returns the full
// Event for admins and a redacted view for non-admin callers (same
// surface area the client itself saw in the denial response — no
// meta bodies, no headers, no binds, no policy-eval trace).
func trafficTools() []tool {
	return []tool{
		{
			Name:        "list_traffic",
			Title:       "List recent requests",
			Description: "Returns recently-recorded requests for context. Optional filters: api, action, method, decision, path_prefix, limit. Equivalent to GET /_api/traffic.",
			InputSchema: schemaObject(map[string]any{
				"api":         map[string]any{"type": "string"},
				"action":      map[string]any{"type": "string"},
				"method":      map[string]any{"type": "string"},
				"decision":    map[string]any{"type": "string", "enum": []string{"permit", "deny", "no_match", "error"}},
				"path_prefix": map[string]any{"type": "string"},
				"limit":       map[string]any{"type": "integer", "minimum": 1},
			}, nil),
			Run: runListTraffic,
		},
		{
			Name:        "get_traffic_event",
			Title:       "Get one traffic event",
			Description: "Fetch a recorded request by id. Non-admin callers receive a redacted view matching the denial response surface; admins receive the full event including headers, bodies, binds, meta fetches, and the policy-evaluation trace.",
			InputSchema: schemaObject(map[string]any{
				"id": map[string]any{"type": "string"},
			}, []string{"id"}),
			Run: runGetTrafficEvent,
		},
	}
}

type listTrafficArgs struct {
	API        string `json:"api,omitempty"`
	Action     string `json:"action,omitempty"`
	Method     string `json:"method,omitempty"`
	Decision   string `json:"decision,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

func runListTraffic(ctx context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.TrafficStore != nil, "traffic store"); e != nil {
		return nil, e
	}
	var args listTrafficArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	rows, _, err := deps.TrafficStore.List(ctx, traffic.ListOpts{
		API:        args.API,
		Action:     args.Action,
		Method:     args.Method,
		Decision:   traffic.Decision(args.Decision),
		PathPrefix: args.PathPrefix,
		Limit:      args.Limit,
	})
	if err != nil {
		return nil, internalError("list traffic: " + err.Error())
	}
	return map[string]any{"rows": rows}, nil
}

type trafficIDArgs struct {
	ID string `json:"id"`
}

func runGetTrafficEvent(ctx context.Context, deps Deps, raw json.RawMessage) (any, *Error) {
	if e := requireService(deps.TrafficStore != nil, "traffic store"); e != nil {
		return nil, e
	}
	var args trafficIDArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, invalidParams("decode: %v", err)
	}
	if args.ID == "" {
		return nil, invalidParams("id is required")
	}
	ev, err := deps.TrafficStore.Get(ctx, traffic.EventID(args.ID))
	if err != nil {
		return nil, mapTrafficError(err)
	}
	if auth.CallerFromContext(ctx).IsAdmin() {
		return ev, nil
	}
	return redactedTrafficEvent(ev), nil
}

// redactedTrafficEventResult is the non-admin response shape. It
// carries the same surface the client saw in its own denial response
// plus the basic request identity — no headers, no bodies, no binds,
// no meta fetches, no policy-evaluation trace. The admin tier still
// returns the full *traffic.Event.
type redactedTrafficEventResult struct {
	ID             traffic.EventID  `json:"id"`
	Timestamp      string           `json:"timestamp"`
	Subject        string           `json:"subject,omitempty"`
	Method         string           `json:"method"`
	URL            string           `json:"url"`
	API            string           `json:"api,omitempty"`
	Action         string           `json:"action,omitempty"`
	Decision       traffic.Decision `json:"decision"`
	Policy         string           `json:"policy,omitempty"`
	UpstreamStatus int              `json:"upstream_status,omitempty"`
	LatencyMS      int64            `json:"latency_ms"`
	Error          string           `json:"error,omitempty"`
}

func redactedTrafficEvent(ev traffic.Event) redactedTrafficEventResult {
	return redactedTrafficEventResult{
		ID:             ev.ID,
		Timestamp:      ev.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
		Subject:        ev.Subject,
		Method:         ev.Method,
		URL:            ev.URL,
		API:            ev.API,
		Action:         ev.Action,
		Decision:       ev.Decision,
		Policy:         ev.Policy,
		UpstreamStatus: ev.UpstreamStatus,
		LatencyMS:      ev.LatencyMS,
		Error:          ev.Error,
	}
}

func mapTrafficError(err error) *Error {
	switch {
	case errors.Is(err, traffic.ErrNotFound):
		return &Error{Code: codeInvalidParams, Message: "traffic event not found"}
	default:
		return internalError(err.Error())
	}
}
