// Package apiclient is a net/http-backed `compiled.PhysicalAPI` that
// drives the side-channel calls a meta's `request` expression expands
// to.
package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/jkylling/bouncer/internal/httpdo"
	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/compiled"
)

// HTTPClient is an alias for the shared httpdo.Client so existing
// callers (and tests that stub it) keep working without import
// churn. New code should reference httpdo.Client directly.
type HTTPClient = httpdo.Client

// UpstreamError carries upstream HTTP status and a truncated body;
// the server peels it via errors.As to map upstream auth failures
// distinctly from proxy auth failures.
type UpstreamError struct {
	Status int
	URL    string
	Body   string
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("upstream %s returned %d: %s", e.URL, e.Status, e.Body)
}

// maxResponseBodyBytes caps the upstream response body the client
// will buffer per call. JSON control-plane responses are small; the
// limit prevents a runaway upstream (or hostile mock) from OOMing
// the proxy via a single side call.
const maxResponseBodyBytes int64 = 10 << 20 // 10 MiB

// HTTPAPI performs upstream HTTP calls and returns the JSON-decoded body
// as an `bouncer.Response`.
type HTTPAPI struct {
	Client      HTTPClient
	BaseURL     *url.URL
	AccessToken string
	// ExtraHeaders are stamped on every outbound request via Set
	// (later entries with the same name overwrite earlier ones),
	// matching the data-plane forward path's applyCredentials. Carries
	// the JWT-bundled headers (Cookie/Origin/Referer for Slack-style
	// browser-session creds, X-API-Key for plain header tokens, etc.)
	// so meta side calls authenticate exactly the same way as the
	// outer forwarded request — Slack rejects an xoxc bearer that
	// arrives without its Cookie+Origin+Referer trio with
	// `invalid_auth`, so the meta needs them too.
	ExtraHeaders []Header
}

// Header is one name/value pair to stamp on every outbound request.
// Mirrors auth.Header field-for-field; redeclared here so apiclient
// stays auth-agnostic (the auth import would create a cycle through
// the http shim's PhysicalAPI factory).
type Header struct {
	Name  string
	Value string
}

// Compile-time interface assertion.
var _ compiled.PhysicalAPI = (*HTTPAPI)(nil)

// New constructs an HTTPAPI with parsed base URL. extra carries any
// JWT-bundled headers to stamp on every outbound request (Cookie /
// Origin / Referer for browser-session creds, X-API-Key for header
// tokens) so meta side calls authenticate the same way as the outer
// forward path. Pass nil for extra when no additional headers apply
// — typical for tests and for upstreams whose auth is purely the
// Authorization bearer.
func New(client HTTPClient, baseURL, accessToken string, extra []Header) (*HTTPAPI, error) {
	if client == nil {
		return nil, errors.New("nil http client")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("base url: %w", err)
	}
	return &HTTPAPI{Client: client, BaseURL: u, AccessToken: accessToken, ExtraHeaders: extra}, nil
}

// Call satisfies runtime.PhysicalAPI.
func (a *HTTPAPI) Call(ctx context.Context, req *pb.MetaRequest) (*pb.Response, error) {
	target, err := JoinPath(a.BaseURL, req.GetPath())
	if err != nil {
		return nil, err
	}
	contentType := req.GetContentType()
	if contentType == "" {
		contentType = "application/json"
	}
	var body io.Reader
	if req.GetBody() != nil {
		raw, err := encodeBody(req.GetBody(), contentType)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.GetMethod(), target.String(), body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if a.AccessToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.AccessToken)
	}
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", contentType)
	}
	// ExtraHeaders last so a JWT-bundled Authorization or Content-Type
	// (rare, but legal) can override the defaults set above. Matches
	// applyCredentials' "operator config wins" semantics.
	for _, h := range a.ExtraHeaders {
		httpReq.Header.Set(h.Name, h.Value)
	}
	resp, err := a.Client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http call: %w", err)
	}
	defer resp.Body.Close()
	// Cap reads at maxResponseBodyBytes+1 so we can distinguish
	// "exactly at limit" (legal) from "ran past limit" (truncated and
	// rejected). Without the +1, a body that hits the cap exactly is
	// indistinguishable from one that overflowed.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(raw)) > maxResponseBodyBytes {
		return nil, fmt.Errorf("upstream body exceeded %d bytes", maxResponseBodyBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &UpstreamError{
			Status: resp.StatusCode,
			URL:    target.String(),
			Body:   truncateBody(raw),
		}
	}
	if len(raw) == 0 {
		return &pb.Response{}, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("decode body: %w", err)
	}
	pv, err := structpb.NewValue(DropJSONNulls(v))
	if err != nil {
		return nil, fmt.Errorf("body to value: %w", err)
	}
	return &pb.Response{Body: pv}, nil
}

// encodeBody serialises a structpb body for the given Content-Type.
// JSON (default) goes through protojson — *structpb.Value carries its
// own encoder that handles NullValue, NaN/Inf, and the rest of the
// well-known-type quirks. application/x-www-form-urlencoded flattens
// the top-level fields per the Slack convention: scalars → raw form
// values, nested objects/arrays → JSON-stringified into a single
// field (e.g. `profile={"status_text":"hi"}` on users.profile.set).
// Sorted keys keep the wire bytes deterministic across Go map iteration.
func encodeBody(v *structpb.Value, contentType string) ([]byte, error) {
	switch contentType {
	case "application/x-www-form-urlencoded":
		return encodeForm(v)
	default:
		return protojson.Marshal(v)
	}
}

func encodeForm(v *structpb.Value) ([]byte, error) {
	s, ok := v.GetKind().(*structpb.Value_StructValue)
	if !ok {
		return nil, fmt.Errorf("form body must be an object, got %T", v.GetKind())
	}
	fields := s.StructValue.GetFields()
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	values := url.Values{}
	for _, k := range keys {
		val, err := formFieldValue(fields[k])
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", k, err)
		}
		values.Set(k, val)
	}
	return []byte(values.Encode()), nil
}

// formFieldValue renders one structpb value as the string that lands
// in the form-encoded body. Strings/numbers/bools render literally;
// arrays and objects JSON-stringify (the Slack convention for compound
// parameters). Null collapses to an empty value.
func formFieldValue(v *structpb.Value) (string, error) {
	switch k := v.GetKind().(type) {
	case *structpb.Value_StringValue:
		return k.StringValue, nil
	case *structpb.Value_NumberValue:
		return strconv.FormatFloat(k.NumberValue, 'f', -1, 64), nil
	case *structpb.Value_BoolValue:
		return strconv.FormatBool(k.BoolValue), nil
	case *structpb.Value_NullValue, nil:
		return "", nil
	case *structpb.Value_StructValue, *structpb.Value_ListValue:
		raw, err := protojson.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	default:
		return "", fmt.Errorf("unsupported value kind %T", k)
	}
}

// DropJSONNulls walks a freshly json.Unmarshal'd value tree and
// removes any object field whose value is `null`. Lists keep nulls
// in place (CEL list lookup `[i]` doesn't have the optional-vs-
// missing surface a struct does).
//
// Why: CEL's optional select `?field` on a struct where `field`
// exists with a JSON null returns `optional.of(null)`, not
// `optional.none()`. A policy author writing
// `body.?name.orValue("")` reasonably expects `""` for both
// "missing" and "null"; without this pass they'd get a "no such
// overload" failure on `.startsWith()` (or any other
// type-specific call) the moment an upstream returned a literal
// JSON null. Dropping the field instead lets `?` correctly
// short-circuit to none.
//
// Exported because both this package's response decoder and the
// server's request-body parsers need to apply the same rule.
func DropJSONNulls(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			if vv == nil {
				continue
			}
			out[k] = DropJSONNulls(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = DropJSONNulls(vv)
		}
		return out
	}
	return v
}

// JoinPath concatenates base.Path and requestPath, treating
// requestPath as relative even when it has a leading slash, so a
// schema path like "/v1/x" lands at "$base/v1/x" rather than
// replacing the base path.
//
// The join is byte-level — `..`, `.`, `//`, percent-escapes, and
// `#` all pass through verbatim so the bytes the upstream sees
// match what the policy evaluated. The stdlib candidates fall short:
// url.URL.JoinPath URL-encodes `?` (destroying query strings on
// the requestPath), and url.URL.ResolveReference applies RFC 3986
// §5.2.4 normalisation — exactly the divergence between what the
// policy gates on and what the upstream serves that we need to
// avoid. The dot-segment guard for CEL-built paths lives in
// celenv.makeMetaRequest, not here.
//
// Implementation: split the reference on the first `?` and `#`,
// append the path tail to base.Path, stash the joined bytes in
// RawPath and the decoded form in Path. URL.String() emits RawPath
// verbatim when unescape(RawPath) == Path, so `/files/abc%2Fdef`
// reaches the upstream as `/files/abc%2Fdef`, not the double-
// encoded `/files/abc%252Fdef`. Lexical rejects guard against a
// scheme or protocol-relative reference smuggled through.
//
// Exported because the server's forward path needs the same join.
func JoinPath(base *url.URL, requestPath string) (*url.URL, error) {
	if strings.HasPrefix(requestPath, "//") {
		return nil, fmt.Errorf("path: protocol-relative reference not allowed: %q", requestPath)
	}
	// `://` in the path portion indicates a scheme-prefixed absolute
	// reference. Query strings are exempt because legitimate values
	// (`redirect_uri`, a docs URL inside a search param) commonly
	// carry one. The whitespace check covers the whole request path
	// because no legitimate path or query carries raw whitespace —
	// the asymmetry with the scheme check is deliberate.
	pathPortion := requestPath
	if i := strings.IndexByte(requestPath, '?'); i >= 0 {
		pathPortion = requestPath[:i]
	}
	if strings.Contains(pathPortion, "://") {
		return nil, fmt.Errorf("path: scheme not allowed in path: %q", requestPath)
	}
	if i := strings.IndexAny(requestPath, " \t\r\n"); i >= 0 {
		return nil, fmt.Errorf("path: whitespace not allowed at index %d: %q", i, requestPath)
	}
	rel := strings.TrimPrefix(requestPath, "/")
	// Split off query (`?`) and fragment (`#`) before joining the
	// path. Fragments don't reach the upstream over the wire, but
	// keeping them populated correctly avoids EscapedPath emitting a
	// literal `%23` in the path.
	pathTail, queryTail, fragTail := rel, "", ""
	if i := strings.IndexByte(rel, '#'); i >= 0 {
		pathTail, fragTail = rel[:i], rel[i+1:]
	}
	if i := strings.IndexByte(pathTail, '?'); i >= 0 {
		pathTail, queryTail = pathTail[:i], pathTail[i+1:]
	}
	out := *base
	rawBase := out.Path
	if !strings.HasSuffix(rawBase, "/") {
		rawBase += "/"
	}
	rawJoined := rawBase + pathTail
	// Path is the decoded form; RawPath the original bytes.
	// URL.String() emits RawPath when unescape(RawPath) == Path, so
	// percent-escapes survive the round-trip without re-escaping.
	decoded, err := url.PathUnescape(rawJoined)
	if err != nil {
		return nil, fmt.Errorf("path: invalid percent-escape: %w", err)
	}
	out.Path = decoded
	out.RawPath = rawJoined
	out.RawQuery = queryTail
	out.Fragment = fragTail
	return &out, nil
}

// truncateBody returns body verbatim when small, otherwise the first
// truncateBodyLimit bytes followed by an ellipsis. Keeps error messages
// useful without flooding the log when an upstream returns a large
// HTML/JSON error page.
func truncateBody(body []byte) string {
	const limit = 512
	if len(body) <= limit {
		return string(body)
	}
	return string(body[:limit]) + "…"
}
