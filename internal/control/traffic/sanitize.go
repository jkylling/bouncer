package traffic

import "strings"

// SanitizeOptions controls Sanitize's redaction policy. Zero values
// pick conservative defaults so callers that pass `SanitizeOptions{}`
// still get header stripping and body truncation.
type SanitizeOptions struct {
	// MaxBodyBytes is the per-side body cap. Bodies longer than this
	// are truncated and Event.Truncated is set. Zero falls back to
	// DefaultMaxBodyBytes (8 KiB).
	MaxBodyBytes int

	// NoBodyAPIs lists API names whose request and upstream bodies
	// must not be persisted at all. Bodies for these APIs are
	// dropped to nil with Truncated=true. Used for APIs whose
	// responses contain user content (Gmail message bodies, Drive
	// file contents). Lookup is case-sensitive against `Event.API`.
	NoBodyAPIs map[string]bool

	// SensitiveHeaders is the list of header keys to drop from both
	// the request and upstream side. Comparison is case-insensitive.
	// Unioned with DefaultSensitiveHeaders; the default floor cannot
	// be shrunk.
	SensitiveHeaders []string
}

// DefaultMaxBodyBytes is the per-side body cap when SanitizeOptions
// leaves it zero. Sized so the 16 MiB recent-requests budget fits
// roughly 1k full events with both sides populated.
const DefaultMaxBodyBytes = 8 * 1024

// DefaultSensitiveHeaders are stripped unconditionally. Cookies and
// Authorization headers reveal credentials; Set-Cookie reveals
// session state. Operators can extend this set per-deployment but
// cannot shrink it below this floor — Sanitize ignores attempts to
// remove a name from the list.
var DefaultSensitiveHeaders = []string{
	"Authorization",
	"Cookie",
	"Set-Cookie",
	"Proxy-Authorization",
}

// DefaultNoBodyAPIs are the bundled APIs whose response bodies
// contain user content and so should never be persisted. Operators
// can extend the set via SanitizeOptions.NoBodyAPIs.
var DefaultNoBodyAPIs = map[string]bool{
	"gmail": true,
	"drive": true,
}

// Sanitize redacts an Event in place per opts. Safe to call on any
// Event including one with nil bodies or headers — a sanitised
// no-op is still cheap. Returns the same pointer for fluent use.
//
// The recorder is expected to call Sanitize before handing the
// event to a Store, so stores can assume their input is already
// safe to persist.
func Sanitize(ev *Event, opts SanitizeOptions) *Event {
	if ev == nil {
		return ev
	}
	maxBytes := opts.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodyBytes
	}
	// Union with the default floor: an operator who extends the list
	// must not be able to silently drop Authorization / Cookie /
	// Set-Cookie redaction. stripHeaders dedupes by lower-cased name,
	// so duplicates from the union are harmless.
	headers := append([]string(nil), DefaultSensitiveHeaders...)
	headers = append(headers, opts.SensitiveHeaders...)
	// Union with the default floor so an operator who supplies a
	// non-nil NoBodyAPIs (even an empty map) cannot silently drop
	// the gmail/drive redaction. Mirrors the SensitiveHeaders
	// pattern above.
	noBody := make(map[string]bool, len(DefaultNoBodyAPIs)+len(opts.NoBodyAPIs))
	for k, v := range DefaultNoBodyAPIs {
		noBody[k] = v
	}
	for k, v := range opts.NoBodyAPIs {
		noBody[k] = v
	}

	ev.RequestHeaders = stripHeaders(ev.RequestHeaders, headers)
	ev.UpstreamHeaders = stripHeaders(ev.UpstreamHeaders, headers)

	if noBody[ev.API] {
		if len(ev.RequestBody) > 0 || len(ev.UpstreamBody) > 0 {
			ev.Truncated = true
		}
		ev.RequestBody = nil
		ev.UpstreamBody = nil
		ev.MetaFetches = redactAllFetchBodies(ev.MetaFetches, &ev.Truncated)
		return ev
	}

	truncateBody(&ev.RequestBody, maxBytes, &ev.Truncated)
	truncateBody(&ev.UpstreamBody, maxBytes, &ev.Truncated)
	ev.MetaFetches = sanitizeFetches(ev.MetaFetches, maxBytes, noBody, &ev.Truncated)
	return ev
}

// sanitizeFetches truncates each fetch's request/response body to
// maxBytes and drops bodies entirely for fetches that hit a NoBody
// API (gmail/drive by default). Status, method, path, and meta name
// pass through — those are already structured metadata, not user
// content.
func sanitizeFetches(in []MetaFetch, maxBytes int, noBody map[string]bool, truncated *bool) []MetaFetch {
	if len(in) == 0 {
		return in
	}
	for i := range in {
		f := &in[i]
		if noBody[f.API] {
			if len(f.RequestBody) > 0 || len(f.ResponseBody) > 0 {
				*truncated = true
			}
			f.RequestBody = nil
			f.ResponseBody = nil
			continue
		}
		truncateBody(&f.RequestBody, maxBytes, truncated)
		truncateBody(&f.ResponseBody, maxBytes, truncated)
	}
	return in
}

// redactAllFetchBodies is the parent-level NoBody case: the inbound
// API is in the redact list, so every captured fetch loses its bodies
// regardless of which upstream the fetch hit. Conservative because a
// fetch from e.g. gmail's policy chain may have read a drive file
// whose body the gmail redaction policy wouldn't otherwise cover.
func redactAllFetchBodies(in []MetaFetch, truncated *bool) []MetaFetch {
	if len(in) == 0 {
		return in
	}
	for i := range in {
		f := &in[i]
		if len(f.RequestBody) > 0 || len(f.ResponseBody) > 0 {
			*truncated = true
		}
		f.RequestBody = nil
		f.ResponseBody = nil
	}
	return in
}

// stripHeaders drops every entry whose Key matches one of names
// (case-insensitive). Returns a fresh slice when anything is dropped
// so the caller's input is left unchanged for unrelated logging.
func stripHeaders(in []KV, names []string) []KV {
	if len(in) == 0 {
		return in
	}
	deny := make(map[string]struct{}, len(names))
	for _, n := range names {
		deny[strings.ToLower(n)] = struct{}{}
	}
	var out []KV
	dropped := false
	for _, kv := range in {
		if _, bad := deny[strings.ToLower(kv.Key)]; bad {
			dropped = true
			continue
		}
		out = append(out, kv)
	}
	if !dropped {
		return in
	}
	return out
}

// truncateBody clips *body to at most maxBytes and sets *truncated if
// truncation occurred. The reallocation (vs slicing body[:maxBytes])
// is intentional: a fresh backing array lets the original (possibly
// multi-MB) buffer be GC'd once the caller drops its reference.
func truncateBody(body *[]byte, maxBytes int, truncated *bool) {
	if len(*body) <= maxBytes {
		return
	}
	out := make([]byte, maxBytes)
	copy(out, (*body)[:maxBytes])
	*body = out
	*truncated = true
}
