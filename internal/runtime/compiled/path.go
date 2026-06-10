package compiled

import (
	"fmt"
	"net/url"
	"strings"

	pb "github.com/jkylling/bouncer/internal/pb"
)

// PathTemplate is the compiled form of an action's `method:` + `path:`
// shorthand. It pre-splits the template into segment rules so each
// incoming request can be matched against a fixed, allocation-light
// schema rather than a chain of CEL boolean ops on `path_segments`.
//
// Syntax:
//
//   - The path is split on `/` after stripping the leading `/`, and
//     empty segments are *preserved* — matching how the server builds
//     `request.path_segments`. A request `/users//me` therefore
//     produces `["users", "", "me"]`, which only matches a template
//     that also has an empty segment in that position. This keeps the
//     proxy's view of the path in lockstep with the upstream's: both
//     see the same number of segments at the same offsets, so a
//     malicious `/users//me` cannot collapse onto `/users/{user}` and
//     speak past a policy gate.
//   - A segment of the form `{name}` is a parameter capture. `name` must
//     be a non-empty identifier (`[A-Za-z_][A-Za-z0-9_]*`) and must be
//     unique within the template. The captured value may be empty if
//     the request had an empty segment in that position; policies are
//     free to reject that with `match.id != ""` if it matters.
//   - Any other segment is a literal: it must equal the request segment
//     byte-for-byte. This includes Google-style `:method` segments such
//     as `values:batchGet` (literal) and bare `messages:send`. An empty
//     literal segment in the template only matches an empty segment in
//     the request.
//   - Captured values are decoded per segment (see SplitEscapedPath):
//     the server splits the *escaped* path first and then decodes each
//     segment, so a segment encoded as `al%2Fice` arrives as `al/ice`
//     in the capture — one segment with a literal slash, not two.
//
// Mixed segments like `{id}:enable` are intentionally not supported in
// this version — actions targeting those continue to use a `filter:`
// expression (possibly alongside a coarser path template).
type PathTemplate struct {
	method string // upper-cased
	segs   []pathSeg
}

type pathSeg struct {
	literal string // empty if param
	param   string // empty if literal
}

// ParsePathTemplate parses a (method, path) pair into a matcher. Returns
// an error if either side is empty, the path has no segments, or any
// `{name}` placeholder is malformed or duplicated.
func ParsePathTemplate(method, path string) (*PathTemplate, error) {
	if method == "" {
		return nil, fmt.Errorf("path template: method is empty")
	}
	if path == "" {
		return nil, fmt.Errorf("path template: path is empty")
	}
	rawSegs := SplitPath(path)
	if len(rawSegs) == 0 {
		return nil, fmt.Errorf("path template %q: no segments", path)
	}
	segs := make([]pathSeg, 0, len(rawSegs))
	seen := map[string]struct{}{}
	for _, raw := range rawSegs {
		name, isParam, err := parseSegment(raw)
		if err != nil {
			return nil, fmt.Errorf("path template %q: %w", path, err)
		}
		if isParam {
			if _, dup := seen[name]; dup {
				return nil, fmt.Errorf("path template %q: duplicate param {%s}", path, name)
			}
			seen[name] = struct{}{}
			segs = append(segs, pathSeg{param: name})
		} else {
			segs = append(segs, pathSeg{literal: raw})
		}
	}
	return &PathTemplate{
		method: strings.ToUpper(method),
		segs:   segs,
	}, nil
}

// Match returns the captured parameters and true if req matches the
// template. On a non-match it returns (nil, false); the caller should
// treat that as "this action does not fire" without erroring. The
// method comparison uses ==, since ParsePathTemplate already stores
// the upper-case form. The returned map is nil when the template has
// no parameter segments — callers downstream materialise an empty
// map if they need one.
func (t *PathTemplate) Match(req *pb.Request) (map[string]string, bool) {
	if req.GetMethod() != t.method {
		return nil, false
	}
	segs := req.GetPathSegments()
	if len(segs) != len(t.segs) {
		return nil, false
	}
	var params map[string]string
	for i, rule := range t.segs {
		if rule.param != "" {
			if params == nil {
				params = make(map[string]string)
			}
			params[rule.param] = segs[i]
			continue
		}
		if rule.literal != segs[i] {
			return nil, false
		}
	}
	return params, true
}

// SplitEscapedPath splits a percent-encoded URL path (as returned by
// url.URL.EscapedPath) into decoded segments. Splitting happens
// *before* decoding, so an encoded slash stays inside its segment —
// `/users/al%2Fice` → ["users", "al/ice"] — instead of becoming a
// separator the way it already has in the pre-decoded r.URL.Path.
// Empty segments are preserved, mirroring SplitPath.
//
// A segment that fails to decode (a malformed escape) returns an
// error; the caller should fail the request rather than match
// policies against bytes the upstream may interpret differently.
func SplitEscapedPath(escaped string) ([]string, error) {
	segs := SplitPath(escaped)
	for i, s := range segs {
		dec, err := url.PathUnescape(s)
		if err != nil {
			return nil, fmt.Errorf("path segment %d: %w", i, err)
		}
		segs[i] = dec
	}
	return segs, nil
}

// SplitPath splits a URL path on `/` after stripping a single leading
// `/`, preserving empty segments. Used for path-template parsing and
// route-prefix parsing (config-side strings, never percent-encoded).
// Request paths go through SplitEscapedPath instead, so an encoded
// slash cannot change the segment count.
//
// Examples:
//
//	"/users/me"   → ["users", "me"]
//	"/users//me"  → ["users", "", "me"]
//	"/users/me/"  → ["users", "me", ""]
//	"/"           → nil
//	""            → nil
//
// Preserving empties (rather than collapsing them as `strings.FieldsFunc`
// would) is what keeps `/users//me` from masquerading as `/users/me`
// against a `/users/{user}` template: the request now has three
// segments, the template has two, and the length check rejects it.
func SplitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// parseSegment classifies one segment. Returns (name, isParam, err).
//
// A pure literal segment (no braces) is returned with isParam=false. A
// segment matching exactly `{identifier}` is returned with isParam=true.
// Anything else — a stray `{`, `{user_id`, `user_id}`, or
// `{id}:enable` — is rejected so a typo fails loudly at config-load
// time rather than producing a literal segment that only matches
// requests with the same typo.
func parseSegment(seg string) (string, bool, error) {
	hasOpen := strings.IndexByte(seg, '{') >= 0
	hasClose := strings.IndexByte(seg, '}') >= 0
	if !hasOpen && !hasClose {
		return "", false, nil
	}
	if len(seg) < 2 || seg[0] != '{' || seg[len(seg)-1] != '}' {
		return "", false, fmt.Errorf("unmatched brace in segment %q: must be either a pure literal or {identifier}", seg)
	}
	body := seg[1 : len(seg)-1]
	if strings.ContainsAny(body, "{}") {
		return "", false, fmt.Errorf("nested brace in segment %q: must be {identifier}", seg)
	}
	if !isIdentifier(body) {
		return "", false, fmt.Errorf("invalid param segment %q: must be {identifier}", seg)
	}
	return body, true, nil
}

// isIdentifier reports whether s matches `[A-Za-z_][A-Za-z0-9_]*`.
// ASCII-only by design — path-template parameter names are an internal
// schema field, not user-facing text.
func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_':
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
		case i > 0 && '0' <= c && c <= '9':
		default:
			return false
		}
	}
	return true
}
