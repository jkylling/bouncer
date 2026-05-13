package traffic

import (
	"bytes"
	"strings"
	"testing"
)

func TestSanitizeStripsSensitiveHeaders(t *testing.T) {
	ev := &Event{
		RequestHeaders: []KV{
			{Key: "Content-Type", Value: "application/json"},
			{Key: "Authorization", Value: "Bearer secret"},
			{Key: "cookie", Value: "session=abc"}, // case-insensitive
			{Key: "User-Agent", Value: "test"},
		},
		UpstreamHeaders: []KV{
			{Key: "Set-Cookie", Value: "x=1"},
			{Key: "Server", Value: "nginx"},
		},
	}
	Sanitize(ev, SanitizeOptions{})
	keys := headerKeys(ev.RequestHeaders)
	if want := []string{"Content-Type", "User-Agent"}; !equalSlices(keys, want) {
		t.Errorf("request headers = %v, want %v", keys, want)
	}
	keys = headerKeys(ev.UpstreamHeaders)
	if want := []string{"Server"}; !equalSlices(keys, want) {
		t.Errorf("upstream headers = %v, want %v", keys, want)
	}
}

func TestSanitizeTruncatesLargeBodies(t *testing.T) {
	ev := &Event{
		RequestBody:  bytes.Repeat([]byte("a"), 100),
		UpstreamBody: bytes.Repeat([]byte("b"), 50),
	}
	Sanitize(ev, SanitizeOptions{MaxBodyBytes: 32})
	if len(ev.RequestBody) != 32 {
		t.Errorf("request len = %d, want 32", len(ev.RequestBody))
	}
	if len(ev.UpstreamBody) != 32 {
		t.Errorf("upstream len = %d, want 32", len(ev.UpstreamBody))
	}
	if !ev.Truncated {
		t.Error("Truncated = false, want true after request+upstream over cap")
	}
}

func TestSanitizeKeepsBodyUnderCap(t *testing.T) {
	ev := &Event{RequestBody: []byte("short")}
	Sanitize(ev, SanitizeOptions{MaxBodyBytes: 32})
	if string(ev.RequestBody) != "short" {
		t.Errorf("body = %q, want %q", ev.RequestBody, "short")
	}
	if ev.Truncated {
		t.Error("Truncated = true on under-cap body")
	}
}

func TestSanitizeNoBodyAPIs(t *testing.T) {
	ev := &Event{
		API:          "google.gmail",
		RequestBody:  []byte("user content"),
		UpstreamBody: []byte("more user content"),
	}
	Sanitize(ev, SanitizeOptions{})
	if ev.RequestBody != nil {
		t.Errorf("request body = %q, want nil for gmail API", ev.RequestBody)
	}
	if ev.UpstreamBody != nil {
		t.Errorf("upstream body = %q, want nil for gmail API", ev.UpstreamBody)
	}
	if !ev.Truncated {
		t.Error("Truncated = false on a no-body API event with bodies")
	}
}

func TestSanitizeNoBodyAPIPreservesEmpty(t *testing.T) {
	ev := &Event{API: "google.gmail"}
	Sanitize(ev, SanitizeOptions{})
	if ev.Truncated {
		t.Error("Truncated set on a no-body API with no body — should stay false")
	}
}

func TestSanitizeNilEventOK(t *testing.T) {
	got := Sanitize(nil, SanitizeOptions{})
	if got != nil {
		t.Errorf("Sanitize(nil) = %v, want nil", got)
	}
}

func TestSanitizeUnchangedHeadersReuseSlice(t *testing.T) {
	in := []KV{{Key: "X-Trace", Value: "1"}}
	ev := &Event{RequestHeaders: in}
	Sanitize(ev, SanitizeOptions{})
	if &ev.RequestHeaders[0] != &in[0] {
		t.Error("expected stripHeaders to return input slice when nothing dropped")
	}
}

func TestSanitizeCustomSensitiveHeadersExtendsFloor(t *testing.T) {
	// Operator extends the list with a custom name; the default
	// floor (Authorization, Cookie, Set-Cookie) must still apply.
	ev := &Event{
		RequestHeaders: []KV{
			{Key: "Authorization", Value: "Bearer secret"},
			{Key: "X-My-Custom", Value: "drop me too"},
			{Key: "User-Agent", Value: "test"},
		},
	}
	Sanitize(ev, SanitizeOptions{SensitiveHeaders: []string{"X-My-Custom"}})
	keys := headerKeys(ev.RequestHeaders)
	if want := []string{"User-Agent"}; !equalSlices(keys, want) {
		t.Errorf("request headers = %v, want %v", keys, want)
	}
}

func TestSanitizeCustomNoBodyAPIs(t *testing.T) {
	ev := &Event{
		API:         "google.calendar",
		RequestBody: []byte("event body"),
	}
	Sanitize(ev, SanitizeOptions{NoBodyAPIs: map[string]bool{"google.calendar": true}})
	if ev.RequestBody != nil {
		t.Errorf("request body = %q, want nil for custom no-body API", ev.RequestBody)
	}
}

// TestSanitizeNoBodyAPIsPreservesDefaultFloor pins that supplying a
// custom NoBodyAPIs map still redacts the gmail/drive defaults. The
// previous implementation replaced rather than unioned, which let an
// operator (or a test) silently disable the floor by passing any
// non-nil map.
func TestSanitizeNoBodyAPIsPreservesDefaultFloor(t *testing.T) {
	ev := &Event{
		API:         "google.gmail",
		RequestBody: []byte("user mail"),
	}
	Sanitize(ev, SanitizeOptions{NoBodyAPIs: map[string]bool{"google.calendar": true}})
	if ev.RequestBody != nil {
		t.Error("gmail body must be redacted even when custom NoBodyAPIs is set")
	}
	if !ev.Truncated {
		t.Error("Truncated = false after default-floor redaction")
	}
}

func TestSanitizeTruncatesMetaFetchBodies(t *testing.T) {
	ev := &Event{
		MetaFetches: []MetaFetch{{
			Meta:         "drive.file",
			API:          "drive_meta", // not in NoBodyAPIs default set
			RequestBody:  bytes.Repeat([]byte("q"), 100),
			ResponseBody: bytes.Repeat([]byte("r"), 50),
		}},
	}
	Sanitize(ev, SanitizeOptions{MaxBodyBytes: 16, NoBodyAPIs: map[string]bool{}})
	if got := len(ev.MetaFetches[0].RequestBody); got != 16 {
		t.Errorf("fetch request body len = %d, want 16", got)
	}
	if got := len(ev.MetaFetches[0].ResponseBody); got != 16 {
		t.Errorf("fetch response body len = %d, want 16", got)
	}
	if !ev.Truncated {
		t.Error("Truncated = false after fetch body truncation")
	}
}

func TestSanitizeMetaFetchHonoursNoBodyAPIByFetchAPI(t *testing.T) {
	ev := &Event{
		API: "google.calendar", // outer event API is fine
		MetaFetches: []MetaFetch{{
			Meta:         "drive.file",
			API:          "google.drive", // sensitive upstream
			RequestBody:  []byte("q"),
			ResponseBody: []byte("r"),
		}},
	}
	Sanitize(ev, SanitizeOptions{})
	if ev.MetaFetches[0].RequestBody != nil {
		t.Errorf("fetch request body = %q, want nil for drive meta-fetch", ev.MetaFetches[0].RequestBody)
	}
	if ev.MetaFetches[0].ResponseBody != nil {
		t.Errorf("fetch response body = %q, want nil for drive meta-fetch", ev.MetaFetches[0].ResponseBody)
	}
	if !ev.Truncated {
		t.Error("Truncated = false after fetch body redaction")
	}
}

func TestSanitizeMetaFetchRedactedWhenOuterAPIIsNoBody(t *testing.T) {
	// Outer event API is gmail (NoBody) — all fetch bodies must drop
	// even if the fetch's own API is not redacted on its own.
	ev := &Event{
		API: "google.gmail",
		MetaFetches: []MetaFetch{{
			Meta:         "calendar.event",
			API:          "google.calendar",
			RequestBody:  []byte("q"),
			ResponseBody: []byte("r"),
		}},
	}
	Sanitize(ev, SanitizeOptions{})
	if ev.MetaFetches[0].RequestBody != nil || ev.MetaFetches[0].ResponseBody != nil {
		t.Error("expected outer-NoBody to redact every fetch body")
	}
}

func headerKeys(kvs []KV) []string {
	out := make([]string, len(kvs))
	for i, kv := range kvs {
		out[i] = kv.Key
	}
	return out
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}
