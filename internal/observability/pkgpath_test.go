package observability_test

import (
	"strings"
	"testing"

	"github.com/jkylling/bouncer/internal/observability"
)

// pkgFromVar exercises the var-initializer call path: a `var`
// declaration at package level with a PackagePath() RHS. Caller frame
// is the package's init function. Result is asserted in
// TestPackagePathFromVarInit so a regression in init-frame parsing
// fails loudly rather than silently registering a misnamed tracer.
var pkgFromVar = observability.PackagePath()

func TestPackagePathFromVarInit(t *testing.T) {
	const want = "github.com/jkylling/bouncer/internal/observability_test"
	if pkgFromVar != want {
		t.Errorf("from var init: %q, want %q", pkgFromVar, want)
	}
}

func TestPackagePathFromFunction(t *testing.T) {
	const want = "github.com/jkylling/bouncer/internal/observability_test"
	got := observability.PackagePath()
	if got != want {
		t.Errorf("from function: %q, want %q", got, want)
	}
}

// TestPackagePathFromMethod exercises the "(*Type).Method" form of
// function names — the parser uses the first dot after the last '/',
// which sits between pkgpath and the receiver, not inside the
// (*Type) suffix.
func TestPackagePathFromMethod(t *testing.T) {
	const want = "github.com/jkylling/bouncer/internal/observability_test"
	got := pkgPathHolder{}.fromMethod()
	if got != want {
		t.Errorf("from method: %q, want %q", got, want)
	}
}

type pkgPathHolder struct{}

func (pkgPathHolder) fromMethod() string { return observability.PackagePath() }

// TestPackagePathFromClosure: anonymous functions get names like
// "pkgpath.TestX.func1". The parser still cuts at the first dot past
// the last '/', producing the package path.
func TestPackagePathFromClosure(t *testing.T) {
	const want = "github.com/jkylling/bouncer/internal/observability_test"
	got := func() string { return observability.PackagePath() }()
	if got != want {
		t.Errorf("from closure: %q, want %q", got, want)
	}
}

// TestPackagePathContainsModulePrefix is a sanity check: whatever
// goes wrong in the parsing, at least the result must start with the
// repo's module path so a misparse cannot accidentally register a
// tracer under a third-party path.
func TestPackagePathContainsModulePrefix(t *testing.T) {
	got := observability.PackagePath()
	const prefix = "github.com/jkylling/bouncer/"
	if !strings.HasPrefix(got, prefix) {
		t.Errorf("PackagePath = %q, want prefix %q", got, prefix)
	}
}
