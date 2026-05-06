package observability

import (
	"runtime"
	"strings"
)

// PackagePath returns the import path of the package that called it.
// Designed for the otel `tracerName` idiom so a package can register
// its tracer without restating its own import path:
//
//	var tracerName = observability.PackagePath()
//
// The path is derived from the calling function's name (which Go
// formats as "<pkgpath>.<symbol>"). Computed once when the caller
// runs — typically a `var` initializer at package init — so the cost
// is amortised over the process lifetime.
//
// Returns "" if the caller frame cannot be resolved. The caller is
// then free to fall back to a literal, but in practice this only
// happens if PackagePath is invoked under a runtime that has stripped
// symbol tables (a `-trimpath`-only build still keeps function names).
func PackagePath() string {
	// runtime.Callers returns return-PCs; CallersFrames maps each PC
	// back to its source-level frame, which is what we want. Using
	// FuncForPC directly is unsafe: a return-PC sitting on the
	// boundary between two functions can resolve to the next one.
	var pcs [1]uintptr
	if runtime.Callers(2, pcs[:]) == 0 {
		return ""
	}
	frame, _ := runtime.CallersFrames(pcs[:]).Next()
	if frame.Function == "" {
		return ""
	}
	// Function names have the form "<pkgpath>.<symbol>" or
	// "<pkgpath>.(*Type).Method". The package name itself cannot
	// contain '.', and path components separated by '/' cannot
	// either, so the first '.' after the last '/' splits pkgpath
	// from whatever follows.
	name := frame.Function
	slash := strings.LastIndex(name, "/")
	dot := strings.Index(name[slash+1:], ".")
	if dot < 0 {
		return name
	}
	return name[:slash+1+dot]
}
