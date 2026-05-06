// Package buildinfo holds version metadata stamped into release
// builds via `-ldflags -X`. Defaults apply to unstamped local builds.
package buildinfo

// Version is the release name (git tag for stamped builds, "dev"
// otherwise).
var Version = "dev"

// Commit is the short git SHA the build was cut from, or "unknown"
// if unstamped. The Makefile passes `git rev-parse --short HEAD`.
var Commit = "unknown"
