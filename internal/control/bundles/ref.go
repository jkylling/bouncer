package bundles

import (
	"fmt"
	"regexp"
	"strings"
)

// Ref is "<host>/<owner>/<repo>[@<version>]". Only github.com is
// supported in v1; Host stays on the struct so adding others is a
// parser change rather than a struct change.
type Ref struct {
	Host    string
	Owner   string
	Repo    string
	Version string
}

func (r Ref) String() string {
	if r.Version == "" {
		return r.Slug()
	}
	return r.Slug() + "@" + r.Version
}

// Slug is the host/owner/repo portion only — the stable on-disk
// identity of a bundle (only one version of a slug installs at a
// time).
func (r Ref) Slug() string {
	return fmt.Sprintf("%s/%s/%s", r.Host, r.Owner, r.Repo)
}

// validRefSegment requires a leading alphanumeric to keep "." / ".."
// out of the language — those would otherwise pass a pure
// character-class check and slip through filepath.Join as traversal.
var validRefSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ParseRef parses "<host>/<owner>/<repo>[@<version>]". A leading
// `https://` / `http://`, trailing `/`, and trailing `.git` are
// stripped so a copy-pasted browser or clone URL works as-is.
func ParseRef(s string) (Ref, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Ref{}, fmt.Errorf("ref is empty")
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	var version string
	if at := strings.IndexByte(s, '@'); at >= 0 {
		version = s[at+1:]
		s = s[:at]
		if version == "" {
			return Ref{}, fmt.Errorf("ref %q: version after @ is empty", s)
		}
	}
	parts := strings.Split(s, "/")
	if len(parts) != 3 {
		return Ref{}, fmt.Errorf("ref %q: must be host/owner/repo[@version]", s)
	}
	host, owner, repo := parts[0], parts[1], parts[2]
	if host != "github.com" {
		return Ref{}, fmt.Errorf("ref %q: only github.com is supported in v1 (got host %q)", s, host)
	}
	for label, seg := range map[string]string{"owner": owner, "repo": repo} {
		if !validRefSegment.MatchString(seg) {
			return Ref{}, fmt.Errorf("ref %q: %s segment %q has invalid characters", s, label, seg)
		}
	}
	if strings.ContainsAny(version, " \t\n\r") {
		return Ref{}, fmt.Errorf("ref %q: version contains whitespace", s)
	}
	return Ref{Host: host, Owner: owner, Repo: repo, Version: version}, nil
}

var shaRegexp = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// IsFullSHA reports whether v is a 40-char hex commit SHA. The
// fetcher skips the resolve roundtrip when this is true.
func IsFullSHA(v string) bool { return shaRegexp.MatchString(v) }
