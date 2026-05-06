package bundles

import (
	"strings"
	"testing"
)

func TestParseRefHappyPath(t *testing.T) {
	cases := []struct {
		in      string
		want    Ref
		wantStr string
	}{
		{"github.com/acme/api-pack@v1.4.0",
			Ref{Host: "github.com", Owner: "acme", Repo: "api-pack", Version: "v1.4.0"},
			"github.com/acme/api-pack@v1.4.0"},
		{"github.com/jkylling/bouncer",
			Ref{Host: "github.com", Owner: "jkylling", Repo: "bouncer"},
			"github.com/jkylling/bouncer"},
		{"github.com/foo/bar@release/1.x",
			Ref{Host: "github.com", Owner: "foo", Repo: "bar", Version: "release/1.x"},
			"github.com/foo/bar@release/1.x"},
		{"github.com/a/b@7a3c1f4abcdef0123456789abcdef0123456789a",
			Ref{Host: "github.com", Owner: "a", Repo: "b", Version: "7a3c1f4abcdef0123456789abcdef0123456789a"},
			"github.com/a/b@7a3c1f4abcdef0123456789abcdef0123456789a"},
		{"https://github.com/jkylling/bouncer-gws",
			Ref{Host: "github.com", Owner: "jkylling", Repo: "bouncer-gws"},
			"github.com/jkylling/bouncer-gws"},
		{"https://github.com/jkylling/bouncer-gws@main",
			Ref{Host: "github.com", Owner: "jkylling", Repo: "bouncer-gws", Version: "main"},
			"github.com/jkylling/bouncer-gws@main"},
		{"https://github.com/jkylling/bouncer-gws/",
			Ref{Host: "github.com", Owner: "jkylling", Repo: "bouncer-gws"},
			"github.com/jkylling/bouncer-gws"},
		{"https://github.com/jkylling/bouncer-gws.git",
			Ref{Host: "github.com", Owner: "jkylling", Repo: "bouncer-gws"},
			"github.com/jkylling/bouncer-gws"},
	}
	for _, c := range cases {
		got, err := ParseRef(c.in)
		if err != nil {
			t.Fatalf("ParseRef(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("ParseRef(%q) = %+v, want %+v", c.in, got, c.want)
		}
		if got.String() != c.wantStr {
			t.Fatalf("ParseRef(%q).String() = %q, want %q", c.in, got.String(), c.wantStr)
		}
	}
}

func TestParseRefRejectsBadInputs(t *testing.T) {
	cases := []struct {
		in      string
		message string
	}{
		{"", "empty"},
		{"not-a-ref", "host/owner/repo"},
		{"gitlab.com/a/b@v1", "github.com"},
		{"github.com//repo", "invalid"},
		{"github.com/owner/", "host/owner/repo"},
		{"github.com/owner/repo@", "version after @ is empty"},
		{"github.com/owner/repo@v 1", "whitespace"},
	}
	for _, c := range cases {
		_, err := ParseRef(c.in)
		if err == nil {
			t.Fatalf("ParseRef(%q): want error, got nil", c.in)
		}
		if !strings.Contains(err.Error(), c.message) {
			t.Fatalf("ParseRef(%q): err = %v, want containing %q", c.in, err, c.message)
		}
	}
}

func TestIsFullSHA(t *testing.T) {
	if !IsFullSHA("7a3c1f4abcdef0123456789abcdef0123456789a") {
		t.Fatal("expected full SHA to match")
	}
	if IsFullSHA("v1.4.0") {
		t.Fatal("expected v1.4.0 not to be a SHA")
	}
	if IsFullSHA("7a3c1f4") {
		t.Fatal("expected short SHA not to match")
	}
}

func TestRefSlug(t *testing.T) {
	r := Ref{Host: "github.com", Owner: "acme", Repo: "api-pack", Version: "v1.4.0"}
	if got := r.Slug(); got != "github.com/acme/api-pack" {
		t.Fatalf("Slug = %q", got)
	}
}
