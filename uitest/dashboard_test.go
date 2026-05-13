//go:build ui

package uitest

import (
	"testing"
)

// TestDashboardTabs visits each sidebar tab and asserts the active
// page heading. Screenshots land in
// uitest/screenshots/TestDashboardTabs/.
func TestDashboardTabs(t *testing.T) {
	proc := startBouncer(t)
	s := newSession(t, proc)
	s.login()

	tabs := []struct {
		path, heading string
	}{
		{"/_admin/traffic", "Traffic"},
		{"/_admin/policies", "Policies"},
		{"/_admin/", "Agents"},
		{"/_admin/services", "Services"},
		{"/_admin/settings", "Settings"},
	}

	for _, tab := range tabs {
		if _, err := s.page.Goto(proc.BaseURL + tab.path); err != nil {
			t.Fatalf("goto %s: %v", tab.path, err)
		}
		text, err := s.page.Locator("h1").First().InnerText()
		if err != nil {
			t.Fatalf("read h1 on %s: %v", tab.path, err)
		}
		if !containsFold(text, tab.heading) {
			t.Fatalf("%s h1 = %q, want to contain %q", tab.path, text, tab.heading)
		}
		s.shot(sanitize(tab.path))
	}
}

func containsFold(haystack, needle string) bool {
	h, n := toLower(haystack), toLower(needle)
	return contains(h, n)
}

func toLower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
