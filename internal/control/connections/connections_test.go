package connections

import (
	"errors"
	"path/filepath"
	"testing"
)

func validCreds() Credentials {
	return Credentials{
		ClientID:     "cid.apps.googleusercontent.com",
		ClientSecret: "shh",
		RefreshToken: "1//0g...",
	}
}

func TestPutAndGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "connections"))

	got, err := s.Put("google", validCreds())
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if got.Credentials.ClientSecret != "" || got.Credentials.RefreshToken != "" {
		t.Fatalf("put response leaked secrets: %+v", got.Credentials)
	}

	// Get must return the full record (with secrets) — that's its only
	// caller's reason to exist.
	rec, err := s.Get("google")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec.Credentials.RefreshToken != "1//0g..." {
		t.Fatalf("get lost refresh_token: %+v", rec.Credentials)
	}
}

func TestListMasksSecrets(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "connections"))
	if _, err := s.Put("google", validCreds()); err != nil {
		t.Fatalf("put: %v", err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}
	if list[0].Credentials.RefreshToken != "" || list[0].Credentials.ClientSecret != "" {
		t.Fatalf("list leaked secrets: %+v", list[0].Credentials)
	}
}

func TestPutRejectsUnknownProvider(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "connections"))
	_, err := s.Put("attacker/../etc/passwd", validCreds())
	if !errors.Is(err, ErrUnknown) {
		t.Fatalf("err = %v, want ErrUnknown", err)
	}
}

func TestPutRejectsIncompleteCreds(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "connections"))
	c := validCreds()
	c.RefreshToken = ""
	_, err := s.Put("google", c)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestDeleteRemoves(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "connections"))
	if _, err := s.Put("google", validCreds()); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.Delete("google"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Get("google"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete: %v, want ErrNotFound", err)
	}
}

func TestProviderAvailability(t *testing.T) {
	got := ProviderAvailability(map[string]string{
		"BOUNCER_GOOGLE_CLIENT_ID":     "x",
		"BOUNCER_GOOGLE_CLIENT_SECRET": "y",
	})
	if !got["google"].OAuthAvailable {
		t.Fatalf("google.oauth_available = false; want true when both env vars set")
	}
	if got["slack.api"].OAuthAvailable {
		t.Fatalf("slack.api.oauth_available = true; want false when not set")
	}
	if !got["google"].PasteAvailable || !got["slack.api"].PasteAvailable {
		t.Fatalf("paste should always be available; got %+v", got)
	}
}
