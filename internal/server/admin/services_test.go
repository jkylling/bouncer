package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/control/services"
)

func newServicesHarness(t *testing.T) *httptest.Server {
	t.Helper()
	loaded := []bundles.LoadedService{{
		Service: &bundles.Service{
			Slug:        "google",
			Title:       "Google",
			Description: "Google Workspace",
		},
		TokenVariants: []bundles.TokenVariant{{
			ID:    "access_token",
			Title: "Access token",
			Fields: []bundles.TokenField{{
				Name:     "access_token",
				Required: true,
				Kind:     "secret",
			}},
		}},
		APIs:       []string{"google.gmail"},
		BundleName: "bouncer-gws",
	}}
	reg := services.New(loaded)

	r := chi.NewRouter()
	MountServices(r, reg)
	return httptest.NewServer(r)
}

func TestServicesList(t *testing.T) {
	srv := newServicesHarness(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + ServicesPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body listServicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Services) != 1 || body.Services[0].Slug != "google" {
		t.Fatalf("got %+v", body.Services)
	}
	if len(body.Services[0].TokenVariants) != 1 {
		t.Fatalf("variants = %d", len(body.Services[0].TokenVariants))
	}
}

func TestServiceGet(t *testing.T) {
	srv := newServicesHarness(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/_api/services/google")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var d services.Descriptor
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.Slug != "google" || d.Title != "Google" {
		t.Fatalf("got %+v", d)
	}
}

func TestServiceGetUnknown(t *testing.T) {
	srv := newServicesHarness(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/_api/services/nope")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}
