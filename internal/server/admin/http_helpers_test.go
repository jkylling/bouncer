package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// requireStatus closes resp on failure; the caller owns it on success.
func requireStatus(t *testing.T, resp *http.Response, want int) *http.Response {
	t.Helper()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("status = %d, want %d, body = %s", resp.StatusCode, want, body)
	}
	return resp
}

// decodeOK asserts status and decodes the body into a fresh T.
func decodeOK[T any](t *testing.T, resp *http.Response, want int) T {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d, body = %s", resp.StatusCode, want, body)
	}
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}
