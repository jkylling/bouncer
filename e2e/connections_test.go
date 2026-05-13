//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestConnectionsPutListDeleteRoundTrip pins the BYOT happy path:
// the operator stages an OAuth triple, sees it in list, then deletes
// it. Stays end-to-end (subprocess) so a CLI-surface change in
// connectionscmd surfaces here.
func TestConnectionsPutListDeleteRoundTrip(t *testing.T) {
	dir := mustInit(t, initOpts{Password: "admin"})

	put := run(t, "connections", "put", "google",
		"--data-dir", dir,
		"--client-id", "client-id-x",
		"--client-secret", "client-secret-y",
		"--refresh-token", "1//refresh",
		"--token-url", "https://oauth2.googleapis.com/token",
	)
	if put.Err != nil {
		t.Fatalf("put: %v\nstderr: %s", put.Err, put.Stderr)
	}
	if !strings.Contains(put.Stdout, "ok google") {
		t.Errorf("put stdout = %q", put.Stdout)
	}

	list := run(t, "connections", "list", "--data-dir", dir)
	if list.Err != nil {
		t.Fatalf("list: %v\nstderr: %s", list.Err, list.Stderr)
	}
	if !strings.Contains(list.Stdout, "google\tclient_id=client-id-x") {
		t.Errorf("list stdout missing google entry:\n%s", list.Stdout)
	}

	del := run(t, "connections", "delete", "google", "--data-dir", dir)
	if del.Err != nil {
		t.Fatalf("delete: %v\nstderr: %s", del.Err, del.Stderr)
	}

	list2 := run(t, "connections", "list", "--data-dir", dir)
	if list2.Err != nil {
		t.Fatalf("list2: %v", list2.Err)
	}
	if !strings.Contains(list2.Stdout, "(no connections)") {
		t.Errorf("list2 stdout = %q, want (no connections)", list2.Stdout)
	}
}

// TestConnectionsPutRequiresCredentials pins the validation surface
// — missing creds is an operator-error and should exit non-zero
// with a clear message rather than silently writing an empty
// credential.
func TestConnectionsPutRequiresCredentials(t *testing.T) {
	dir := mustInit(t, initOpts{Password: "admin"})
	res := run(t, "connections", "put", "google", "--data-dir", dir)
	if res.Err == nil {
		t.Fatalf("expected error, got stdout=%q", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "--client-id") {
		t.Errorf("stderr = %q, want mention of --client-id", res.Stderr)
	}
}

// TestConnectionsRejectsUnknownProvider pins the SupportedProviders
// allow-list — a typo'd provider is an operator-error rejected at
// the boundary, not allowed to write a stray file.
func TestConnectionsRejectsUnknownProvider(t *testing.T) {
	dir := mustInit(t, initOpts{Password: "admin"})
	res := run(t, "connections", "put", "not-a-real-provider",
		"--data-dir", dir,
		"--client-id", "x", "--client-secret", "y", "--refresh-token", "z")
	if res.Err == nil {
		t.Fatalf("expected error, got stdout=%q", res.Stdout)
	}
}
