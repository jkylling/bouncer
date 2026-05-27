package policies

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jkylling/bouncer/internal/runtime"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// trivialAPI is the smallest API that lets the runtime accept a policy.
// One match-all action, no metas — keeps the tests focused on the
// CRUD pipeline rather than CEL/meta plumbing.
func trivialAPI(name string) *models.API {
	return &models.API{
		Name:         name,
		BaseURL:      "https://" + name + ".invalid",
		PathPrefixes: []string{"/" + name},
		Actions: []models.Action{{
			Name:   "any",
			Filter: "true",
		}},
	}
}

func newRuntime(t *testing.T, apis ...*models.API) *runtime.Runtime {
	t.Helper()
	b := runtime.NewBuilder()
	for _, a := range apis {
		if err := b.AddAPI(a); err != nil {
			t.Fatalf("add api %q: %v", a.Name, err)
		}
	}
	rt, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return rt
}

func goodPolicy(api, name string) models.Policy {
	return models.Policy{
		API:       api,
		Name:      name,
		Action:    "true",
		Condition: "true",
		Result:    models.Permit,
	}
}

func TestServiceCreateRejectsDuplicate(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())
	p := goodPolicy("svc", "p1")

	if err := svc.Create(context.Background(), &p); err != nil {
		t.Fatalf("first create: %v", err)
	}
	err := svc.Create(context.Background(), &p)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("second create err = %v, want ErrConflict", err)
	}
}

func TestServiceReplaceUpserts(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())

	// Replace acts as create when nothing exists.
	p := goodPolicy("svc", "p1")
	if err := svc.Replace(context.Background(), "svc", "p1", &p); err != nil {
		t.Fatalf("first replace: %v", err)
	}
	// And as update on a second call with a tweaked condition.
	p.Condition = "1 == 1"
	if err := svc.Replace(context.Background(), "svc", "p1", &p); err != nil {
		t.Fatalf("second replace: %v", err)
	}
	got, err := svc.Get("svc", "p1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Condition != "1 == 1" {
		t.Errorf("condition = %q, want updated value", got.Condition)
	}
}

func TestServiceReplaceRejectsPathBodyMismatch(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())
	p := goodPolicy("svc", "p1")

	err := svc.Replace(context.Background(), "svc", "different-name", &p)
	if !errors.Is(err, ErrAPIPath) {
		t.Errorf("err = %v, want ErrAPIPath", err)
	}
}

func TestServiceValidateSurfacesCompileError(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())
	bad := goodPolicy("svc", "p1")
	bad.Condition = "no_such_var" // CEL: unknown identifier
	err := svc.Validate(&bad)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestServiceCreateLeavesNothingOnFailedValidate(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	store := NewMemoryStore()
	svc := New(rt, store)

	bad := goodPolicy("svc", "p1")
	bad.Condition = "no_such_var"
	if err := svc.Create(context.Background(), &bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if got := svc.List(); len(got) != 0 {
		t.Errorf("runtime got %v, want empty", got)
	}
	if all, _ := store.List(context.Background()); len(all) != 0 {
		t.Errorf("store got %v, want empty", all)
	}
}

func TestServiceDeleteIdempotent(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())
	p := goodPolicy("svc", "p1")
	if err := svc.Create(context.Background(), &p); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.Delete(context.Background(), "svc", "p1"); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	err := svc.Delete(context.Background(), "svc", "p1")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete err = %v, want ErrNotFound", err)
	}
}

// TestServiceCreateSerialisesDuplicateRace pins B4: two concurrent
// Creates of the same (api, name) must produce exactly one success
// and one ErrConflict. Without the service-level mutex both could
// pass the find-then-persist check and clobber each other.
func TestServiceCreateSerialisesDuplicateRace(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())

	var success, conflict atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := goodPolicy("svc", "p1")
			err := svc.Create(context.Background(), &p)
			switch {
			case err == nil:
				success.Add(1)
			case errors.Is(err, ErrConflict):
				conflict.Add(1)
			default:
				t.Errorf("unexpected create err: %v", err)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Errorf("success=%d, want 1", success.Load())
	}
	if conflict.Load() != 7 {
		t.Errorf("conflict=%d, want 7", conflict.Load())
	}
}

func TestLoadFromStoreReplaysIntoRuntime(t *testing.T) {
	store := NewMemoryStore()
	for _, p := range []models.Policy{
		goodPolicy("svc", "p1"),
		goodPolicy("svc", "p2"),
	} {
		if err := store.Put(context.Background(), p); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, store)
	if err := svc.LoadFromStore(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := svc.List(); len(got) != 2 {
		t.Errorf("runtime policies = %d, want 2: %+v", len(got), got)
	}
}

// TestReadOnlyRejectsMutations covers the read-only switch:
// Create / Replace / Delete must return ErrReadOnly without touching
// the store or runtime, while Validate / List / Get keep working.
func TestReadOnlyRejectsMutations(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	store := NewMemoryStore()
	svc := New(rt, store)

	// Seed one policy through the writeable path so we have something
	// to read back through the read-only Service.
	seed := goodPolicy("svc", "seed")
	if err := svc.Create(context.Background(), &seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	svc.SetReadOnly(true)
	if svc.Writeable() {
		t.Fatalf("Writeable() = true after SetReadOnly(true)")
	}

	cases := []struct {
		name string
		fn   func() error
	}{
		{"Create", func() error {
			p := goodPolicy("svc", "fresh")
			return svc.Create(context.Background(), &p)
		}},
		{"Replace", func() error {
			p := goodPolicy("svc", "seed")
			return svc.Replace(context.Background(), "svc", "seed", &p)
		}},
		{"Delete", func() error { return svc.Delete(context.Background(), "svc", "seed") }},
	}
	for _, c := range cases {
		if err := c.fn(); !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s: err = %v, want ErrReadOnly", c.name, err)
		}
	}

	// Reads keep working — the seed policy survives every rejected
	// mutation above.
	if _, err := svc.Get("svc", "seed"); err != nil {
		t.Errorf("Get after read-only: %v", err)
	}
	if got := svc.List(); len(got) != 1 {
		t.Errorf("List after read-only = %+v, want one entry", got)
	}
	// Validate is a pure compile check; readonly should not gate it.
	p := goodPolicy("svc", "anything")
	if err := svc.Validate(&p); err != nil {
		t.Errorf("Validate after read-only: %v", err)
	}
}

// TestReadOnlyDefaultsToWriteable pins the default — a fresh Service
// must accept writes so existing call sites that never call
// SetReadOnly keep working.
func TestReadOnlyDefaultsToWriteable(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())
	if !svc.Writeable() {
		t.Errorf("Writeable() = false on a fresh Service, want true")
	}
}

func TestImportCreatesNewPolicies(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())

	incoming := []models.Policy{
		goodPolicy("svc", "p1"),
		goodPolicy("svc", "p2"),
	}
	result, err := svc.Import(context.Background(), incoming, false)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(result.Created) != 2 {
		t.Errorf("created = %v, want 2 entries", result.Created)
	}
	if len(result.Overwritten) != 0 {
		t.Errorf("overwritten = %v, want empty", result.Overwritten)
	}
	if got := svc.List(); len(got) != 2 {
		t.Errorf("list = %d, want 2", len(got))
	}
}

func TestImportOverwritesExisting(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())

	seed := goodPolicy("svc", "p1")
	if err := svc.Create(context.Background(), &seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	incoming := []models.Policy{
		goodPolicy("svc", "p1"), // overwrite
		goodPolicy("svc", "p2"), // new
	}
	result, err := svc.Import(context.Background(), incoming, false)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(result.Created) != 1 || result.Created[0] != "svc/p2" {
		t.Errorf("created = %v, want [svc/p2]", result.Created)
	}
	if len(result.Overwritten) != 1 || result.Overwritten[0] != "svc/p1" {
		t.Errorf("overwritten = %v, want [svc/p1]", result.Overwritten)
	}
}

func TestImportDryRunDoesNotMutate(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())

	incoming := []models.Policy{goodPolicy("svc", "p1")}
	result, err := svc.Import(context.Background(), incoming, true)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if len(result.Created) != 1 {
		t.Errorf("created = %v, want 1", result.Created)
	}
	if got := svc.List(); len(got) != 0 {
		t.Errorf("list after dry-run = %d, want 0", len(got))
	}
}

func TestImportRejectsInvalidPolicies(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())

	incoming := []models.Policy{
		goodPolicy("svc", "p1"),
		{API: "svc", Name: "bad", Action: "true", Condition: "no_such_var", Result: models.Permit},
	}
	result, err := svc.Import(context.Background(), incoming, false)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if len(result.Errors) != 1 {
		t.Errorf("errors = %v, want 1 entry", result.Errors)
	}
	if got := svc.List(); len(got) != 0 {
		t.Errorf("list after failed import = %d, want 0 (no partial writes)", len(got))
	}
}

func TestImportDeduplicatesLastWins(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())

	p1 := goodPolicy("svc", "p1")
	p1.Condition = "1 == 1"
	p1dup := goodPolicy("svc", "p1")
	p1dup.Condition = "2 == 2"

	incoming := []models.Policy{p1, p1dup}
	result, err := svc.Import(context.Background(), incoming, false)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(result.Created) != 1 {
		t.Errorf("created = %v, want 1 (deduplicated)", result.Created)
	}
	got, err := svc.Get("svc", "p1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Condition != "2 == 2" {
		t.Errorf("condition = %q, want last-wins value", got.Condition)
	}
}

func TestImportReadOnlyRejects(t *testing.T) {
	rt := newRuntime(t, trivialAPI("svc"))
	svc := New(rt, NewMemoryStore())
	svc.SetReadOnly(true)

	_, err := svc.Import(context.Background(), []models.Policy{goodPolicy("svc", "p1")}, false)
	if !errors.Is(err, ErrReadOnly) {
		t.Errorf("err = %v, want ErrReadOnly", err)
	}
}
