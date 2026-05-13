package agentseen

import (
	"testing"
	"time"
)

func TestTouchInsertsAndIncrements(t *testing.T) {
	tk := New()
	t0 := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	tk.Touch("a", t0)
	tk.Touch("a", t0.Add(time.Second))

	rows := tk.List()
	if len(rows) != 1 {
		t.Fatalf("len = %d, want 1", len(rows))
	}
	if rows[0].Subject != "a" || rows[0].RequestCount != 2 {
		t.Errorf("row = %+v, want subject=a count=2", rows[0])
	}
	if !rows[0].FirstSeen.Equal(t0) {
		t.Errorf("first_seen = %v, want %v", rows[0].FirstSeen, t0)
	}
	if !rows[0].LastSeen.Equal(t0.Add(time.Second)) {
		t.Errorf("last_seen = %v, want %v", rows[0].LastSeen, t0.Add(time.Second))
	}
}

func TestTouchEmptySubjectIsNoOp(t *testing.T) {
	tk := New()
	tk.Touch("", time.Now())
	if rows := tk.List(); len(rows) != 0 {
		t.Errorf("len = %d, want 0", len(rows))
	}
}

func TestListSortedByLastSeenDesc(t *testing.T) {
	tk := New()
	t0 := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	tk.Touch("a", t0)
	tk.Touch("b", t0.Add(time.Minute))
	tk.Touch("c", t0.Add(time.Second))

	rows := tk.List()
	want := []string{"b", "c", "a"}
	for i, s := range want {
		if rows[i].Subject != s {
			t.Errorf("rows[%d].Subject = %q, want %q", i, rows[i].Subject, s)
		}
	}
}

func TestLastSeenDoesNotRegress(t *testing.T) {
	tk := New()
	t0 := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	tk.Touch("a", t0.Add(time.Minute))
	tk.Touch("a", t0)

	rows := tk.List()
	if !rows[0].LastSeen.Equal(t0.Add(time.Minute)) {
		t.Errorf("last_seen = %v, want %v (an older Touch must not regress it)", rows[0].LastSeen, t0.Add(time.Minute))
	}
}
