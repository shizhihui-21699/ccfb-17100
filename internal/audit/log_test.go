package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestChainVerifies(t *testing.T) {
	l := New()
	for i := 0; i < 5; i++ {
		if _, err := l.Append(Event{Action: "create", Actor: "u1", LinkID: "l1"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	l := New()
	for i := 0; i < 5; i++ {
		_, _ = l.Append(Event{Action: "create", Actor: "u1", Target: "https://a.com"})
	}
	// Alter an entry in the middle.
	l.entries[2].Actor = "someone_else"
	if err := l.Verify(); err == nil {
		t.Fatal("tampering not detected")
	}
}

func TestReorderingIsDetected(t *testing.T) {
	l := New()
	for i := 0; i < 4; i++ {
		_, _ = l.Append(Event{Action: "x", Actor: "u"})
	}
	l.entries[1], l.entries[2] = l.entries[2], l.entries[1]
	if err := l.Verify(); err == nil {
		t.Fatal("reordering not detected")
	}
}

func TestTruncationIsDetected(t *testing.T) {
	l := New()
	for i := 0; i < 4; i++ {
		_, _ = l.Append(Event{Action: "x", Actor: "u"})
	}
	// Removing a middle entry breaks seq continuity and the prev-hash link.
	l.entries = append(l.entries[:2], l.entries[3:]...)
	if err := l.Verify(); err == nil {
		t.Fatal("truncation not detected")
	}
}

func TestPersistAndReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	l.nowFn = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if _, err := l.Append(Event{Action: "create", Actor: "u1", LinkID: "l1"}); err != nil {
			t.Fatal(err)
		}
	}
	head := l.prev
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen and continue: the chain must link across the restart.
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if l2.prev != head {
		t.Fatalf("recovered head %s != %s", l2.prev, head)
	}
	if err := l2.Verify(); err != nil {
		t.Fatalf("replayed chain broken: %v", err)
	}
	if _, err := l2.Append(Event{Action: "revoke", Actor: "sec"}); err != nil {
		t.Fatal(err)
	}
	if err := l2.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestFileTamperDetectedOnReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, _ := Open(path)
	for i := 0; i < 3; i++ {
		_, _ = l.Append(Event{Action: "create", Actor: "u1", Target: "https://a.com"})
	}
	l.Close()

	data, _ := os.ReadFile(path)
	// Flip a byte in the target field of the first record.
	mutated := []byte(string(data))
	idx := 0
	for i := 0; i+len("https://a.com") <= len(mutated); i++ {
		if string(mutated[i:i+len("https://a.com")]) == "https://a.com" {
			mutated[i+len("https://a.com")-1] = 'x'
			idx = i
			break
		}
	}
	if idx == 0 {
		t.Skip("could not locate target string")
	}
	_ = os.WriteFile(path, mutated, 0o600)

	l2, err := Open(path)
	if err != nil {
		t.Fatalf("replay should succeed but chain should fail: %v", err)
	}
	defer l2.Close()
	if err := l2.Verify(); err == nil {
		t.Fatal("on-disk tampering not detected")
	}
}
