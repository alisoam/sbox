package notes

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStampPathSanitizes(t *testing.T) {
	for _, c := range []struct{ key, name string }{
		{"userns-fallback", "userns-fallback.stamp"},
		{"a/b/../../etc/passwd", "a_b_.._.._etc_passwd.stamp"},
		{"spaces and\ttabs", "spaces_and_tabs.stamp"},
	} {
		if got := stampPath("/base", c.key); got != filepath.Join("/base", c.name) {
			t.Errorf("stampPath(%q) = %q, want %q", c.key, got, filepath.Join("/base", c.name))
		}
	}
	if got := stampPath("/base", "0123456789012345678901234567890123456789012345678901234567890123456789"); len(filepath.Base(got)) > 64+len(".stamp") {
		t.Errorf("stamp file name not bounded: %q", filepath.Base(got))
	}
}

func TestOncePerDay(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	p := stampPath(dir, "caps-fallback")

	if noteRecentlyShownAt(p, now) {
		t.Fatalf("missing stamp counts as shown")
	}
	if err := markNoteShownAt(p, now); err != nil {
		t.Fatalf("markNoteShownAt: %v", err)
	}
	if !noteRecentlyShownAt(p, now) {
		t.Errorf("just-shown note not suppressed")
	}
	if !noteRecentlyShownAt(p, now.Add(23*time.Hour)) {
		t.Errorf("note should still be suppressed 23h after showing")
	}
	if noteRecentlyShownAt(p, now.Add(25*time.Hour)) {
		t.Errorf("note still suppressed 25h after showing, want shown again")
	}
	// future mtimes (clock skew) count as shown — err toward fewer notes
	if !noteRecentlyShownAt(p, now.Add(-2*time.Hour)) {
		t.Errorf("future stamp should count as shown")
	}
}

func TestExportedRoundTrip(t *testing.T) {
	// The exported API must be silent best-effort even when the cache
	// dir is unusable (here: a file where the dir should be).
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := os.Getenv("XDG_CACHE_HOME")
	os.Setenv("XDG_CACHE_HOME", blocker)
	defer os.Setenv("XDG_CACHE_HOME", old)

	if NoteRecentlyShown("anything") {
		t.Errorf("unusable cache dir must read as not-shown")
	}
	MarkNoteShown("anything") // must not panic or fail loudly
}
