package notes

import (
	"os"
	"path/filepath"
	"syscall"
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
	name := "caps-fallback.stamp"

	if noteRecentlyShownAt(dir, name, now) {
		t.Fatalf("missing stamp counts as shown")
	}
	if err := markNoteShownAt(dir, name, now); err != nil {
		t.Fatalf("markNoteShownAt: %v", err)
	}
	if !noteRecentlyShownAt(dir, name, now) {
		t.Errorf("just-shown note not suppressed")
	}
	if !noteRecentlyShownAt(dir, name, now.Add(23*time.Hour)) {
		t.Errorf("note should still be suppressed 23h after showing")
	}
	if noteRecentlyShownAt(dir, name, now.Add(25*time.Hour)) {
		t.Errorf("note still suppressed 25h after showing, want shown again")
	}
	// future mtimes (clock skew) count as shown — err toward fewer notes
	if !noteRecentlyShownAt(dir, name, now.Add(-2*time.Hour)) {
		t.Errorf("future stamp should count as shown")
	}
}

// A stamp symlink planted by a sandbox with cache write access must
// never redirect the write: the stamp is replaced by rename through the
// directory fd, and the victim keeps its bytes.
func TestStampSymlinkDoesNotEscape(t *testing.T) {
	dir := t.TempDir()
	notes := filepath.Join(dir, "notes")
	if err := os.MkdirAll(notes, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(notes, "caps.stamp")); err != nil {
		t.Fatal(err)
	}

	if noteRecentlyShownAt(notes, "caps.stamp", time.Now()) {
		t.Fatal("a planted stamp symlink must count as not shown")
	}
	if err := markNoteShownAt(notes, "caps.stamp", time.Now()); err != nil {
		t.Fatalf("markNoteShownAt over a planted symlink: %v", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "precious" {
		t.Fatalf("victim file was truncated through the symlink: %q", got)
	}
	fi, err := os.Lstat(filepath.Join(notes, "caps.stamp"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the planted symlink was not replaced by a real stamp")
	}
	if !noteRecentlyShownAt(notes, "caps.stamp", time.Now()) {
		t.Fatal("the replaced stamp must suppress the note")
	}
}

// A symlinked notes DIRECTORY (a sandbox swapping ~/.cache/sbox/notes,
// or any component at or below the cache root) must be refused, not
// followed onto ground outside it — and the missing-directory creation
// must not build the tree BEHIND the link while refusing it.
func TestStampDirSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	if err := markNoteShownAt(link, "k", time.Now()); err == nil {
		t.Fatal("markNoteShownAt through a symlinked dir must fail")
	}
	if noteRecentlyShownAt(link, "k", time.Now()) {
		t.Fatal("a stamp behind a symlinked dir must read as not shown")
	}
	if _, err := os.Lstat(filepath.Join(real, "k.stamp")); !os.IsNotExist(err) {
		t.Fatal("a write crossed a symlinked directory component")
	}

	// A MISSING notes dir behind a symlinked parent: the walk refuses
	// the link and must not create anything under its target.
	cache := filepath.Join(dir, "cache")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cache, "sbox")); err != nil {
		t.Fatal(err)
	}
	if err := markNoteShownAt(filepath.Join(cache, "sbox", "notes"), "k", time.Now()); err == nil {
		t.Fatal("markNoteShownAt must refuse the symlinked sbox component")
	}
	if _, err := os.Lstat(filepath.Join(outside, "notes")); !os.IsNotExist(err) {
		t.Fatal("directory creation followed a symlinked component")
	}

	// Without the symlink the same walk must CREATE the missing dirs.
	if err := markNoteShownAt(filepath.Join(dir, "fresh", "sbox", "notes"), "k", time.Now()); err != nil {
		t.Fatalf("creating the notes dir: %v", err)
	}
	if !noteRecentlyShownAt(filepath.Join(dir, "fresh", "sbox", "notes"), "k", time.Now()) {
		t.Fatal("the created stamp must suppress the note")
	}
}

// A planted FIFO stamp must not hang the launcher: the metadata check
// opens an O_PATH handle and never touches the file's data path.
func TestStampFifoDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "caps.stamp"), 0o600); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}
	// A blocking open would deadlock here; both calls must return.
	if noteRecentlyShownAt(dir, "caps.stamp", time.Now()) {
		t.Fatal("a FIFO stamp must count as not shown")
	}
	if err := markNoteShownAt(dir, "caps.stamp", time.Now()); err != nil {
		t.Fatalf("markNoteShownAt over a FIFO: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "caps.stamp")); err != nil || fi.Mode()&os.ModeNamedPipe != 0 {
		t.Fatal("the planted FIFO was not replaced by a real stamp")
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
