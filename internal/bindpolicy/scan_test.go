package bindpolicy

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func itoa(fd uintptr) string { return strconv.Itoa(int(fd)) }

func TestScanFindsSocketsByDepth(t *testing.T) {
	dir := t.TempDir()
	// depth 1: puma.sock; depth 2: .git/fsmonitor--daemon.ipc. The prune
	// with a depth cap of 3, directories three levels
	// below the root are still LISTED (their files checked), only their
	// subdirectories are not — so a depth-4 file is found, a depth-5
	// file is not.
	mustSocketAt(t, filepath.Join(dir, "puma.sock"))
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSocketAt(t, filepath.Join(dir, ".git", "fsmonitor--daemon.ipc"))
	if err := os.MkdirAll(filepath.Join(dir, "d1", "d2", "d3"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSocketAt(t, filepath.Join(dir, "d1", "d2", "d3", "level4.sock"))

	if got := ContainsSocket(dir, "", false, nil); got == "" {
		t.Fatal("scan found nothing")
	} else if !strings.HasSuffix(got, "puma.sock") && !strings.HasSuffix(got, "fsmonitor--daemon.ipc") {
		t.Errorf("scan found %q — not one of the shallow sockets", got)
	}

	// a level-5 socket alone in its own tree is not reached
	onlyDeep := t.TempDir()
	if err := os.MkdirAll(filepath.Join(onlyDeep, "d1", "d2", "d3", "d4"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSocketAt(t, filepath.Join(onlyDeep, "d1", "d2", "d3", "d4", "deep.sock"))
	if got := ContainsSocket(onlyDeep, "", false, nil); got != "" {
		t.Errorf("socket beyond the depth window found: %q", got)
	}
}

func TestScanSymlinkSemantics(t *testing.T) {
	outer := t.TempDir()
	realDir := filepath.Join(outer, "real")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustSocketAt(t, filepath.Join(realDir, "s.sock"))

	scanDir := filepath.Join(outer, "scan")
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// a symlink TO a socket counts (stat follows — the name connects);
	// a symlinked DIRECTORY is not descended into
	if err := os.Symlink(filepath.Join(realDir, "s.sock"), filepath.Join(scanDir, "socklink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(scanDir, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if got := ContainsSocket(scanDir, "", false, nil); !strings.HasSuffix(got, "socklink") {
		t.Errorf("scan = %q, want the symlinked socket name", got)
	}

	// only the dir-symlink: nothing found
	onlyLink := filepath.Join(outer, "onlylink")
	if err := os.MkdirAll(onlyLink, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(onlyLink, "d")); err != nil {
		t.Fatal(err)
	}
	if got := ContainsSocket(onlyLink, "", false, nil); got != "" {
		t.Errorf("scan descended through a directory symlink: %q", got)
	}
}

// The entry cap is FAIL-OPEN by design: big trees keep binding, with a
// lossy (verbose-gated) note instead of a refusal.
func TestScanEntryCapFailsOpenWithNote(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < DefaultScanEntries+5; i++ {
		if err := os.WriteFile(filepath.Join(dir, "f"+strconv.Itoa(i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var warns []string
	got := ContainsSocket(dir, dir, true, func(w string) { warns = append(warns, w) })
	if got != "" {
		t.Fatalf("plain files reported as sockets: %q", got)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "gave up after "+strconv.Itoa(DefaultScanEntries)+" entries") {
		t.Errorf("warnings = %v, want the gave-up note", warns)
	}
	if !strings.Contains(warns[0], "the bind is allowed") {
		t.Errorf("gave-up note must say the bind is still allowed: %q", warns[0])
	}
}

// Unreadable directories are noted on EVERY launch (no stamp): a socket
// connectable by name could hide there.
func TestScanNotesUnreadableDirs(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads through 0000 directories")
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.Mkdir(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	mustSocketAt(t, filepath.Join(secret, "hidden.sock"))
	if err := os.Chmod(secret, 0o0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(secret, 0o755) }) //nolint:errcheck

	shown := filepath.Join(t.TempDir(), "shown")
	var warns []string
	got := ContainsSocket(dir, shown, false, func(w string) { warns = append(warns, w) })
	if got != "" {
		t.Fatalf("scan saw through the unreadable dir: %q", got)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "could not read 1 directory") {
		t.Fatalf("warnings = %v, want the unreadable-dir note", warns)
	}
	if !strings.Contains(warns[0], shown) {
		t.Errorf("note must use the HOST-path spelling: %q", warns[0])
	}
}

// The unreadable-dir note interpolates a directory ENTRY NAME the tree's
// writer controls: it must be QUOTED, so a hostile file name cannot
// inject terminal control characters into the warning.
func TestScanQuotesUntrustedNames(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads through 0000 directories")
	}
	dir := t.TempDir()
	// ESC + a fake CSI sequence in a directory name
	evil := filepath.Join(dir, "go\x1b[31mwarm")
	if err := os.Mkdir(evil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(evil, 0o0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(evil, 0o755) }) //nolint:errcheck

	var warns []string
	if got := ContainsSocket(dir, "", true, func(w string) { warns = append(warns, w) }); got != "" {
		t.Fatalf("scan found a socket that does not exist: %q", got)
	}
	if len(warns) != 1 {
		t.Fatalf("warnings = %q, want exactly the unreadable-dir note", warns)
	}
	// The name must appear ESCAPED (backslash-x-1-b text), never as a raw
	// ESC byte: strconv.Quote spelling inside the quoted path.
	if !strings.Contains(warns[0], `go\x1b[31mwarm`) {
		t.Errorf("note must quote the hostile name with escapes: %q", warns[0])
	}
	if strings.Contains(warns[0], "\x1b") {
		t.Errorf("note leaked a raw ESC byte: %q", warns[0])
	}
}

// The DEPTH cap used to close the scan window silently: a tree whose
// only directories live below the depth limit scanned "clean" with no
// indication anything was left unvisited. The note is lossy (verbose or
// once a day) like the entry-cap one, but it must fire.
func TestScanNotesDepthPrune(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "d1", "d2", "d3", "d4"), 0o755); err != nil {
		t.Fatal(err)
	}
	var warns []string
	if got := ContainsSocket(dir, dir, true, func(w string) { warns = append(warns, w) }); got != "" {
		t.Fatalf("scan found nothing: %q", got)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "did not descend below depth 3") {
		t.Fatalf("warnings = %q, want the depth-prune note", warns)
	}
	if !strings.Contains(warns[0], dir) || !strings.Contains(warns[0], "the bind is allowed") {
		t.Errorf("depth note must name the tree and keep the bind allowed: %q", warns[0])
	}

	// A shallow tree scans clean and silent.
	shallow := t.TempDir()
	if err := os.Mkdir(filepath.Join(shallow, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	warns = nil
	if got := ContainsSocket(shallow, shallow, true, func(w string) { warns = append(warns, w) }); got != "" {
		t.Fatalf("scan = %q", got)
	}
	if len(warns) != 0 {
		t.Errorf("shallow scan warned anyway: %q", warns)
	}
}
