package bindpolicy

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// listenUnix creates a real filesystem Unix socket (the listener stays
// open for the test's lifetime; the socket file persists either way).
func listenUnix(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}

func mustSocketAt(t *testing.T, path string) {
	t.Helper()
	l, err := listenUnix(path)
	if err != nil {
		t.Fatalf("socket %s: %v", path, err)
	}
	t.Cleanup(func() { l.Close() })
}

// mustCwd is the working directory (-b ” resolves to it, like Python's
// realpath("") on CPython >= 3.13).
func mustCwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

func TestOpenPathPinned(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "b"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"/", dir, filepath.Join(dir, "a"), filepath.Join(dir, "a", "b")} {
		f, err := OpenPathPinned(p)
		if err != nil {
			t.Fatalf("pin %s: %v", p, err)
		}
		if !FdReaches(f, p) {
			t.Errorf("pin of %s does not reach its own path", p)
		}
		f.Close()
	}

	// dot-dot components pop the stack like Python's walk
	f, err := OpenPathPinned(filepath.Join(dir, "a", "..", "a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, err = OpenPathPinned(filepath.Join(dir, "missing"))
	if !errors.Is(err, syscall.ENOENT) {
		t.Errorf("missing source: got %v, want ENOENT preserved for allowMissing", err)
	}
	if _, err := OpenPathPinned(filepath.Join(dir, "a", "b", "deeper")); err == nil ||
		!strings.Contains(err.Error(), "cannot pin bind source") {
		t.Errorf("component under a file: got %v", err)
	}
	if _, err := OpenPathPinned("relative/path"); err == nil ||
		!strings.Contains(err.Error(), "absolute path") {
		t.Errorf("relative input: got %v", err)
	}
}

// The walk refuses symlinks only for post-realpath races — the callers
// resolve first, so a symlink met during the pin means the tree changed
// under validation (a concurrent sandbox redirecting the bind).
func TestOpenPathPinnedRefusesPostRealpathSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}

	// simulate the race: realpath said /dir/d/x (a file), but by pin time
	// the component is a symlink
	raced := filepath.Join(dir, "d", "x")
	if err := os.WriteFile(raced, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(raced); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, raced); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPathPinned(raced); err == nil || !strings.Contains(err.Error(), "is a symlink — the path changed between realpath() and the pin") {
		t.Errorf("final-component race: got %v", err)
	}

	// same for an intermediate component
	if err := os.Symlink(filepath.Join(dir, "d"), filepath.Join(dir, "dlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPathPinned(filepath.Join(dir, "dlink", "x")); err == nil ||
		!strings.Contains(err.Error(), "component") {
		t.Errorf("intermediate-component race: got %v", err)
	}
}

// TestFdReachesCatchesRename: a rename after pinning must make the fd
// fail the /proc/self/fd identity check.
func TestFdReachesCatchesRename(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := OpenPathPinned(filepath.Join(dir, "f"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !FdReaches(f, filepath.Join(dir, "f")) {
		t.Fatal("fresh pin does not reach its own path")
	}
	if err := os.Rename(filepath.Join(dir, "f"), filepath.Join(dir, "g")); err != nil {
		t.Fatal(err)
	}
	if FdReaches(f, filepath.Join(dir, "f")) {
		t.Error("renamed file still 'reaches' its old path — race check broken")
	}

	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := OpenPathPinned(filepath.Join(dir, "a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if err := os.Rename(filepath.Join(dir, "a"), filepath.Join(dir, "a2")); err != nil {
		t.Fatal(err)
	}
	if FdReaches(fd, filepath.Join(dir, "a", "b")) {
		t.Error("pin under renamed ancestor still 'reaches' its old path")
	}
}

func TestPinner(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean")
	if err := os.Mkdir(clean, 0o755); err != nil {
		t.Fatal(err)
	}

	p := NewPinner(true)
	f1, err := p.Pin(clean, false)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := p.Pin(clean, false) // one fd per source, cached
	if err != nil {
		t.Fatal(err)
	}
	if f1 != f2 {
		t.Fatal("second Pin of the same source must return the cached fd")
	}

	// a refused bind's pin is released: closed and forgotten (a live
	// O_PATH fd for host ground must never linger)
	p.Release(clean)
	if _, err := os.Readlink("/proc/self/fd/" + itoa(f1.Fd())); err == nil {
		t.Error("released pin still open")
	}
	p.Release(clean) // no-op for unpinned paths
	p.Close()

	// allowMissing: only --bind-socket of not-yet-created runtime paths
	p2 := NewPinner(true)
	defer p2.Close()
	if fd, err := p2.Pin(filepath.Join(dir, "nosock"), true); err != nil || fd != nil {
		t.Errorf("allowMissing pin = %v, %v; want nil, nil", fd, err)
	}
	if _, err := p2.Pin(filepath.Join(dir, "nosock"), false); err == nil ||
		!errors.Is(err, syscall.ENOENT) {
		t.Errorf("missing -b/-r source must be fatal: %v", err)
	}

	// disabled (old bwrap): every pin is a no-op — path-based mounts
	p3 := NewPinner(false)
	defer p3.Close()
	if fd, err := p3.Pin(clean, false); err != nil || fd != nil {
		t.Errorf("disabled pin = %v, %v; want nil, nil", fd, err)
	}
}
