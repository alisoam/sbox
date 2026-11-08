package outputfilter

// pty.go tests: the pair, winsize forwarding, raw mode enter/restore
// (on a real pty swapped in as stdin), the child-stdin decision table
// and its fail-closed refusals, the early stdin check, and the
// CR-safe diagnostic emitter. Skips when /dev/ptmx is unavailable.

import (
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func requirePty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, s, err := OpenPty()
	if err != nil {
		t.Skipf("no ptmx available: %v", err)
	}
	t.Cleanup(func() { m.Close(); s.Close() })
	return m, s
}

func TestOpenPtyPair(t *testing.T) {
	master, slave := requirePty(t)
	// slave→master is the child-output direction
	if _, err := slave.Write([]byte("hi")); err != nil {
		t.Fatalf("slave write: %v", err)
	}
	if err := master.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("master not poller-registered: %v", err)
	}
	buf := make([]byte, 8)
	n, err := master.Read(buf)
	if err != nil || string(buf[:n]) != "hi" {
		t.Fatalf("master read = %q, %v", buf[:n], err)
	}
	// the slave is a tty; the master is one too
	if !isTTY(slave.Fd()) || !isTTY(master.Fd()) {
		t.Errorf("pty ends are not ttys")
	}
}

func TestCopyWinsize(t *testing.T) {
	src, _ := requirePty(t)
	dst, _ := requirePty(t)
	set := func(f *os.File, rows, cols uint16) {
		t.Helper()
		ws := winSize{Rows: rows, Cols: cols, Xpixel: cols * 8, Ypixel: rows * 16}
		if err := ioctlPtr(f.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&ws)); err != nil {
			t.Fatalf("TIOCSWINSZ: %v", err)
		}
	}
	get := func(f *os.File) winSize {
		t.Helper()
		var ws winSize
		if err := ioctlPtr(f.Fd(), syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
			t.Fatalf("TIOCGWINSZ: %v", err)
		}
		return ws
	}
	set(src, 37, 111)
	CopyWinsize(src, dst)
	if got := get(dst); got != (winSize{Rows: 37, Cols: 111, Xpixel: 888, Ypixel: 592}) {
		t.Errorf("copied winsize = %+v", got)
	}
	// nil ends and dead fds are dropped, never fatal
	CopyWinsize(nil, dst)
	CopyWinsize(src, nil)
	CopyWinsize(src, mustTempFile(t))
}

func unsafePtr(ws *winSize) any { return ws }

func mustTempFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "dead")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestHostTTYWithoutTty(t *testing.T) {
	// The test environment's stdio is not a tty (a pty-swapping test
	// would race this one — same package, but keep it explicit).
	if isTTY(os.Stdin.Fd()) || isTTY(os.Stdout.Fd()) {
		t.Skip("stdio is a tty here; the non-tty arm needs a pipe")
	}
	if f := HostTTY(); f != nil {
		t.Errorf("HostTTY() = %v, want nil", f)
	}
}

// swapStdin swaps the process stdin for f for the duration of one
// test (tests in a package run sequentially). Returns the old stdin.
func swapStdin(t *testing.T, f *os.File) {
	t.Helper()
	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = old })
}

func TestEnterRawModeAndRestore(t *testing.T) {
	master, slave := requirePty(t)
	_ = master // keeping it open keeps the pty healthy
	swapStdin(t, slave)
	if HostTTY() != os.Stdin {
		t.Errorf("HostTTY() must pick the tty stdin")
	}

	fd, saved := EnterRawMode()
	if fd == nil || saved == nil {
		t.Fatal("EnterRawMode refused a healthy pty stdin")
	}
	defer SetRawTerm(false)
	var now syscall.Termios
	if err := tcgetattr(slave.Fd(), &now); err != nil {
		t.Fatal(err)
	}
	if now.Oflag&syscall.OPOST != 0 {
		t.Errorf("OPOST still on")
	}
	if now.Lflag&syscall.ECHO != 0 || now.Lflag&syscall.ICANON != 0 || now.Lflag&syscall.ISIG != 0 {
		t.Errorf("ECHO/ICANON/ISIG still on")
	}
	if now.Iflag&syscall.ICRNL != 0 || now.Iflag&syscall.IXON != 0 {
		t.Errorf("ICRNL/IXON still on")
	}
	if now.Cc[syscall.VMIN] != 1 || now.Cc[syscall.VTIME] != 0 {
		t.Errorf("VMIN/VTIME = %d/%d, want 1/0", now.Cc[syscall.VMIN], now.Cc[syscall.VTIME])
	}
	if !RawTerm() {
		t.Errorf("raw diagnostic flag not set")
	}

	RestoreTermios(fd, saved)
	SetRawTerm(false)
	if err := tcgetattr(slave.Fd(), &now); err != nil {
		t.Fatal(err)
	}
	if now != *saved {
		t.Errorf("termios not restored")
	}
	if RawTerm() {
		t.Errorf("raw diagnostic flag not cleared")
	}
}

func TestEnterRawModeNonTty(t *testing.T) {
	f := mustTempFile(t)
	swapStdin(t, f)
	if fd, saved := EnterRawMode(); fd != nil || saved != nil {
		t.Errorf("EnterRawMode on a regular file = (%v, %v), want nils", fd, saved)
	}
	if RawTerm() {
		t.Setenv("SBOX_TEST_RAW_LEAK", "1") // mark, then clear: never leave it set
		SetRawTerm(false)
		t.Fatal("raw flag set by a failed raw-mode entry")
	}
}

func TestFilterChildStdinDecisions(t *testing.T) {
	master, slave := requirePty(t)
	_ = master
	// A raw-mode stdin exists ⇒ the slave.
	fakeRaw := slave
	got, err := FilterChildStdin(slave, fakeRaw)
	if err != nil || got != slave {
		t.Errorf("tty case = (%v, %v), want the slave", got, err)
	}

	// Non-tty stdin ⇒ the EXACT fd, byte-identical inherit.
	reg := mustTempFile(t)
	swapStdin(t, reg)
	got, err = FilterChildStdin(slave, nil)
	if err != nil || got != os.Stdin {
		t.Errorf("non-tty case = (%v, %v), want os.Stdin itself", got, err)
	}

	// A stdin that IS a tty but raw mode failed ⇒ LOUD refusal.
	swapStdin(t, slave)
	_, err = FilterChildStdin(slave, nil)
	if err == nil {
		t.Fatalf("unrawable tty accepted")
	}
	want := "--filter-output: stdin is a terminal but raw mode failed"
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("refusal = %q, want prefix %q", err, want)
	}
}

func TestCheckStdinEarly(t *testing.T) {
	// non-tty: fine
	f := mustTempFile(t)
	swapStdin(t, f)
	if err := CheckStdinEarly(); err != nil {
		t.Errorf("non-tty stdin refused: %v", err)
	}
	// healthy tty: fine
	_, slave := requirePty(t)
	swapStdin(t, slave)
	if err := CheckStdinEarly(); err != nil {
		t.Errorf("healthy tty refused: %v", err)
	}
	// A hung-up tty: isatty itself fails (glibc isatty and tcgetattr
	// are the same TCGETS ioctl), so the early check passes benignly —
	// exactly python's observable behavior. The "is a terminal but
	// cannot be configured" branch is a defensive race guard (a tty
	// hanging up BETWEEN the two ioctls) that is unreachable
	// deterministically in either implementation; the port keeps it.
	m2, s2, err := OpenPty()
	if err != nil {
		t.Skipf("no ptmx: %v", err)
	}
	defer s2.Close()
	m2.Close() // hangs the slave up: reads and ioctls turn EIO
	if isTTY(s2.Fd()) {
		t.Fatalf("hung-up slave still reports isatty")
	}
	swapStdin(t, s2)
	if err := CheckStdinEarly(); err != nil {
		t.Errorf("hung-up (no-longer-)tty refused: %v", err)
	}
}

func TestEmitDiagRawCrSafety(t *testing.T) {
	SetRawTerm(false)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = old; w.Close(); r.Close() })

	var wg sync.WaitGroup
	wg.Add(1)
	var got string
	go func() {
		defer wg.Done()
		b, _ := io.ReadAll(r)
		got = string(b)
	}()
	EmitDiag("line one\nline two\n")
	SetRawTerm(true)
	EmitDiag("raw line\n")
	SetRawTerm(false)
	w.Close()
	os.Stderr = old
	wg.Wait()
	if want := "line one\nline two\nraw line\r\n"; got != want {
		t.Errorf("EmitDiag = %q, want %q", got, want)
	}
}

func TestEmitFilteredBestEffort(t *testing.T) {
	// a closed output must not panic; stdout is swapped for a pipe we
	// close first
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = old })
	w.Close()
	_ = r.Close()
	EmitFiltered("still supervising\n") // must not panic
}
