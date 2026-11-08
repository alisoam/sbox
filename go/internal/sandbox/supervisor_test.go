package sandbox

// Supervisor tests: full-run e2e against a fake Provider whose backend
// binary is a recording shell shim (no bwrap needed), the signal
// lifecycle (early → forward → escalate), the seccomp and
// userns-hardening gates, WaitForSocket and RmTreeWritable.

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"sbox/internal/cliutil"
	"sbox/internal/outputfilter"
	"sbox/internal/seccomp"
)

func TestFilteredProxyLogConcurrentClose(t *testing.T) {
	var output strings.Builder
	log := &filteredProxyLog{
		sanitizer: outputfilter.NewSanitizer(false),
		emit:      func(s string) { output.WriteString(s) },
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				log.write("allowed\x1b]52;c:clipboard\x07")
			}
		}()
	}
	log.write("first\x1b]52;c:clipboard\x07")
	close(start)
	log.close()
	wg.Wait()
	before := output.String()
	log.write("late")
	log.close()
	if got := output.String(); got != before {
		t.Fatal("closed proxy log emitted more output")
	}
	if !strings.HasPrefix(before, "sbox-proxy: first\n") || strings.ContainsAny(before, "\x1b\x07") {
		t.Fatalf("unsafe or missing proxy log: %q", before)
	}
}

func TestFilteredProxyLogCloseWithBlockedSink(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var output strings.Builder
	log := &filteredProxyLog{
		sanitizer: outputfilter.NewSanitizer(false),
		emit: func(s string) {
			close(entered)
			<-release
			output.WriteString(s)
		},
	}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		log.write("first")
	}()
	<-entered // The sink is blocked, with a write definitely in progress.
	closed := make(chan struct{})
	go func() {
		log.close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		close(release)
		<-writerDone
		<-closed
		t.Fatal("closing the proxy log waited for its blocked sink")
	}
	lateDone := make(chan struct{})
	go func() {
		defer close(lateDone)
		log.write("late")
	}()
	close(release)
	<-writerDone
	<-lateDone
	if got := output.String(); got != "sbox-proxy: first\n" {
		t.Fatalf("closed proxy log emitted a late record: %q", got)
	}
}

// fakeProvider stands in for the bwrap backend: preset caps, a possibly
// recording userns probe, and Build returning a Launch for a shim
// binary.
type fakeProvider struct {
	caps     Caps
	bin      string
	userns   int
	usernsOK bool
	specs    []*Spec
	build    func(*Spec) (*Launch, error)
}

func (f *fakeProvider) Name() string          { return "fake" }
func (f *fakeProvider) Probe() (Caps, error)  { return f.caps, nil }
func (f *fakeProvider) UsernsProbe(bool) bool { f.userns++; return f.usernsOK }
func (f *fakeProvider) Build(spec *Spec) (*Launch, error) {
	f.specs = append(f.specs, spec)
	if f.build != nil {
		return f.build(spec)
	}
	return &Launch{Bin: f.bin}, nil
}

// writeShim writes an executable /bin/sh script.
func writeShim(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// newTestSupervisor builds a Supervisor around a fake Provider whose
// backend shim exits 42 (unit tests that watch the spec/notes/exit
// code, not the rendered argv). $WORK goes to <root>/tmp. The root is
// SHORT on purpose: $WORK holds a Unix socket, and sun_path caps paths
// at ~108 bytes (t.TempDir()'s long names overflow).
func newTestSupervisor(t *testing.T) (*Supervisor, *fakeProvider, string) {
	t.Helper()
	t.Setenv("USER", "tester")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("SSH_AUTH_SOCK", "")
	root, err := os.MkdirTemp("", "sboxsup.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	home := filepath.Join(root, "home")
	cwd := filepath.Join(root, "proj")
	workroot := filepath.Join(root, "tmp")
	for _, d := range []string{home, cwd, workroot} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rec := filepath.Join(root, "argv")
	fp := &fakeProvider{bin: shimRecording(t, root, "fake-backend", rec)}
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(sigs) })
	sup := &Supervisor{
		Opts:     &cliutil.Options{NoSeccomp: true}, // the seccomp gate has its own tests
		Command:  []string{"echo", "hi"},
		Provider: fp,
		Warn:     func(string) {},
		SigCh:    sigs,
		Home:     home,
		TempRoot: workroot,
		Getwd:    func() (string, error) { return cwd, nil },
	}
	return sup, fp, root
}

// shimRecording writes a shim that records its argv to rec and exits 42.
func shimRecording(t *testing.T, dir, name, rec string) string {
	t.Helper()
	return writeShim(t, filepath.Join(dir, name),
		fmt.Sprintf("printf '%%s\\n' \"$@\" > %s\nexit 42", rec))
}

// pollFile waits for the shim's argv record to appear (the child is up).
func pollFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("shim never wrote %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// argvContains checks for a run of CONSECUTIVE argv tokens in the shim's
// one-token-per-line record (multi-line tokens like the bridge script
// are matched with plain Contains instead).
func argvContains(rec string, want ...string) bool {
	return strings.Contains("\n"+rec+"\n", "\n"+strings.Join(want, "\n")+"\n")
}

func requireEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%s not cleaned: %v", dir, entries)
	}
}

func TestSupervisorSpawnFailureCleansWork(t *testing.T) {
	sup, _, root := newTestSupervisor(t)
	sup.Provider.(*fakeProvider).bin = filepath.Join(root, "no-such-backend")
	var notes []string
	sup.Warn = func(w string) { notes = append(notes, w) }

	if rc := sup.Run(); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	found := false
	for _, n := range notes {
		if strings.Contains(n, "cannot start the sandbox") {
			found = true
		}
	}
	if !found {
		t.Errorf("no spawn-failure note: %v", notes)
	}
	requireEmptyDir(t, filepath.Join(root, "tmp"))
}

func TestSupervisorSeccompGate(t *testing.T) {
	if seccomp.Syscalls[seccomp.Machine("")] == nil {
		t.Skip("no seccomp syscall table for this architecture")
	}
	dir := t.TempDir()
	okProbe := writeShim(t, filepath.Join(dir, "probe-ok"), "exit 0")

	t.Run("hands the filter to the provider", func(t *testing.T) {
		sup, fp, _ := newTestSupervisor(t)
		fp.caps = Caps{AddSeccompFD: true}
		sup.Opts.NoSeccomp = false
		sup.Opts.Verbose = true
		sup.Exe = okProbe
		var notes []string
		sup.Warn = func(w string) { notes = append(notes, w) }

		if rc := sup.Run(); rc != 42 {
			t.Fatalf("rc = %d", rc)
		}
		bpf, err := seccomp.BuildBPF("")
		if err != nil {
			t.Fatal(err)
		}
		if string(fp.specs[0].Seccomp) != string(bpf) {
			t.Errorf("spec.Seccomp does not carry the compiled filter")
		}
		found := false
		for _, n := range notes {
			if strings.HasPrefix(n, "seccomp: deny-list handed to bwrap via --add-seccomp-fd (") &&
				strings.HasSuffix(n, "filter instructions)") {
				found = true
			}
		}
		if !found {
			t.Errorf("no verbose seccomp note: %v", notes)
		}
	})

	t.Run("bwrap without seccomp support fails closed", func(t *testing.T) {
		sup, fp, _ := newTestSupervisor(t)
		fp.caps = Caps{BindFD: true} // no seccomp option at all
		sup.Opts.NoSeccomp = false
		sup.Exe = okProbe
		var notes []string
		sup.Warn = func(w string) { notes = append(notes, w) }

		if rc := sup.Run(); rc != 1 {
			t.Fatalf("rc = %d, want 1", rc)
		}
		if len(notes) != 1 || !strings.Contains(notes[0], "supports neither --add-seccomp-fd nor --seccomp") {
			t.Errorf("fail-closed note = %v", notes)
		}
		if len(fp.specs) != 0 {
			t.Errorf("the provider must never see a spec: %d", len(fp.specs))
		}
	})

	t.Run("failing self-probe refuses to run", func(t *testing.T) {
		badProbe := writeShim(t, filepath.Join(dir, "probe-bad"), "exit 3") // unshare not denied
		sup, fp, _ := newTestSupervisor(t)
		fp.caps = Caps{LegacySeccomp: true}
		sup.Opts.NoSeccomp = false
		sup.Exe = badProbe
		var notes []string
		sup.Warn = func(w string) { notes = append(notes, w) }

		if rc := sup.Run(); rc != 1 {
			t.Fatalf("rc = %d, want 1", rc)
		}
		if len(notes) != 1 || !strings.Contains(notes[0], "self-probe failed") ||
			!strings.Contains(notes[0], "unshare(0)") {
			t.Errorf("probe-failure note = %v", notes)
		}
	})
}

func TestSupervisorUsernsHardening(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir()) // keep the note stamp out of ~/.cache

	t.Run("probe ok hardens and notes verbosely", func(t *testing.T) {
		sup, fp, _ := newTestSupervisor(t)
		fp.caps = Caps{DisableUserns: true}
		fp.usernsOK = true
		sup.Opts.Verbose = true
		var notes []string
		sup.Warn = func(w string) { notes = append(notes, w) }

		if rc := sup.Run(); rc != 42 {
			t.Fatalf("rc = %d, notes = %v", rc, notes)
		}
		if fp.userns != 1 {
			t.Errorf("userns probe runs = %d, want 1", fp.userns)
		}
		if !fp.specs[0].DisableUserns {
			t.Error("spec.DisableUserns not set")
		}
		found := false
		for _, n := range notes {
			if strings.HasPrefix(n, "userns: nested user namespaces disabled") {
				found = true
			}
		}
		if !found {
			t.Errorf("no verbose userns note: %v", notes)
		}
	})

	t.Run("probe fail falls back with a once-a-day note", func(t *testing.T) {
		sup, fp, _ := newTestSupervisor(t)
		fp.caps = Caps{DisableUserns: true}
		fp.usernsOK = false
		var notes []string
		sup.Warn = func(w string) { notes = append(notes, w) }

		if rc := sup.Run(); rc != 42 {
			t.Fatalf("rc = %d", rc)
		}
		if fp.specs[0].DisableUserns {
			t.Error("hardening must stay off when the probe fails")
		}
		if len(notes) != 1 || !strings.Contains(notes[0], "cannot run --disable-userns") {
			t.Fatalf("fallback note = %v", notes)
		}

		// second run: the stamp suppresses the note
		sup2, fp2, _ := newTestSupervisor(t)
		fp2.caps = Caps{DisableUserns: true}
		fp2.usernsOK = false
		var notes2 []string
		sup2.Warn = func(w string) { notes2 = append(notes2, w) }
		if rc := sup2.Run(); rc != 42 {
			t.Fatalf("rc = %d", rc)
		}
		if len(notes2) != 0 {
			t.Errorf("note must be suppressed within 24h: %v", notes2)
		}
	})
}

func TestSupervisorTOCTOUNote(t *testing.T) {
	sup, _, root := newTestSupervisor(t)
	bind := filepath.Join(root, "bindable")
	if err := os.Mkdir(bind, 0o755); err != nil {
		t.Fatal(err)
	}
	sup.Opts.Bind = []string{bind}
	var notes []string
	sup.Warn = func(w string) { notes = append(notes, w) }

	if rc := sup.Run(); rc != 42 {
		t.Fatalf("rc = %d", rc)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "lacks --bind-fd") {
		t.Errorf("TOCTOU note = %v", notes)
	}
}

// --- signals -----------------------------------------------------------

func TestSupervisorForwardsSingleSignal(t *testing.T) {
	sup, _, root := newTestSupervisor(t)
	rec := filepath.Join(root, "argv")
	// exec: ONE process, like bwrap itself — the forwarded SIGINT kills
	// it directly (a shell keeping a `sleep` child alive would defer).
	sup.Provider.(*fakeProvider).bin = writeShim(t, filepath.Join(root, "sig-backend"),
		fmt.Sprintf("printf '%%s\\n' \"$@\" > %s\nexec sleep 30", rec))

	done := make(chan int, 1)
	go func() { done <- sup.Run() }()
	pollFile(t, rec)
	_ = syscall.Kill(os.Getpid(), syscall.SIGINT)

	select {
	case rc := <-done:
		if rc != 130 { // 128 + SIGINT(2): the shim's default disposition
			t.Fatalf("rc = %d, want 130", rc)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sandbox never exited after the forwarded SIGINT")
	}
	requireEmptyDir(t, filepath.Join(root, "tmp"))
}

func TestSupervisorEscalatesRepeatedSignal(t *testing.T) {
	sup, _, root := newTestSupervisor(t)
	rec := filepath.Join(root, "argv")
	// The backend swallows TERM and INT (trap '' = SIG_IGN, which
	// survives the exec below): only the escalation (SIGKILL) can end it
	// — the belt-and-braces path for bwrap's no-relay window.
	sup.Provider.(*fakeProvider).bin = writeShim(t, filepath.Join(root, "stubborn-backend"),
		fmt.Sprintf("trap '' TERM INT\nprintf '%%s\\n' \"$@\" > %s\nexec sleep 30", rec))

	done := make(chan int, 1)
	go func() { done <- sup.Run() }()
	pollFile(t, rec)
	_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	time.Sleep(100 * time.Millisecond)            // the first forward lands (and is swallowed)
	_ = syscall.Kill(os.Getpid(), syscall.SIGINT) // repeat ⇒ kill

	select {
	case rc := <-done:
		if rc != 137 { // 128 + SIGKILL(9)
			t.Fatalf("rc = %d, want 137", rc)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stubborn backend survived the escalation")
	}
	requireEmptyDir(t, filepath.Join(root, "tmp"))
}

func TestSupervisorEarlySignalKillsNothingAndCleansUp(t *testing.T) {
	sup, _, root := newTestSupervisor(t)
	rec := filepath.Join(root, "argv")
	fp := sup.Provider.(*fakeProvider)

	// Block inside the provider's Build: a wide window in "setup".
	entered := make(chan struct{})
	release := make(chan struct{})
	fp.build = func(spec *Spec) (*Launch, error) {
		close(entered)
		<-release
		return &Launch{Bin: fp.bin}, nil
	}

	done := make(chan int, 1)
	go func() { done <- sup.Run() }()
	<-entered
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	time.Sleep(100 * time.Millisecond) // let the hub record it (early_signal)
	close(release)

	select {
	case rc := <-done:
		if rc != 143 { // 128 + SIGTERM(15)
			t.Fatalf("rc = %d, want 143", rc)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run never returned after the early signal")
	}
	if _, err := os.Stat(rec); err == nil {
		t.Error("the backend must not have been spawned")
	}
	requireEmptyDir(t, filepath.Join(root, "tmp"))
}

// --- wait_for_socket / rm_tree_writable ---------------------------------

func TestWaitForSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	if err := WaitForSocket(sock, 100*time.Millisecond); err == nil ||
		err.Error() != "the proxy did not come up" {
		t.Errorf("missing socket: err = %v", err)
	}

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	start := time.Now()
	if err := WaitForSocket(sock, 5*time.Second); err != nil {
		t.Fatalf("listening socket: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("waited %v for a listening socket", elapsed)
	}
}

func TestRmTreeWritable(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	deep := filepath.Join(work, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(deep, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	roDir := filepath.Join(work, "ro")
	if err := os.Mkdir(roDir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(roDir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(roDir, 0o555); err != nil {
		t.Fatal(err)
	}

	// A symlink to a precious HOST file: the sweep must skip it (the
	// O_NOFOLLOW pin shows S_ISLNK) and never chmod the target.
	precious := filepath.Join(dir, "precious")
	if err := os.WriteFile(precious, []byte("host ground"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(precious, filepath.Join(work, "escape")); err != nil {
		t.Fatal(err)
	}
	// A socket: skipped by the chmod sweep, removed by the sweep-up.
	sockLn, err := net.Listen("unix", filepath.Join(work, "s.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer sockLn.Close()

	RmTreeWritable(work)

	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Errorf("work dir survived: %v", err)
	}
	st, err := os.Stat(precious)
	if err != nil {
		t.Fatalf("the symlink target was removed: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("the symlink target was chmod'd through the link: %o", st.Mode().Perm())
	}
}

func TestWaitExitCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func() error
		want int
	}{
		{"exit 0", func() error { return nil }, 0},
		{"exit 42", func() error {
			return runShimErr(t.TempDir(), "exit 42")
		}, 42},
		{"killed by TERM", func() error {
			return runShimErr(t.TempDir(), "kill -TERM $$")
		}, 143},
		{"other error", func() error { return io.ErrUnexpectedEOF }, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := waitExitCode(tc.run()); got != tc.want {
				t.Errorf("waitExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

func runShimErr(dir, body string) error {
	p := filepath.Join(dir, "shim")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		return err
	}
	return exec.Command(p).Run()
}

// TestSupervisorFilterOutput drives the whole --filter-output path
// against the fake provider: the shim's stdout IS the pty slave (the
// argv record still lands in a file), everything it prints passes the
// sanitizer before it reaches sup.Out, the exit code propagates, and
// $WORK is cleaned. Stdin here is not a tty, so the sandbox inherits
// the exact fd (FilterChildStdin's non-tty arm) and nothing is
// forwarded.
func TestSupervisorFilterOutput(t *testing.T) {
	sup, fp, root := newTestSupervisor(t)
	sup.Opts.FilterOutput = true
	// The shim prints an OSC 52 clipboard attack, a query, safe SGR
	// and plain text to ITS stdout (the pty slave), then exits 7.
	rec := filepath.Join(root, "argv")
	fp.bin = writeShim(t, filepath.Join(root, "printer"), fmt.Sprintf(
		`printf '%%s' "$@" > %s
 printf 'ok\033]52;c:aGk=\a\033[?25l\033[32mgreen\033[0m\n'
 exit 7`, rec))

	var out strings.Builder
	sup.Out = &out
	var notes []string
	sup.Warn = func(w string) { notes = append(notes, w) }

	rc := sup.Run()
	if rc != 7 {
		t.Fatalf("rc = %d, want 7", rc)
	}
	// ONLCR: the pty delivers the trailing \n as \r\n
	want := "ok\x1b[32mgreen\x1b[0m\r\n"
	if got := out.String(); got != want {
		t.Errorf("filtered output = %q, want %q", got, want)
	}
	for _, n := range notes {
		if strings.Contains(n, "filter") || strings.Contains(n, "pty") {
			t.Errorf("unexpected --filter-output note: %q", n)
		}
	}
	requireEmptyDir(t, sup.TempRoot)
}

// TestSupervisorFilterOutputStrictCrlf runs --strict-crlf (a
// --filter-output mode): a bare \r from the payload is dropped.
func TestSupervisorFilterOutputStrictCrlf(t *testing.T) {
	sup, fp, root := newTestSupervisor(t)
	sup.Opts.FilterOutput = true
	sup.Opts.StrictCrlf = true
	rec := filepath.Join(root, "argv")
	fp.bin = writeShim(t, filepath.Join(root, "printer"), fmt.Sprintf(
		`printf '%%s' "$@" > %s
 printf 'a\rb\r\nok'
 exit 0`, rec))
	var out strings.Builder
	sup.Out = &out
	sup.Warn = func(string) {}

	if rc := sup.Run(); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if got, want := out.String(), "ab\r\nok"; got != want {
		t.Errorf("strict filtered output = %q, want %q", got, want)
	}
	requireEmptyDir(t, sup.TempRoot)
}

// TestSupervisorFilterOutputDrainTail checks the post-exit drain: the
// shim forks a grandchild that holds the slave open and prints AFTER
// the shim exits — the bounded drain must still deliver its output
// (sanitized) and flush the truncated tail.
func TestSupervisorFilterOutputDrainTail(t *testing.T) {
	sup, fp, root := newTestSupervisor(t)
	sup.Opts.FilterOutput = true
	rec := filepath.Join(root, "argv")
	fp.bin = writeShim(t, filepath.Join(root, "printer"), fmt.Sprintf(
		`printf '%%s' "$@" > %s
 ( sleep 0.15; printf 'late\033]52;c:x\a\377' ) >/dev/stdout &
 exit 3`, rec))
	var out strings.Builder
	sup.Out = &out
	sup.Warn = func(string) {}

	if rc := sup.Run(); rc != 3 {
		t.Fatalf("rc = %d, want 3", rc)
	}
	// "late" arrives during the drain window; the trailing 0xff byte
	// is an incomplete UTF-8 sequence flushed to U+FFFD (the deadline
	// path — the grandchild still holds the slave at that moment).
	if got, want := out.String(), "late\ufffd"; got != want {
		t.Errorf("drained output = %q, want %q", got, want)
	}
	requireEmptyDir(t, sup.TempRoot)
}
