package sandbox

// The launch supervisor — sbox.py's run_sandbox. One Run() call owns:
// the 0700 $WORK (mkdtemp under /tmp; its tmp/ dir becomes the
// sandbox's /tmp), the in-process proxy goroutine plus the readiness
// wait and the fail-closed self-test, the seccomp gate (compile the
// table, fail closed when bwrap cannot install it, self-probe on THIS
// machine, hand the bytes to the provider), the per-launch
// userns-hardening probe with its once-a-day fallback note, fd-first
// bind validation, the backend spawn, the signal lifecycle, exit-code
// propagation and RmTreeWritable teardown. Every early exit unwinds
// through the same teardown (python's try/finally): $WORK never
// survives the launcher.
//
// Two deliberate deltas vs sbox.py (both documented in PLAN.md):
//
//   - the proxy is a goroutine in this process, not a --_proxy re-exec
//     child: no proxy.json ever exists (credentials stay in memory),
//     and any launcher death — SIGKILL included — takes the proxy with
//     it, so the PR_SET_PDEATHSIG/ppid machinery is redundant.
//   - the seccomp self-probe re-executes this binary (--_selfprobe)
//     instead of forking; the supervisor runs it through
//     seccomp.SelfProbe before anything spawns.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"sbox/internal/allow"
	"sbox/internal/bindpolicy"
	"sbox/internal/cliutil"
	"sbox/internal/notes"
	"sbox/internal/outputfilter"
	"sbox/internal/proxy"
	"sbox/internal/seccomp"
)

// usernsFallbackNote is the once-a-day key for the --disable-userns
// fallback note (on hosts without user namespaces it would print on
// EVERY launch and get lost in the noise).
const usernsFallbackNote = "userns-fallback.note"

// Supervisor wires one full launch together. Construct it in cmd/sbox
// (or tests) and call Run; the returned int is the process exit code.
type Supervisor struct {
	// Opts is the parsed CLI. The supervisor reads Net, NoSeccomp,
	// Verbose, FilterOutput, StrictCrlf, SSHAgent, Home, RoCwd and the
	// bind flags (the latter two through bindpolicy/BuildSpec).
	Opts *cliutil.Options
	// Command is the sandboxed argv (everything after "--", or the
	// resolved --shell).
	Command []string
	// Allows is the parsed allowlist (empty ⇒ deny-everything, which
	// still works — the self-test then proves the denials).
	Allows []allow.Entry
	// Upstream is the parsed --upstream (nil ⇒ direct egress).
	Upstream *proxy.Upstream
	// NoProxy overrides the $no_proxy derivation; nil ⇒
	// allow.NoProxyFromEnv (lowercase wins, curl semantics).
	NoProxy *allow.NoProxy
	// Provider is the sandbox backend, its caps probed ONCE in main
	// (Probe here returns that cached result — a $PATH test shim must
	// never be asked twice).
	Provider Provider
	// Exe is this binary (os.Executable()): the --_selfprobe re-exec
	// target for the seccomp gate.
	Exe string
	// Warn receives every diagnostic python prints via err() — notes,
	// warnings and die() messages alike (the caller adds the "sbox: "
	// prefix). nil drops them.
	Warn func(string)
	// SigCh is the signal channel main armed before anything slow
	// (SIGINT/SIGTERM/SIGHUP). The supervisor owns the handlers from
	// Run() on: early exit during startup, forwarding once the sandbox
	// is up, ignore during teardown.
	SigCh <-chan os.Signal
	// Home is the $HOME the launcher resolved (main verified it is set).
	Home string

	// Out receives --filter-output's sanitized sandbox output; nil ⇒
	// the host terminal (outputfilter.EmitFiltered → stdout).
	Out io.Writer

	// Test knobs (production: zero values).
	TempRoot  string                 // "" ⇒ /tmp, $WORK's parent
	Getwd     func() (string, error) // "" ⇒ os.Getwd
	ProxyLogf func(string)           // proxy verbose log sink; nil ⇒ stderr
}

// Run launches the sandbox and blocks until the payload exits; the
// return value is the exit code to propagate (128+signal for a killed
// sandbox, 128+signum for an early signal, 1 for every startup
// failure). The teardown (deferred) always runs.
func (s *Supervisor) Run() int {
	warn := s.Warn
	if warn == nil {
		warn = func(string) {}
	}
	if s.Provider == nil {
		warn("internal: no sandbox provider configured")
		return 1
	}
	if s.Opts == nil {
		s.Opts = &cliutil.Options{}
	}
	// Fail fast, before anything spawns: an unrawable terminal stdin
	// under --filter-output is a hard error (the cheap tcgetattr half
	// of the check depends on nothing below — the pty, the proxy and
	// the self-test all come later).
	if s.Opts.FilterOutput {
		if err := outputfilter.CheckStdinEarly(); err != nil {
			warn(err.Error())
			return 1
		}
	}
	if len(s.Command) == 0 {
		warn("internal: no command to run")
		return 1
	}

	// During startup there is nothing to forward signals to yet; die so
	// the teardown below removes $WORK. Replaced by the forwarding
	// handler once the sandbox is up. Armed before $WORK exists so every
	// startup signal is caught by these handlers (python: early_signal).
	hub := &sigHub{ch: s.SigCh, seen: map[os.Signal]bool{}}
	hub.start()

	var (
		work     string
		proxySrv *proxy.Server
		proxyLog *outputfilter.Sanitizer // --filter-output proxy log
		pump     *outputfilter.Pump      // --filter-output pty pump
		pinner   *bindpolicy.Pinner
		held     []*os.File // parent copies of everything handed to the child
		cmd      *exec.Cmd
		waitCh   chan int
		reaped   bool
	)
	teardown := func() {
		// A second Ctrl-C while cleaning up must not abort the cleanup
		// (a skipped RmTreeWritable would leave the work dir behind).
		// Python flips the three signals to SIG_IGN; here the hub's done
		// phase IS the ignore: the disposition stays "caught" (children
		// spawned later inherit the DEFAULT, not an inherited ignore —
		// Go's Reset does not undo Ignore), and nothing in phase done
		// forwards or raises. Go signal delivery cannot interrupt the
		// synchronous teardown below the way a Python handler raises.
		hub.done()
		// --filter-output teardown FIRST after the ignore phase: the
		// host terminal must be restored before anything below blocks
		// (a raw terminal is unusable meanwhile) — sbox.py's finally
		// restores termios, SIGWINCH and the pty fds before killing
		// anything else. Also the last word of the sanitized proxy
		// log (an unterminated tail stays pending in its sanitizer).
		if pump != nil {
			pump.Close()
		}
		if proxyLog != nil {
			outputfilter.EmitDiag(proxyLog.Flush())
		}
		for _, f := range held {
			f.Close()
		}
		held = nil
		if pinner != nil {
			pinner.Close()
		}
		if cmd != nil && cmd.Process != nil && !reaped {
			// python: terminate(), wait(3), kill() — a sandbox that
			// survived the SIGTERM gets the hard kill.
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-waitCh:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				<-waitCh
			}
		}
		if proxySrv != nil {
			// Bounded: a handler mid-dial must not wedge the teardown
			// (the python proxy child got terminate/wait(3)/kill; the
			// goroutines here die with the process anyway).
			closed := make(chan struct{})
			go func() { proxySrv.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
			}
		}
		if work != "" {
			RmTreeWritable(work)
		}
	}
	defer teardown()

	// earlyExit is the boundary check for signals that arrived during
	// setup (python's early_signal raises wherever it lands; Go checks
	// between the short setup phases — same observable outcome: cleanup
	// plus 128+signum).
	earlyExit := func() (int, bool) {
		if n := hub.earlySignal(); n != 0 {
			return 128 + n, true
		}
		return 0, false
	}

	// bwrap capabilities (probed once in main; deliberately NOT probed
	// here — a test shim on $PATH must not be re-probed mid-launch).
	// Missing means unknown: only the conservative path-based forms are
	// used, and seccomp (which cannot degrade) fails closed below.
	caps, _ := s.Provider.Probe()

	// mkdtemp inside the guarded region: a signal landing anywhere
	// between MkdirTemp and the spawn below must still unwind through
	// the teardown instead of leaking $WORK on the host.
	root := s.TempRoot
	if root == "" {
		root = "/tmp"
	}
	var err error
	work, err = os.MkdirTemp(root, "sbox.")
	if err != nil {
		warn(fmt.Sprintf("cannot create the work directory in %s: %v", root, err))
		return 1
	}
	sand := filepath.Join(work, "tmp")
	sock := filepath.Join(work, "net.sock")
	sshCfg := filepath.Join(work, "ssh_config")
	if err := os.Mkdir(sand, 0o755); err != nil {
		warn(fmt.Sprintf("cannot create %s: %v", sand, err))
		return 1
	}
	// Explicit, like mkdtemp+chmod in python: umask must never loosen it
	// (this dir holds the proxy socket and the ssh_config).
	if err := os.Chmod(work, 0o700); err != nil {
		warn(fmt.Sprintf("cannot chmod %s: %v", work, err))
		return 1
	}
	if rc, dead := earlyExit(); dead {
		return rc
	}

	// TOCTOU-free binds, fd-FIRST: CheckBindPaths pins every source
	// another sandbox could race (user binds; the cwd mount and $HOME
	// follow inside BuildSpec) and validates the pinned object; bwrap
	// >= 0.10 then mounts exactly those fds. Old bwrap keeps the
	// path-based flags and checks instead — loud, not silent.
	pinner = bindpolicy.NewPinner(caps.BindFD)
	userBinds, err := bindpolicy.CheckBindPaths(s.Opts, s.Home, pinner, warn)
	if err != nil {
		warn(err.Error())
		return 1
	}
	if rc, dead := earlyExit(); dead {
		return rc
	}

	agent := ""
	if s.Opts.SSHAgent {
		agent, err = AgentSocketPath()
		if err != nil {
			warn(err.Error()) // fails loudly: never silently forward nothing
			return 1
		}
	}
	if len(userBinds) > 0 && !caps.BindFD {
		warn("note: this bwrap lacks --bind-fd — binds re-resolve their source path " +
			"at mount time (TOCTOU window if another sandbox can write a parent " +
			"dir); bwrap >= 0.10 mounts by pinned fd")
	}

	var bpf []byte
	hardenUserns := false
	if !s.Opts.NoSeccomp {
		// Fail-closed (seccomp_fd_args): the filter is not optional, and
		// a bwrap that cannot install it must not silently run the
		// payload unfiltered. --no-seccomp is the explicit opt-out and
		// never reaches here.
		bpf, err = seccomp.BuildBPF("")
		if err != nil {
			warn(fmt.Sprintf("no seccomp syscall table for this machine (%s) — refusing "+
				"to run without the filter (pass --no-seccomp to override)", seccomp.Machine("")))
			return 1
		}
		flag := caps.SeccompFlag()
		if flag == "" {
			warn("this bwrap supports neither --add-seccomp-fd nor --seccomp — cannot " +
				"install the seccomp deny-list (upgrade bwrap >= 0.4.1, or pass --no-seccomp)")
			return 1
		}
		// Fail-closed ON THIS MACHINE, not just in the test suite: the
		// compiled filter must really deny unshare(0) & co before it is
		// handed to bwrap (a wrong table entry fails silently otherwise).
		if err := seccomp.SelfProbe(s.Exe, []string{"--_selfprobe"}, bpf); err != nil {
			warn(err.Error())
			return 1
		}
		if s.Opts.Verbose {
			warn(fmt.Sprintf("seccomp: deny-list handed to bwrap via %s (%d filter instructions)",
				flag, len(bpf)/8))
		}
	}
	if rc, dead := earlyExit(); dead {
		return rc
	}

	if caps.DisableUserns {
		// Kernel-level: bwrap sets max_user_namespaces=1 in a nested
		// user namespace, consumes the one slot itself, and (with
		// --assert-userns-disabled) refuses to run unless nesting is
		// really dead — belt and braces under the unshare/setns deny
		// rules, immune to hand-typed-number mistakes. The probe runs
		// once per launch with the same ns/pid/session flags as the
		// real argv: hosts where the combination cannot work at all
		// (setuid bwrap, unprivileged_userns_clone=0,
		// max_user_namespaces=0) keep working on the deny rules alone —
		// with a note shown at most once a day.
		if s.Provider.UsernsProbe(s.Opts.Net) {
			hardenUserns = true
			if s.Opts.Verbose {
				warn("userns: nested user namespaces disabled at the kernel level " +
					"(--disable-userns --assert-userns-disabled)")
			}
		} else if !notes.NoteRecentlyShown(usernsFallbackNote) {
			notes.MarkNoteShown(usernsFallbackNote)
			warn("note: this bwrap/kernel cannot run --disable-userns (probed once; " +
				"e.g. setuid bwrap or user namespaces disabled system-wide) — relying " +
				"on the seccomp unshare/setns/clone deny rules only")
		}
	}
	if rc, dead := earlyExit(); dead {
		return rc
	}

	if !s.Opts.Net {
		// The proxy replaces python's --_proxy re-exec child: same
		// socket, same checks, in this process (no proxy.json — the
		// credentials never touch disk, and the known-limit shrinks to
		// nothing: any launcher death takes the proxy with it).
		np := s.NoProxy
		if np == nil {
			np = allow.NoProxyFromEnv(os.Getenv)
		}
		// Under --filter-output the proxy's decision log (the python
		// analog is a PIPE the pump selects on) is emitted sanitized:
		// tracebacks can quote sandbox-supplied bytes, and diagnostics
		// must CR their newlines while the host tty is raw. Same
		// bytes as the default sink ("sbox-proxy: ..."), one
		// Sanitizer in front.
		logf := s.ProxyLogf
		if s.Opts.FilterOutput {
			proxyLog = outputfilter.NewSanitizer(false)
			var pmu sync.Mutex
			logf = func(msg string) {
				pmu.Lock()
				defer pmu.Unlock()
				outputfilter.EmitDiag(proxyLog.Feed([]byte("sbox-proxy: " + msg + "\n")))
			}
		}
		proxySrv, err = proxy.Listen(sock, proxy.Config{
			Allows:   s.Allows,
			Upstream: s.Upstream,
			NoProxy:  np,
			Verbose:  s.Opts.Verbose,
			Logf:     logf,
		})
		if err != nil {
			warn(fmt.Sprintf("cannot start the network proxy: %v", err))
			return 1
		}
		if err := WaitForSocket(sock, 5*time.Second); err != nil {
			warn(err.Error())
			return 1
		}
		// Fail-closed gate on the real socket before the sandbox starts:
		// a non-allowed destination must be refused on both protocols.
		if err := proxy.SelfTest(sock, s.Allows, warn); err != nil {
			warn(err.Error())
			return 1
		}
		// No secrets here (the proxy does the allowlist checks), so this
		// one is world-readable and merely deleted with $WORK at exit.
		if err := os.WriteFile(sshCfg, []byte(SSHClientConfig), 0o644); err != nil {
			warn(fmt.Sprintf("cannot write the sandbox ssh_config: %v", err))
			return 1
		}
	}
	if rc, dead := earlyExit(); dead {
		return rc
	}

	getwd := s.Getwd
	if getwd == nil {
		getwd = os.Getwd
	}
	cwd, err := getwd()
	if err != nil {
		warn(fmt.Sprintf("cannot determine the current directory: %v", err))
		return 1
	}
	spec, err := BuildSpec(s.Opts, cwd, sand, sock, s.Home, userBinds, agent, sshCfg, pinner, warn)
	if err != nil {
		warn(err.Error())
		return 1
	}
	spec.Seccomp = bpf // nil ⇒ --no-seccomp, the explicit opt-out
	spec.DisableUserns = hardenUserns
	if rc, dead := earlyExit(); dead {
		return rc
	}

	launch, err := s.Provider.Build(spec)
	if err != nil {
		warn(err.Error())
		return 1
	}
	if launch.Bin == "" {
		warn("internal: the provider returned no backend binary")
		return 1
	}
	if rc, dead := earlyExit(); dead {
		return rc
	}

	held = append(append(held, launch.PassFDs...), launch.CloseAfterSpawn...)

	// --filter-output setup (fail closed at every step: without a pty
	// there is no host-side filtering, and an untameable host tty is
	// never handed to the sandbox raw). The returned childStdin is the
	// slave for a real (raw-mode) host tty, the exact non-tty stdin
	// fd otherwise — never a blind inherit of fd 0.
	var childStdin *os.File
	if s.Opts.FilterOutput {
		var err error
		pump, childStdin, err = outputfilter.Setup(s.Opts.StrictCrlf)
		if err != nil {
			warn(err.Error())
			return 1
		}
		pump.Out = s.Out
	}

	// argv = backend argv + "--" + /bin/sh -c BRIDGE sbox-sh COMMAND...
	// The backend installs the seccomp filter (when enabled) as the very
	// last step before exec'ing THAT shell, so the shell, the socat
	// bridge AND the command inherit the filter from their first
	// instruction — see PayloadArgv for why the ordering is
	// load-bearing.
	argv := append(append([]string{}, launch.Argv...), "--")
	argv = append(argv, PayloadArgv(spec.Bridge, s.Command)...)
	cmd = exec.Command(launch.Bin, argv...)
	if pump != nil {
		// The sandbox's ONLY terminal is the pty slave: fds 1/2 are it
		// always (ExtraFiles hands over nothing else, so the host's
		// real terminal fd never enters the sandbox; the master stays
		// host-side and feeds the sanitizer), and fd 0 is the slave
		// ONLY for a real host tty. Anything else is the fd
		// FilterChildStdin picked — decided on that very fd, never a
		// blind inherit of fd 0, which could be a tty the pump never
		// agreed to hand over.
		cmd.Stdin = childStdin
		cmd.Stdout = pump.Slave
		cmd.Stderr = pump.Slave
	} else {
		// Plain inherit stdio (0/1/2).
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	// ExtraFiles carries EXACTLY the fds the argv names: Go itself
	// guarantees the CVE-2024-21626 invariant — no stray O_PATH pin
	// crosses the exec boundary into the payload.
	cmd.ExtraFiles = launch.PassFDs
	if err := cmd.Start(); err != nil {
		warn(fmt.Sprintf("cannot start the sandbox: %v", err))
		return 1
	}

	// bwrap has inherited everything it needs; our copies may go (the
	// pinner's first-use pins ARE the PassFDs entries, and the provider's
	// dups for twice-named pins follow — bwrap consumes setup-op fds
	// itself, so the parent copies are pure bookkeeping now).
	for _, f := range held {
		f.Close()
	}
	held = nil
	pinner.Close()

	if pump != nil {
		// The parent's slave copy must go too — else the host holds EOF
		// away from the pump — and the pump starts (sbox.py arms
		// SIGWINCH only once the sandbox exists).
		_ = pump.Slave.Close()
		pump.Start()
	}

	// A signal that raced the spawn is still in early_signal territory
	// (python installs the forward handler only after Popen): teardown
	// kills the just-started sandbox. Otherwise forwarding takes over.
	hub.run(cmd)
	waitCh = make(chan int, 1)
	go func() { waitCh <- waitExitCode(cmd.Wait()) }()
	if rc, dead := earlyExit(); dead {
		return rc
	}

	rc := <-waitCh
	reaped = true
	// --filter-output drain (python: if sanitizer and not master_eof:
	// _drain_master): final output may still be in flight while the
	// payload dies a beat later, but a daemonized child holding the
	// slave open forever bounds the wait to half a second.
	if pump != nil {
		pump.Stop(500 * time.Millisecond)
	}
	hub.done()
	return rc
}

// sigHub is the signal lifecycle. One goroutine drains the armed
// channel; the supervisor flips the phase at the boundaries: setup
// (early_signal — nothing to forward to yet, die so the teardown
// removes $WORK), run (forward to the sandbox, escalate a repeat to a
// kill), done (teardown: ignore).
type sigHub struct {
	ch    <-chan os.Signal
	mu    sync.Mutex
	phase int // phaseSetup / phaseRun / phaseDone
	early int // first signal seen during setup (0 = none); signum
	cmd   *exec.Cmd
	seen  map[os.Signal]bool
}

const (
	phaseSetup = iota
	phaseRun
	phaseDone
)

func (h *sigHub) start() {
	if h.ch == nil {
		return
	}
	go func() {
		for s := range h.ch {
			h.deliver(s)
		}
	}()
}

func (h *sigHub) deliver(s os.Signal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch h.phase {
	case phaseSetup:
		if h.early == 0 {
			h.early = signum(s)
		}
	case phaseRun:
		// Reality check: bwrap does NOT relay signals. SIGINT/SIGTERM to
		// it kill the bwrap parent outright, and --die-with-parent's
		// PDEATHSIG then SIGKILLs the sandbox payload — so Ctrl-C has
		// always been a hard kill and the sandboxed command never sees a
		// catchable signal. The escalation below is only belt and braces
		// for the window where bwrap has not died yet; --die-with-parent
		// covers a SIGKILL of the launcher itself.
		if h.cmd == nil || h.cmd.Process == nil {
			return
		}
		if h.seen[s] {
			_ = h.cmd.Process.Kill()
		} else {
			h.seen[s] = true
			_ = h.cmd.Process.Signal(s)
		}
	}
}

func (h *sigHub) run(cmd *exec.Cmd) {
	h.mu.Lock()
	h.cmd = cmd
	h.phase = phaseRun
	h.mu.Unlock()
}

func (h *sigHub) done() {
	h.mu.Lock()
	h.phase = phaseDone
	h.cmd = nil
	h.mu.Unlock()
}

func (h *sigHub) earlySignal() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.early
}

func signum(s os.Signal) int {
	if ss, ok := s.(syscall.Signal); ok {
		return int(ss)
	}
	return 0
}

// waitExitCode turns cmd.Wait()'s error into the shell-style exit code
// python's run_sandbox propagates: 0, the payload's own code, or
// 128+signal for a killed sandbox (anything else ⇒ 1).
func waitExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		if c := ee.ExitCode(); c >= 0 {
			return c
		}
	}
	return 1
}

// WaitForSocket waits until the proxy is actually accepting connections
// (wait_for_socket). The socket file appears at bind() time, before
// listen(), so existence alone is not enough — poll with a real
// connect() to avoid an ECONNREFUSED race. In-process the listener is
// listening the moment proxy.Listen returns; this is belt-and-braces
// parity with the Python child-process proxy (and a guard for any
// future out-of-process backend).
func WaitForSocket(sockPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			break
		}
		if conn, err := net.DialTimeout("unix", sockPath, remain); err == nil {
			conn.Close()
			return nil
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("the proxy did not come up")
}

// oPath is O_PATH (bindpolicy spells the same constant): open the path
// as a handle to the dentry itself — no read permission needed, which a
// 0000 directory would deny even to its owner.
const oPath = 0x200000

// RmTreeWritable makes $WORK removable again no matter what modes the
// sandbox left behind (rm_tree_writable). The sandbox may have created
// 0555 (or 0000/0300) directories; chmod goes through an
// O_PATH|O_NOFOLLOW fd, never through the path: /tmp inside the sandbox
// is attacker-controlled, and a symlink like x -> ~/.ssh/config swapped
// in between the stat and a path-based chmod would chmod the HOST
// target. O_PATH (not O_RDONLY: opening a directory O_RDONLY needs read
// permission, which the owner lacks on a 0000 dir — the open used to
// fail EACCES, the entry was skipped, and rmtree then failed
// underneath, LEAKING the whole $WORK). The chmod itself goes through
// the /proc/self/fd/N magic link: O_NOFOLLOW pinned the link ITSELF, so
// a planted symlink shows up as S_ISLNK and is skipped (the removal
// unlinks it unfollowed) — the magic link only ever resolves to the
// pinned object. Sockets, FIFOs and vanished entries are skipped too
// (nothing to chmod).
func RmTreeWritable(path string) {
	// WalkDir visits a directory before reading it, so each entry is
	// chmod'd (+0700) via its pinned fd exactly when its parent listed
	// it — a 0000 dir is openable by the time we descend into it, like
	// python's top-down os.walk chmod loop.
	_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == path {
			// Unreadable/vanished entries are skipped; the root itself is
			// 0700 by construction and never chmod'd (python's os.walk
			// chmods only the listed CHILDREN).
			return nil
		}
		fd, err := syscall.Open(p, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil // a symlink (ELOOP) or a raced entry: skipped
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err == nil {
			switch st.Mode & syscall.S_IFMT {
			case syscall.S_IFDIR, syscall.S_IFREG:
				// os.Chmod drops the type bits like chmod(2); the magic
				// link resolves to the pinned object only.
				_ = os.Chmod(fmt.Sprintf("/proc/self/fd/%d", fd), os.FileMode(st.Mode|0o700))
			}
		}
		_ = syscall.Close(fd)
		return nil // no single entry may abort the sweep
	})
	_ = os.RemoveAll(path) // rmtree(ignore_errors=True)
}
