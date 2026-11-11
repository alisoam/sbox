package sandbox

// Each Run owns a private work directory, the in-process proxy and its
// denial self-test, seccomp validation and the nested-userns probe,
// pinned bind sources, backend launch, signal forwarding and cleanup.
// Proxy credentials stay in memory; any launcher death takes the proxy
// with it. The seccomp self-probe re-executes this binary before launch.
// Normal and early returns share one deferred teardown.

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

// overlayStoreSize resolves the effective overlay budget: the parsed
// --overlay-size, or the 1 GiB default.
func overlayStoreSize(opts *cliutil.Options) int64 {
	if opts.OverlaySize > 0 {
		return opts.OverlaySize
	}
	return cliutil.DefaultOverlaySize
}

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
	// Warn receives diagnostics — notes,
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

	// Out receives the PTY's forwarded (optionally sanitized) output; nil ⇒
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
	terminal := outputfilter.IsTTY(os.Stdin) && (s.Opts.FilterOutput || outputfilter.InteractiveStdio())
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
	// startup signal is caught by these handlers.
	hub := &sigHub{ch: s.SigCh, seen: map[os.Signal]bool{}}
	hub.start()

	var (
		work     string
		proxySrv *proxy.Server
		proxyLog *filteredProxyLog  // --filter-output proxy log
		pump     *outputfilter.Pump // interactive / --filter-output pty pump
		pinner   *bindpolicy.Pinner
		held     []*os.File // parent copies of everything handed to the child
		cmd      *exec.Cmd
		waitCh   chan int
		reaped   bool
	)
	teardown := func() {
		// A second Ctrl-C while cleaning up must not abort the cleanup
		// (a skipped RmTreeWritable would leave the work dir behind).
		// The hub keeps catching signals during cleanup but no longer
		// forwards them. No ignored disposition reaches child processes.
		hub.done()
		// Terminal teardown FIRST after the ignore phase: the
		// host terminal must be restored before anything below blocks
		// (a raw terminal is unusable meanwhile). Restore termios and
		// SIGWINCH, then close the pty before killing anything else.
		// Also emit the last word of the sanitized proxy
		// log (an unterminated tail stays pending in its sanitizer).
		if pump != nil {
			pump.Close()
		}
		if proxyLog != nil {
			proxyLog.close()
		}
		for _, f := range held {
			f.Close()
		}
		held = nil
		if pinner != nil {
			pinner.Close()
		}
		if cmd != nil && cmd.Process != nil && !reaped {
			// Terminate, wait three seconds, then kill: a sandbox that
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
			// (these goroutines die with the launcher process anyway).
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
	// setup. Each setup phase ends with this check: cleanup then
	// 128+signum when a signal arrived.
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
	// Explicit permissions: umask must never loosen them
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
	// Overlays: validated like binds (fd-first, no opt-ins), then the
	// capability and runtime gates for the explicitly selected mode.
	// A host that cannot run the selected arrangement refuses the launch;
	// neither mode may silently fall back to the other.
	overlays, err := bindpolicy.CheckOverlays(s.Opts, s.Home, pinner, userBinds, warn)
	if err != nil {
		warn(err.Error())
		return 1
	}
	if len(overlays) > 0 {
		if s.Opts.OverlaySingle && s.Opts.OverlaySize != 0 {
			warn("--overlay-size is not supported with --overlay-mode single")
			return 1
		}
		if s.Opts.OverlaySingle && !caps.TmpOverlay {
			warn("--overlay-mode single requires bwrap --overlay-src/--tmp-overlay support — refusing")
			return 1
		}
		if !s.Opts.OverlaySingle && !caps.Overlay {
			warn("--overlay requires bwrap >= 0.11 (--overlay-src/--overlay support) — refusing")
			return 1
		}
		if !caps.BindFD {
			warn("--overlay requires fd-pinned binds (bwrap >= 0.10) — refusing to " +
				"mount unverified overlay sources")
			return 1
		}
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

	if len(overlays) > 0 {
		if s.Opts.OverlaySingle {
			warn("warning: --overlay-mode single reopens validated sources by pathname at mount time; " +
				"concurrent source replacement can redirect the mount. No sbox storage cap applies " +
				"(only the kernel's default tmpfs limit); --overlay-size is unsupported")
			if err := s.Provider.SingleOverlayProbe(s.Opts.Net, hardenUserns, bpf); err != nil {
				warn("--overlay-mode single: this bwrap/kernel cannot run the single-launch overlay " +
					"(probed with the same flags as the launch) — refusing: " + err.Error())
				return 1
			}
		} else if err := s.Provider.OverlayProbe(s.Opts.Net, hardenUserns, bpf); err != nil {
			// The COMPLETE arrangement ran and failed: setuid bwrap (which
			// refuses the overlay options), a kernel without unprivileged
			// overlayfs, blocked namespace nesting, or a staging detail the
			// caps probe cannot see. Refuse — a path-based overlay lower
			// layer would give up the source-swap guarantee entirely.
			warn("--overlay: this bwrap/kernel cannot run the overlay staging arrangement " +
				"(probed with the same flags as the launch) — refusing; needs bwrap >= 0.11 " +
				"(non-setuid) and a kernel with unprivileged overlayfs (>= 5.11): " + err.Error())
			return 1
		}
	}
	if len(overlays) > 0 && s.Opts.Verbose && !s.Opts.OverlaySingle {
		warn(fmt.Sprintf("overlay: %d source(s) staged; shared writable layer capped at %d bytes",
			len(overlays), overlayStoreSize(s.Opts)))
	}
	if rc, dead := earlyExit(); dead {
		return rc
	}

	if !s.Opts.Net {
		// The proxy lives in this process: credentials never touch
		// disk, and any launcher death takes the proxy with it.
		np := s.NoProxy
		if np == nil {
			np = allow.NoProxyFromEnv(os.Getenv)
		}
		// Under --filter-output sanitize the proxy decision log too:
		// errors can quote sandbox-supplied bytes. Diagnostics add CR
		// before newlines while the host tty is raw.
		logf := s.ProxyLogf
		if s.Opts.FilterOutput {
			proxyLog = &filteredProxyLog{
				sanitizer: outputfilter.NewSanitizer(false),
				emit:      outputfilter.EmitDiag,
			}
			logf = proxyLog.write
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
	spec, err := BuildSpec(s.Opts, cwd, sand, sock, s.Home, userBinds, overlays, agent, sshCfg, pinner, warn)
	if err != nil {
		warn(err.Error())
		return 1
	}
	// Terminal sessions (the automatic interactive PTY and
	// --filter-output with a host tty on stdin) run the payload as the
	// bridge shell's foreground CHILD instead of exec'ing it in place:
	// bwrap's --new-session child — the PID the payload would exec into
	// — is the session leader, and the kernel drops
	// default-disposition tty signals for PID 1, so an exec'd
	// `sleep 30` silently ignored Ctrl-C in BOTH modes (the filtered
	// slave does become a controlling terminal). The shell (still PID
	// 1, still filtered) survives the group SIGINT by the same rule
	// and reports the child's status.
	if terminal {
		if child, ok := PayloadAsChild(spec.Bridge); ok {
			spec.Bridge = child
		} else {
			warn("internal: the bridge has no exec tail — the payload runs with exec " +
				"(Ctrl-C may be ignored by commands that do not handle SIGINT)")
		}
	}
	spec.Seccomp = bpf // nil ⇒ --no-seccomp, the explicit opt-out
	spec.DisableUserns = hardenUserns
	if terminal {
		helper, err := terminalHelper(work)
		if err != nil {
			warn(fmt.Sprintf("cannot prepare interactive terminal helper: %v", err))
			return 1
		}
		spec.Ops = append(spec.Ops, Mount{Src: helper, Dst: terminalHelperPath})
	}
	if spec.EnvData != nil {
		// The --env values must stay out of every argv (the backend's
		// /proc/<pid>/cmdline is world-readable for the whole run): a
		// read-only copy of this binary reads the fd-handed records
		// inside the sandbox and execs the bridge with them applied.
		helper, err := helperCopy(work, "envexec")
		if err != nil {
			warn(fmt.Sprintf("cannot prepare the environment handoff helper: %v", err))
			return 1
		}
		spec.Ops = append(spec.Ops, Mount{Src: helper, Dst: envExecHelperPath})
	}
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

	// Terminal setup fails closed: an untameable host tty is never
	// passed into a launch that requires a private PTY. childStdin is the
	// slave for a real (raw-mode) host tty, the exact non-tty stdin
	// fd otherwise — never a blind inherit of fd 0.
	var childStdin *os.File
	if s.Opts.FilterOutput || terminal {
		var err error
		if s.Opts.FilterOutput {
			pump, childStdin, err = outputfilter.Setup(s.Opts.StrictCrlf)
		} else {
			pump, childStdin, err = outputfilter.SetupTerminal()
		}
		if err != nil {
			warn(err.Error())
			return 1
		}
		pump.Out = s.Out
	}

	// argv = backend argv + "--" + [/run/sbox-terminal --_terminal-exec]
	// + [/run/sbox-envexec --_env-exec] + /bin/sh -c BRIDGE sbox-sh COMMAND...
	// The backend installs the seccomp filter (when enabled) as the very
	// last step before exec'ing the terminal helper (when needed) or
	// THAT shell, so the helper, shell, socat bridge AND command inherit
	// the filter from their first
	// instruction — see PayloadArgv for why the ordering is
	// load-bearing. The env helper (when --env values ride the fd
	// handoff) execs the bridge in place after applying them — still
	// PID 1, still filtered, no value in any argv.
	argv := append(append([]string{}, launch.Argv...), "--")
	if terminal {
		argv = append(argv, terminalHelperPath, "--_terminal-exec")
	}
	if spec.EnvData != nil {
		argv = append(argv, envExecHelperPath, "--_env-exec")
	}
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
		// away from the pump. SIGWINCH forwarding starts after spawn.
		_ = pump.Slave.Close()
		pump.Start()
	}

	// A signal that raced the spawn still triggers startup teardown,
	// killing the new sandbox. Otherwise forwarding takes over.
	hub.run(cmd)
	waitCh = make(chan int, 1)
	go func() { waitCh <- waitExitCode(cmd.Wait()) }()
	if rc, dead := earlyExit(); dead {
		return rc
	}

	rc := <-waitCh
	reaped = true
	// PTY drain: final output may still be in flight while the
	// payload dies a beat later, but a daemonized child holding the
	// slave open forever bounds the wait to half a second.
	if pump != nil {
		pump.Stop(500 * time.Millisecond)
	}
	hub.done()
	return rc
}

// Proxy handlers can finish while the supervisor is tearing down. The
// emission lock keeps log records ordered, but the state lock covers only
// sanitizer access: a blocked stderr must never hold up close. An in-flight
// sink write can finish later; waiting and new records are dropped on close.
type filteredProxyLog struct {
	mu        sync.Mutex
	emitMu    sync.Mutex
	sanitizer *outputfilter.Sanitizer
	emit      func(string)
	closed    bool
}

func (l *filteredProxyLog) write(msg string) {
	l.emitMu.Lock()
	defer l.emitMu.Unlock()
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	text := l.sanitizer.Feed([]byte("sbox-proxy: " + msg + "\n"))
	l.mu.Unlock()
	l.emit(text)
}

func (l *filteredProxyLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		// Every record ends in a newline, so UTF-8 decoding has no
		// incomplete printable tail. Discard any pending escape without
		// touching the possibly blocked sink or draining waiting records.
		l.sanitizer.Flush()
	}
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

// waitExitCode turns cmd.Wait()'s error into a shell-style exit code:
// 0, the payload's own code, or
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
// protection for any future backend with asynchronous startup.
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
	// a top-down permission-repair pass.
	_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == path {
			// Unreadable/vanished entries are skipped; the root itself is
			// 0700 by construction and never chmod'd.
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
