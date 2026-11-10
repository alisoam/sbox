// Package bwrap is the ONLY bwrap-aware backend code: the caps
// probe (parse_bwrap_caps/bwrap_caps — capability probing, not version
// parsing, because distro backports of individual options exist and
// upstream version numbers lie), the unprivileged-userns probe
// (userns_probe_ok, run per launch with the same ns/pid/session flags
// as the real argv), the complete-arrangement overlay probe
// (overlay_probe_ok: staging sandbox, pinned sources, bounded store,
// seccomp bridge, nested namespaces and a real overlayfs write), and
// the argv renderer for a sandbox.Spec (build_bwrap's tail): the fixed
// hardening skeleton, one flag per op in Spec order, and the
// fd-number accounting that guarantees only argv-named fds reach the
// child.
//
// The fd accounting is the security core: bwrap closes the fds attached
// to setup ops (--bind-fd, the seccomp fd), but an fd attached to
// NOTHING would survive into the payload with its CLOEXEC cleared, and
// an O_PATH fd to host filesystem ground makes /proc/self/fd/N/.. walk
// the HOST mount tree — the runc CVE-2024-21626 ("Leaky Vessels") class
// of escape. PassFDs is built from the argv alone and becomes
// cmd.ExtraFiles (child fds 3,4,5… in order), so no pin can cross the
// exec boundary unless the argv names it. A pin NAMED twice in one argv
// (the cwd mount plus a -b of the same path, -b $HOME --home) gets a
// DISTINCT dup per use — whether a later --bind-fd N still resolves
// after an earlier op attached to N must never depend on bwrap's
// close ordering — and the dups are closed right after the spawn
// (Launch.CloseAfterSpawn).
//
// OVERLAYS (Specs carrying sandbox.Overlay ops) render as a two-level
// launch because bwrap resolves overlay sources by pathname in its parent
// mount namespace. A read-only host-root mirror still follows host renames;
// using original host paths there would discard the fd-pinning guarantee.
//
// The trusted outer bwrap mirrors the host root read-only for its runtime,
// mounts fresh proc/dev and a private tmpfs at /tmp, and stages ALL mount
// sources at independent paths under /tmp/sbox-stage. Every validated pin
// is mounted from its descriptor; ordinary binds retain their requested
// mode, while overlay lowers are always read-only. Setup files and the
// inner bwrap binary also live on this private tmpfs. A separate, single
// size-bounded tmpfs holds all overlay upper/work directories.
//
// The inner bwrap resolves only those stable staged sources, builds the
// final sandbox on a fresh root, and installs seccomp as its last step
// before exec. When filtering, a fixed trusted shell bridge opens the
// staged filter as fd 3; bwrap consumes it before running the payload.
// The payload and its descendants are filtered from their first instruction,
// with --as-pid-1 retained. Staging paths, pivot leftovers and setup
// descriptors are unreachable from that final root.
//
// A host rename or replacement cannot redirect a staged pin to a different
// source. This is not a content snapshot: host edits within a source remain
// visible. Overlay writes go only to the bounded store and fail with ENOSPC
// when full. Explicit writable binds continue to write to their host sources.
package bwrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"sbox/internal/bindpolicy"
	"sbox/internal/sandbox"
	"sbox/internal/seccomp"
)

// probeTimeout bounds subprocess probes.
const probeTimeout = 10 * time.Second

// Provider renders sandbox.Specs as bwrap argv. Construct with New,
// Probe ONCE in main (the caps are carried, never re-probed
// mid-launch), then Build per launch.
type Provider struct {
	Bin    string // bwrap binary; "" ⇒ "bwrap" (resolved via $PATH)
	Caps   sandbox.Caps
	probed bool // Probe caches the capability result
}

// the bwrap backend is A sandbox.Provider (asserted here; cmd/sbox
// drives it through the interface)
var _ sandbox.Provider = (*Provider)(nil)

// New returns a provider for bin with unknown (zero) caps.
func New(bin string) *Provider { return &Provider{Bin: bin} }

// Name implements sandbox.Provider.
func (p *Provider) Name() string { return "bwrap" }

func (p *Provider) bin() string {
	if p.Bin == "" {
		return "bwrap"
	}
	return p.Bin
}

// hasOpt is parse_bwrap_caps' `has()`: opt must appear as a whole word
// (no [A-Za-z0-9_] or '-' adjacent — "--bind-fd" must not match inside
// "--bind-fds" nor "--ro-bind-fd" inside "--ro-bind-fds"). Bytes >=
// 0x80 count as word characters: a
// non-ASCII letter glued to the option is as much a non-boundary as an
// ASCII one.
func hasOpt(text, opt string) bool {
	n := len(opt)
	for i := 0; i+n <= len(text); i++ {
		if text[i:i+n] != opt {
			continue
		}
		if i > 0 && isWordByte(text[i-1]) {
			continue
		}
		if i+n < len(text) && isWordByte(text[i+n]) {
			continue
		}
		return true
	}
	return false
}

func isWordByte(c byte) bool {
	return c == '-' || c == '_' || (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

// ParseCaps parses `bwrap --help` output into the capabilities this
// launcher relies on (parse_bwrap_caps): capability probing, not
// version parsing — options have appeared in distro releases ahead of
// the upstream version that introduced them, and the probe does not
// care either way.
func ParseCaps(text string) sandbox.Caps {
	return sandbox.Caps{
		AddSeccompFD:  hasOpt(text, "--add-seccomp-fd"),
		LegacySeccomp: !hasOpt(text, "--add-seccomp-fd") && hasOpt(text, "--seccomp"),
		// >= 0.8: nested user namespaces die at the kernel level
		// (max_user_namespaces in a nested userns); --assert-... makes
		// bwrap verify it and die otherwise. Both spellings required.
		DisableUserns: hasOpt(text, "--disable-userns") && hasOpt(text, "--assert-userns-disabled"),
		// >= 0.10 (or a distro backport): TOCTOU-free binds via pinned
		// O_PATH fds.
		BindFD: hasOpt(text, "--bind-fd") && hasOpt(text, "--ro-bind-fd"),
		// >= 0.11: disposable overlays. Both spellings required —
		// --overlay alone (no way to name a source) is useless here.
		// NOTE: bwrap refuses these options in setuid mode; the runtime
		// overlay probe is what actually decides the host can run one.
		Overlay: hasOpt(text, "--overlay-src") && hasOpt(text, "--overlay"),
	}
}

// Probe caches bwrap --help capabilities. A test shim on PATH must never be
// asked twice. Failures leave conservative zero caps; the supervisor reports
// degradation and refuses to launch if required seccomp support is unavailable.
func (p *Provider) Probe() (sandbox.Caps, error) {
	if p.probed {
		return p.Caps, nil
	}
	p.probed = true
	p.Caps = sandbox.Caps{}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.bin(), "--help")
	var out bytes.Buffer // bwrap prints some options on stderr
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return p.Caps, fmt.Errorf("bwrap capability probe failed: %v", err)
	}
	p.Caps = ParseCaps(out.String())
	return p.Caps, nil
}

// UsernsProbe answers: can this bwrap+kernel really run --unshare-user
// --disable-userns --assert-userns-disabled (userns_probe_ok)? Probed
// once per launch with a throwaway minimal sandbox before the flags are
// committed to the real argv. The explicit --unshare-user (required:
// --unshare-all only sets --unshare-user-try) replaces bwrap's non-root
// "just DWIM" fallback, and on hosts where unprivileged user namespaces
// are off — setuid bwrap, kernel.unprivileged_userns_clone=0, hardened
// kernels with max_user_namespaces=0 — that combination used to turn
// working setups into hard launch failures. Failing closed there is
// not a security gain (the whole sandbox cannot start at all), so probe
// instead: on failure the launcher keeps the flags off, notes it once a
// day, and rests on the seccomp unshare/setns/clone deny rules alone.
//
// The probe argv mirrors the real launch's namespace/pid/session flags:
// the point is to catch flag INTERACTIONS on some bwrap version, so a
// probe that runs a different argv than the launch would pass while the
// launch dies. The seccomp fd is the one deliberate difference (bwrap
// consumes the pipe's bytes at argv-parse time, long before namespace
// setup).
func (p *Provider) UsernsProbe(shareNet bool) bool {
	argv := []string{"--unshare-all", "--die-with-parent", "--new-session", "--as-pid-1"}
	if shareNet {
		argv = append(argv, "--share-net")
	}
	argv = append(argv, "--unshare-user", "--disable-userns", "--assert-userns-disabled",
		"--ro-bind", "/", "/", "--", "/bin/true")
	return p.runOk(argv)
}

func (p *Provider) runOk(argv []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.bin(), argv...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

// OverlayProbe answers: can THIS host really run the complete --overlay
// arrangement — trusted staging sandbox (ro host mirror, pinned source,
// bounded store), the fixed seccomp bridge when a filter applies, nested
// namespaces, the inner hardening skeleton, an actual overlayfs mount
// and a write through it — with the SAME flags the real launch will
// use? Capability probing cannot see any of this: bwrap refuses the
// overlay options in setuid mode, unprivileged overlayfs needs a
// suitable kernel (>= 5.11 for userxattr), and the staging arrangement
// depends on namespace nesting the userns probe never exercises. The
// probe runs once per launch, before the real argv is committed; an error
// means the launcher REFUSES to run overlays (never a silent fallback —
// a path-based overlay would give up the fd-pinning guarantee).
//
// The payload verifies more than exit status: it writes through the
// overlay (a broken mount fails), checks that neither the staging tree nor the
// pivot leftovers are visible, and the launcher side then verifies the
// write did NOT reach the host source (an overlay silently mounted
// read-write onto the source itself would "pass" every other check).
func (p *Provider) OverlayProbe(shareNet, hardenUserns bool, filter []byte) error {
	root, err := os.MkdirTemp("/tmp", "sboxovl.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	src := filepath.Join(root, "src")
	sand := filepath.Join(root, "sand")
	if err := os.Mkdir(src, 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(sand, 0o755); err != nil {
		return err
	}
	fd, err := bindpolicy.OpenPathPinned(src)
	if err != nil {
		return err
	}
	defer fd.Close()
	if !bindpolicy.FdReaches(fd, src) {
		return errors.New("overlay probe source changed while pinning")
	}

	spec := overlayProbeSpec(src, sand, fd, shareNet, hardenUserns, filter)

	launch, err := p.Build(spec)
	if err != nil {
		return err
	}
	defer func() {
		for _, f := range launch.PassFDs {
			f.Close()
		}
		for _, f := range launch.CloseAfterSpawn {
			f.Close()
		}
	}()
	if launch.Bin == "" {
		return errors.New("overlay probe has no backend binary")
	}
	argv := append(append([]string{}, launch.Argv...), "--",
		"/bin/sh", "-c",
		`test ! -e "$2" && test ! -e /oldroot && : > "$1"`,
		"sbox-overlay-probe", filepath.Join(src, "probe"), stageDir)

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, launch.Bin, argv...)
	// The staging argv names its fds (--file, staged binds): hand them
	// over exactly like the supervisor does.
	cmd.ExtraFiles = launch.PassFDs
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("overlay probe: %w (output %q)", err, out)
	}
	// The write must have landed in the disposable store, never on the
	// host source: a present probe file means the "overlay" was writing
	// through to the real tree.
	if _, err := os.Stat(filepath.Join(src, "probe")); err == nil {
		_ = os.RemoveAll(filepath.Join(src, "probe"))
		return errors.New("overlay probe wrote through to the host source")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot check overlay probe source: %w", err)
	}
	return nil
}

// overlayProbeSpec shares the production runtime mounts and launch options.
// Kept separate so the runtime can also be exercised on hosts that disallow
// the second user namespace, without skipping the shell/runtime regression.
func overlayProbeSpec(src, sand string, fd *os.File, shareNet, hardenUserns bool, filter []byte) *sandbox.Spec {
	spec := &sandbox.Spec{
		Ops: []sandbox.Op{
			sandbox.ProcFS{Path: "/proc"},
			sandbox.DevFS{Path: "/dev"},
			// The $WORK-style rw path mount is staged separately from
			// the private /tmp holding setup files and the overlay store.
			sandbox.Mount{Src: sand, Dst: "/tmp", RW: true},
			sandbox.Overlay{Src: src, Dst: src, FD: fd},
		},
		DisableUserns:    hardenUserns,
		OverlayStoreSize: 1 << 20,
		Seccomp:          filter,
	}
	spec.Ops = append(spec.Ops, sandbox.SystemMounts()...)
	if shareNet {
		spec.Ops = append(spec.Ops, sandbox.ShareNet{})
	}

	return spec
}

// extraFDBase is the first child fd os/exec assigns to ExtraFiles.
const extraFDBase = 3

// Staging paths, visible ONLY inside the staging sandbox: the real
// sandbox pivots to a fresh root, so the payload can never reach them.
const (
	stageDir      = "/tmp/sbox-stage"
	stageBinary   = stageDir + "/bwrap"
	stageSeccomp  = stageDir + "/seccomp.bpf" // the filter bytes, staged for the inner bwrap
	stageStore    = stageDir + "/st"          // the ONE size-bounded tmpfs (all overlays)
	stageMountFmt = stageDir + "/mounts/%d"   // ordinary mounts, with their requested mode
	stageSrcFmt   = stageDir + "/src/%d"      // pinned overlay sources, ro
	stageUpperFmt = stageStore + "/u%d"
	stageWorkFmt  = stageStore + "/w%d"
)

// stageSeccompBridge is the staging payload when seccomp is enabled:
// bwrap closes every fd its argv does not name, so the filter cannot
// ride an inherited descriptor into the inner bwrap. The staging sandbox
// materializes the bytes host-side (--file), this fixed script opens
// them as fd 3, and `exec "$@"` hands control to the inner bwrap with
// its options expanded VERBATIM from argv (never re-parsed by the
// shell). The script is a constant: no untrusted bytes reach it.
const stageSeccompBridge = "exec 3<" + stageSeccomp + "\nexec \"$@\""

// stageBin resolves the host binary to bind at stageBinary. Staging the
// executable also preserves binaries located under the host's /tmp, which
// the staging namespace hides. Bare or relative names resolve through PATH
// here, never inside the staging payload.
func (p *Provider) stageBin() (string, error) {
	bin := p.Bin
	if bin == "" {
		bin = "bwrap"
	}
	if !filepath.IsAbs(bin) {
		resolved, err := exec.LookPath(bin)
		if err != nil {
			return "", err
		}
		bin = resolved
	}
	// Fail HERE, not inside the staging sandbox: a missing binary is a
	// launch-time error with a host-side message.
	if st, err := os.Stat(bin); err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", bin)
	}
	return bin, nil
}

// Build renders the spec as a bwrap Launch: [seccomp flag+fd] + [userns
// hardening] + the fixed skeleton (--unshare-all … --clearenv) + one
// flag group per Spec op; the caller appends "--" and the payload.
// Fail-closed by contract: seccomp bytes with a backend that cannot
// install them is an ERROR (never a silent skip — --no-seccomp is the
// explicit opt-out and never produces Seccomp bytes), and so is a
// pinned-fd mount on a backend without --bind-fd.
//
// Specs with Overlay ops render as a two-level launch (see the package
// comment). Every source gets a private staging mountpoint, with pins
// consumed by the outer bwrap. The inner argv retains the operation order
// and requested mount modes, but resolves its sources only through these
// independent mountpoints. Host pathname swaps cannot redirect them.
func (p *Provider) Build(spec *sandbox.Spec) (*sandbox.Launch, error) {
	l := &sandbox.Launch{Bin: p.bin()}
	var owned []*os.File
	built := false
	defer func() {
		if !built {
			for _, f := range owned {
				f.Close()
			}
		}
	}()
	// childFD names f in the child: the FIRST use passes the original
	// file; every further use gets its own dup (CloseAfterSpawn) — a
	// pin named twice in one argv (the cwd mount plus a -b of the same
	// path, -b $HOME --home) must emit a DISTINCT fd number per use,
	// because bwrap consumes setup-op fds itself and whether a later
	// --bind-fd N still resolves after an earlier op attached to N must
	// not depend on bwrap's close ordering.
	named := map[*os.File]bool{}
	childFD := func(f *os.File) (string, error) {
		if !named[f] {
			named[f] = true
			l.PassFDs = append(l.PassFDs, f)
			return strconv.Itoa(extraFDBase + len(l.PassFDs) - 1), nil
		}
		nfd, err := syscall.Dup(int(f.Fd()))
		if err != nil {
			return "", fmt.Errorf("cannot dup pinned bind fd: %v", err)
		}
		dup := os.NewFile(uintptr(nfd), f.Name()+" dup")
		owned = append(owned, dup)
		l.PassFDs = append(l.PassFDs, dup)
		l.CloseAfterSpawn = append(l.CloseAfterSpawn, dup)
		return strconv.Itoa(extraFDBase + len(l.PassFDs) - 1), nil
	}
	// nameFD reserves a fresh slot for a file the provider itself
	// created (the seccomp pipe read end).
	nameFD := func(f *os.File) string {
		l.PassFDs = append(l.PassFDs, f)
		return strconv.Itoa(extraFDBase + len(l.PassFDs) - 1)
	}

	hasOverlay := false
	shareNet := false
	for _, op := range spec.Ops {
		if _, ok := op.(sandbox.Overlay); ok {
			hasOverlay = true
		}
		if _, ok := op.(sandbox.ShareNet); ok {
			shareNet = true
		}
	}
	if hasOverlay {
		// Fail closed before anything spawns: overlays depend on both
		// the overlay options and fd-pinned sources (a path-based lower
		// layer would re-open the exact check-to-mount race --bind-fd
		// exists to close).
		if !p.Caps.Overlay {
			return nil, errors.New("this bwrap lacks --overlay-src/--overlay — " +
				"cannot run --overlay (bwrap >= 0.11 required)")
		}
		if !p.Caps.BindFD {
			return nil, errors.New("this bwrap lacks --bind-fd/--ro-bind-fd — --overlay " +
				"refuses to run without pinned sources (bwrap >= 0.10)")
		}
		if spec.OverlayStoreSize <= 0 {
			return nil, errors.New("internal: Spec.OverlayStoreSize not set for overlays")
		}
	}

	// inner is the REAL sandbox's bwrap argv (without the payload); the
	// staging fragments below are named in staging-argv order so the fd
	// numbers assigned by childFD/nameFD match the ExtraFiles slots.
	var inner []string
	var stagedMounts []string // all mount sources, on independent private paths
	var stagedDirs []string   // per-overlay upper/work dir creations
	var seccompFD string      // the staging --file fd number, "" when unfiltered

	if spec.Seccomp != nil {
		// Fail-closed: this mirrors seccomp_fd_args' die — the filter
		// is not optional, and a bwrap that cannot install it must not
		// silently run the payload unfiltered. (The self-probe and the
		// no-syscall-table die happen launcher-side, before Build.)
		flag := p.Caps.SeccompFlag()
		if flag == "" {
			return nil, errors.New("this bwrap supports neither --add-seccomp-fd nor --seccomp — " +
				"cannot install the seccomp deny-list (upgrade bwrap >= 0.4.1, or pass --no-seccomp)")
		}
		r, err := seccomp.FilterFD(spec.Seccomp)
		if err != nil {
			return nil, fmt.Errorf("seccomp: cannot hand the filter to bwrap: %v", err)
		}
		owned = append(owned, r)
		if hasOverlay {
			// bwrap #1 copies the pipe into the staging sandbox (--file);
			// the staging bridge re-opens it as fd 3, which the inner
			// bwrap consumes at argv-parse time — the filter is still
			// installed by the INNER bwrap as its very last setup step,
			// so the payload is covered from its first instruction.
			// (Overlays imply bwrap >= 0.11, which always has this
			// spelling; a hypothetical overlay+legacy build refuses.)
			if flag != "--add-seccomp-fd" {
				return nil, errors.New("--overlay requires --add-seccomp-fd for the " +
					"staged filter (this bwrap only offers --seccomp)")
			}
			seccompFD = nameFD(r)
			inner = append(inner, "--add-seccomp-fd", "3")
		} else {
			inner = append(inner, flag, nameFD(r))
		}
	}
	if spec.DisableUserns {
		// Kernel-level: bwrap sets max_user_namespaces=1 in a nested
		// user namespace, consumes the one slot itself, and (with
		// --assert-userns-disabled) refuses to run unless nesting is
		// really dead — belt and braces under the unshare/setns deny
		// rules, immune to hand-typed-number mistakes. The explicit
		// --unshare-user is required: --unshare-all only sets
		// --unshare-user-try, and bwrap checks the combination before
		// its non-root "just DWIM" fallback gets a chance to run.
		if !p.Caps.DisableUserns {
			return nil, errors.New("internal: Spec.DisableUserns set but bwrap lacks " +
				"--disable-userns/--assert-userns-disabled (caps not probed?)")
		}
		inner = append(inner, "--unshare-user", "--disable-userns", "--assert-userns-disabled")
	}
	inner = append(inner,
		"--unshare-all",
		"--die-with-parent",
		"--new-session",
		// Run the payload as pid 1 instead of bwrap's own zombie-reaper
		// init: that init is NOT covered by our seccomp filter and is
		// the command's PARENT, so on Yama ptrace_scope=0 systems a
		// filtered process could write to /proc/1/mem and inject
		// syscalls into it (the ptrace-syscall ban does not cover
		// /proc/<pid>/mem). Trade-off: orphaned grandchildren are not
		// reaped while pid 1 lives.
		"--as-pid-1",
		"--clearenv",
	)

	overlayIdx := 0
	mountIdx := 0
	for _, op := range spec.Ops {
		switch o := op.(type) {
		case sandbox.Setenv:
			inner = append(inner, "--setenv", o.Name, o.Value)
		case sandbox.ProcFS:
			inner = append(inner, "--proc", o.Path)
		case sandbox.DevFS:
			inner = append(inner, "--dev", o.Path)
		case sandbox.ShareNet:
			inner = append(inner, "--share-net")
		case sandbox.Tmpfs:
			inner = append(inner, "--perms", perms(o.Perms), "--tmpfs", o.Path)
		case sandbox.Mkdir:
			inner = append(inner, "--perms", perms(o.Perms), "--dir", o.Path)
		case sandbox.Chdir:
			// bwrap applies --chdir after all mounts, wherever it
			// sits in argv.
			inner = append(inner, "--chdir", o.Dir)
		case sandbox.Mount:
			base := "--ro-bind"
			if o.RW {
				base = "--bind"
			}
			staged := ""
			if hasOverlay {
				staged = fmt.Sprintf(stageMountFmt, mountIdx)
				mountIdx++
			}
			if o.FD != nil {
				if !p.Caps.BindFD {
					return nil, fmt.Errorf("internal: mount of %s carries a pinned fd "+
						"but bwrap lacks --bind-fd/--ro-bind-fd (enable the pinner "+
						"only when caps.BindFD)", o.Src)
				}
				n, err := childFD(o.FD)
				if err != nil {
					return nil, err
				}
				if hasOverlay {
					// A host-root mirror still follows host-side renames.
					// Every pin therefore needs its own mountpoint on the
					// PRIVATE tmpfs, never the original host pathname.
					stagedMounts = append(stagedMounts, base+"-fd", n, staged)
					inner = append(inner, base, staged, o.Dst)
				} else {
					inner = append(inner, base+"-fd", n, o.Dst)
				}
			} else {
				if o.Try {
					base += "-try"
				}
				if hasOverlay {
					// This also preserves sources under the host's /tmp,
					// which the staging sandbox replaces with a tmpfs.
					// bwrap reads these sources from its original root.
					stagedMounts = append(stagedMounts, base, o.Src, staged)
					inner = append(inner, base, staged, o.Dst)
				} else {
					inner = append(inner, base, o.Src, o.Dst)
				}
			}
		case sandbox.Overlay:
			// The lower layer MUST be the pinned object: bwrap resolves
			// overlay sources by pathname, so the pin is re-mounted
			// read-only at a stable staging path and the inner overlay
			// references THAT — a swapped source component cannot
			// redirect it after validation.
			if o.FD == nil {
				return nil, fmt.Errorf("internal: overlay of %s carries no pinned fd — "+
					"overlays without fd validation are refused (bwrap >= 0.10)", o.Src)
			}
			n, err := childFD(o.FD)
			if err != nil {
				return nil, err
			}
			src := fmt.Sprintf(stageSrcFmt, overlayIdx)
			upper := fmt.Sprintf(stageUpperFmt, overlayIdx)
			work := fmt.Sprintf(stageWorkFmt, overlayIdx)
			stagedMounts = append(stagedMounts, "--ro-bind-fd", n, src)
			inner = append(inner, "--overlay-src", src, "--overlay", upper, work, o.Dst)
			stagedDirs = append(stagedDirs,
				"--perms", perms(0o700), "--dir", upper,
				"--perms", perms(0o700), "--dir", work)
			overlayIdx++
		default:
			return nil, fmt.Errorf("internal: unknown sandbox op %T", op)
		}
	}

	if !hasOverlay {
		l.Argv = inner
		built = true
		return l, nil
	}

	bin, err := p.stageBin()
	if err != nil {
		return nil, fmt.Errorf("--overlay: cannot resolve the bwrap binary for the staging sandbox: %v", err)
	}
	// The staging sandbox: unprivileged, hermetic (own pid/net/ipc/uts
	// namespaces, fresh /proc and /dev — the host's stay invisible),
	// die-with-parent chained under the launcher, host root mirrored
	// read-only for the trusted setup runtime. The inner argv uses only
	// independently staged sources. --share-net of the real launch keeps
	// staging on the launcher's network namespace (the inner "shared"
	// netns is staging's view of it).
	staging := []string{
		"--unshare-user",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
	}
	if !shareNet {
		staging = append(staging, "--unshare-net")
	}
	staging = append(staging,
		"--die-with-parent",
		"--ro-bind", "/", "/",
		"--proc", "/proc",
		"--dev", "/dev",
		// /tmp already exists on the host, so mounting over it does
		// not need a mkdir on the read-only root. All setup paths are
		// created beneath this private, writable tmpfs.
		"--perms", perms(0o700), "--tmpfs", "/tmp",
		"--ro-bind", bin, stageBinary,
	)
	if seccompFD != "" {
		staging = append(staging, "--perms", perms(0o400), "--file", seccompFD, stageSeccomp)
	}
	staging = append(staging, stagedMounts...)
	staging = append(staging, "--perms", perms(0o700),
		"--size", strconv.FormatInt(spec.OverlayStoreSize, 10), "--tmpfs", stageStore)
	staging = append(staging, stagedDirs...)
	staging = append(staging, "--")
	if seccompFD != "" {
		staging = append(staging, "/bin/sh", "-c", stageSeccompBridge, "sbox-stage", stageBinary)
	} else {
		staging = append(staging, stageBinary)
	}
	staging = append(staging, inner...)

	// The fd invariant still holds, with staging as the consumer: every
	// ExtraFiles slot is named by the STAGING argv (--file, the staged
	// --*-bind-fd ops); the inner argv names only fd 3, which the
	// staging bridge opened from the staged file — never a launcher fd.
	l.Argv = staging
	built = true
	return l, nil
}

// perms renders an octal permission word the way bwrap spells it
// ("0755").
func perms(p uint32) string { return fmt.Sprintf("%04o", p) }
