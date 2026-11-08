// Package bwrap is the ONLY bwrap-aware code in the port: the caps
// probe (parse_bwrap_caps/bwrap_caps — capability probing, not version
// parsing, because distro backports of individual options exist and
// upstream version numbers lie), the unprivileged-userns probe
// (userns_probe_ok, run per launch with the same ns/pid/session flags
// as the real argv), and the argv renderer for a sandbox.Spec
// (build_bwrap's tail): the fixed hardening skeleton, one flag per op
// in Spec order, and the fd-number accounting that guarantees only
// argv-named fds reach the child.
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
package bwrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"sbox/internal/sandbox"
	"sbox/internal/seccomp"
)

// probeTimeout bounds both subprocess probes (python: 10 s).
const probeTimeout = 10 * time.Second

// Provider renders sandbox.Specs as bwrap argv. Construct with New,
// Probe ONCE in main (the caps are carried, never re-probed
// mid-launch), then Build per launch.
type Provider struct {
	Bin    string // bwrap binary; "" ⇒ "bwrap" (resolved via $PATH)
	Caps   sandbox.Caps
	probed bool // Probe() caches, like sbox.py's _BWRAP_CAPS global
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
// 0x80 count as word characters: python's \w is unicode-aware, and a
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
	}
}

// Probe runs `bwrap --help` and fills the provider's caps (bwrap_caps).
// CACHED: a second call returns the first result without re-running
// bwrap --help (python's _BWRAP_CAPS global; a test shim on $PATH must
// never be asked twice). On failure the caps stay unknown (zero) — the
// error is INFORMATIONAL: python's bwrap_caps swallows OSError and the
// launcher keeps going, so the caller must not die on it either; the
// degradation is loud where it can be (path-based binds, the TOCTOU
// note) and seccomp, which cannot degrade, fails closed in Build with
// python's exact message.
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

// extraFDBase is the first child fd os/exec assigns to ExtraFiles.
const extraFDBase = 3

// Build renders the spec as a bwrap Launch. Argv layout mirrors
// sbox.py's run_sandbox assembly: [seccomp flag+fd] + [userns
// hardening] + the fixed skeleton (--unshare-all … --clearenv) + one
// flag group per Spec op; the caller appends "--" and the payload.
// Fail-closed by contract: seccomp bytes with a backend that cannot
// install them is an ERROR (never a silent skip — --no-seccomp is the
// explicit opt-out and never produces Seccomp bytes), and so is a
// pinned-fd mount on a backend without --bind-fd.
func (p *Provider) Build(spec *sandbox.Spec) (*sandbox.Launch, error) {
	l := &sandbox.Launch{Bin: p.bin()}
	argv := []string{}
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
		argv = append(argv, flag, nameFD(r))
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
		argv = append(argv, "--unshare-user", "--disable-userns", "--assert-userns-disabled")
	}
	argv = append(argv,
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

	for _, op := range spec.Ops {
		switch o := op.(type) {
		case sandbox.Setenv:
			argv = append(argv, "--setenv", o.Name, o.Value)
		case sandbox.ProcFS:
			argv = append(argv, "--proc", o.Path)
		case sandbox.DevFS:
			argv = append(argv, "--dev", o.Path)
		case sandbox.ShareNet:
			argv = append(argv, "--share-net")
		case sandbox.Tmpfs:
			argv = append(argv, "--perms", perms(o.Perms), "--tmpfs", o.Path)
		case sandbox.Mkdir:
			argv = append(argv, "--perms", perms(o.Perms), "--dir", o.Path)
		case sandbox.Chdir:
			// bwrap applies --chdir after all mounts, wherever it
			// sits in argv.
			argv = append(argv, "--chdir", o.Dir)
		case sandbox.Mount:
			base := "--ro-bind"
			if o.RW {
				base = "--bind"
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
				argv = append(argv, base+"-fd", n, o.Dst)
			} else {
				if o.Try {
					base += "-try"
				}
				argv = append(argv, base, o.Src, o.Dst)
			}
		default:
			return nil, fmt.Errorf("internal: unknown sandbox op %T", op)
		}
	}
	l.Argv = argv
	return l, nil
}

// perms renders an octal permission word the way bwrap spells it
// ("0755").
func perms(p uint32) string { return fmt.Sprintf("%04o", p) }
