package bindpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"sbox/internal/cliutil"
)

// Bind is one validated (bwrap-flag, realpath, pinned-fd) triple returned
// by CheckBindPaths for mounting. Flag is
// spelled as the bwrap mount option ("--bind" / "--ro-bind": the
// --bind-socket MOUNT MODE is decided here — read-only for connect-only
// ground, read-write for plain directories). FD is the pinned O_PATH fd
// (nil when the source does not exist yet or fd pinning is unavailable —
// old bwrap: the path is then mounted by name, the documented fallback).
type Bind struct {
	Flag string
	Path string
	FD   *os.File
}

// ValidateBindSource validates one bind source for -b/-r/--bind-socket
// AND the automatic cwd mount (label "cwd"): pin FIRST (after the
// string-only rules), then validate the pinned object — the fd you
// validated is the fd you mount.
//
// Returns the refusal reason when the bind must not happen
// (CheckBindPaths dies on it; the cwd path downgrades it to the
// "not mounting it" warning and releases the pin), the persistence
// warning (or ""), the resolved path, the pinned fd (nil in path mode),
// and a fatal error for pin failures (a missing -b/-r source, an
// actively raced path).
//
// opts is the parsed CLI (Home, RoCwd, Verbose, BindSocket are read);
// home is the $HOME the launcher resolved; warn receives the scan's
// lossy notes.
func ValidateBindSource(pinner *Pinner, label, p string, opts *cliutil.Options,
	home string, warn func(string)) (refusal, warning, rp string, fd *os.File, fatal error) {

	realHome := RealPath(home)
	rp = RealPath(p)
	// -b $HOME together with --home re-binds what --home binds anyway:
	// exempt from ALL socket checks (but the risk surfaces in the --home
	// note, so it is never silent).
	exempt := label == "--bind" && opts.Home && rp == realHome

	// String-only rules FIRST (pure prefix matching, no filesystem
	// access): a path refused on its shape must report the refusal, not a
	// pin error from an unsearchable component.
	if !exempt {
		var hits []string
		for _, q := range ProtectedPaths(home) {
			if Covers(rp, q) {
				hits = append(hits, q)
			}
		}
		if len(hits) > 0 {
			sort.Strings(hits)
			refusal = fmt.Sprintf("%s %s covers protected path(s): %s", label, p, strings.Join(hits, ", "))
			if label == "--bind" && rp == realHome {
				refusal += "; use --home to bind $HOME itself"
			}
			return refusal, "", rp, nil, nil
		}
		// Kernel/pseudo-fs ground: /proc/<pid>/root, /proc/<pid>/fd/*,
		// /dev/pts, /dev/shm, ... resolve in the HOST task's context even
		// after a plain bind (magic links; the ptrace_may_access gate is
		// a kuid comparison, so the same uid passes from a child userns).
		// Never bindable, --bind-socket is NOT an opt-in here.
		for _, r := range NoDescendRoots {
			if Covers(r, rp) {
				return fmt.Sprintf("%s %s: %s is inside %s — kernel/pseudo-fs ground "+
						"(/proc/<pid>/root, /proc/<pid>/fd, /dev/pts, ... are host escapes; "+
						"the sandbox already gets a fresh, safe /proc and /dev)", label, p, rp, r),
					"", rp, nil, nil
			}
		}
		// Bidirectional: neither an ancestor of a listed socket
		// (-b /run/docker) nor a descendant of a listed directory
		// (--bind-socket .../keyring/ssh) may pass.
		var sockHits []string
		for _, cs := range ControlSockets() {
			if Covers(rp, cs.Path) || Covers(cs.Path, rp) {
				sockHits = append(sockHits, cs.Path)
			}
		}
		if len(sockHits) > 0 {
			sort.Strings(sockHits)
			return fmt.Sprintf("%s %s overlaps host control socket(s): %s — "+
				"that hands the sandbox full control of the host "+
				"(container runtime, D-Bus/systemd, keyring, X11, ...)",
				label, p, strings.Join(sockHits, ", ")), "", rp, nil, nil
		}
	}

	explicit := map[string]bool{}
	for _, x := range opts.BindSocket {
		explicit[RealPath(x)] = true
	}
	runtimeRoots := RuntimeRoots()

	// fd-first for every filesystem-backed check. allowMissing only for
	// --bind-socket (not-yet-created runtime paths): a missing -b/-r
	// source must die, not fall back to the racy path form.
	if pinner != nil {
		fd, fatal = pinner.Pin(rp, label == "--bind-socket")
		if fatal != nil {
			return "", "", rp, nil, fatal
		}
	}
	if exempt {
		return "", "", rp, fd, nil
	}

	isSocket := false
	if fd != nil {
		mode, err := fstatMode(int(fd.Fd()))
		isSocket = err == nil && mode&syscall.S_IFMT == syscall.S_IFSOCK
	} else {
		isSocket = IsSocket(rp)
	}
	if isSocket || anyCovers(runtimeRoots, rp) {
		// Read-write never opts in: a rw mount of a socket file or a
		// runtime-dir path lets the sandbox unlink and replace the
		// socket, impersonating the host service to host clients —
		// `-b P --bind-socket P` used to smuggle exactly that past the
		// shape rule. Socket files and runtime-dir paths are
		// connect-only: read-only, full stop.
		if label == "--bind" || (label == "cwd" && !opts.RoCwd) {
			how := "--ro-cwd --bind-socket \"$PWD\""
			if label == "--bind" {
				how = "-r PATH --bind-socket PATH"
			}
			return fmt.Sprintf("%s %s: %s is a socket or lives under a runtime dir — "+
				"connect-only ground never mounts read-write (rw would let the sandbox "+
				"replace the socket and impersonate the host service); read-only works: %s",
				label, p, rp, how), "", rp, fd, nil
		}
		if !explicit[rp] {
			return fmt.Sprintf("%s %s: %s is a socket or lives under a runtime dir — "+
					"control-socket territory (a full host escape waiting for a name we "+
					"forgot); pass --bind-socket to bind it anyway", label, p, rp),
				"", rp, fd, nil
		}
	}

	isDir := false
	if fd != nil {
		mode, err := fstatMode(int(fd.Fd()))
		isDir = err == nil && mode&syscall.S_IFMT == syscall.S_IFDIR
	} else {
		if st, err := os.Stat(rp); err == nil {
			isDir = st.IsDir()
		}
	}
	if !explicit[rp] && isDir {
		// Scan the PINNED object when there is one: the directory whose
		// contents were checked is the directory that gets mounted.
		scanRoot := rp
		if fd != nil {
			scanRoot = fmt.Sprintf("/proc/self/fd/%d", fd.Fd())
		}
		found := ContainsSocket(scanRoot, rp, opts.Verbose, warn)
		if found != "" {
			shown := found
			if strings.HasPrefix(found, scanRoot) {
				shown = rp + found[len(scanRoot):] // name the HOST path, not the fd spelling
			}
			// The name is carved from a directory entry the tree's writer
			// controls: quote it — a hostile file name must not inject
			// terminal controls into the refusal message.
			return fmt.Sprintf("%s %s: contains a Unix socket (%s) — control-socket "+
					"territory; pass --bind-socket to bind it anyway", label, p, strconv.Quote(shown)),
				"", rp, fd, nil
		}
	}

	warning = ""
	if label == "--bind" {
		// Persistence, not escape: code planted through these rw binds
		// executes AS THE HOST USER at the next login/session. (The cwd
		// mount deliberately does not warn here — the epilog documents
		// the rw-cwd trade-off once; --bind-socket directories that
		// resolve to rw warn in CheckBindPaths, where the final flag is
		// known.)
		warning = PersistenceWarning(label, p, rp, home)
	}
	return "", warning, rp, fd, nil
}

// CheckBindPaths validates -b/--ro-bind/--bind-socket before anything is
// started; it returns the resolved (bwrap-flag, realpath, pinned-fd)
// triples the sandbox builder mounts, in flag-group order (--bind,
// --ro-bind, --bind-socket) — later mounts shadow earlier ones in bwrap,
// so `-r P --bind-socket P` stays read-only and a plain dir after a
// runtime path never carries a stale read-write decision. fd-first: each
// source is pinned (OpenPathPinned refuses every symlink — validation
// and mount use the SAME object), so symlink swaps and relative paths
// can't make bwrap mount something that was never checked. Any refusal
// is fatal (the launch dies); warnings (persistence notes, the scan's
// lossy notes, the --home control-socket note) go through warn.
func CheckBindPaths(opts *cliutil.Options, home string, pinner *Pinner,
	warn func(string)) ([]Bind, error) {
	if warn == nil {
		warn = func(string) {}
	}
	var binds []Bind
	bound := map[string]bool{} // resolved paths already emitting a mount
	groups := []struct {
		label       string
		defaultFlag string
		paths       []string
	}{
		// --bind-socket's mount flag is decided per path below:
		// read-only for connect-only ground, read-write for plain
		// directories.
		{"--bind", "--bind", opts.Bind},
		{"--ro-bind", "--ro-bind", opts.RoBind},
		{"--bind-socket", "--ro-bind", opts.BindSocket},
	}
	for _, g := range groups {
		for _, p := range g.paths {
			// Re-seed the flag for EVERY path: the --bind-socket branch
			// below overwrites it for plain directories, and a stale rw
			// decision used to carry into the NEXT path of the same
			// group (plain dir, then a runtime-dir socket -> the socket
			// mounted READ-WRITE — exactly the impersonation the rules
			// refuse).
			flag := g.defaultFlag
			refusal, warning, rp, fd, fatal := ValidateBindSource(pinner, g.label, p, opts, home, warn)
			if fatal != nil {
				return nil, fatal
			}
			if refusal != "" {
				return nil, fmt.Errorf("%s; refusing", refusal)
			}
			if warning != "" {
				warn(warning)
			}
			if g.label == "--bind-socket" {
				if bound[rp] {
					// -b/-r of the same path already mounts it with the
					// mode the user asked for; --bind-socket acted as the
					// shape/scan opt-in only — emitting its own mount
					// would shadow an -r back to read-only or worse.
					continue
				}
				// Socket files and runtime-dir paths are connect-only
				// ground: read-only (rw would let the sandbox replace
				// the socket file). Plain DIRECTORIES mount READ-WRITE —
				// the opt-in for socket-bearing project dirs (puma.sock,
				// .s.PGSQL.5432, .git/fsmonitor--daemon.ipc) that the
				// contains-socket scan refuses; `-r P --bind-socket P`
				// keeps them read-only (the -r mount above already
				// claimed the path).
				isDir := false
				if fd != nil {
					mode, err := fstatMode(int(fd.Fd()))
					isDir = err == nil && mode&syscall.S_IFMT == syscall.S_IFDIR
				} else if st, err := os.Stat(rp); err == nil {
					isDir = st.IsDir()
				}
				if isDir && !anyCovers(RuntimeRoots(), rp) {
					flag = "--bind"
					// rw is rw, whatever the flag was spelled as: the
					// persistence note must fire for --bind-socket dirs
					// too (it used to be gated on the label and stayed
					// silent for exactly these).
					if warning = PersistenceWarning(g.label, p, rp, home); warning != "" {
						warn(warning)
					}
				}
			}
			binds = append(binds, Bind{Flag: flag, Path: rp, FD: fd})
			bound[rp] = true
		}
	}
	if opts.Home {
		var homeSocks []string
		for _, cs := range ControlSockets() {
			if Covers(RealPath(home), cs.Path) && pathExists(cs.Path) {
				homeSocks = append(homeSocks, cs.Path)
			}
		}
		if len(homeSocks) > 0 {
			sort.Strings(homeSocks)
			warn("note: --home carries known control socket(s) inside $HOME: " +
				strings.Join(homeSocks, ", ") +
				" — that is your full identity; see the --home notes")
		}
	}
	return binds, nil
}

func anyCovers(roots []string, p string) bool {
	for _, r := range roots {
		if Covers(r, p) {
			return true
		}
	}
	return false
}

// Overlay is one validated --overlay source returned by CheckOverlays for
// staging: the resolved realpath plus its PINNED descriptor. Overlays keep
// no mount-mode decision — the writable layer is always the private store,
// never the source, which is exactly why the source can be pinned read-only.
type Overlay struct {
	Path string
	FD   *os.File
}

// CheckOverlays validates every --overlay source before anything is
// started and returns the resolved (realpath, pinned-fd) pairs in CLI
// order. Sources pass the SAME fd-first validation as -b/-r (protected
// paths, bidirectional control-socket matching, socket shape, the bounded
// contains-socket scan) with these overlay-specific differences:
//
//   - Only existing DIRECTORIES: a missing source or a file is a hard
//     error (there is nothing to merge a writable layer onto).
//   - NO opt-in anywhere: runtime-dir ground, socket files and
//     socket-bearing directories are refused outright — an overlay whose
//     lower layer is control-socket territory is as much an escape as a
//     rw bind of it, and there is no --bind-socket for overlays.
//   - A pinned fd is REQUIRED (nil is an error): bwrap resolves overlay
//     sources by PATH, so the launcher can only keep its swap protection
//     by re-mounting the pinned object in a private staging namespace.
//     Without fd binds (bwrap < 0.10) overlays refuse to run at all.
//
// Overlays are ephemeral by design (writes never reach the source tree),
// so persistence warnings do not apply. Cross-checks: duplicate or nested
// overlays, and any overlapping writable exposure — explicit binds
// (-b/-r/--bind-socket) or --home — are hard errors; a path must not be
// both an overlay's disposable view and some bind's persistent mount.
func CheckOverlays(opts *cliutil.Options, home string, pinner *Pinner,
	userBinds []Bind, warn func(string)) ([]Overlay, error) {
	if warn == nil {
		warn = func(string) {}
	}
	var out []Overlay
	for _, p := range opts.Overlay {
		rp := RealPath(p)
		if rp == "" || !filepath.IsAbs(rp) {
			return nil, fmt.Errorf("--overlay %s: cannot resolve to an absolute path", p)
		}
		// String-only rules first (no exemption, no opt-in): a path
		// refused on its shape reports the refusal, not a pin error.
		var hits []string
		for _, q := range ProtectedPaths(home) {
			if Covers(rp, q) {
				hits = append(hits, q)
			}
		}
		if len(hits) > 0 {
			sort.Strings(hits)
			return nil, fmt.Errorf("--overlay %s covers protected path(s): %s",
				p, strings.Join(hits, ", "))
		}
		for _, r := range NoDescendRoots {
			if Covers(r, rp) {
				return nil, fmt.Errorf("--overlay %s: %s is inside %s — kernel/pseudo-fs "+
					"ground (host escapes; the sandbox gets a fresh, safe view anyway)", p, rp, r)
			}
		}
		var sockHits []string
		for _, cs := range ControlSockets() {
			if Covers(rp, cs.Path) || Covers(cs.Path, rp) {
				sockHits = append(sockHits, cs.Path)
			}
		}
		if len(sockHits) > 0 {
			sort.Strings(sockHits)
			return nil, fmt.Errorf("--overlay %s overlaps host control socket(s): %s — "+
				"that hands the sandbox full control of the host", p, strings.Join(sockHits, ", "))
		}
		if anyCovers(RuntimeRoots(), rp) {
			return nil, fmt.Errorf("--overlay %s: %s lives under a runtime dir — control-socket "+
				"territory, and overlays have no opt-in for it", p, rp)
		}

		// fd-first, exactly like -b: pin, then validate the pinned object.
		if pinner == nil {
			return nil, fmt.Errorf("--overlay %s: internal: no pinner configured", p)
		}
		fd, fatal := pinner.Pin(rp, false)
		if fatal != nil {
			return nil, fmt.Errorf("--overlay %s: %v", p, fatal)
		}
		if fd == nil {
			return nil, fmt.Errorf("--overlay %s: no pinned descriptor — overlays require "+
				"fd binds (bwrap >= 0.10); refusing rather than mounting an unpinned source", p)
		}
		mode, err := fstatMode(int(fd.Fd()))
		if err != nil {
			return nil, fmt.Errorf("--overlay %s: cannot stat the pinned source: %v", p, err)
		}
		if mode&syscall.S_IFMT != syscall.S_IFDIR {
			return nil, fmt.Errorf("--overlay %s: %s is not a directory — overlays merge a "+
				"writable layer onto a directory", p, rp)
		}
		scanRoot := fmt.Sprintf("/proc/self/fd/%d", fd.Fd())
		if found := ContainsSocket(scanRoot, rp, opts.Verbose, warn); found != "" {
			shown := found
			if strings.HasPrefix(found, scanRoot) {
				shown = rp + found[len(scanRoot):]
			}
			return nil, fmt.Errorf("--overlay %s: contains a Unix socket (%s) — control-socket "+
				"territory; overlays have no --bind-socket-style opt-in", p, strconv.Quote(shown))
		}

		// Cross-checks against earlier overlays.
		for _, o := range out {
			if o.Path == rp {
				return nil, fmt.Errorf("--overlay %s: %s is already overlaid", p, rp)
			}
			if Covers(o.Path, rp) || Covers(rp, o.Path) {
				return nil, fmt.Errorf("--overlay %s overlaps --overlay %s — nested overlays "+
					"are not supported; overlay the outermost directory", p, o.Path)
			}
		}
		// And against every explicit mount: an overlay must not double as
		// a bind (the bind would shadow or persist what the overlay
		// promises to keep disposable).
		for _, b := range userBinds {
			if Covers(b.Path, rp) || Covers(rp, b.Path) {
				return nil, fmt.Errorf("--overlay %s overlaps the %s mount of %s — pick one "+
					"view per path", p, b.Flag, b.Path)
			}
		}
		// And --home: a rw $HOME bind under or over the overlay hands
		// writes a persistent path around the disposable layer.
		if opts.Home {
			if realHome := RealPath(home); Covers(realHome, rp) || Covers(rp, realHome) {
				return nil, fmt.Errorf("--overlay %s overlaps $HOME under --home — the home "+
					"bind would expose the same tree writable; drop --home or move the overlay", p)
			}
		}
		out = append(out, Overlay{Path: rp, FD: fd})
	}
	return out, nil
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
