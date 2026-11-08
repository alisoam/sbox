package bindpolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// oPath is Linux's O_PATH (010000000, asm-generic). The stdlib syscall
// package exports it only on some GOARCHs (amd64 notably lacks it), but
// the value is uniform across the architectures sbox targets.
const oPath = 0x200000

// OpenPathPinned O_PATH|O_NOFOLLOW-opens path, refusing ANY symlink on
// the way (sbox.py's open_path_pinned). The input is always a RealPath()
// result (fully resolved — every caller resolves first), so a symlink met
// anywhere in the walk — intermediate component or final object — means
// the tree changed since realpath() ran: a concurrent sandbox swapped a
// component (or the object itself) for a symlink to redirect the bind
// (e.g. onto ~/.ssh). Each component is opened with openat(O_PATH|
// O_NOFOLLOW) relative to the pinned parent directory only, so the walk
// cannot be steered through a re-resolved path. There is deliberately NO
// "expected inode" parameter and no symlink resolution: validation
// happens fd-FIRST (the caller fstat()s and scans this very fd), so the
// fd you validated is the fd you mount. Errors are the die()-equivalents
// the Python produces (the caller propagates them fatally); the original
// errno is wrapped for ENOENT recognition (Pin's allowMissing).
func OpenPathPinned(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("cannot pin bind source %s (pinning needs an absolute path) — refusing", path)
	}
	root, err := syscall.Open("/", oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot pin bind source %s (%s) — refusing", path, err)
	}
	stack := []int{root}
	final := -1
	// Close every ancestor still held on any exit path; `final` is never
	// in the stack (it is popped below when it is the root itself).
	defer func() {
		for _, fd := range stack {
			syscall.Close(fd)
		}
	}()

	comps := strings.Split(path, "/")
	for len(comps) > 0 {
		comp := comps[0]
		comps = comps[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			if len(stack) > 1 {
				syscall.Close(stack[len(stack)-1])
				stack = stack[:len(stack)-1]
			}
			continue
		}
		cur, err := syscall.Openat(stack[len(stack)-1], comp,
			oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("cannot pin bind source %s (%s) — refusing: %w",
				path, errnoText(err), err)
		}
		mode, err := fstatMode(cur)
		if err != nil {
			syscall.Close(cur)
			return nil, fmt.Errorf("cannot pin bind source %s (%s) — refusing: %w",
				path, errnoText(err), err)
		}
		if mode&syscall.S_IFMT == syscall.S_IFLNK {
			syscall.Close(cur)
			return nil, fmt.Errorf("%s: component %q is a symlink — "+
				"the path changed between realpath() and the pin "+
				"(a concurrent sandbox trying to redirect the bind?) — refusing", path, comp)
		}
		if len(comps) > 0 {
			stack = append(stack, cur)
		} else {
			final = cur
		}
	}
	if final < 0 { // path was "/" (or only . / .. components)
		final = stack[len(stack)-1]
		stack = stack[:len(stack)-1]
	}
	return os.NewFile(uintptr(final), path), nil
}

// FdReaches reports whether the kernel still reaches fd's object at
// exactly path: the readlink of /proc/self/fd/<fd> is the kernel's own
// view of what the fd holds — immune to whatever raced with the open (a
// rename or swap shows up as a different path, a deleted object as
// " (deleted)").
func FdReaches(f *os.File, path string) bool {
	got, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	return err == nil && got == path
}

// fstatMode stats a raw fd and returns its st_mode word.
func fstatMode(fd int) (uint32, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return 0, err
	}
	return st.Mode, nil
}

// errnoText is an errno's strerror (Python's e.strerror — capitalized,
// like libc's strerror: "No such file or directory").
func errnoText(err error) string {
	s := err.Error()
	if s != "" {
		s = strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

// Pinner pins validated bind sources as O_PATH fds for bwrap
// --[ro-]bind-fd (sbox.py's BindPinner). One fd per source path (cached):
// the cwd mount and a -b of the same path share the object validation
// checked. With enabled=false (old bwrap, or capabilities unknown) every
// Pin is a no-op returning nil, and callers emit the plain path-based
// flags instead — with the documented path-based (TOCTOU) checks.
type Pinner struct {
	enabled bool
	fds     map[string]*os.File
}

// NewPinner returns a Pinner; pins are real only when enabled.
func NewPinner(enabled bool) *Pinner {
	return &Pinner{enabled: enabled, fds: map[string]*os.File{}}
}

// Pin returns an O_PATH fd for path (a realpath), or nil when the path
// is legitimately missing (allowMissing, used for --bind-socket of
// not-yet-created runtime paths: the path form then preserves bwrap's
// own not-found error). A missing -b/-r source DIES instead: those use
// non--try bwrap flags, so bwrap would fail on a missing source anyway,
// and falling back to the path form would re-open the swap race (pin
// nothing, let bwrap resolve a path a concurrent sandbox can plant a
// symlink at). Anything else — a symlink on the walk, or the kernel no
// longer reaching the pinned object at path — dies too: an actively
// raced path must not silently fall back to the TOCTOU-vulnerable path
// form.
func (p *Pinner) Pin(path string, allowMissing bool) (*os.File, error) {
	if f, ok := p.fds[path]; ok {
		return f, nil
	}
	if !p.enabled {
		return nil, nil
	}
	f, err := OpenPathPinned(path)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) && allowMissing {
			return nil, nil
		}
		return nil, err
	}
	if !FdReaches(f, path) {
		actual, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
		f.Close()
		return nil, fmt.Errorf("%s: changed during validation — the kernel reaches it as %q (rename or swap?) — refusing",
			path, actual)
	}
	p.fds[path] = f
	return f, nil
}

// Release closes and forgets the pin for path — called when a validated
// source ends up NOT being mounted (a refused cwd): a live O_PATH fd for
// host ground must never linger in the bookkeeping, because the spawned
// argv derives from the pins but the cache is what gets closed after the
// spawn. No-op for unpinned paths.
func (p *Pinner) Release(path string) {
	if f, ok := p.fds[path]; ok {
		delete(p.fds, path)
		f.Close()
	}
}

// Close tears every pin down (launch teardown).
func (p *Pinner) Close() {
	for k, f := range p.fds {
		delete(p.fds, k)
		f.Close()
	}
}
