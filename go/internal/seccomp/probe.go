package seccomp

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

// errno values straight from the syscall package (kernel-header ground
// truth; both are arch-independent on Linux: EPERM=1, ENOSYS=38).
const (
	syscallEPERM  uint32 = uint32(syscall.EPERM)
	syscallENOSYS uint32 = uint32(syscall.ENOSYS)
)

// prctl constants from linux/prctl.h.
const (
	prSetNoNewPrivs   = 38
	prSetSeccomp      = 22
	seccompModeFilter = 2
)

// Probe exit codes map child failures to diagnostics in the launcher.
const (
	probeOK           = 0
	probeUnshare      = 3  // unshare(0) not denied (the number that once shipped wrong)
	probeIoctlTIOCSTI = 30 // ioctl(TIOCSTI) not denied
	probeSocketVSOCK  = 31 // socket(AF_VSOCK) not denied
	probePersonaSet   = 32 // personality(0) not denied
	probePtrace       = 33 // ptrace(PTRACE_ATTACH) not denied
	probePersonaGet   = 34 // personality(0xffffffff) query not ALLOWED
	probeCrashed      = 4  // exception in the probe child
	probeNoInstall    = 5  // prctl(PR_SET_SECCOMP) failed: cannot install here
)

// sockFilter is one cBPF instruction (linux/filter.h); LE-packed 8 bytes.
type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// sockFprog is the prctl(PR_SET_SECCOMP) program wrapper.
type sockFprog struct {
	len    uint16
	filter *sockFilter
}

// SelfProbe verifies on THIS machine, before anything starts, that the
// compiled filter denies what it claims — a wrong table entry fails
// silently otherwise (the filter loads and denies the WRONG syscall;
// unshare once shipped with ioctl's number). Go cannot safely return
// from a raw fork and PR_SET_SECCOMP is per-thread, so the
// binary re-executes itself as the probe child (sbox --_selfprobe): exe
// is the launcher (os.Executable()), argv the hidden flag spelling. The
// probe child receives the filter bytes on stdin and uses Go's
// syscall.SYS_* numbers — kernel-header-derived ground truth the
// hand-typed table cannot fool. Returns nil when every probe came back as expected, else
// the die()-equivalent error. Cost: one exec, about a millisecond.
func SelfProbe(exe string, argv []string, bpf []byte) error {
	cmd := exec.Command(exe, argv...)
	cmd.Stdin = bytes.NewReader(bpf)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	err := cmd.Run()
	code := probeOK
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			return fmt.Errorf("seccomp self-probe: cannot run the probe child: %v", err)
		}
		code = ee.ExitCode() // -1 when a signal killed the child
	}
	detail := map[int]string{
		probeOK:           "",
		probeUnshare:      "unshare(0) was not denied by the filter — the hand-typed syscall table does not match this machine",
		probeIoctlTIOCSTI: "ioctl(TIOCSTI) was not denied by the filter",
		probeSocketVSOCK:  "socket(AF_VSOCK) was not denied by the filter",
		probePersonaSet:   "personality(0) was not denied by the filter",
		probePtrace:       "ptrace(PTRACE_ATTACH) was not denied by the filter",
		probePersonaGet:   "personality(0xffffffff) query was not ALLOWED by the filter",
		probeCrashed:      "probe child crashed",
		probeNoInstall:    "cannot install seccomp filters here (prctl PR_SET_SECCOMP)",
	}[code]
	if detail == "" && code != probeOK {
		detail = "probe child died unexpectedly"
	}
	if code == probeOK {
		return nil
	}
	return fmt.Errorf("seccomp self-probe failed: %s — refusing to run (pass --no-seccomp to override)", detail)
}

// ProbeChild is the --_selfprobe child entry (cmd/sbox routes the hidden
// flag here; tests re-exec the test binary through it). It never
// returns: reads the compiled filter on stdin, installs it
// (PR_SET_NO_NEW_PRIVS + PR_SET_SECCOMP — the same prctl path the old
// in-sandbox helper used), then calls the probe syscalls and reports via
// the exit-code vocabulary above. All probes are harmless no-ops with
// distinguishable UNFILTERED errors: unshare(0) (EINVAL), ioctl(TIOCSTI)
// on a non-tty fd (ENOTTY), socket(AF_VSOCK) (succeeds or EAFNOSUPPORT),
// personality(0) (succeeds), ptrace(PTRACE_ATTACH, 0) (EPERM-free path is
// ESRCH) — and, as the one ALLOW check, personality(0xffffffff) (the
// setarch read a too-strict filter would break silently).
func ProbeChild() {
	// PR_SET_SECCOMP filters the calling THREAD; the Go runtime may
	// migrate us otherwise. Everything between here and exit stays on
	// this thread.
	runtime.LockOSThread()

	ok := func() (code int) {
		defer func() {
			if recover() != nil {
				code = probeCrashed // reported through the exit status only
			}
		}()
		bpf, err := io.ReadAll(os.Stdin)
		if err != nil || len(bpf) == 0 || len(bpf)%8 != 0 {
			return probeCrashed
		}
		n := len(bpf) / 8
		filters := (*[1 << 20]sockFilter)(unsafe.Pointer(&bpf[0]))[:n:n]
		prog := sockFprog{len: uint16(n), filter: &filters[0]}

		// /dev/null opened before the filter: after it, openat still
		// passes, but there is no reason to exercise anything but probes.
		devnull, err := os.OpenFile(os.DevNull, os.O_RDWR|syscall.O_CLOEXEC, 0)
		if err != nil {
			return probeCrashed
		}
		var arg = [1]byte{'x'}

		install := func(trap, a1, a2, a3 uintptr) bool {
			r0, _, _ := syscall.Syscall6(trap, a1, a2, a3, 0, 0, 0)
			return r0 == 0
		}
		if !install(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0) {
			return probeNoInstall // cannot install — bwrap could not either
		}
		if !install(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter,
			uintptr(unsafe.Pointer(&prog))) {
			return probeNoInstall
		}

		call := func(nr, a1, a2, a3 uintptr) syscall.Errno {
			_, _, errno := syscall.Syscall(nr, a1, a2, a3)
			return errno
		}
		denied := func(errno syscall.Errno) bool {
			return errno == syscall.EPERM
		}

		if !denied(call(syscall.SYS_UNSHARE, 0, 0, 0)) {
			return probeUnshare
		}
		if !denied(call(syscall.SYS_IOCTL, devnull.Fd(), tiocsti,
			uintptr(unsafe.Pointer(&arg[0])))) {
			return probeIoctlTIOCSTI
		}
		// AF_VSOCK is 40 on every ABI we support.
		if !denied(call(syscall.SYS_SOCKET, afVSOCK, 1 /*SOCK_STREAM*/, 0)) {
			return probeSocketVSOCK
		}
		if !denied(call(syscall.SYS_PERSONALITY, 0, 0, 0)) {
			return probePersonaSet
		}
		// ... and the 0xffffffff QUERY must stay ALLOWED — setarch-style
		// reads would silently break if the filter denied it too.
		if denied(call(syscall.SYS_PERSONALITY, PersonalityQuery, 0, 0)) {
			return probePersonaGet
		}
		// PTRACE_ATTACH to pid 0 errors either way; EPERM only under
		// the filter.
		if !denied(call(syscall.SYS_PTRACE, 16 /*PTRACE_ATTACH*/, 0, 0)) {
			return probePtrace
		}
		return probeOK
	}()
	os.Exit(ok)
}

// FilterFD hands the compiled filter to bwrap through a pipe, exactly
// like seccomp_fd_args' tail: the filter bytes are written (looped — a
// plain pipe write completes for << 64K but the loop is belt and braces)
// and the write end closed, so bwrap reads a clean EOF after the last
// instruction. Returns the read end for the bwrap argv (--add-seccomp-fd
// N / --seccomp N) and ExtraFiles; the caller closes it after the spawn.
func FilterFD(bpf []byte) (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	view := bpf
	for len(view) > 0 {
		n, err := w.Write(view)
		if err != nil {
			r.Close()
			w.Close()
			return nil, err
		}
		view = view[n:]
	}
	if err := w.Close(); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}
