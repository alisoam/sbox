// The pty pair and the host-terminal shims: openpty, isatty, raw mode,
// winsize forwarding, the --filter-output child-stdin decision and its
// fail-closed refusals, and the diagnostic emitters (CR-safe while the
// host tty is raw). These helpers use the standard syscall package.

package outputfilter

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// pty/tty ioctls and tcsetattr modes Go's syscall package does not name
// on linux (TCGETS/TCSETS/TIOCGWINSZ/TIOCSWINSZ are there).
const (
	tiocgptn   = 0x80045430 // TIOCGPTN: pty slave number
	tiocsptlck = 0x40045431 // TIOCSPTLCK: pty locking (0 = unlock)
	tcsetsf    = 0x5404     // TCSAFLUSH (tcsetattr drains + flushes)
	tcsetsw    = 0x5403     // TCSADRAIN (tcsetattr drains)
)

// winSize is struct winsize (TIOCGWINSZ/TIOCSWINSZ).
type winSize struct {
	Rows, Cols, Xpixel, Ypixel uint16
}

func ioctlPtr(fd, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

func tcgetattr(fd uintptr, t *syscall.Termios) error {
	return ioctlPtr(fd, syscall.TCGETS, unsafe.Pointer(t))
}

func tcsetattr(fd uintptr, req uintptr, t *syscall.Termios) error {
	return ioctlPtr(fd, req, unsafe.Pointer(t))
}

// isTTY reports whether fd is a terminal (a successful TCGETS — the
// classic isatty(3), which os.File ModeCharDevice cannot replace:
// /dev/null is a character device too).
func isTTY(fd uintptr) bool {
	var t syscall.Termios
	return tcgetattr(fd, &t) == nil
}

// IsTTY reports whether f is an open terminal. It also handles absent stdio.
func IsTTY(f *os.File) bool { return f != nil && isTTY(f.Fd()) }

// InteractiveStdio selects automatic terminal forwarding only when all three
// streams are terminals. Redirected output and piped input keep their byte-exact
// direct-stream behavior unless --filter-output explicitly selects a PTY.
func InteractiveStdio() bool {
	return IsTTY(os.Stdin) && IsTTY(os.Stdout) && IsTTY(os.Stderr)
}

// OpenPty allocates a fresh pty pair (pty.openpty): a non-blocking
// master (poller-registered by os.OpenFile, so the pump can evict a
// parked Read with a read deadline) and a blocking slave (the
// sandbox's stdio; the parent closes its copy right after the spawn —
// else the host holds EOF away from the pump).
func OpenPty() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx",
		os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	unlock := int32(0) // TIOCSPTLCK with 0: grantpt/unlockpt
	if err := ioctlPtr(master.Fd(), tiocsptlck, unsafe.Pointer(&unlock)); err != nil {
		master.Close()
		return nil, nil, err
	}
	var n uint32
	if err := ioctlPtr(master.Fd(), tiocgptn, unsafe.Pointer(&n)); err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n),
		os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

// CopyWinsize forwards a terminal resize (_copy_winsize): TIOCGWINSZ
// on the host tty, TIOCSWINSZ on the pty master (which also SIGWINCHes
// the pty's foreground pgrp). Best-effort: a resize racing a closed
// tty is dropped, never fatal.
func CopyWinsize(src, dst *os.File) {
	if src == nil || dst == nil {
		return
	}
	var ws winSize
	if err := ioctlPtr(src.Fd(), syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
		return
	}
	_ = ioctlPtr(dst.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&ws))
}

// HostTTY returns a host terminal fd for TIOCGWINSZ (_host_tty_fd):
// stdin, else stdout — nil when neither is a usable terminal.
func HostTTY() *os.File {
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		if f != nil && isTTY(f.Fd()) {
			return f
		}
	}
	return nil
}

// makeRaw applies POSIX.1-2017 raw mode, including the input-flow and
// local flags glibc cfmakeraw leaves unchanged. No output processing,
// 8-bit bytes with parity off, and MIN=1/TIME=0 byte-wise reads.
func makeRaw(t *syscall.Termios) {
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.IGNPAR |
		syscall.PARMRK | syscall.INPCK | syscall.ISTRIP | syscall.INLCR |
		syscall.IGNCR | syscall.ICRNL | syscall.IXON | syscall.IXANY |
		syscall.IXOFF
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHOE | syscall.ECHOK |
		syscall.ECHONL | syscall.ICANON | syscall.IEXTEN | syscall.ISIG |
		syscall.NOFLSH | syscall.TOSTOP
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0
}

// EnterRawMode puts the host stdin tty into raw mode (_enter_raw_mode):
// returns the fd and the saved termios for restoring, or (nil, nil)
// when stdin is not a usable tty. Raw mode is what makes byte-wise
// stdin forwarding possible (no line buffering, no host-side
// signal/echo processing). On success the package's raw-diagnostic
// flag flips (SetRawTerm): while the host tty is raw, every launcher
// diagnostic CRs its own newlines (OPOST is off).
func EnterRawMode() (*os.File, *syscall.Termios) {
	if os.Stdin == nil || !isTTY(os.Stdin.Fd()) {
		return nil, nil
	}
	fd := os.Stdin.Fd()
	var saved syscall.Termios
	if err := tcgetattr(fd, &saved); err != nil {
		return nil, nil
	}
	raw := saved
	makeRaw(&raw)
	// TCSAFLUSH: pending input is dropped at the
	// switch (a half-typed line must not leak into the sandbox).
	if err := tcsetattr(fd, tcsetsf, &raw); err != nil {
		return nil, nil
	}
	rawTerm.Store(true)
	return os.Stdin, &saved
}

// RestoreTermios restores a saved termios (_restore_termios), with
// TCSADRAIN. Best-effort: a dead tty cannot be restored.
func RestoreTermios(f *os.File, saved *syscall.Termios) {
	if f == nil || saved == nil {
		return
	}
	_ = tcsetattr(f.Fd(), tcsetsw, saved)
}

// CheckStdinEarly fails FAST (top of the launch, before the proxy, the
// self-test or the pty exist) on the cheap half of FilterChildStdin's
// refusal (_check_filter_stdin_early): a stdin that IS a terminal but
// cannot even be tcgetattr'd (hung-up tty) must die here rather than
// three subsystems later. The expensive half — raw mode itself failing
// while tcgetattr succeeds — is still caught by FilterChildStdin
// before anything is spawned.
func CheckStdinEarly() error {
	if os.Stdin == nil || !isTTY(os.Stdin.Fd()) {
		return nil
	}
	var t syscall.Termios
	if err := tcgetattr(os.Stdin.Fd(), &t); err != nil {
		return fmt.Errorf("--filter-output: stdin is a terminal but cannot be configured "+
			"(%v) — refusing to hand the host tty to the sandbox unfiltered", err)
	}
	return nil
}

// FilterChildStdin picks what to hand the sandbox as stdin under
// --filter-output (_filter_child_stdin): the pty slave for a real
// (raw-mode) host tty; the EXACT non-tty fd stdin wraps otherwise (a
// pipe/file inherits byte-exact — routing it through the pty would
// feed it to the slave's canonical line discipline: 4095-byte line
// truncation, ^D/^U/^W/^V/^R editing, ICRNL, ISIG). FAILS CLOSED (the
// returned error is die()) on a terminal that could not be put in raw
// mode: inheriting it would give the sandbox the host terminal fd
// itself, and a shell-launched process's tty fd 0 is O_RDWR —
// write(0, "\x1b]52;...") reaches the terminal emulator UNFILTERED, and
// keystrokes become readable. The decision is made on the very fd
// returned, never a different descriptor inherited blindly.
func FilterChildStdin(slave, rawStdin *os.File) (*os.File, error) {
	if rawStdin != nil {
		return slave, nil
	}
	if os.Stdin != nil && isTTY(os.Stdin.Fd()) {
		return nil, errors.New("--filter-output: stdin is a terminal but raw mode failed — " +
			"refusing to hand the host tty to the sandbox unfiltered")
	}
	return os.Stdin, nil
}

// rawTerm is true while --filter-output holds the host tty in raw mode:
// launcher diagnostics must CR their own newlines then (OPOST is off).
var rawTerm atomic.Bool

// SetRawTerm flips the raw-diagnostic flag (EnterRawMode sets it; the
// pump's teardown clears it right after restoring the termios).
func SetRawTerm(v bool) { rawTerm.Store(v) }

// RawTerm reports the flag.
func RawTerm() bool { return rawTerm.Load() }

// EmitDiag writes host-side diagnostic text on stderr (_emit_diag),
// CR-safe for a raw tty (the --filter-output pump and the sanitized
// proxy log both go through here). Best-effort: a closed stderr must
// not crash the launcher. Diagnostics are emitted as UTF-8.
func EmitDiag(text string) {
	if text == "" {
		return
	}
	if rawTerm.Load() {
		text = strings.ReplaceAll(text, "\n", "\r\n")
	}
	writeBestEffort(os.Stderr, text)
}

// EmitFiltered writes filtered sandbox output to the host terminal
// (_emit_filtered). Best-effort: stdout closed ⇒ filtering is moot,
// keep supervising.
func EmitFiltered(text string) {
	if text == "" {
		return
	}
	writeBestEffort(os.Stdout, text)
}

// Write through the descriptor's poller without os.File.Write's special
// SIGPIPE re-raise for fd 1/2. A closed consumer must leave the launcher
// alive to supervise its child and restore the terminal. This changes no
// signal dispositions, including those inherited by sandboxed commands.
func writeBestEffort(file *os.File, text string) {
	if file == nil {
		return
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return
	}
	data := []byte(text)
	_ = raw.Write(func(fd uintptr) bool {
		for len(data) > 0 {
			n, err := syscall.Write(int(fd), data)
			if n > 0 {
				data = data[n:]
			}
			switch err {
			case syscall.EINTR:
				continue
			case syscall.EAGAIN:
				return false // wait for the descriptor to become writable
			case nil:
				if n == 0 {
					return true
				}
			default:
				return true // EPIPE, a closed fd, or another permanent error
			}
		}
		return true
	})
}
