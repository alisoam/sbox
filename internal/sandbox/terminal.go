package sandbox

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
)

const terminalHelperPath = "/run/sbox-terminal"

// terminalHelper copies the running executable, not a pathname that can be
// replaced, into the launcher's private work directory. This also supports
// bwrap versions without fd binds. The sandbox only receives a read-only mount.
func terminalHelper(work string) (path string, err error) {
	src, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer src.Close()
	path = filepath.Join(work, "terminal")
	dst, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return path, nil
}

// TerminalExec is the hidden --_terminal-exec entry. Bwrap has already installed
// seccomp and created the new session. Claim only the fresh PTY on fd 0, then
// replace this process with the proxy bridge/payload: no unfiltered helper or
// extra reaper remains, and the payload keeps --as-pid-1 semantics.
func TerminalExec(argv []string) error {
	if os.Getpid() != 1 || len(argv) == 0 {
		return fmt.Errorf("internal: --_terminal-exec requires a sandbox PID 1 and a command")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, 0, syscall.TIOCSCTTY, 0); err != 0 {
		return fmt.Errorf("cannot attach sandbox controlling terminal: %w", err)
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, argv, os.Environ())
}
