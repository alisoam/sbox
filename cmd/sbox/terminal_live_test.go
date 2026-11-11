package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"sbox/internal/outputfilter"
)

type terminalSize struct{ Rows, Cols, X, Y uint16 }

func terminalIOCTL(fd uintptr, request uintptr, value unsafe.Pointer) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(value))
	if err != 0 {
		return err
	}
	return nil
}

func liveTerminalPayload(args []string) error {
	if len(args) != 1 || os.Getpid() == 1 {
		return fmt.Errorf("terminal payload requires a foreground child of the PID-1 bridge")
	}
	// The bridge shell must be PID 1 and this payload its foreground
	// child (exec-in-place would make the payload PID 1, which drops
	// default-disposition tty signals such as Ctrl-C's SIGINT).
	if os.Getppid() != 1 {
		return fmt.Errorf("payload ppid = %d, want the PID-1 bridge shell", os.Getppid())
	}
	pid1, err := os.ReadFile("/proc/1/cmdline")
	if err != nil {
		return err
	}
	if !bytes.Contains(pid1, []byte("sbox-sh")) {
		return fmt.Errorf("PID 1 is not the sbox bridge shell: %q", pid1)
	}
	if err := liveFilterCheck(); err != nil {
		return err
	}
	if err := noOPathFDs(); err != nil {
		return err
	}
	if grepStatus("", "Seccomp") != "2" {
		return fmt.Errorf("terminal payload is not filtered")
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("no controlling terminal: %w", err)
	}
	defer tty.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(0, &st); err != nil {
		return err
	}
	if strconv.FormatUint(st.Rdev, 10) == args[0] {
		return fmt.Errorf("host tty entered the sandbox")
	}
	var size terminalSize
	if err := terminalIOCTL(0, syscall.TIOCGWINSZ, unsafe.Pointer(&size)); err != nil {
		return err
	}
	if size.Rows != 37 || size.Cols != 111 {
		return fmt.Errorf("initial size: %+v", size)
	}
	fmt.Print("\x1b[2J\x1b[Hterminal-ready\n")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	if input != "keyboard-ok\n" {
		return fmt.Errorf("input = %q", input)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := terminalIOCTL(0, syscall.TIOCGWINSZ, unsafe.Pointer(&size)); err != nil {
			return err
		}
		if size.Rows == 41 && size.Cols == 113 {
			fmt.Println("terminal-passed")
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("resize was not forwarded: %+v", size)
}

// A private outer PTY acts as the user's terminal. The sandbox must receive a
// different one, restore the outer termios, retain seccomp, and resize correctly.
func TestRealBwrapInteractiveTerminal(t *testing.T) {
	for _, mode := range []string{"bind", "single", "filtered", "single-filtered", "staged"} {
		t.Run(mode, func(t *testing.T) {
			exe := overlayModePreflight(t, mode != "staged")
			flags := []string{}
			if strings.Contains(mode, "filtered") {
				flags = append(flags, "--filter-output")
			}
			if strings.HasPrefix(mode, "single") {
				flags = append(flags, "--overlay-mode", "single")
			}
			p := startTerminalTest(t, exe, flags, mode != "bind" && mode != "filtered", func(hostTTY uint64) []string {
				return []string{exe, "--_test-terminal", strconv.FormatUint(hostTTY, 10)}
			})
			output := p.until(t, "terminal-ready")
			if strings.Contains(output, "\x1b[2J") == strings.Contains(mode, "filtered") {
				t.Fatalf("unexpected terminal filtering: %q", output)
			}
			size := terminalSize{Rows: 41, Cols: 113}
			if err := terminalIOCTL(p.master.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&size)); err != nil {
				t.Fatal(err)
			}
			if err := p.cmd.Process.Signal(syscall.SIGWINCH); err != nil {
				t.Fatal(err)
			}
			p.send(t, "keyboard-ok\n")
			p.until(t, "terminal-passed")
			p.wait(t)
		})
	}
}

func TestRealBwrapInteractiveInterrupt(t *testing.T) {
	exe := overlayModePreflight(t, true)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	p := startTerminalTest(t, exe, []string{"--overlay-mode", "single"}, true, func(uint64) []string {
		return []string{"/bin/bash", "--noprofile", "--norc", "-i"}
	})
	p.until(t, "bash-") // startup raw-mode transition intentionally flushes old input
	p.send(t, "printf 'ready-%s\\n' shell\n")
	p.until(t, "ready-shell")
	p.send(t, "printf 'waiting-%s\\n' child; sleep 30\n")
	p.until(t, "waiting-child")
	time.Sleep(100 * time.Millisecond) // allow the shell to foreground sleep
	p.send(t, "\x03")
	p.send(t, "printf 'survived-%s\\n' interrupt; exit\n")
	p.until(t, "survived-interrupt")
	p.wait(t)
}

// A DIRECT command (no interactive shell around it) used to be exec'd
// as PID 1, and the kernel drops default-disposition SIGINTs to PID 1 —
// Ctrl-C did nothing. The bridge must run it as a foreground child so
// the signal lands, and the sandbox must exit with the child's
// 128+SIGINT status. Readiness is signaled by the payload itself: a
// fixed delay would race slow starts (the race build caught exactly
// that), and an interrupt landing before the exec still kills the
// wrapper shell, which reports the same status.
func TestRealBwrapInteractiveInterruptDirectCommand(t *testing.T) {
	exe := overlayModePreflight(t, true)
	p := startTerminalTest(t, exe, []string{"--overlay-mode", "single"}, true, func(uint64) []string {
		return []string{"/bin/sh", "-c", `printf 'direct-ready\n'; exec /bin/sleep 30`}
	})
	p.until(t, "direct-ready")
	p.send(t, "\x03")
	select {
	case err := <-p.done:
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 128+int(syscall.SIGINT) {
			t.Fatalf("exit = %v, want status 130 (128+SIGINT)", err)
		}
	case <-time.After(10 * time.Second):
		p.cmd.Process.Kill()
		t.Fatal("Ctrl-C did not stop a direct PID-1 command")
	}
	var after syscall.Termios
	if err := terminalIOCTL(p.slave.Fd(), syscall.TCGETS, unsafe.Pointer(&after)); err != nil {
		t.Fatal(err)
	}
	if after != p.before {
		t.Fatal("host terminal settings were not restored")
	}
}

type terminalTestProcess struct {
	cmd           *exec.Cmd
	master, slave *os.File
	before        syscall.Termios
	done          chan error
}

func startTerminalTest(t *testing.T, exe string, flags []string, overlay bool, payload func(uint64) []string) *terminalTestProcess {
	t.Helper()
	master, slave, err := outputfilter.OpenPty()
	if err != nil {
		t.Fatal(err)
	}
	p := &terminalTestProcess{master: master, slave: slave, done: make(chan error, 1)}
	t.Cleanup(func() { master.Close(); slave.Close() })
	if err := terminalIOCTL(slave.Fd(), syscall.TCGETS, unsafe.Pointer(&p.before)); err != nil {
		t.Fatal(err)
	}
	size := terminalSize{Rows: 37, Cols: 111}
	if err := terminalIOCTL(master.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&size)); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(slave.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	home, project := filepath.Join(dir, "home"), filepath.Join(dir, "project")
	for _, path := range []string{home, project} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	argv := append([]string{"--_test-launch", "--upstream=", "-r", exe}, flags...)
	if overlay {
		argv = append(argv, "--overlay", project)
	}
	argv = append(argv, "--")
	argv = append(argv, payload(st.Rdev)...)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	p.cmd = exec.CommandContext(ctx, exe, argv...)
	p.cmd.Dir = project
	p.cmd.Env = append(os.Environ(), "HOME="+home, "XDG_RUNTIME_DIR=", "XDG_CACHE_HOME="+filepath.Join(dir, "cache"), "TERM=xterm-256color")
	p.cmd.Stdin, p.cmd.Stdout, p.cmd.Stderr = slave, slave, slave
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.cmd.Process.Kill(); <-p.done })
	return p
}

func (p *terminalTestProcess) send(t *testing.T, input string) {
	t.Helper()
	if _, err := p.master.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
}

func (p *terminalTestProcess) until(t *testing.T, marker string) string {
	t.Helper()
	if err := p.master.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	buf := make([]byte, 4096)
	for !strings.Contains(output.String(), marker) {
		n, err := p.master.Read(buf)
		output.Write(buf[:n])
		if err != nil {
			t.Fatalf("waiting for %q: %v; output %q", marker, err, output.String())
		}
	}
	return output.String()
}

func (p *terminalTestProcess) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-p.done:
		if err != nil {
			t.Fatalf("terminal launch: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminal launch did not exit")
	}
	var after syscall.Termios
	if err := terminalIOCTL(p.slave.Fd(), syscall.TCGETS, unsafe.Pointer(&after)); err != nil {
		t.Fatal(err)
	}
	if after != p.before {
		t.Fatal("host terminal settings were not restored")
	}
}
