package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Reuse the test executable as the real launcher and sandbox payload. This
// exercises the installed-filter handoff without a second language or compiler.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--_selfprobe":
			os.Exit(run(os.Args[1:]))
		case "--_test-launch":
			os.Exit(run(os.Args[2:]))
		case "--_test-payload":
			if err := livePayload(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("sandbox probe passed")
			os.Exit(0)
		case "--_test-descendant":
			if err := liveFilterCheck(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("ready")
			_, _ = io.Copy(io.Discard, os.Stdin)
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func TestRealBwrapSecurityBoundary(t *testing.T) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("real-bwrap smoke: bwrap is not installed")
	}
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("real-bwrap smoke: socat is not installed")
	}
	// Probe the namespace boundary without a filter first. Only recognized
	// host restrictions skip; an actual filtered launch failure is a failure.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	probe := exec.CommandContext(ctx, bwrap, "--unshare-all", "--die-with-parent",
		"--new-session", "--as-pid-1", "--ro-bind", "/", "/", "--", "/bin/true")
	out, probeErr := probe.CombinedOutput()
	cancel()
	if probeErr != nil {
		for _, reason := range []string{
			"No permissions to create a new namespace",
			"Creating new namespace failed: Operation not permitted",
			"Creating new namespace failed: Permission denied",
			"setting up uid map: Permission denied",
		} {
			if strings.Contains(string(out), reason) {
				t.Skipf("real-bwrap smoke: host does not permit the required namespaces: %s", out)
			}
		}
		t.Fatalf("namespace preflight: %v\n%s", probeErr, out)
	}

	// A short root avoids the Unix socket pathname limit under -race as well.
	root, err := os.MkdirTemp("/tmp", "sboxlive.")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	home, binddir := filepath.Join(root, "home"), filepath.Join(root, "project")
	for _, p := range []string{home, binddir} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(root, "probe.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.WriteString(c, "socket-ok")
		}
	}()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The automatic cwd and explicit bind reuse one validated source. Modern
	// bwrap must consume both distinct fd slots without leaking either one.
	cmd := exec.CommandContext(ctx, exe, "--_test-launch", "--upstream=",
		"-b", binddir, "--bind-socket", socket, "-r", exe, "--",
		exe, "--_test-payload", binddir, socket)
	cmd.Dir = binddir
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_RUNTIME_DIR=",
		"XDG_CACHE_HOME="+filepath.Join(root, "cache"))
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("filtered real-bwrap launch: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "sandbox probe passed") {
		t.Fatalf("sandbox payload did not report success:\n%s", out)
	}
	if data, err := os.ReadFile(filepath.Join(binddir, "payload-wrote")); err != nil || string(data) != "ok" {
		t.Fatalf("read-write bind did not reach the host source: %q, %v", data, err)
	}
}

func liveFilterCheck() error {
	// Kernel-derived constants are independent of the hand-maintained table.
	for _, nr := range []uintptr{syscall.SYS_UNSHARE, syscall.SYS_VMSPLICE} {
		_, _, errno := syscall.Syscall6(nr, 0, 0, 0, 0, 0, 0)
		if errno != syscall.EPERM {
			return fmt.Errorf("syscall %d in pid %d returned %v, want EPERM", nr, os.Getpid(), errno)
		}
	}
	return nil
}

func livePayload(args []string) error {
	if len(args) != 2 || os.Getpid() != 1 {
		return fmt.Errorf("payload must run as pid 1 with bind paths: pid=%d args=%q", os.Getpid(), args)
	}
	if err := liveFilterCheck(); err != nil {
		return err
	}
	binddir, socket := args[0], args[1]
	if st, err := os.Stat(socket); err != nil || st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("bound socket missing or wrong type: %v", err)
	}
	c, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		return fmt.Errorf("connect through read-only socket bind: %w", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	data, err := io.ReadAll(c)
	c.Close()
	if err != nil || string(data) != "socket-ok" {
		return fmt.Errorf("bound socket response: %q, %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(binddir, "payload-wrote"), []byte("ok"), 0o600); err != nil {
		return fmt.Errorf("write through directory bind: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	child := exec.Command(exe, "--_test-descendant")
	input, err := child.StdinPipe()
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := child.StdoutPipe()
	if err != nil {
		return err
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return err
	}
	defer func() { input.Close(); child.Wait() }()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "ready\n" {
		return fmt.Errorf("filtered descendant was not ready: %q, %v", line, err)
	}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	seenBridge, seenChild := false, false
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		status, err := os.ReadFile("/proc/" + p.Name() + "/status")
		if errors.Is(err, os.ErrNotExist) {
			continue // a transient bridge connection child exited
		}
		if err != nil {
			return err
		}
		filtered := false
		for _, line := range strings.Split(string(status), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "Seccomp:" && f[1] == "2" {
				filtered = true
			}
			if len(f) == 2 && f[0] == "Name:" && f[1] == "socat" {
				seenBridge = true
			}
		}
		if !filtered {
			return fmt.Errorf("unfiltered process inside sandbox: pid %d", pid)
		}
		seenChild = seenChild || pid == child.Process.Pid
	}
	if !seenBridge || !seenChild {
		return fmt.Errorf("missing processes in seccomp scan: bridge=%v descendant=%v", seenBridge, seenChild)
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, f := range fds {
		fd, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
		if errno == syscall.EBADF {
			continue // ReadDir's own descriptor has closed
		}
		if errno != 0 {
			return errno
		}
		if flags&0x200000 != 0 { // O_PATH: a leaked host mount traversal capability
			target, _ := os.Readlink("/proc/self/fd/" + f.Name())
			return fmt.Errorf("O_PATH descriptor leaked into payload: fd %d -> %s", fd, target)
		}
	}
	return nil
}
