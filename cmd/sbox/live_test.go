package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
		case "--_selfprobe", "--_terminal-exec":
			os.Exit(run(os.Args[1:]))
		case "--_test-launch":
			os.Exit(run(os.Args[2:]))
		case "--_test-terminal":
			if err := liveTerminalPayload(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		case "--_test-payload":
			if err := livePayload(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("sandbox probe passed")
			os.Exit(0)
		case "--_test-ovl-payload":
			if err := liveOverlayPayload(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("overlay probe passed")
			os.Exit(0)
		case "--_test-ovl-child":
			if err := liveOverlayChild(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		case "--_test-ovl-hold":
			if err := liveOverlayHold(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("hold done")
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

// --- live --overlay boundary tests --------------------------------------

// overlayPreflight skips unless the host can run the arrangement: bwrap
// with the overlay options, socat for the in-sandbox bridge, and
// namespaces the plain boundary test also needs. Returns the test
// binary (symlinks resolved).
func overlayPreflight(t *testing.T) string {
	return overlayModePreflight(t, false)
}

func overlayModePreflight(t *testing.T, single bool) string {
	t.Helper()
	bwrapBin, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("overlay boundary: bwrap is not installed")
	}
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("overlay boundary: socat is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bwrapBin, "--help").CombinedOutput()
	if err != nil {
		t.Skipf("overlay boundary: bwrap --help failed: %v", err)
	}
	if !strings.Contains(string(out), "--overlay-src") {
		t.Skipf("overlay boundary: bwrap lacks overlay support (need >= 0.11)")
	}
	probe := exec.CommandContext(ctx, bwrapBin, "--unshare-all", "--die-with-parent",
		"--new-session", "--as-pid-1", "--ro-bind", "/", "/", "--", "/bin/true")
	pout, probeErr := probe.CombinedOutput()
	if probeErr != nil {
		for _, reason := range []string{
			"No permissions to create a new namespace",
			"Creating new namespace failed: Operation not permitted",
			"Creating new namespace failed: Permission denied",
			"setting up uid map: Permission denied",
		} {
			if strings.Contains(string(pout), reason) {
				t.Skipf("overlay boundary: host does not permit the required namespaces: %s", pout)
			}
		}
		t.Fatalf("overlay boundary: namespace preflight: %v\n%s", probeErr, pout)
	}
	// This independent preflight uses no sbox-generated mount arrangement.
	// A failure here identifies a host namespace restriction, not a launch bug.
	if !single {
		nested := exec.CommandContext(ctx, bwrapBin,
			"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
			"--unshare-net", "--die-with-parent", "--ro-bind", "/", "/",
			"--proc", "/proc", "--dev", "/dev", "--", bwrapBin,
			"--unshare-all", "--die-with-parent", "--new-session", "--as-pid-1",
			"--ro-bind", "/", "/", "--", "/bin/true")
		if out, err := nested.CombinedOutput(); err != nil {
			for _, reason := range []string{
				"No permissions to create a new namespace",
				"Creating new namespace failed: Operation not permitted",
				"Creating new namespace failed: Permission denied",
				"setting up uid map: Permission denied",
			} {
				if strings.Contains(string(out), reason) {
					t.Skipf("overlay boundary: host blocks nested namespaces: %s", out)
				}
			}
			t.Fatalf("overlay boundary: nested namespace preflight: %v\n%s", err, out)
		}
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// overlayLaunch runs the real launcher with sboxOpts before "--" and
// the payload argv after it. Returns combined output and exit code.
func overlayLaunch(t *testing.T, dir, home string, timeout time.Duration,
	sboxOpts []string, payload ...string) (string, int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	argv := append([]string{"--_test-launch", "--upstream=", "-r", exe}, sboxOpts...)
	argv = append(argv, "--")
	argv = append(argv, payload...)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, argv...)
	cmd.Dir = dir
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"XDG_RUNTIME_DIR=",
		"XDG_CACHE_HOME="+filepath.Join(filepath.Dir(home), "cache"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	}
	return string(out), -1
}

// snapshotTree captures (path, mode, link target, content digest) of a
// tree for a deep-equality check that nothing leaked through an overlay.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		info, err := d.Info()
		if err != nil {
			return err
		}
		key := rel + "|mode=" + strconv.FormatUint(uint64(info.Mode().Perm()), 8)
		switch {
		case d.IsDir():
			out[key] = "dir"
		case info.Mode()&os.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			out[key+"|link"] = target
		default:
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			out[key] = hex.EncodeToString(sum[:])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// plantTree seeds a deterministic project fixture and returns its
// snapshot.
func plantTree(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{
		"README.md":     "# project\n",
		"src/main.c":    "int main(void){return 0;}\n",
		"docs/notes.md": "notes\n",
		"to-delete.txt": "delete me\n",
		"to-rename.txt": "rename me\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return snapshotTree(t, root)
}

func requireTreeUnchanged(t *testing.T, root string, want map[string]string, what string) {
	t.Helper()
	got := snapshotTree(t, root)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: tree %s changed under the overlay:\n got %v\nwant %v", what, root, got, want)
	}
}

// TestOverlayValidationRefusals uses dependency shims so validation runs
// regardless of the installed bwrap version (or whether it is installed).
// Only the capability probe may execute; every refusal precedes sandbox setup.
func TestOverlayValidationRefusals(t *testing.T) {
	binDir := t.TempDir()
	writeShimMain(t, binDir, "bwrap", `if [ "$#" -eq 1 ] && [ "$1" = "--help" ]; then
    printf '%s\n' '--bind-fd FD DEST' '--ro-bind-fd FD DEST' \
        '--overlay-src SRC' '--overlay RWSRC WORKDIR DEST' '--add-seccomp-fd FD'
    exit 0
fi
echo 'unexpected bwrap invocation' >&2
exit 99`)
	writeShimMain(t, binDir, "socat", "echo 'unexpected socat invocation' >&2\nexit 99")
	t.Setenv("PATH", binDir)
	bwrapBin := filepath.Join(binDir, "bwrap")
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	proj := filepath.Join(dir, "proj")
	homeChild := filepath.Join(home, "inner")
	for _, d := range []string{home, proj, homeChild, filepath.Join(dir, "cache")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name     string
		sboxOpts []string
		want     string
	}{
		{"missing source", []string{"--overlay", filepath.Join(dir, "nope")}, "cannot pin bind source"},
		{"protected path", []string{"--overlay", "/etc"}, "covers protected path"},
		{"inside /proc", []string{"--overlay", "/proc/1"}, "is inside /proc"},
		{"file not dir", []string{"--overlay", bwrapBin}, "is not a directory"},
		{"duplicate", []string{"--overlay", proj, "--overlay", proj}, "already overlaid"},
		{"conflicting bind", []string{"--overlay", proj, "-b", proj}, "overlaps the --bind mount"},
		{"conflicting --home", []string{"--home", "--overlay", homeChild}, "overlaps $HOME under --home"},
		{"bad size", []string{"--overlay-size", "wat"}, "invalid size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, rc := overlayLaunch(t, dir, home, 20*time.Second, tc.sboxOpts, "/bin/true")
			if rc == 0 || !strings.Contains(out, tc.want) {
				t.Errorf("rc = %d out = %q, want a refusal mentioning %q", rc, out, tc.want)
			}
		})
	}
}

// grepStatus reads a key line from /proc/<pid>/status (self for "").
func grepStatus(pid, key string) string {
	f := "/proc/self/status"
	if pid != "" {
		f = "/proc/" + pid + "/status"
	}
	data, err := os.ReadFile(f)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if fld := strings.Fields(line); len(fld) == 2 && fld[0] == key+":" {
			return fld[1]
		}
	}
	return ""
}

// liveOverlayChild is the filtered-descendant check inside the overlay
// sandbox (dispatched from TestMain).
func liveOverlayChild() error {
	if err := liveFilterCheck(); err != nil {
		return err
	}
	if got := grepStatus("", "Seccomp"); got != "2" {
		return fmt.Errorf("descendant Seccomp = %q, want 2", got)
	}
	return nil
}

// noOPathFDs verifies no O_PATH descriptor leaked into the payload (the
// CVE-2024-21626 class — /proc/self/fd/N/.. would walk host ground).
func noOPathFDs() error {
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
			continue
		}
		if errno != 0 {
			return errno
		}
		if flags&0x200000 != 0 { // O_PATH
			target, _ := os.Readlink("/proc/self/fd/" + f.Name())
			return fmt.Errorf("O_PATH descriptor leaked into payload: fd %d -> %s", fd, target)
		}
	}
	return nil
}

// liveOverlayPayload runs as pid 1 inside the overlay sandbox and hammers
// the merged views: create/overwrite/delete/rename/chmod/symlink/
// hardlink, staging invisibility, fd closure, filter coverage of a
// descendant, and the storage cap. args: src1 src2 cwd [single]
func liveOverlayPayload(args []string) error {
	single := len(args) == 4 && args[3] == "single"
	if len(args) != 3 && !single {
		return fmt.Errorf("payload wants src1 src2 cwd, got %q", args)
	}
	if os.Getpid() != 1 {
		return fmt.Errorf("payload must run as pid 1, got %d", os.Getpid())
	}
	if err := liveFilterCheck(); err != nil {
		return err
	}
	if got := grepStatus("", "Seccomp"); got != "2" {
		return fmt.Errorf("payload Seccomp = %q, want 2 (filter must survive the staging arrangement)", got)
	}
	// staging paths and the pivot leftovers are unreachable
	for _, p := range []string{"/tmp/sbox-stage", "/oldroot"} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			return fmt.Errorf("%s is visible inside the sandbox (err = %v)", p, err)
		}
	}
	if err := noOPathFDs(); err != nil {
		return err
	}
	// the cwd is the overlay's merged view (the launch ran here)
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	if wd != args[2] {
		return fmt.Errorf("cwd = %q, want the overlaid %q", wd, args[2])
	}

	for _, src := range []string{args[0], args[1]} {
		// create
		if err := os.WriteFile(filepath.Join(src, "created.txt"), []byte("new\n"), 0o644); err != nil {
			return fmt.Errorf("create through %s: %w", src, err)
		}
		if got, err := os.ReadFile(filepath.Join(src, "created.txt")); err != nil || string(got) != "new\n" {
			return fmt.Errorf("read back created file in %s: %q %v", src, got, err)
		}
		// overwrite (merged view must show the new bytes)
		if err := os.WriteFile(filepath.Join(src, "README.md"), []byte("changed\n"), 0o644); err != nil {
			return fmt.Errorf("overwrite through %s: %w", src, err)
		}
		if got, _ := os.ReadFile(filepath.Join(src, "README.md")); string(got) != "changed\n" {
			return fmt.Errorf("merged view of %s/README.md shows %q", src, got)
		}
		// delete
		if err := os.Remove(filepath.Join(src, "to-delete.txt")); err != nil {
			return fmt.Errorf("delete through %s: %w", src, err)
		}
		if _, err := os.Lstat(filepath.Join(src, "to-delete.txt")); !os.IsNotExist(err) {
			return fmt.Errorf("deleted file still visible in %s (err = %v)", src, err)
		}
		// rename
		if err := os.Rename(filepath.Join(src, "to-rename.txt"), filepath.Join(src, "renamed.txt")); err != nil {
			return fmt.Errorf("rename through %s: %w", src, err)
		}
		if got, _ := os.ReadFile(filepath.Join(src, "renamed.txt")); string(got) != "rename me\n" {
			return fmt.Errorf("renamed file content in %s: %q", src, got)
		}
		// chmod
		if err := os.Chmod(filepath.Join(src, "README.md"), 0o600); err != nil {
			return fmt.Errorf("chmod through %s: %w", src, err)
		}
		if st, err := os.Stat(filepath.Join(src, "README.md")); err != nil || st.Mode().Perm() != 0o600 {
			return fmt.Errorf("chmod not visible in %s: %v", src, err)
		}
		// symlink
		if err := os.Symlink("README.md", filepath.Join(src, "link.md")); err != nil {
			return fmt.Errorf("symlink through %s: %w", src, err)
		}
		if got, err := os.Readlink(filepath.Join(src, "link.md")); err != nil || got != "README.md" {
			return fmt.Errorf("symlink readback in %s: %q %v", src, got, err)
		}
		// hard link (both ends freshly created, so both live on the upper)
		if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("link\n"), 0o644); err != nil {
			return fmt.Errorf("hardlink source in %s: %w", src, err)
		}
		if err := os.Link(filepath.Join(src, "a.txt"), filepath.Join(src, "b.txt")); err != nil {
			return fmt.Errorf("hardlink through %s: %w", src, err)
		}
		if got, _ := os.ReadFile(filepath.Join(src, "b.txt")); string(got) != "link\n" {
			return fmt.Errorf("hardlink content in %s: %q", src, got)
		}
		// nested directory creation
		if err := os.MkdirAll(filepath.Join(src, "build", "obj"), 0o755); err != nil {
			return fmt.Errorf("mkdir through %s: %w", src, err)
		}
		if err := os.WriteFile(filepath.Join(src, "build", "obj", "o.bin"), []byte("x"), 0o644); err != nil {
			return fmt.Errorf("write in new dir in %s: %w", src, err)
		}
	}

	// the storage cap: a 2MiB write into the 1MiB shared store must
	// FAIL — never fall back onto the host tree.
	big := make([]byte, 2<<20)
	err = os.WriteFile(filepath.Join(args[0], "big.bin"), big, 0o644)
	if single && err != nil {
		return fmt.Errorf("single overlay 2MiB write failed: %w", err)
	}
	if !single && !errors.Is(err, syscall.ENOSPC) {
		return fmt.Errorf("2MiB write into a 1MiB overlay store: %v; want ENOSPC", err)
	}

	// a descendant inherits the filter and the same constraints
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	out, err := exec.Command(exe, "--_test-ovl-child").CombinedOutput()
	if err != nil {
		return fmt.Errorf("filtered descendant: %v\n%s", err, out)
	}
	return nil
}

// liveOverlayHold waits for <signal>/go (host-side coordination), then
// writes hostile.txt into the overlaid src — used by the rename-swap and
// teardown tests. args: src signal
func liveOverlayHold(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("hold wants src signal, got %q", args)
	}
	if err := os.WriteFile(filepath.Join(args[1], "ready"), []byte("1"), 0o644); err != nil {
		return fmt.Errorf("signal ready: %w", err)
	}
	for i := 0; i < 500; i++ { // 5s
		if _, err := os.Stat(filepath.Join(args[1], "go")); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.WriteFile(filepath.Join(args[0], "hostile.txt"), []byte("pwn\n"), 0o644); err != nil {
		return fmt.Errorf("write after host rename: %w", err)
	}
	if got, err := os.ReadFile(filepath.Join(args[0], "hostile.txt")); err != nil || string(got) != "pwn\n" {
		return fmt.Errorf("read back after rename: %q %v", got, err)
	}
	return nil
}

// TestRealBwrapOverlayBoundary is the full live gate for --overlay: a
// real (filtered) launch through the staging arrangement must show
// writable merged views while the host trees stay byte-identical, the
// storage cap must fail writes without touching the host, staging paths
// and setup descriptors must be unreachable, a renamed source keeps
// working through its pin, and SIGTERM/SIGKILL teardown leaves nothing
// behind.
func TestRealBwrapSingleOverlayBoundary(t *testing.T) {
	exe := overlayModePreflight(t, true)
	dir := t.TempDir()
	home, src1, src2 := filepath.Join(dir, "home"), filepath.Join(dir, "proj1"), filepath.Join(dir, "proj2")
	for _, p := range []string{home, src1, src2} {
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	snap1, snap2 := plantTree(t, src1), plantTree(t, src2)
	out, rc := overlayLaunch(t, src1, home, 60*time.Second,
		[]string{"--overlay", src1, "--overlay", src2, "--overlay-mode", "single"},
		exe, "--_test-ovl-payload", src1, src2, src1, "single")
	if rc != 0 || !strings.Contains(out, "overlay probe passed") {
		t.Fatalf("rc %d out %q", rc, out)
	}
	if !strings.Contains(out, "No sbox storage cap") {
		t.Fatalf("missing mode warning: %q", out)
	}
	requireTreeUnchanged(t, src1, snap1, "src1")
	requireTreeUnchanged(t, src2, snap2, "src2")
}

func TestRealBwrapOverlayBoundary(t *testing.T) {
	exe := overlayPreflight(t)

	t.Run("writes are disposable", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "home"), 0o755); err != nil {
			t.Fatal(err)
		}
		src1 := filepath.Join(dir, "proj1")
		src2 := filepath.Join(dir, "proj2")
		for _, d := range []string{src1, src2} {
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		snap1, snap2 := plantTree(t, src1), plantTree(t, src2)

		out, rc := overlayLaunch(t, src1, filepath.Join(dir, "home"), 60*time.Second,
			[]string{"--overlay", src1, "--overlay", src2, "--overlay-size", "1MiB"},
			exe, "--_test-ovl-payload", src1, src2, src1)
		if rc != 0 || !strings.Contains(out, "overlay probe passed") {
			t.Fatalf("rc = %d out = %q", rc, out)
		}
		requireTreeUnchanged(t, src1, snap1, "src1")
		requireTreeUnchanged(t, src2, snap2, "src2")
	})

	t.Run("renamed source keeps working through the pin", func(t *testing.T) {
		dir := t.TempDir()
		home := filepath.Join(dir, "home")
		src := filepath.Join(dir, "proj")
		signal := filepath.Join(dir, "signal")
		for _, d := range []string{home, src, signal, filepath.Join(dir, "cache")} {
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		snap := plantTree(t, src)
		moved := filepath.Join(dir, "moved")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		cmd := exec.CommandContext(ctx, exe, "--_test-launch", "--upstream=", "-r", exe,
			"--overlay", src, "-b", signal, "--",
			exe, "--_test-ovl-hold", src, signal)
		cmd.Dir = home
		cmd.Env = append(os.Environ(), "HOME="+home, "XDG_RUNTIME_DIR=",
			"XDG_CACHE_HOME="+filepath.Join(dir, "cache"))
		proc := startOverlayProcess(t, cmd)
		proc.waitForFile(t, filepath.Join(signal, "ready"), 15*time.Second)
		// The validated source path vanishes on the host AFTER
		// validation: the pinned object must keep serving the overlay.
		if err := os.Rename(src, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(signal, "go"), []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := proc.wait(); err != nil {
			t.Fatalf("payload failed after the host renamed the source: %v\n%s", err, proc.output.String())
		}
		// the write landed in the disposable store, never in the
		// (renamed) host tree
		requireTreeUnchanged(t, moved, snap, "renamed source")
		if _, err := os.Stat(filepath.Join(moved, "hostile.txt")); err == nil {
			t.Error("hostile.txt reached the host tree after the rename")
		}
	})

	t.Run("SIGTERM tears the whole arrangement down", func(t *testing.T) {
		dir := t.TempDir()
		home := filepath.Join(dir, "home")
		src := filepath.Join(dir, "proj")
		signal := filepath.Join(dir, "signal")
		for _, d := range []string{home, src, signal, filepath.Join(dir, "cache")} {
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		snap := plantTree(t, src)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		cmd := exec.CommandContext(ctx, exe, "--_test-launch", "--upstream=", "-r", exe,
			"--overlay", src, "-b", signal, "--",
			"/bin/sh", "-c", "touch "+signal+"/ready; exec sleep 30777")
		cmd.Dir = home
		cmd.Env = append(os.Environ(), "HOME="+home, "XDG_RUNTIME_DIR=",
			"XDG_CACHE_HOME="+filepath.Join(dir, "cache"))
		proc := startOverlayProcess(t, cmd)
		proc.waitForFile(t, filepath.Join(signal, "ready"), 15*time.Second)
		_ = cmd.Process.Signal(syscall.SIGTERM)
		waitErr := proc.wait()
		var ee *exec.ExitError
		if !errors.As(waitErr, &ee) || ee.ExitCode() != 128+int(syscall.SIGTERM) {
			t.Errorf("launcher exit after SIGTERM = %v, want 128+15", waitErr)
		}
		requireTreeUnchanged(t, src, snap, "SIGTERM teardown")
		if leaked := findProcs("30777"); len(leaked) != 0 {
			t.Errorf("sandbox survived SIGTERM teardown: %v", leaked)
		}
	})

	t.Run("launcher death (SIGKILL) takes the sandbox with it", func(t *testing.T) {
		dir := t.TempDir()
		home := filepath.Join(dir, "home")
		src := filepath.Join(dir, "proj")
		signal := filepath.Join(dir, "signal")
		for _, d := range []string{home, src, signal, filepath.Join(dir, "cache")} {
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		snap := plantTree(t, src)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		cmd := exec.CommandContext(ctx, exe, "--_test-launch", "--upstream=", "-r", exe,
			"--overlay", src, "-b", signal, "--",
			"/bin/sh", "-c", "touch "+signal+"/ready; exec sleep 30778")
		cmd.Dir = home
		cmd.Env = append(os.Environ(), "HOME="+home, "XDG_RUNTIME_DIR=",
			"XDG_CACHE_HOME="+filepath.Join(dir, "cache"))
		proc := startOverlayProcess(t, cmd)
		proc.waitForFile(t, filepath.Join(signal, "ready"), 15*time.Second)
		if err := cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = proc.wait()
		if leaked := findProcs("30778"); len(leaked) != 0 {
			t.Errorf("sandbox survived the launcher SIGKILL (die-with-parent chain broken): %v", leaked)
		}
		requireTreeUnchanged(t, src, snap, "launcher death")
	})
}

// overlayProcess owns the wait and output buffer. Completion closes done before
// callers inspect either the error or output, including startup failures.
type overlayProcess struct {
	cmd    *exec.Cmd
	output bytes.Buffer
	done   chan struct{}
	err    error
}

func startOverlayProcess(t *testing.T, cmd *exec.Cmd) *overlayProcess {
	t.Helper()
	p := &overlayProcess{cmd: cmd, done: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = &p.output, &p.output
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-p.done
	})
	return p
}

func (p *overlayProcess) wait() error {
	<-p.done
	return p.err
}

// waitForFile reports an exited launcher immediately, with its diagnostics.
func (p *overlayProcess) waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-p.done:
			t.Fatalf("launcher exited before creating %s: %v\n%s", path, p.err, p.output.String())
		case <-timer.C:
			_ = p.cmd.Process.Kill()
			_ = p.wait()
			t.Fatalf("never saw %s\n%s", path, p.output.String())
		case <-tick.C:
		}
	}
}

// findProcs returns pids whose cmdline contains marker (teardown checks).
func findProcs(marker string) []int {
	var out []int
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), marker) {
			out = append(out, pid)
		}
	}
	return out
}
