package bwrap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sbox/internal/sandbox"
	"sbox/internal/seccomp"
)

func liveOverlayProvider(t *testing.T) *Provider {
	t.Helper()
	bin, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap is not installed")
	}
	p := New(bin)
	caps, err := p.Probe()
	if err != nil {
		t.Fatal(err)
	}
	if !caps.Overlay || !caps.BindFD || !caps.AddSeccompFD {
		t.Skip("bwrap lacks overlay, fd bind or seccomp support")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--unshare-all", "--die-with-parent",
		"--ro-bind", "/", "/", "--", "/bin/true").CombinedOutput()
	if err != nil {
		for _, reason := range []string{
			"No permissions to create a new namespace",
			"Creating new namespace failed: Operation not permitted",
			"Creating new namespace failed: Permission denied",
			"setting up uid map: Permission denied",
		} {
			if strings.Contains(string(out), reason) {
				t.Skipf("host blocks user namespaces: %s", out)
			}
		}
		t.Fatalf("namespace preflight: %v\n%s", err, out)
	}
	return p
}

func closeOverlayLaunch(t *testing.T, launch *sandbox.Launch) {
	t.Helper()
	t.Cleanup(func() {
		for _, f := range launch.PassFDs {
			f.Close()
		}
		for _, f := range launch.CloseAfterSpawn {
			f.Close()
		}
	})
}

// Exercise the production staging argv without a second user namespace. A
// barrier lets the host rename both sources and replace them with symlinks
// after mounting, before the inner launch would resolve its source paths.
func TestRealOverlayStagingSourceSwap(t *testing.T) {
	p := liveOverlayProvider(t)
	for _, rw := range []bool{false, true} {
		t.Run(fmt.Sprintf("bind_RW_%t", rw), func(t *testing.T) {
			spec, sand, src, _, _ := overlaySpec(t)
			bind := spec.Ops[3].(sandbox.Mount)
			bind.RW = rw
			spec.Ops[3] = bind
			for _, path := range []string{src, bind.Src} {
				if err := os.WriteFile(filepath.Join(path, "marker"), []byte("VALIDATED\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			victim := t.TempDir()
			if err := os.WriteFile(filepath.Join(victim, "marker"), []byte("UNVALIDATED\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			spec.Seccomp, err = seccomp.BuildBPF("")
			if err != nil {
				t.Fatal(err)
			}
			launch, err := p.Build(spec)
			if err != nil {
				t.Fatal(err)
			}
			closeOverlayLaunch(t, launch)
			boundary := indexOfArgv(launch.Argv, "--")
			bindOp := indexOfArgv(launch.Argv, "--ro-bind-fd")
			if rw {
				bindOp = indexOfArgv(launch.Argv, "--bind-fd")
			}
			bindSource := launch.Argv[bindOp+2]
			// Use the source paths the INNER argv actually names, so this
			// fails if it ever reopens the original host pathname again.
			inner := launch.Argv[boundary+1:]
			for i := 0; i+2 < len(inner); i++ {
				if (inner[i] == "--bind" || inner[i] == "--ro-bind") && inner[i+2] == bind.Dst {
					bindSource = inner[i+1]
					break
				}
			}
			lowerSource := inner[indexOfArgv(inner, "--overlay-src")+1]
			argv := append([]string{}, launch.Argv[:boundary]...)
			argv = append(argv, "--", "/bin/sh", "-eu", "-c", `
test -s "$1"
test -x "$2"
printf 'READY\n'
read token
cat "$3/marker" "$4/marker"
if ( : > "$4/forbidden" ) 2>/dev/null; then exit 20; fi
if [ "$6" = true ]; then
    : > "$3/writable"
else
    if ( : > "$3/forbidden" ) 2>/dev/null; then exit 21; fi
fi
: > "$5/scratch"
`, "staging-test", stageSeccomp, stageBinary, bindSource, lowerSource,
				fmt.Sprintf(stageMountFmt, 0), fmt.Sprint(rw))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, launch.Bin, argv...)
			cmd.ExtraFiles = launch.PassFDs
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			reader := bufio.NewReader(stdout)
			if ready, err := reader.ReadString('\n'); err != nil || ready != "READY\n" {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatalf("staging failed before source swap: ready=%q err=%v stderr=%s", ready, err, &stderr)
			}
			for _, path := range []string{bind.Src, src} {
				if err := os.Rename(path, path+"-moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := io.WriteString(stdin, "resume\n"); err != nil {
				t.Fatal(err)
			}
			stdin.Close()
			out, readErr := io.ReadAll(reader)
			waitErr := cmd.Wait()
			if readErr != nil || waitErr != nil || string(out) != "VALIDATED\nVALIDATED\n" {
				t.Fatalf("staged sources changed: read=%v wait=%v stdout=%q stderr=%s", readErr, waitErr, out, &stderr)
			}
			if _, err := os.Stat(filepath.Join(sand, "scratch")); err != nil {
				t.Fatalf("staged scratch lost its writable mode: %v", err)
			}
			if rw {
				if _, err := os.Stat(filepath.Join(bind.Src+"-moved", "writable")); err != nil {
					t.Fatalf("explicit writable bind did not retain the pinned source: %v", err)
				}
			}
		})
	}
}

// Reuse the ACTUAL probe spec, omitting only the overlay itself. This catches
// missing shell/runtime mounts even on hosts that block nested user namespaces.
func TestRealOverlayProbeRuntime(t *testing.T) {
	p := liveOverlayProvider(t)
	_, sand, src, fd, _ := overlaySpec(t)
	filter, err := seccomp.BuildBPF("")
	if err != nil {
		t.Fatal(err)
	}
	spec := overlayProbeSpec(src, sand, fd, false, false, filter)
	var ops []sandbox.Op
	for _, op := range spec.Ops {
		if _, ok := op.(sandbox.Overlay); !ok {
			ops = append(ops, op)
		}
	}
	spec.Ops = ops
	launch, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	closeOverlayLaunch(t, launch)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	argv := append(launch.Argv, "--", "/bin/sh", "-c", ": > /tmp/runtime-ok")
	cmd := exec.CommandContext(ctx, launch.Bin, argv...)
	cmd.ExtraFiles = launch.PassFDs
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("probe runtime cannot execute its filtered shell: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(sand, "runtime-ok")); err != nil {
		t.Fatalf("probe shell did not run: %v", err)
	}
}
