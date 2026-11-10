package bwrap

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"sbox/internal/bindpolicy"
	"sbox/internal/sandbox"
	"sbox/internal/seccomp"
)

// overlayCaps is a bwrap 0.11-class capability set.
func overlayCaps() sandbox.Caps {
	return sandbox.Caps{BindFD: true, AddSeccompFD: true, DisableUserns: true, Overlay: true}
}

// overlaySpec builds a representative overlay spec: the
// rw /tmp sand path mount, a pinned rw user bind, the pinned overlay
// source and the chdir — the shape the supervisor produces.
func overlaySpec(t *testing.T) (*sandbox.Spec, string, string, *os.File, *os.File) {
	t.Helper()
	t.Setenv("USER", "tester")
	t.Setenv("XDG_RUNTIME_DIR", "")
	dir := t.TempDir()
	sand := filepath.Join(dir, "work", "tmp")
	src := filepath.Join(dir, "proj")
	bind := filepath.Join(dir, "binds")
	for _, d := range []string{sand, src, bind} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	srcFD, err := bindpolicy.OpenPathPinned(src)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srcFD.Close() })
	bindFD, err := bindpolicy.OpenPathPinned(bind)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bindFD.Close() })

	spec := &sandbox.Spec{
		Ops: []sandbox.Op{
			sandbox.ProcFS{Path: "/proc"},
			sandbox.DevFS{Path: "/dev"},
			sandbox.Mount{Src: sand, Dst: "/tmp", RW: true},
			sandbox.Mount{Src: bind, Dst: bind, RW: true, FD: bindFD},
			sandbox.Overlay{Src: src, Dst: src, FD: srcFD},
			sandbox.Chdir{Dir: src},
		},
		OverlayStoreSize: 1 << 30,
	}
	return spec, sand, src, srcFD, bindFD
}

func requireArgv(t *testing.T, argv []string, want ...string) {
	t.Helper()
	// contiguous subsequence match on token granularity
	for i := 0; i+len(want) <= len(argv); i++ {
		match := true
		for j := range want {
			if argv[i+j] != want[j] {
				match = false
				break
			}
		}
		if match {
			return
		}
	}
	t.Errorf("argv does not contain %q:\n%s", want, strings.Join(argv, " "))
}

func TestBuildOverlayStagingSeccomp(t *testing.T) {
	spec, sand, src, _, _ := overlaySpec(t)
	bpf, err := seccomp.BuildBPF("x86_64")
	if err != nil {
		t.Fatal(err)
	}
	spec.Seccomp = bpf
	spec.DisableUserns = true

	shim := fakeBwrap(t, "exit 0")
	p := New(shim)
	p.Caps = overlayCaps()
	l, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	closeOverlayLaunch(t, l)
	if l.Bin != shim {
		t.Errorf("Bin = %q", l.Bin)
	}

	// The staging skeleton: hermetic namespaces, host root mirrored
	// read-only, fresh /proc and /dev, private writable staging /tmp,
	// the staged seccomp file, scratch and pinned mounts, the
	// bounded store, then the fixed bridge and the inner bwrap.
	requireArgv(t, l.Argv,
		"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
		"--unshare-net", "--die-with-parent",
		"--ro-bind", "/", "/",
		"--proc", "/proc",
		"--dev", "/dev",
		"--perms", "0700", "--tmpfs", "/tmp",
		"--ro-bind", shim, stageBinary,
		"--perms", "0400", "--file", "3", stageSeccomp,
		"--bind", sand, fmt.Sprintf(stageMountFmt, 0),
		"--bind-fd", "4", fmt.Sprintf(stageMountFmt, 1))
	requireArgv(t, l.Argv, "--ro-bind-fd", "5", "/tmp/sbox-stage/src/0")
	requireArgv(t, l.Argv,
		"--perms", "0700", "--size", strconv.FormatInt(1<<30, 10), "--tmpfs", "/tmp/sbox-stage/st",
		"--perms", "0700", "--dir", "/tmp/sbox-stage/st/u0",
		"--perms", "0700", "--dir", "/tmp/sbox-stage/st/w0",
		"--",
		"/bin/sh", "-c", stageSeccompBridge, "sbox-stage", stageBinary,
		"--add-seccomp-fd", "3",
		"--unshare-user", "--disable-userns", "--assert-userns-disabled",
		"--unshare-all", "--die-with-parent", "--new-session", "--as-pid-1", "--clearenv",
	)
	// the inner overlay pair, adjacent as bwrap requires
	requireArgv(t, l.Argv,
		"--overlay-src", "/tmp/sbox-stage/src/0",
		"--overlay", "/tmp/sbox-stage/st/u0", "/tmp/sbox-stage/st/w0", src)

	// the pinned bind is staged at a private mountpoint (fd 4) and the inner
	// argv re-binds that STAGED path, not a launcher fd
	i := indexOfArgv(l.Argv, "--bind-fd")
	staged := l.Argv[i+2]
	if staged != fmt.Sprintf(stageMountFmt, 1) {
		t.Fatalf("staged bind path = %q", staged)
	}
	requireArgv(t, l.Argv, "--bind", staged, spec.Ops[3].(sandbox.Mount).Dst)

	// fd accounting: exactly three named fds (the filter file, the bind
	// pin, the overlay pin), each named once — nothing else crosses the
	// exec boundary, and no dup is needed.
	if len(l.PassFDs) != 3 || len(l.CloseAfterSpawn) != 0 {
		t.Fatalf("PassFDs = %d CloseAfterSpawn = %d, want 3/0", len(l.PassFDs), len(l.CloseAfterSpawn))
	}
	// slots 3,4,5 named by --file/--bind-fd/--ro-bind-fd respectively
	for i, want := range []string{"--file", "--bind-fd", "--ro-bind-fd"} {
		j := indexOfArgv(l.Argv, want)
		if j < 0 || l.Argv[j+1] != strconv.Itoa(extraFDBase+i) {
			t.Errorf("%s names %v, want fd %d", want, argAfter(l.Argv, j), extraFDBase+i)
		}
	}
}

func argAfter(argv []string, i int) string {
	if i < 0 || i+1 >= len(argv) {
		return "<none>"
	}
	return argv[i+1]
}

func indexOfArgv(argv []string, tok string) int {
	for i, a := range argv {
		if a == tok {
			return i
		}
	}
	return -1
}

func TestBuildOverlayNoSeccomp(t *testing.T) {
	spec, sand, src, _, _ := overlaySpec(t)
	p := New(fakeBwrap(t, "exit 0"))
	p.Caps = overlayCaps()
	l, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	// no filter: the inner bwrap is the staging payload DIRECTLY — no
	// shell bridge, no --file, no fd 3.
	if strings.Contains(strings.Join(l.Argv, " "), stageSeccompBridge) {
		t.Error("unfiltered launch must not use the staging bridge")
	}
	if strings.Contains(strings.Join(l.Argv, " "), "--file") {
		t.Error("unfiltered launch must not stage a seccomp file")
	}
	requireArgv(t, l.Argv, "--bind", sand, fmt.Sprintf(stageMountFmt, 0))
	requireArgv(t, l.Argv, "--bind", fmt.Sprintf(stageMountFmt, 0), "/tmp")
	requireArgv(t, l.Argv, "--", stageBinary, "--unshare-all")
	requireArgv(t, l.Argv, "--overlay-src", "/tmp/sbox-stage/src/0",
		"--overlay", "/tmp/sbox-stage/st/u0", "/tmp/sbox-stage/st/w0", src)
	if len(l.PassFDs) != 2 { // the bind pin and the overlay pin only
		t.Errorf("PassFDs = %d, want 2", len(l.PassFDs))
	}
}

func TestBuildOverlayShareNet(t *testing.T) {
	spec, _, _, _, _ := overlaySpec(t)
	spec.Ops = append(spec.Ops, sandbox.ShareNet{})
	p := New(fakeBwrap(t, "exit 0"))
	p.Caps = overlayCaps()
	l, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	// the inner --share-net shares STAGING's view of the network: the
	// staging sandbox must stay on the launcher's net namespace.
	if strings.Contains(strings.Join(l.Argv[:24], " "), "--unshare-net") {
		t.Error("staging must not unshare net when the launch shares it")
	}
	requireArgv(t, l.Argv, "--share-net")
}

func TestBuildOverlayFailClosed(t *testing.T) {
	spec, _, src, _, _ := overlaySpec(t)

	p := New(fakeBwrap(t, "exit 0"))
	p.Caps = overlayCaps()
	p.Caps.Overlay = false
	if _, err := p.Build(spec); err == nil || !strings.Contains(err.Error(), "--overlay-src/--overlay") {
		t.Errorf("no overlay caps: err = %v", err)
	}

	p.Caps = overlayCaps()
	p.Caps.BindFD = false
	if _, err := p.Build(spec); err == nil || !strings.Contains(err.Error(), "without pinned sources") {
		t.Errorf("no bind-fd caps: err = %v", err)
	}

	p.Caps = overlayCaps()
	spec.OverlayStoreSize = 0
	if _, err := p.Build(spec); err == nil || !strings.Contains(err.Error(), "OverlayStoreSize") {
		t.Errorf("no store size: err = %v", err)
	}

	spec.OverlayStoreSize = 1 << 20
	spec.Ops = []sandbox.Op{sandbox.Overlay{Src: src, Dst: src}} // no fd
	if _, err := p.Build(spec); err == nil || !strings.Contains(err.Error(), "no pinned fd") {
		t.Errorf("unpinned overlay: err = %v", err)
	}
}

// The staging payload path must be an absolute bwrap the staging sandbox
// can exec; a relative Bin resolves through $PATH at Build time.
func TestBuildOverlayBinResolution(t *testing.T) {
	spec, _, _, _, _ := overlaySpec(t)
	shim := fakeBwrap(t, "exit 0")
	p := New(shim)
	p.Caps = overlayCaps()
	l, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	requireArgv(t, l.Argv, "--ro-bind", shim, stageBinary)
	requireArgv(t, l.Argv, "--", stageBinary, "--unshare-all")

	// an unresolvable binary fails the build loudly
	p2 := New(filepath.Join(t.TempDir(), "missing-bwrap"))
	p2.Caps = overlayCaps()
	if _, err := p2.Build(spec); err == nil || !strings.Contains(err.Error(), "cannot resolve the bwrap binary") {
		t.Errorf("missing bin: err = %v", err)
	}
}

func TestOverlayProbeShim(t *testing.T) {
	shim := fakeBwrap(t, "exit 0")
	p := New(shim)
	p.Caps = overlayCaps()
	if err := p.OverlayProbe(false, false, nil); err != nil {
		t.Fatal("shim exits 0; probe must report ok")
	}
	if err := p.OverlayProbe(false, true, nil); err != nil {
		t.Fatal("hardened variant must also probe ok against the shim")
	}

	fail := fakeBwrap(t, "exit 1")
	pf := New(fail)
	pf.Caps = overlayCaps()
	if err := pf.OverlayProbe(false, false, nil); err == nil {
		t.Error("failing shim must probe false")
	}

	// caps missing entirely (Build refuses): fail closed
	pn := New(shim)
	if err := pn.OverlayProbe(false, false, nil); err == nil {
		t.Error("unprobed caps must probe false (Build refuses)")
	}
}

// The probe's spec must actually describe the launch arrangement — its
// recorded argv shows the staging skeleton, the staged source and the
// inner overlay pair, and the write-through check in the payload.
func TestOverlayProbeArgvShape(t *testing.T) {
	for _, shareNet := range []bool{false, true} {
		for _, filtered := range []bool{false, true} {
			t.Run(fmt.Sprintf("net_%t_filter_%t", shareNet, filtered), func(t *testing.T) {
				argvFile := filepath.Join(t.TempDir(), "argv")
				recording := fakeBwrap(t, fmt.Sprintf(`printf '%%s\n' "$@" > %s`, argvFile))
				p := New(recording)
				p.Caps = overlayCaps()
				var filter []byte
				if filtered {
					var err error
					filter, err = seccomp.BuildBPF("")
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := p.OverlayProbe(shareNet, true, filter); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(argvFile)
				if err != nil {
					t.Fatal(err)
				}
				data := string(got)
				argv := strings.Split(strings.TrimRight(data, "\n"), "\n")
				requireArgv(t, argv, "--ro-bind", "/", "/")
				requireArgv(t, argv, "--ro-bind-fd")
				requireArgv(t, argv, "--size")
				requireArgv(t, argv, "--overlay-src", stageDir+"/src/0")
				requireArgv(t, argv, "--disable-userns", "--assert-userns-disabled")
				if (indexOfArgv(argv, "--unshare-net") < 0) != shareNet ||
					(indexOfArgv(argv, "--share-net") >= 0) != shareNet {
					t.Errorf("probe does not match requested network mode: %s", data)
				}
				if (indexOfArgv(argv, "--file") >= 0) != filtered ||
					(indexOfArgv(argv, "--add-seccomp-fd") >= 0) != filtered {
					t.Errorf("probe does not match requested filter mode: %s", data)
				}
				// Check every production runtime mount is staged and rebound.
				for i, op := range sandbox.SystemMounts() {
					m := op.(sandbox.Mount)
					flag := "--ro-bind"
					if m.Try {
						flag += "-try"
					}
					staged := fmt.Sprintf(stageMountFmt, i+1)
					requireArgv(t, argv, flag, m.Src, staged)
					requireArgv(t, argv, flag, staged, m.Dst)
				}
				if !strings.Contains(data, `test ! -e "$2"`) ||
					!strings.Contains(data, "test ! -e /oldroot") ||
					!strings.Contains(data, "/probe") {
					t.Errorf("probe payload must check invisibility and write through the overlay: %q", data)
				}
			})
		}
	}
}
