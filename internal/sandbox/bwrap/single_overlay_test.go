package bwrap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbox/internal/sandbox"
	"sbox/internal/seccomp"
)

func TestBuildSingleOverlay(t *testing.T) {
	spec, _, src, sourceFD, _ := overlaySpec(t)
	for i, op := range spec.Ops {
		if o, ok := op.(sandbox.Overlay); ok {
			spec.Ops[i] = sandbox.PathOverlay{Src: o.Src, Dst: o.Dst}
		}
	}
	spec.OverlayStoreSize = 0
	spec.DisableUserns = true
	var err error
	spec.Seccomp, err = seccomp.BuildBPF("")
	if err != nil {
		t.Fatal(err)
	}
	p := New(fakeBwrap(t, "exit 0"))
	p.Caps = sandbox.Caps{BindFD: true, TmpOverlay: true, AddSeccompFD: true, DisableUserns: true}
	launch, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	closeOverlayLaunch(t, launch)
	requireArgv(t, launch.Argv, "--overlay-src", src, "--tmp-overlay", src)
	for _, flag := range []string{"--as-pid-1", "--new-session", "--clearenv", "--unshare-user", "--disable-userns", "--assert-userns-disabled", "--add-seccomp-fd", "--bind-fd"} {
		requireArgv(t, launch.Argv, flag)
	}
	for _, forbidden := range []string{"--size", "--overlay", "--file", p.Bin} {
		if indexOfArgv(launch.Argv, forbidden) >= 0 {
			t.Errorf("single argv contains %q", forbidden)
		}
	}
	if strings.Contains(strings.Join(launch.Argv, " "), stageDir) {
		t.Fatal("single launch has staging paths")
	}
	if len(launch.PassFDs) != 2 {
		t.Fatalf("fds = %d; want bind and filter only", len(launch.PassFDs))
	}
	for _, fd := range launch.PassFDs {
		a, err := fd.Stat()
		if err != nil {
			t.Fatal(err)
		}
		b, err := sourceFD.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(a, b) {
			t.Fatal("overlay validation fd leaked to child")
		}
	}
}

func TestBuildSingleOverlayRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		caps  sandbox.Caps
		size  int64
		mixed bool
		want  string
	}{
		{"missing caps", sandbox.Caps{}, 0, false, "requires"},
		{"cap", sandbox.Caps{TmpOverlay: true}, 1 << 20, false, "storage cap"},
		{"mixed", sandbox.Caps{TmpOverlay: true, Overlay: true}, 0, true, "cannot mix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New(fakeBwrap(t, "exit 0"))
			p.Caps = tc.caps
			spec := &sandbox.Spec{Ops: []sandbox.Op{sandbox.PathOverlay{Src: "/src", Dst: "/src"}}, OverlayStoreSize: tc.size}
			if tc.mixed {
				spec.Ops = append(spec.Ops, sandbox.Overlay{Src: "/other", Dst: "/other"})
			}
			if _, err := p.Build(spec); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestSingleOverlayProbe(t *testing.T) {
	for _, shareNet := range []bool{false, true} {
		for _, filtered := range []bool{false, true} {
			t.Run(fmt.Sprintf("net_%t_filter_%t", shareNet, filtered), func(t *testing.T) {
				argvFile := filepath.Join(t.TempDir(), "argv")
				p := New(fakeBwrap(t, fmt.Sprintf(`printf '%%s\n' "$@" > %s`, argvFile)))
				p.Caps = sandbox.Caps{TmpOverlay: true, AddSeccompFD: true, DisableUserns: true}
				var filter []byte
				if filtered {
					var err error
					filter, err = seccomp.BuildBPF("")
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := p.SingleOverlayProbe(shareNet, true, filter); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(argvFile)
				if err != nil {
					t.Fatal(err)
				}
				argv := strings.Split(strings.TrimRight(string(got), "\n"), "\n")
				requireArgv(t, argv, "--tmp-overlay")
				requireArgv(t, argv, "--disable-userns", "--assert-userns-disabled")
				if indexOfArgv(argv, "--size") >= 0 || indexOfArgv(argv, p.Bin) >= 0 {
					t.Fatalf("nested probe: %q", argv)
				}
				if (indexOfArgv(argv, "--share-net") >= 0) != shareNet || (indexOfArgv(argv, "--add-seccomp-fd") >= 0) != filtered {
					t.Fatalf("probe doesn't match network/filter: %q", argv)
				}
				for _, op := range sandbox.SystemMounts() {
					m := op.(sandbox.Mount)
					flag := "--ro-bind"
					if m.Try {
						flag += "-try"
					}
					requireArgv(t, argv, flag, m.Src, m.Dst)
				}
			})
		}
	}
	p := New(fakeBwrap(t, "exit 1"))
	p.Caps.TmpOverlay = true
	if err := p.SingleOverlayProbe(false, false, nil); err == nil {
		t.Fatal("failing single probe accepted")
	}
}
