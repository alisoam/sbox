package sandbox

import (
	"path/filepath"
	"strings"
	"testing"

	"sbox/internal/bindpolicy"
	"sbox/internal/cliutil"
)

func TestBuildSpecSingleOverlayReleasesPin(t *testing.T) {
	root, home, proj, other := overlaySpec(t)
	pinner := bindpolicy.NewPinner(true)
	defer pinner.Close()
	opts := &cliutil.Options{Overlay: []string{proj}, OverlaySingle: true}
	overlays, err := bindpolicy.CheckOverlays(opts, home, pinner, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pin := overlays[0].FD
	spec, err := BuildSpec(opts, other, filepath.Join(root, "sand"), filepath.Join(root, "sock"), home,
		nil, overlays, "", "", pinner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pin.Stat(); err == nil {
		t.Fatal("unused source pin was not closed")
	}
	if spec.OverlayStoreSize != 0 {
		t.Fatalf("single overlay budget = %d", spec.OverlayStoreSize)
	}
	got := fmtOps(spec.Ops)
	requireOps(t, got[len(got)-3:], []string{
		"ro " + other + "->" + other + " fd",
		"path-overlay " + proj + "=>" + proj,
		"chdir " + other,
	})
}

func TestSupervisorSingleOverlay(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		ok, missingCap, invalid, cap bool
		wantRC, wantProbe            int
	}{
		{name: "success", ok: true, wantRC: 42, wantProbe: 1},
		{name: "probe fails without fallback", wantRC: 1, wantProbe: 1},
		{name: "missing capability", ok: true, missingCap: true, wantRC: 1},
		{name: "invalid source", ok: true, invalid: true, wantRC: 1},
		{name: "cap refuses", ok: true, cap: true, wantRC: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup, fp, root := newTestSupervisor(t)
			cwd, _ := sup.Getwd()
			sup.Opts.Overlay = []string{cwd}
			sup.Opts.OverlaySingle = true
			if tc.invalid {
				sup.Opts.Overlay = []string{filepath.Join(root, "missing")}
			}
			if tc.cap {
				sup.Opts.OverlaySize = 1 << 20
			}
			fp.caps = Caps{BindFD: true, TmpOverlay: !tc.missingCap}
			fp.singleOverlayOK = tc.ok
			var notes []string
			sup.Warn = func(s string) { notes = append(notes, s) }
			if rc := sup.Run(); rc != tc.wantRC {
				t.Fatalf("rc %d; notes %q", rc, notes)
			}
			if fp.overlay != 0 || fp.singleOverlay != tc.wantProbe {
				t.Fatalf("staged probes %d single probes %d", fp.overlay, fp.singleOverlay)
			}
			if tc.wantRC != 42 {
				if len(fp.specs) != 0 {
					t.Fatal("failed mode launched a fallback")
				}
				return
			}
			if len(fp.specs) != 1 {
				t.Fatalf("specs = %d", len(fp.specs))
			}
			spec := fp.specs[0]
			if spec.OverlayStoreSize != 0 {
				t.Fatal("unexpected cap")
			}
			got := fmtOps(spec.Ops)
			requireOps(t, got[len(got)-2:], []string{"path-overlay " + cwd + "=>" + cwd, "chdir " + cwd})
			for _, want := range []string{"source replacement", "No sbox storage cap"} {
				if !strings.Contains(strings.Join(notes, "\n"), want) {
					t.Fatalf("missing %q: %q", want, notes)
				}
			}
		})
	}
}
