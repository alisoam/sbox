package cliutil

// The differential cross-check of the help snapshot against the Python
// reference (the REPO's sbox.py — the spec under port). --help is
// user-facing spec: the usage line, description, option paragraphs and
// epilog must be byte-identical to what sbox.py's argparse renders,
// modulo exactly two documented deltas:
//
//   - the prog name (sbox.py -> sbox), and
//   - the seccomp-install paragraph in the epilog, which describes the
//     Go probe child (self re-exec, raw syscall numbers, this repo's
//     test suite) instead of python's forked-child/libc-wrapper
//     wording.
//
// Skips cleanly without python3/sbox.py ($SBOX_PY / $SBOX_PYTHON).

import (
	"strings"
	"testing"

	"sbox/internal/oracle"
)

// seccompBulletSpan locates the seccomp-install paragraph that carries
// the documented wording delta (from the "Every launch self-probes" line
// back to the start of its enclosing bullet, through the "installs the
// filter" tail line).
func seccompBulletSpan(s string) (start, end int) {
	probe := strings.Index(s, "Every launch self-probes the compiled filter")
	if probe < 0 {
		return -1, -1
	}
	start = strings.LastIndex(s[:probe], "\n  - ") + 1
	if start <= 0 {
		start = 0
	}
	end = strings.Index(s[probe:], "needed inside the sandbox")
	if end < 0 {
		return -1, -1
	}
	end += probe
	if nl := strings.Index(s[end:], "\n"); nl >= 0 {
		end += nl
	} else {
		end = len(s)
	}
	return start, end
}

func TestDifferentialUsage(t *testing.T) {
	if !oracle.Available() {
		t.Skip("differential oracle unavailable: python3 + sbox.py not found (set $SBOX_PY / $SBOX_PYTHON)")
	}
	help, err := oracle.Help()
	if err != nil {
		t.Fatalf("oracle help: %v", err)
	}
	want := strings.ReplaceAll(help, "sbox.py", "sbox")

	// Cut the one paragraph with the documented wording delta from both
	// sides; everything else must match byte-for-byte.
	gs, ge := seccompBulletSpan(Usage)
	ws, we := seccompBulletSpan(want)
	if gs < 0 || ws < 0 {
		t.Fatal("seccomp paragraph not found in help text")
	}
	goCut, wantCut := Usage[:gs]+Usage[ge:], want[:ws]+want[we:]
	if goCut != wantCut {
		i := 0
		for i < len(goCut) && i < len(wantCut) && goCut[i] == wantCut[i] {
			i++
		}
		lo := i - 120
		if lo < 0 {
			lo = 0
		}
		t.Fatalf("help snapshot drifted from the oracle around byte %d:\n...go... %q\n...py... %q",
			i, clip(goCut[lo:i+120]), clip(wantCut[lo:i+120]))
	}

	// The delta paragraph itself must carry the Go probe-child wording.
	bullet := Usage[gs:ge]
	for _, marker := range []string{
		"installed in a probe child", "the unshare(),",
		"ptrace calls", "the syscall numbers are verified",
		"pinned by the test suite", "(no helper needed inside the sandbox)",
	} {
		if !strings.Contains(bullet, marker) {
			t.Errorf("seccomp paragraph lost its Go wording marker %q", marker)
		}
	}
}

func clip(s string) string {
	if len(s) > 240 {
		return s[:240] + "..."
	}
	return s
}
