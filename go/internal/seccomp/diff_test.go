package seccomp

// The differential cross-check: the compiled filter must be BYTE-IDENTICAL
// to sbox.py's build_seccomp_bpf — bwrap consumes the raw bytes, so any
// divergence is a behavioral difference (instruction order, jump offsets,
// label layout are the spec). The oracle is the repo's sbox.py found by
// oracle.SboxPy() walking up from the working directory; everything skips
// cleanly when python3 or sbox.py is missing ($SBOX_PY / $SBOX_PYTHON
// override), so the suite stays green without the oracle.

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"sbox/internal/oracle"
)

func requireOracle(t *testing.T) {
	t.Helper()
	if !oracle.Available() {
		t.Skip("differential oracle unavailable: python3 + sbox.py not found (set $SBOX_PY / $SBOX_PYTHON)")
	}
}

func TestDifferentialBuildBPF(t *testing.T) {
	requireOracle(t)
	machines := []string{"x86_64", "aarch64", "riscv64", "i386"}

	var sb strings.Builder
	for _, m := range machines {
		b, err := json.Marshal(map[string]string{"machine": m})
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	// bytes.hex() (None stays None); both sides feed from the same corpus
	out, err := oracle.RunBatch(oracle.DriverFor(`m.build_seccomp_bpf(req["machine"]).hex() if m.build_seccomp_bpf(req["machine"]) is not None else None`), sb.String())
	if err != nil {
		t.Fatalf("oracle batch: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != len(machines) {
		t.Fatalf("oracle returned %d lines, want %d", len(lines), len(machines))
	}
	for i, machine := range machines {
		var resp [2]any
		if err := json.Unmarshal([]byte(lines[i]), &resp); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if resp[0] != "OK" {
			t.Fatalf("%s: oracle error: %v", machine, resp[1])
		}
		goBPF, goErr := BuildBPF(machine)
		if goErr != nil { // i386: no table
			if resp[1] != nil {
				t.Errorf("%s: python built a filter (%v) where Go has no table", machine, resp[1])
			}
			continue
		}
		pyHex, ok := resp[1].(string)
		if !ok {
			t.Errorf("%s: python returned %v, want hex bytes", machine, resp[1])
			continue
		}
		if want := hex.EncodeToString(goBPF); pyHex != want {
			t.Errorf("%s: filter bytes diverge from sbox.py\n  py = %s\n  go = %s", machine, pyHex, want)
		}
	}
}
