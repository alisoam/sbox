package seccomp

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

// These reviewed bytecode fixtures preserve the original filter for every
// supported architecture. The interpreter and kernel-header tests separately
// check behavior and syscall numbers; a fixture update must pass both.
func TestBuildBPFGolden(t *testing.T) {
	for _, machine := range []string{"x86_64", "aarch64", "riscv64"} {
		t.Run(machine, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/" + machine + ".bpf.hex")
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
			if err != nil {
				t.Fatal(err)
			}
			got, err := BuildBPF(machine)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("compiled filter changed: got %x, want %x", got, want)
			}
		})
	}
}
