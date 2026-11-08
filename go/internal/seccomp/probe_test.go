package seccomp

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
)

// buildNative compiles the filter for the machine running the test (the
// launcher's default) and fails loudly on unsupported arches — this
// suite only runs on machines the tables cover.
func buildNative(t *testing.T) []byte {
	t.Helper()
	bpf, err := BuildBPF("")
	if err != nil {
		t.Fatalf("BuildBPF: %v", err)
	}
	return bpf
}

// skipWithoutSeccompInstall skips when this environment cannot install
// filters at all (exit 5): the live probes then prove nothing here.
func skipWithoutSeccompInstall(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "cannot install") {
		t.Skipf("seccomp filters cannot be installed here: %v", err)
	}
}

func TestSelfProbeAcceptsRealFilter(t *testing.T) {
	bpf := buildNative(t)
	err := SelfProbe(os.Args[0], []string{"--_selfprobe"}, bpf)
	skipWithoutSeccompInstall(t, err)
	if err != nil {
		t.Fatal(err)
	}
}

// The probe must fail CLOSED the other way too: a filter that denies
// nothing must not pass (otherwise a truncated/empty table could ship).
func TestSelfProbeRejectsPermissiveFilter(t *testing.T) {
	var insn [8]byte
	binary.LittleEndian.PutUint16(insn[0:], bpfRETK)
	binary.LittleEndian.PutUint32(insn[4:], seccompRetAllow)
	err := SelfProbe(os.Args[0], []string{"--_selfprobe"}, insn[:])
	skipWithoutSeccompInstall(t, err)
	if err == nil {
		t.Fatal("an allow-everything filter passed the self-probe")
	}
	if !strings.Contains(err.Error(), "unshare(0) was not denied") {
		t.Fatalf("want the unshare(0) mismatch detail, got: %v", err)
	}
}

func TestFilterFDRoundTrip(t *testing.T) {
	bpf := buildNative(t)
	r, err := FilterFD(bpf)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bpf) {
		t.Fatalf("filter pipe: got %d bytes, want the exact %d-byte filter", len(got), len(bpf))
	}
	if len(got)%8 != 0 {
		t.Error("piped filter is not a multiple of 8 bytes")
	}
}
