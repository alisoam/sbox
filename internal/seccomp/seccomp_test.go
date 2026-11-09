package seccomp

import (
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"runtime"
	"syscall"
	"testing"
)

// TestMain routes the hidden --_selfprobe flag of a re-exec'd test
// binary to the probe child, exactly like cmd/sbox's main() will: the
// live-probe tests re-exec os.Args[0] with that one argument.
func TestMain(m *testing.M) {
	for _, a := range os.Args[1:] {
		if a == "--_selfprobe" {
			ProbeChild() // never returns
		}
	}
	os.Exit(m.Run())
}

func TestMachine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"amd64", "x86_64"},
		{"arm64", "aarch64"},
		{"x86_64", "x86_64"},
		{"aarch64", "aarch64"},
		{"riscv64", "riscv64"},
		{"i386", "i386"}, // unsupported spellings pass through and fail table lookup
	} {
		if got := Machine(tc.in); got != tc.want {
			t.Errorf("Machine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := Machine(""); got != Machine(runtime.GOARCH) {
		t.Errorf(`Machine("") = %q, want the live arch %q`, got, Machine(runtime.GOARCH))
	}
}

func TestTableShape(t *testing.T) {
	if !reflect.DeepEqual(Syscalls["riscv64"], Syscalls["aarch64"]) {
		t.Error("riscv64 must alias the asm-generic aarch64 table")
	}
	needed := append(append([]string{}, FakeMissing...), EPerm...)
	needed = append(needed, "clone", "ioctl", "personality", "socket")
	for machine, table := range Syscalls {
		for _, name := range needed {
			if _, ok := table[name]; !ok {
				t.Errorf("%s table is missing %q", machine, name)
			}
		}
	}
	// errno values are kernel ground truth (arch-independent on Linux)
	if uint32(syscall.EPERM) != 1 || uint32(syscall.ENOSYS) != 38 {
		t.Errorf("EPERM=%d ENOSYS=%d — the ERRNO actions would be wrong", syscall.EPERM, syscall.ENOSYS)
	}
	if _, err := BuildBPF("i386"); !errors.Is(err, ErrNoTable) {
		t.Errorf("BuildBPG(i386) = %v, want ErrNoTable", err)
	}
}

// --- a golden cBPF interpreter: decode the emitted bytes and execute
// them against synthetic seccomp_data, so the semantics (not just the
// bytes) are checked independently of the bytecode fixtures. ---

type bpfInsn struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

func decode(t *testing.T, bpf []byte) []bpfInsn {
	t.Helper()
	if len(bpf)%8 != 0 || len(bpf) == 0 {
		t.Fatalf("filter is not a non-empty multiple of 8 bytes: %d", len(bpf))
	}
	insns := make([]bpfInsn, 0, len(bpf)/8)
	for i := 0; i < len(bpf); i += 8 {
		insns = append(insns, bpfInsn{
			code: binary.LittleEndian.Uint16(bpf[i:]),
			jt:   bpf[i+2],
			jf:   bpf[i+3],
			k:    binary.LittleEndian.Uint32(bpf[i+4:]),
		})
	}
	return insns
}

// runFilter executes the program against one seccomp_data and returns
// the RET action. The interpreter reloads A on every LD — a stale-register
// implementation would hide exactly the fall-through bugs the "reload nr"
// instructions exist for.
func runFilter(t *testing.T, insns []bpfInsn, nr, arch uint32, args [6]uint64) uint32 {
	t.Helper()
	var data [16 + 48]byte
	binary.LittleEndian.PutUint32(data[0:], nr)
	binary.LittleEndian.PutUint32(data[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(data[16+8*i:], a)
	}
	var a uint32
	for pc := 0; pc < len(insns); pc++ {
		in := insns[pc]
		switch in.code {
		case bpfLDWAbs:
			a = binary.LittleEndian.Uint32(data[in.k:])
		case bpfJEQK:
			if a == in.k {
				pc += int(in.jt)
			} else {
				pc += int(in.jf)
			}
		case bpfJSETK:
			if a&in.k != 0 {
				pc += int(in.jt)
			} else {
				pc += int(in.jf)
			}
		case bpfRETK:
			return in.k
		default:
			t.Fatalf("interpreter: unknown opcode %#x at pc %d", in.code, pc)
		}
	}
	t.Fatal("interpreter: fell off the end of the program")
	return 0
}

func TestBuildAndInterpretX86_64(t *testing.T) {
	bpf, err := BuildBPF("x86_64")
	if err != nil {
		t.Fatal(err)
	}
	if len(bpf) < 60*8 {
		t.Fatalf("x86_64 filter suspiciously short: %d bytes", len(bpf))
	}
	insns := decode(t, bpf)
	tbl := Syscalls["x86_64"]
	arch := AuditArch["x86_64"]
	var zero [6]uint64

	withArgs := func(a0, a1 uint64) [6]uint64 { return [6]uint64{a0, a1} }
	for _, tc := range []struct {
		name string
		nr   uint32
		arch uint32
		args [6]uint64
		want uint32
	}{
		{"unshare → EPERM (the number that once shipped wrong)", tbl["unshare"], arch, zero, seccompRetErrno | 1},
		{"bpf → EPERM", tbl["bpf"], arch, zero, seccompRetErrno | 1},
		{"userfaultfd → EPERM", tbl["userfaultfd"], arch, zero, seccompRetErrno | 1},
		{"clone3 → ENOSYS (glibc falls back to clone)", tbl["clone3"], arch, zero, seccompRetErrno | 38},
		{"io_uring_register → ENOSYS", tbl["io_uring_register"], arch, zero, seccompRetErrno | 38},
		{"clone without CLONE_NEWUSER allowed (threads)", tbl["clone"], arch, withArgs(0, 0), seccompRetAllow},
		{"clone CLONE_NEWUSER denied", tbl["clone"], arch, withArgs(cloneNewUser, 0), seccompRetErrno | 1},
		{"clone CLONE_THREAD|CLONE_NEWUSER denied (JSET, not JEQ)", tbl["clone"], arch, withArgs(cloneNewUser|0x100, 0), seccompRetErrno | 1},
		{"ioctl TCGETS allowed", tbl["ioctl"], arch, withArgs(0, 0x5401), seccompRetAllow},
		{"ioctl TIOCSTI denied", tbl["ioctl"], arch, withArgs(0, tiocsti), seccompRetErrno | 1},
		{"ioctl TIOCLINUX denied", tbl["ioctl"], arch, withArgs(0, tioclinux), seccompRetErrno | 1},
		{"ioctl TIOCSTI high word ignored (cmd is u32)", tbl["ioctl"], arch, withArgs(0, 0x1_0000_5412), seccompRetErrno | 1},
		{"personality(0) denied", tbl["personality"], arch, withArgs(0, 0), seccompRetErrno | 1},
		{"personality(0xffffffff) query allowed", tbl["personality"], arch, withArgs(0xFFFFFFFF, 0), seccompRetAllow},
		{"personality query high word ignored", tbl["personality"], arch, withArgs(0x1_FFFF_FFFF, 0), seccompRetAllow},
		{"socket AF_UNIX allowed", tbl["socket"], arch, withArgs(1, 0), seccompRetAllow},
		{"socket AF_INET allowed", tbl["socket"], arch, withArgs(2, 0), seccompRetAllow},
		{"socket AF_INET6 allowed", tbl["socket"], arch, withArgs(10, 0), seccompRetAllow},
		{"socket AF_NETLINK allowed", tbl["socket"], arch, withArgs(16, 0), seccompRetAllow},
		{"socket AF_PACKET denied", tbl["socket"], arch, withArgs(3, 0), seccompRetErrno | 1},
		{"socket AF_VSOCK denied (netns bypass)", tbl["socket"], arch, withArgs(afVSOCK, 0), seccompRetErrno | 1},
		{"unlisted syscall (getpid) allowed", 39, arch, zero, seccompRetAllow},
		{"foreign ABI killed (aarch64 arch word)", 39, AuditArch["aarch64"], zero, seccompRetKillProcess},
		{"x32 killed (bit 30 in the number)", tbl["clone"] | 0x40000000, arch, zero, seccompRetKillProcess},
		{"x32 killed even for an unlisted number", 0x40000000 | 39, arch, zero, seccompRetKillProcess},
	} {
		if got := runFilter(t, insns, tc.nr, tc.arch, tc.args); got != tc.want {
			t.Errorf("%s: action = %#x, want %#x", tc.name, got, tc.want)
		}
	}
}

func TestBuildAndInterpretAarch64(t *testing.T) {
	bpf, err := BuildBPF("aarch64")
	if err != nil {
		t.Fatal(err)
	}
	insns := decode(t, bpf)
	tbl := Syscalls["aarch64"]
	arch := AuditArch["aarch64"]
	var zero [6]uint64

	for _, tc := range []struct {
		name string
		nr   uint32
		arch uint32
		args [6]uint64
		want uint32
	}{
		{"unshare → EPERM", tbl["unshare"], arch, zero, seccompRetErrno | 1},
		{"clone3 → ENOSYS", tbl["clone3"], arch, zero, seccompRetErrno | 38},
		{"socket AF_VSOCK denied", tbl["socket"], arch, [6]uint64{afVSOCK, 0}, seccompRetErrno | 1},
		{"personality query allowed", tbl["personality"], arch, [6]uint64{0xFFFFFFFF, 0}, seccompRetAllow},
		{"clone without CLONE_NEWUSER allowed", tbl["clone"], arch, zero, seccompRetAllow},
		{"clone CLONE_NEWUSER denied", tbl["clone"], arch, [6]uint64{cloneNewUser, 0}, seccompRetErrno | 1},
		// no x32 on aarch64: bit 30 of the number is just part of an
		// unlisted (allowed) number, and the x86_64 arch word is foreign.
		{"no x32 rule: high bit in nr is an unlisted number", 56 | 0x40000000, arch, zero, seccompRetAllow},
		{"foreign ABI killed (x86_64 arch word)", 39, AuditArch["x86_64"], zero, seccompRetKillProcess},
	} {
		if got := runFilter(t, insns, tc.nr, tc.arch, tc.args); got != tc.want {
			t.Errorf("%s: action = %#x, want %#x", tc.name, got, tc.want)
		}
	}

	// riscv64 shares the aarch64 program except the arch constant.
	rbpf, err := BuildBPF("riscv64")
	if err != nil {
		t.Fatal(err)
	}
	rinsns := decode(t, rbpf)
	if got := runFilter(t, rinsns, tbl["unshare"], AuditArch["riscv64"], zero); got != seccompRetErrno|1 {
		t.Errorf("riscv64 native arch: action = %#x, want EPERM", got)
	}
	if got := runFilter(t, rinsns, tbl["unshare"], AuditArch["aarch64"], zero); got != seccompRetKillProcess {
		t.Errorf("riscv64 with aarch64 arch word: action = %#x, want KILL_PROCESS", got)
	}
}

func TestBuildDeterministic(t *testing.T) {
	a, err := BuildBPF("")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBPF("")
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("the builder is not deterministic")
	}
	if len(a)%8 != 0 {
		t.Errorf("filter length %d is not a multiple of 8", len(a))
	}
}
