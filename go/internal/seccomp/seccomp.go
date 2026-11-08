// Package seccomp implements the syscall deny-list, cBPF compiler and
// launch-time self-probe. bwrap consumes the compiled bytes through
// --add-seccomp-fd or --seccomp.
//
// Model (deny-list, fail-closed):
//
//   - bwrap installs the compiled filter itself, as the very last step
//     before exec'ing the payload (--add-seccomp-fd, --seccomp on older
//     bwrap) — after its own namespace setup, before the payload's first
//     instruction: the bridge, the command and all descendants inherit
//     it. An in-sandbox installer would leave a pre-filter execution window.
//   - Namespaces cannot hide kernel attack surface: io_uring_*,
//     bpf/perf_event_open/userfaultfd, the un-namespaced keyring,
//     namespace syscalls (unshare/setns/clone3/clone+CLONE_NEWUSER),
//     admin calls (mount/pivot_root/kexec/modules/open_by_handle_at/
//     quotactl/syslog/fanotify_init and the new mount API), process
//     injection/inspection (ptrace/process_vm_*/kcmp/pidfd_getfd/
//     vmsplice), personality CHANGES and chroot are denied — the same
//     list Flatpak/Chrome disable. socket() is gated to
//     AF_UNIX/INET/INET6/NETLINK (AF_VSOCK bypasses netns isolation in
//     VM guests), ioctl(TIOCSTI/TIOCLINUX) is denied.
//   - Denied calls get ENOSYS where callers have fallbacks (io_uring
//     users fall back to threads; glibc falls back from clone3 to clone —
//     EPERM would break threading) and EPERM elsewhere. Foreign-ABI
//     binaries are KILLED (SECCOMP_RET_KILL_PROCESS — number-based
//     filtering is meaningless across ABIs); x32 (same AUDIT_ARCH_X86_64,
//     bit 0x40000000 in the number) is killed explicitly on x86_64.
//   - personality is denied EXCEPT the 0xffffffff "query" magic: the
//     kernel returns the current persona and changes nothing for that
//     one value (setarch/glibc read idiom); setarch -R et al. still need
//     --no-seccomp. ioctl/personality arguments are taken as u32 by the
//     kernel, so only the low words are compared.
//   - The tables are hand-typed: a wrong number fails SILENTLY (the
//     filter loads and denies the wrong syscall). Three pins: the
//     cross-checks against kernel headers/ausyscall, reviewed golden fixtures
//     and interpreter cases, and SelfProbe —
//     which re-checks on EVERY launch, host-side, that the compiled
//     filter denies what it claims (unshare(0) once shipped with
//     ioctl's number).
package seccomp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
)

// ErrNoTable means this architecture has no supported syscall table. The
// launcher must fail closed unless --no-seccomp was explicitly selected.
var ErrNoTable = errors.New("no seccomp syscall table for this machine")

// Syscalls are native syscall numbers for x86_64, aarch64 and riscv64.
// A wrong number silently denies the wrong syscall. Extend the kernel-header,
// interpreter and golden tests whenever this table changes.
var Syscalls = map[string]map[string]uint32{
	"x86_64": {
		"ioctl": 16, "clone": 56, "socket": 41, "syslog": 103, "ptrace": 101,
		"personality": 135, "pivot_root": 155, "mount": 165, "chroot": 161,
		"umount2": 166, "quotactl": 179, "init_module": 175, "delete_module": 176,
		"kexec_load": 246, "add_key": 248, "request_key": 249, "keyctl": 250,
		"perf_event_open": 298, "fanotify_init": 300, "open_by_handle_at": 304,
		"name_to_handle_at": 303, "setns": 308, "vmsplice": 278,
		"process_vm_readv": 310, "process_vm_writev": 311, "kcmp": 312,
		"unshare": 272, "finit_module": 313, "kexec_file_load": 320,
		"bpf": 321, "userfaultfd": 323, "io_uring_setup": 425,
		"io_uring_enter": 426, "io_uring_register": 427, "open_tree": 428,
		"move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
		"fspick": 433,
		"clone3": 435, "pidfd_getfd": 438, "mount_setattr": 442,
	},
	"aarch64": {
		"umount2": 39, "mount": 40, "pivot_root": 41, "ptrace": 117,
		"chroot": 51, "personality": 92, "unshare": 97, "kexec_load": 104,
		"init_module": 105, "delete_module": 106, "socket": 198,
		"clone": 220, "add_key": 217, "request_key": 218, "keyctl": 219,
		"ioctl": 29, "quotactl": 60, "vmsplice": 75, "syslog": 116,
		"perf_event_open": 241, "fanotify_init": 262, "name_to_handle_at": 264,
		"open_by_handle_at": 265,
		"process_vm_readv":  270, "process_vm_writev": 271, "kcmp": 272,
		"finit_module": 273, "setns": 268, "kexec_file_load": 294,
		"bpf": 280, "userfaultfd": 282, "io_uring_setup": 425,
		"io_uring_enter": 426, "io_uring_register": 427, "open_tree": 428,
		"move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
		"fspick": 433,
		"clone3": 435, "pidfd_getfd": 438, "mount_setattr": 442,
	},
}

// riscv64 shares the asm-generic aarch64 table.
func init() {
	Syscalls["riscv64"] = Syscalls["aarch64"]
}

// AuditArch are the AUDIT_ARCH_* values of seccomp_data.arch for the
// native ABI.
var AuditArch = map[string]uint32{
	"x86_64":  0xC000003E,
	"aarch64": 0xC00000B7,
	"riscv64": 0xC00000F3,
}

// FakeMissing is denied with ENOSYS: calling code has fallbacks
// (io_uring users fall back to plain threads; glibc falls back from
// clone3 to clone — EPERM there would break threading).
var FakeMissing = []string{"clone3", "io_uring_setup", "io_uring_enter", "io_uring_register"}

// EPerm is denied with EPERM: no legitimate fallback exists.
var EPerm = []string{
	"bpf", "perf_event_open", "userfaultfd",
	"keyctl", "add_key", "request_key",
	"unshare", "setns", "ptrace", "process_vm_readv", "process_vm_writev",
	"kcmp", "pidfd_getfd", "chroot", "vmsplice",
	"mount", "umount2", "pivot_root", "kexec_load", "kexec_file_load",
	"init_module", "finit_module", "delete_module", "open_by_handle_at",
	"name_to_handle_at", "quotactl", "syslog", "fanotify_init",
	"open_tree", "move_mount", "fsopen", "fsconfig", "fsmount",
	"fspick", "mount_setattr",
}

// PersonalityQuery (0xffffffff) is the one personality() argument that
// stays allowed: the kernel returns the current persona without changing
// anything for that value (setarch/glibc read idiom).
const PersonalityQuery = 0xFFFFFFFF

const (
	cloneNewUser = 0x10000000 // CLONE_NEWUSER: clone() denied only with this flag
	tiocsti      = 0x5412     // inject a keystroke into the controlling tty
	tioclinux    = 0x541C     // raw console ioctls
)

// SocketFamilies are the families socket() is gated to (identical values
// on every supported arch): AF_UNIX, AF_INET, AF_INET6, AF_NETLINK —
// the Flatpak set. AF_VSOCK notably bypasses netns isolation in VM
// guests on older kernels.
var SocketFamilies = []uint32{1, 2, 10, 16}

// cBPF machine constants (linux/filter.h) + seccomp return actions.
const (
	bpfLDWAbs = 0x20 // A = u32 at seccomp_data offset k
	bpfJEQK   = 0x15 // if A == k jump jt else jf
	bpfJSETK  = 0x45 // if A & k jump jt else jf
	bpfRETK   = 0x06

	seccompRetAllow       = 0x7FFF0000
	seccompRetErrno       = 0x00050000
	seccompRetKillProcess = 0x80000000 // whole thread group (kernel >= 4.14)
)

// AF_VSOCK on every ABI sbox supports (the family the self-probe tries).
const afVSOCK = 40

// Machine normalizes platform.machine()/runtime.GOARCH spellings to the
// Syscalls keys (seccomp_machine).
func Machine(machine string) string {
	if machine == "" {
		machine = runtime.GOARCH
	}
	switch machine {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	return machine
}

// insn is one emitted instruction before resolving symbolic jump labels.
type insn struct {
	code uint16
	k    uint32
	jt   string // "" = fall through (offset 0)
	jf   string
}

// BuildBPF compiles the deny-list into raw cBPF instructions: a multiple of
// 8 bytes, with no length prefix. It returns ErrNoTable for unsupported
// architectures, or an error for invalid jump offsets. Callers fail closed.
func BuildBPF(machine string) ([]byte, error) {
	machine = Machine(machine)
	table := Syscalls[machine]
	if table == nil {
		return nil, fmt.Errorf("%w (%s)", ErrNoTable, machine)
	}

	var insns []insn
	emit := func(code uint16, k uint32, jt, jf string) {
		insns = append(insns, insn{code, k, jt, jf})
	}

	// seccomp_data: { int nr; u32 arch; u64 ip; u64 args[6]; } (native LE)
	emit(bpfLDWAbs, 4, "", "") // arch
	emit(bpfJEQK, AuditArch[machine], "", "kill")
	emit(bpfLDWAbs, 0, "", "") // syscall nr
	if machine == "x86_64" {
		// x32 shares AUDIT_ARCH_X86_64 but sets bit 0x40000000 in the
		// number, so the arch check does not catch it and the
		// exact-number rules below would silently miss it (fall through
		// to ALLOW). Kill it like any other foreign ABI.
		emit(bpfJSETK, 0x40000000, "kill", "")
	}
	for _, name := range FakeMissing {
		emit(bpfJEQK, table[name], "enosys", "")
	}
	for _, name := range EPerm {
		emit(bpfJEQK, table[name], "eperm", "")
	}
	// Fall-through labels are positions in the instruction list; the tail
	// action blocks below are added to the same map.
	marks := map[string]int{}
	// clone(): deny only CLONE_NEWUSER (bit 28, below 2^32 on every arch
	// we support, so the low flags word is enough); threads use clone freely.
	emit(bpfJEQK, table["clone"], "", "after_clone")
	emit(bpfLDWAbs, 16, "", "") // args[0] low word (flags)
	emit(bpfJSETK, cloneNewUser, "eperm", "")
	emit(bpfLDWAbs, 0, "", "") // reload nr: A holds the flags
	marks["after_clone"] = len(insns)
	// ioctl(): TIOCSTI (fake tty input) / TIOCLINUX (raw console ioctls).
	// The kernel takes cmd as an unsigned int — the upper 32 bits of the
	// register are ignored — so only the low word is compared (Flatpak
	// uses MASKED_EQ 0xFFFFFFFF for the same reason). Requiring the high
	// word to be 0 here would let 0x1_0000_5412 through as TIOCSTI.
	emit(bpfJEQK, table["ioctl"], "", "after_ioctl")
	emit(bpfLDWAbs, 24, "", "") // args[1] low word (cmd is u32)
	emit(bpfJEQK, tiocsti, "eperm", "")
	emit(bpfJEQK, tioclinux, "eperm", "")
	emit(bpfLDWAbs, 0, "", "") // reload nr: A holds the cmd
	marks["after_ioctl"] = len(insns)
	// personality(): deny every persona CHANGE, allow the 0xffffffff
	// "query" magic only (the kernel returns the current persona and
	// changes nothing for that argument). Like ioctl, the argument is an
	// unsigned int, so only the low word is compared (0x1_0000_ffff_ffff
	// executes as the query).
	emit(bpfJEQK, table["personality"], "", "after_personality")
	emit(bpfLDWAbs, 16, "", "") // args[0] low word (u32)
	emit(bpfJEQK, PersonalityQuery, "allow", "")
	emit(bpfRETK, seccompRetErrno|syscallEPERM, "", "") // any change: EPERM
	marks["after_personality"] = len(insns)
	// socket(): allow only the usual families (SOCKET_FAMILIES; Flatpak's
	// set). socketpair() is not restricted: a socket pair never connects
	// anywhere.
	emit(bpfJEQK, table["socket"], "", "after_socket")
	emit(bpfLDWAbs, 16, "", "") // args[0] low word (domain)
	for _, fam := range SocketFamilies {
		emit(bpfJEQK, fam, "allow", "")
	}
	emit(bpfRETK, seccompRetErrno|syscallEPERM, "", "")
	// The default ALLOW comes directly after the last rule (fall-through
	// and skip targets must reach it, not the RET blocks below).
	marks["after_socket"] = len(insns)
	marks["allow"] = len(insns)
	emit(bpfRETK, seccompRetAllow, "", "")
	// Action blocks for the deny rules and the arch-mismatch kill.
	for _, block := range []struct {
		label  string
		action uint32
	}{
		{"enosys", seccompRetErrno | syscallENOSYS},
		{"eperm", seccompRetErrno | syscallEPERM},
		{"kill", seccompRetKillProcess},
	} {
		marks[block.label] = len(insns)
		emit(bpfRETK, block.action, "", "")
	}

	out := make([]byte, 0, len(insns)*8)
	for i, in := range insns {
		jt, err := jumpOffset(marks, in.jt, i)
		if err != nil {
			return nil, err
		}
		jf, err := jumpOffset(marks, in.jf, i)
		if err != nil {
			return nil, err
		}
		// struct.pack("<HBBI", code, jt, jf, k)
		var b [8]byte
		binary.LittleEndian.PutUint16(b[0:], in.code)
		b[2] = jt
		b[3] = jf
		binary.LittleEndian.PutUint32(b[4:], in.k)
		out = append(out, b[:]...)
	}
	return out, nil
}

// jumpOffset resolves a label to a forward cBPF jump offset (0 for the
// fall-through "" label); errors when the target is out of the 8-bit
// range (a builder bug — the deny-list is far too small to hit it).
func jumpOffset(marks map[string]int, label string, i int) (uint8, error) {
	if label == "" {
		return 0, nil
	}
	delta := marks[label] - i - 1
	if delta < 0 || delta > 255 {
		return 0, errors.New("seccomp: cBPF jump out of 8-bit range")
	}
	return uint8(delta), nil
}
