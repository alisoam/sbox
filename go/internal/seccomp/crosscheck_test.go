package seccomp

// Cross-check the hand-typed tables against kernel-header ground truth
// (tests/test_seccomp.py's cross-check, ported): parse __NR_<name> from
// the installed asm/unistd_64.h headers, and, when audit-tools is
// installed, `ausyscall <arch> --dump`. Both are best-effort: every
// source that is not present on this machine skips (the tables are
// additionally pinned by the differential test and the runtime probe).
//
// Run after editing Syscalls — a wrong number silently denies the wrong
// syscall.

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// candidate header locations per machine: the multiarch triplet first,
// then the plain /usr/include/asm symlink some single-arch systems ship.
var kernelHeaders = map[string][]string{
	"x86_64": {
		"/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
		"/usr/include/asm/unistd_64.h",
	},
	"aarch64": {
		"/usr/include/aarch64-linux-gnu/asm/unistd_64.h",
		"/usr/include/asm/unistd_64.h",
	},
	"riscv64": {
		"/usr/include/riscv64-linux-gnu/asm/unistd_64.h",
		"/usr/include/asm/unistd_64.h",
	},
}

var nrDefine = regexp.MustCompile(`^#define\s+__NR_(\w+)\s+(\d+)`)

func TestCrossCheckKernelHeaders(t *testing.T) {
	for machine, paths := range kernelHeaders {
		machine, paths := machine, paths
		t.Run(machine, func(t *testing.T) {
			var data []byte
			for _, p := range paths {
				if b, err := os.ReadFile(p); err == nil {
					data = b
					break
				}
			}
			if data == nil {
				t.Skipf("no kernel header here (tried %v)", paths)
			}
			nums := map[string]uint32{}
			for _, line := range strings.Split(string(data), "\n") {
				if m := nrDefine.FindStringSubmatch(line); m != nil {
					n, _ := strconv.ParseUint(m[2], 10, 32)
					nums[m[1]] = uint32(n)
				}
			}
			if len(nums) == 0 {
				t.Skip("header parsed to nothing — unexpected layout")
			}
			for name, want := range Syscalls[machine] {
				got, ok := nums[name]
				if !ok {
					t.Errorf("%s: kernel header has no __NR_%s — rename or drop the entry (and extend the cross-check)", machine, name)
					continue
				}
				if got != want {
					t.Errorf("%s: %s = %d in the table, kernel header says %d", machine, name, want, got)
				}
			}
		})
	}
}

func TestCrossCheckAusyscall(t *testing.T) {
	bin, err := exec.LookPath("ausyscall")
	if err != nil {
		t.Skip("ausyscall not installed")
	}
	for machine := range Syscalls {
		machine := machine
		t.Run(machine, func(t *testing.T) {
			out, err := exec.Command(bin, machine, "--dump").Output()
			if err != nil {
				t.Skipf("ausyscall does not know %s: %v", machine, err)
			}
			nums := map[string]uint32{}
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) != 2 {
					continue
				}
				n, err := strconv.ParseUint(fields[1], 10, 32)
				if err != nil {
					continue
				}
				nums[fields[0]] = uint32(n)
			}
			if len(nums) == 0 {
				t.Skip("ausyscall produced no name->number rows")
			}
			for name, want := range Syscalls[machine] {
				got, ok := nums[name]
				if !ok {
					t.Errorf("%s: ausyscall does not know %q", machine, name)
					continue
				}
				if got != want {
					t.Errorf("%s: %s = %d in the table, ausyscall says %d", machine, name, want, got)
				}
			}
		})
	}
}
