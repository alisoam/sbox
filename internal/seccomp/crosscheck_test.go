package seccomp

// Cross-check hand-typed tables against installed kernel headers and ausyscall.
// Missing reference tools skip; golden fixtures, interpreter cases and the
// native runtime probe provide independent coverage on every test run.

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
		"/usr/include/asm-generic/unistd.h",
	},
	"riscv64": {
		"/usr/include/asm-generic/unistd.h",
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
			nums := parseAusyscallDump(string(out))
			if len(nums) == 0 {
				t.Fatal("ausyscall produced no syscall rows")
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

// ausyscall --dump emits NUMBER NAME rows beneath an architecture heading.
func parseAusyscallDump(out string) map[string]uint32 {
	nums := map[string]uint32{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 32)
		if err == nil {
			nums[fields[1]] = uint32(n)
		}
	}
	return nums
}

func TestParseAusyscallDump(t *testing.T) {
	nums := parseAusyscallDump("Using x86_64 syscall table:\n0\tread\n16\tioctl\n272\tunshare\n")
	if len(nums) != 3 || nums["ioctl"] != 16 || nums["unshare"] != 272 {
		t.Fatalf("wrong kernel reference numbers: %v", nums)
	}
}
