package cliutil

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Forward names endpoints in two namespaces. Remote puts the listener in the sandbox.
type Forward struct {
	Remote bool
	Listen netip.AddrPort
	Target netip.AddrPort
}

const forwardIP = `(?:localhost|[0-9.]+|\[[0-9a-fA-F:.]+\])`

var forwardSpec = regexp.MustCompile(`^(?:(` + forwardIP + `):)?([0-9]+):(` + forwardIP + `):([0-9]+)$`)

func parseForward(s string, remote bool) (Forward, error) {
	bind, listenPort, dest, destPort := "", "", "", ""
	if a, b, ok := strings.Cut(s, ":"); ok && digitsOnly(a) && digitsOnly(b) {
		listenPort, destPort = a, b
	} else if m := forwardSpec.FindStringSubmatch(s); m != nil {
		bind, listenPort, dest, destPort = m[1], m[2], m[3], m[4]
	} else {
		return Forward{}, fmt.Errorf("invalid forward %q (expected [BIND_IP:]PORT:DEST_IP:DEST_PORT or PORT:DEST_PORT)", s)
	}
	listen, err := forwardEndpoint(bind, listenPort)
	if err != nil {
		return Forward{}, err
	}
	target, err := forwardEndpoint(dest, destPort)
	if err != nil {
		return Forward{}, err
	}
	if target.Addr().IsUnspecified() {
		return Forward{}, fmt.Errorf("forward destination %q needs a specific IP address", dest)
	}
	return Forward{Remote: remote, Listen: listen, Target: target}, nil
}

func forwardEndpoint(ip, port string) (netip.AddrPort, error) {
	if ip == "" || ip == "localhost" {
		ip = "127.0.0.1"
	}
	addr, err := netip.ParseAddr(strings.Trim(ip, "[]"))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid forward IP %q", ip)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid forward port %q (expected 1..65535)", port)
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(n)), nil
}

// ValidateForwards rejects rule sets whose relays can dial each other's
// listeners. Every accepted connection spawns a fresh dial, so a loop
// multiplies one client connection until the launcher exhausts its file
// descriptors; it must die before any listener starts. A dial is captured by
// a listener when both endpoints live in the same network namespace — --net
// puts every endpoint in the host namespace, an isolated -L listens on the
// host and dials in the sandbox, an isolated -R the reverse — the ports
// match, and the listener is bound to the exact address or to a wildcard.
//
// Wildcards fail closed: 0.0.0.0/[::] claim their whole port for EVERY
// destination in the namespace, both address families, even addresses that
// might turn out to be remote — the validator cannot know which addresses
// the namespace owns, and connect() to an unspecified address lands on
// loopback anyway (that substitution is applied to dials here).
func ValidateForwards(netShared bool, forwards []Forward) error {
	const hostNS, sandboxNS = 0, 1
	type fwEnd struct {
		ap netip.AddrPort
		ns int
	}
	listen, dial := make([]fwEnd, len(forwards)), make([]fwEnd, len(forwards))
	for i, f := range forwards {
		ln, tg := hostNS, hostNS
		if !netShared {
			ln, tg = sandboxNS, hostNS // -R: listener inside, dial on the host
			if !f.Remote {
				ln, tg = hostNS, sandboxNS // -L: listener on the host, dial inside
			}
		}
		listen[i], dial[i] = fwEnd{f.Listen, ln}, fwEnd{f.Target, tg}
	}
	loopback := func(a netip.Addr) netip.Addr {
		if !a.IsUnspecified() {
			return a
		}
		if a.Is4() {
			return netip.AddrFrom4([4]byte{127, 0, 0, 1})
		}
		return netip.AddrFrom16([16]byte{15: 1}) // ::1
	}
	captures := func(d, l fwEnd) bool {
		return d.ns == l.ns && d.ap.Port() == l.ap.Port() &&
			(l.ap.Addr().IsUnspecified() || l.ap.Addr() == loopback(d.ap.Addr()))
	}
	// Edge i→j when rule i's dial lands on rule j's listener (i == j
	// included); any cycle can spin forever. DFS with an explicit stack.
	const unseen, active, done = 0, 1, 2
	state := make([]int, len(forwards))
	var stack []int
	var visit func(int) []string
	visit = func(i int) []string {
		state[i] = active
		stack = append(stack, i)
		for j := range forwards {
			if !captures(dial[i], listen[j]) {
				continue
			}
			if state[j] == active {
				k := 0
				for stack[k] != j {
					k++
				}
				cycle := make([]string, 0, len(stack)-k)
				for _, r := range stack[k:] {
					cycle = append(cycle, forwardLabel(forwards[r]))
				}
				return cycle
			}
			if state[j] == unseen {
				if c := visit(j); c != nil {
					return c
				}
			}
		}
		state[i] = done
		stack = stack[:len(stack)-1]
		return nil
	}
	for i := range forwards {
		if c := visit(i); c != nil {
			if len(c) == 1 {
				return fmt.Errorf("forwarding loop: %s connects back to its own listener", c[0])
			}
			return fmt.Errorf("forwarding loop: %s (every connection is relayed around "+
				"the cycle until the launcher runs out of file descriptors)", strings.Join(c, " -> "))
		}
	}
	return nil
}

// forwardLabel renders one rule for diagnostics: "-L 127.0.0.1:80->127.0.0.1:81".
func forwardLabel(f Forward) string {
	flag := "-L"
	if f.Remote {
		flag = "-R"
	}
	return flag + " " + f.Listen.String() + "->" + f.Target.String()
}
