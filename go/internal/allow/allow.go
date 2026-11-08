// Package allow implements sbox's network allowlist: entry parsing
// (parse_allow_entry), loading from -a/-A (load_allows), destination
// matching (destination_allowed) and the resolved-address guard (bad_ip)
// — a faithful port of sbox.py's allowlist layer, plus the !private
// marker, single-label warning and $no_proxy handling from the current
// spec.
//
// Security model (default-deny):
//
//   - A destination is checked against the allowlist BEFORE anything else;
//     in particular hostnames of DENIED destinations are never resolved —
//     there is no DNS side channel. DestinationAllowed performs NO DNS and
//     NO connection.
//   - Suffix match is on dot boundaries: -a example.com allows example.com
//     and sub.example.com, but not notexample.com. Entries may carry a
//     port (example.com:443); IPs and CIDRs are also accepted.
//   - Catch-all entries (bare '*', 0.0.0.0/0, ::/0) and effectively
//     catch-all networks (shorter than /8 for v4, /16 for v6, e.g.
//     0.0.0.0/1 + 128.0.0.0/1 which would bypass the private-range guard
//     for literal-IP destinations) are rejected loudly instead of being
//     widened or allowed silently. So are CIDRs with host bits set —
//     never silently widen "203.0.113.7/24" to the whole /24.
//   - Names resolved host-side are additionally checked with BadIP
//     (private/loopback/link-local/CGNAT/multicast/reserved ranges...),
//     so an allowed name cannot be used to reach host/LAN services (SSRF
//     guard, incl. 169.254.169.254). Literal-IP destinations match only
//     IP/CIDR entries and are never resolved, so they bypass that guard
//     on purpose (explicit intent). The !private marker extends that
//     explicit intent to names: answers for a marked entry may resolve
//     into guarded ranges (split-horizon DNS etc.) — use with care.
//   - Anything that looks like an address but is not a valid one
//     ("300.1.2.3") is rejected loudly, never reclassified as a name.
//
// Entries carry the port-scoped form (example.com:443, [2001:db8::]:443);
// a port-scoped entry matches only that destination port.
package allow

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Entry is one parsed allow entry (sbox.py's {"kind","value","port"} dict).
type Entry struct {
	Kind    string // "name" (hostname, dot-boundary suffix match) or "net" (IP/CIDR)
	Value   string // canonical form: hostname, or "a.b.c.d/nn" / "2001:db8::/nn"
	Port    int    // 0 = any port
	Private bool   // !private marker: resolved answers may fall in guarded ranges

	prefix netip.Prefix // parsed CIDR for kind == "net"
}

var nameRE = regexp.MustCompile(
	`^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*$`)

// bracketRE matches [v6], [v6]/plen and [v6]:port forms.
var bracketRE = regexp.MustCompile(`^\[([0-9a-f:.]+)\](?:/(\d{1,3}))?(?::(\d+))?$`)

// ParseAllowEntry parses one allow entry. Accepts: example.com,
// *.example.com (same thing), example.com:443, 203.0.113.7,
// 203.0.113.0/24, [2001:db8::]/32, [2001:db8::]:443 and the !private
// marker suffix (example.com!private). '#' starts a comment. Rejects
// anything else loudly (this is a fail-closed tool) — including !private
// on IP/CIDR entries, which the guard never applies to anyway.
func ParseAllowEntry(raw string) (Entry, error) {
	e := strings.ToLower(strings.TrimSpace(strings.SplitN(raw, "#", 2)[0]))
	private := false
	if strings.HasSuffix(e, "!private") {
		private = true
		e = strings.TrimSpace(strings.TrimSuffix(e, "!private"))
	}
	for strings.HasPrefix(e, "*.") {
		e = e[2:]
	}
	e = strings.Trim(e, ".")
	if e == "" {
		return Entry{}, errors.New("empty entry")
	}
	if onlyChars(e, "*.") {
		return Entry{}, errors.New("wildcard-only entry would allow everything; use --net for unrestricted egress")
	}

	port := 0
	hasPort := false
	host := e
	if strings.HasPrefix(e, "[") {
		m := bracketRE.FindStringSubmatch(e)
		if m == nil || !strings.Contains(m[1], ":") { // a bracketed host must be IPv6
			return Entry{}, fmt.Errorf("malformed IPv6 entry: %q", raw)
		}
		host = m[1]
		if m[2] != "" {
			host += "/" + m[2]
		}
		if m[3] != "" {
			p, err := strconv.Atoi(m[3])
			if err != nil {
				return Entry{}, fmt.Errorf("bad port in allow entry %q (expected 1-65535)", raw)
			}
			port, hasPort = p, true
		}
	} else if strings.Count(e, ":") == 1 {
		var p string
		host, p, _ = strings.Cut(e, ":")
		if !isDigits(p) {
			return Entry{}, fmt.Errorf("bad port in allow entry %q (expected host:port)", raw)
		}
		pn, err := strconv.Atoi(p)
		if err != nil {
			return Entry{}, fmt.Errorf("bad port in allow entry %q (expected 1-65535)", raw)
		}
		port, hasPort = pn, true
	}
	if hasPort && (port < 1 || port > 65535) {
		return Entry{}, fmt.Errorf("bad port in allow entry %q (expected 1-65535)", raw)
	}

	if strings.Contains(host, "*") {
		return Entry{}, fmt.Errorf("wildcards are only supported as a leading '*.' in %q", raw)
	}

	if addr, bits, ok := parseAddrNet(host); ok {
		p := netip.PrefixFrom(addr, bits) // zone-stripped, for matching
		if p == p.Masked() {
			// /0 is an explicit catch-all, but 0.0.0.0/1 + 128.0.0.0/1
			// (or ::/1) amount to the same thing while silently bypassing
			// the private-range guard for literal-IP destinations. Refuse
			// effectively-global nets.
			minBits := 16
			if addr.BitLen() == 32 {
				minBits = 8
			}
			if bits < minBits {
				return Entry{}, fmt.Errorf(
					"%q is an effectively catch-all network (/%d); add narrower entries or use --net for unrestricted egress",
					raw, bits)
			}
			if private {
				return Entry{}, fmt.Errorf(
					"%q: !private only applies to name entries — literal IP/CIDR entries bypass the private-range guard anyway",
					raw)
			}
			// Value mirrors str(ip_network(...)) — zone included;
			// matching itself is zone-blind (see prefixContains).
			return Entry{
				Kind:   "net",
				Value:  addr.String() + "/" + strconv.Itoa(bits),
				Port:   port,
				prefix: p,
			}, nil
		}
		// fall through: host bits set — strict refuses (handled below)
	}

	// Not a strict network. Anything that *looks* like an address must be
	// a valid one — never silently reclassify e.g. "300.1.2.3" or
	// "example.com:443" as a name.
	if (host != "" && onlyChars(host, "0123456789.")) || strings.Contains(host, ":") {
		if w, ok := widenedNetwork(host); ok {
			return Entry{}, fmt.Errorf("%q: host bits set — refusing to widen to %s; write %s instead",
				raw, w, w)
		}
		return Entry{}, fmt.Errorf("invalid IP/CIDR entry: %q", raw)
	}
	if !nameRE.MatchString(host) {
		return Entry{}, fmt.Errorf("not a valid hostname, IP or CIDR: %q", raw)
	}
	return Entry{Kind: "name", Value: host, Port: port, Private: private}, nil
}

// LoadAllows loads entries from -A files (first) and -a values (after),
// like sbox.py's load_allows. warn receives advisory warnings (single-label
// entries); it may be nil. Every parse problem is an error — fail closed.
func LoadAllows(optAllows, optFiles []string, warn func(string)) ([]Entry, error) {
	if warn == nil {
		warn = func(string) {}
	}
	add := func(raw string, e Entry) {
		if e.Kind == "name" && !strings.Contains(e.Value, ".") {
			warn(fmt.Sprintf(
				"warning: allow entry %q is a single label — it allows every host under %q (a whole TLD/registry); "+
					"add a domain part unless that is intended", raw, e.Value))
		}
	}
	var entries []Entry
	for _, path := range optFiles {
		st, err := os.Stat(path)
		if err != nil || !st.Mode().IsRegular() {
			return nil, fmt.Errorf("cannot read allow file: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("cannot read allow file: %s", path)
		}
		for lineno, line := range strings.Split(string(data), "\n") {
			// '#' comments and blank lines are stripped BEFORE parsing
			// (sbox.py's load_allows does the same) — so error messages
			// quote the entry, not the trailing comment.
			raw := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			if raw == "" {
				continue
			}
			e, err := ParseAllowEntry(raw)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, lineno+1, err)
			}
			add(raw, e)
			entries = append(entries, e)
		}
	}
	for _, raw := range optAllows {
		e, err := ParseAllowEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("--allow: %w", err)
		}
		add(raw, e)
		entries = append(entries, e)
	}
	return entries, nil
}

// DestinationAllowed is the allowlist check for a destination. It performs
// NO DNS and NO connection. Literal IPs match only IP/CIDR entries; names
// match name entries by exact or dot-boundary suffix comparison.
// Port-scoped entries additionally require the destination port to match.
func DestinationAllowed(allows []Entry, host string, port int) (bool, string) {
	h := strings.ToLower(strings.TrimRight(host, "."))
	addr, err := netip.ParseAddr(h)
	if err == nil {
		for _, a := range allows {
			if a.Kind == "net" && (a.Port == 0 || a.Port == port) && prefixContains(a.prefix, addr) {
				return true, fmt.Sprintf("matches allowed network %s", a.Value)
			}
		}
		return false, "IP destination not in any allowed network"
	}
	for _, a := range allows {
		if a.Kind == "name" && (a.Port == 0 || a.Port == port) {
			v := a.Value
			if h == v || strings.HasSuffix(h, "."+v) {
				return true, fmt.Sprintf("matches allowed name %s", v)
			}
		}
	}
	return false, "hostname not on the allowlist"
}

// PrivateAllowed reports whether host:port is exempt from the resolved-
// address guard (BadIP): an entry marked !private covers it. This is the
// name-side analog of the deliberate literal-IP bypass — explicit intent.
func PrivateAllowed(allows []Entry, host string, port int) bool {
	h := strings.ToLower(strings.TrimRight(host, "."))
	for _, a := range allows {
		if !a.Private || a.Kind != "name" || (a.Port != 0 && a.Port != port) {
			continue
		}
		if h == a.Value || strings.HasSuffix(h, "."+a.Value) {
			return true
		}
	}
	return false
}

// ValidHostname reports whether host is a well-formed lowercase hostname
// per sbox.py's NAME_RE (the full-match form used by the proxy before it
// hands a sandbox-supplied name to the resolver; allowlist entry parsing
// uses the same grammar). It performs no DNS and no lowercasing.
func ValidHostname(host string) bool {
	return nameRE.MatchString(host)
}

// prefixContains is Python's `addr in ip_network(...)`: v4 addresses never
// match v6 prefixes and vice versa (IPv4-mapped destinations count as v6),
// and zones are ignored, like ipaddress's integer __contains__.
func prefixContains(p netip.Prefix, a netip.Addr) bool {
	if !p.IsValid() || !a.IsValid() {
		return false
	}
	if p.Addr().BitLen() != a.BitLen() {
		return false
	}
	return p.Contains(a.WithZone(""))
}

// parseAddrNet is the parsing half of ip_network(host): a bare address
// gets the full-length prefix, "addr/bits" the given length. Python
// accepts leading zeros in the prefix length ("/08" is /8); netip does
// not, so they are stripped. The returned address keeps its zone (if
// any); the ok flag does NOT cover host bits — that is strictness, which
// the caller checks on the masked prefix.
func parseAddrNet(host string) (netip.Addr, int, bool) {
	if base, bits, ok := strings.Cut(host, "/"); ok {
		if trimmed := strings.TrimLeft(bits, "0"); trimmed != "" {
			bits = trimmed
		} else {
			bits = "0"
		}
		n, err := strconv.Atoi(bits)
		if err != nil || n < 0 || n > 128 {
			return netip.Addr{}, 0, false
		}
		addr, err := netip.ParseAddr(base)
		if err != nil || n > addr.BitLen() {
			return netip.Addr{}, 0, false
		}
		return addr, n, true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	return addr, addr.BitLen(), true
}

// widenedNetwork is ip_network(host, strict=False): the network under an
// address with host bits set (used only in the "refusing to widen" error).
func widenedNetwork(host string) (netip.Prefix, bool) {
	addr, bits, ok := parseAddrNet(host)
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}

func onlyChars(s, set string) bool {
	for _, r := range s {
		if !strings.ContainsRune(set, r) {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
