package allow

import "net/netip"

// BadIP reports whether addr must never be reached by RESOLVING an allowed
// name (the SSRF guard of sbox.py's bad_ip): private, loopback, link-local,
// multicast, reserved, unspecified or CGNAT ranges — plus, for IPv6, the
// address forms that embed an IPv4 address, judged by the EMBEDDED address:
//
//   - NAT64 (RFC 6052, 64:ff9b::/96): ipaddress marks the whole prefix
//     reserved, but on DNS64 networks legitimate public IPv4-only hosts
//     come back this way — unwrap the low 32 bits and recurse.
//   - 6to4 (RFC 3056, 2002::/16): the v6 form looks global, but relays
//     decapsulate to the embedded IPv4 (bits 16..47), which may be
//     loopback/LAN — SSRF via e.g. a 2002:7f00:1:: answer.
//   - Teredo (RFC 4380, 2001:0::/32): deprecated — refuse the whole
//     prefix instead of decoding it, and do not rely on is_private
//     covering 2001::/23 on every Python version.
//
// IPv4-mapped IPv6 addresses are judged as their embedded IPv4 (CPython's
// predicate delegation semantics). The tables below mirror CPython 3.15's
// ipaddress module (iana-ipv4/6-special-registry derived, including
// exceptions like 192.0.0.9/.10 and 2001:1::1) so the Go port is pinned to
// one deterministic ground truth instead of whichever Python happens to be
// installed; the boundary tests in ip_test.go pin them.
func BadIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true // unparseable answers are not usable answers
	}
	if addr.Is4In6() {
		return badV4(addr.Unmap())
	}
	if addr.Is4() {
		return badV4(addr)
	}
	// true IPv6: embedded-IPv4 forms first, then the predicate union
	if nat64Prefix.Contains(addr) {
		b := addr.As16()
		return BadIP(netip.AddrFrom4([4]byte(b[12:16])))
	}
	if sixTo4Prefix.Contains(addr) {
		b := addr.As16()
		return BadIP(netip.AddrFrom4([4]byte(b[2:6])))
	}
	if teredoPrefix.Contains(addr) {
		return true
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	return inAny(badV6Nets, addr) && !inAny(badV6Exceptions, addr)
}

func badV4(addr netip.Addr) bool {
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	return inAny(badV4Nets, addr) && !inAny(badV4Exceptions, addr)
}

var (
	nat64Prefix  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4Prefix = netip.MustParsePrefix("2002::/16")
	teredoPrefix = netip.MustParsePrefix("2001::/32")
)

// badV4Nets: the union of CPython 3.15's IPv4 private networks, the
// reserved network (240.0.0.0/4, which includes 255.255.255.255) and the
// CGNAT range EXTRA_BAD_NETS from sbox.py (100.64.0.0/10 — not is_private
// on older Pythons, listed explicitly). 192.0.0.170/31 and
// 255.255.255.255/32 from the private list are subsumed by 192.0.0.0/24
// and 240.0.0.0/4.
var badV4Nets = mustParsePrefixes(
	"0.0.0.0/8",       // "this network" + unspecified
	"10.0.0.0/8",      // RFC 1918
	"100.64.0.0/10",   // CGNAT (EXTRA_BAD_NETS)
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local (incl. 169.254.169.254)
	"172.16.0.0/12",   // RFC 1918
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.168.0.0/16",  // RFC 1918
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved for future use (+ broadcast)
)

// badV4Exceptions: globally reachable holes in the private ranges above
// (Port Control Protocol Anycast and NAT64/IPv6 translators Anycast).
var badV4Exceptions = mustParsePrefixes(
	"192.0.0.9/32",
	"192.0.0.10/32",
)

// badV6Nets: CPython 3.15's IPv6 private networks (with 4in6 delegation
// handled in BadIP, so ::ffff:0:0/96 only matters for exactness), the
// reserved unallocated-space list and multicast ff00::/8.
var badV6Nets = mustParsePrefixes(
	// private (iana-ipv6-special-registry)
	"::1/128",        // loopback
	"::/128",         // unspecified
	"::ffff:0:0/96",  // v4-mapped (see BadIP: judged as embedded v4 there)
	"64:ff9b:1::/48", // local-use NAT64
	"100::/64",       // discard-only
	"2001::/23",      // IETF protocol assignments / Teredo / ORCHID...
	"2001:db8::/32",  // documentation
	"2002::/16",      // 6to4 (judged by embedded v4 in BadIP; kept for
	//                table fidelity with CPython's is_private)
	"3fff::/20", // benchmarking (new registries)
	"fc00::/7",  // unique local
	"fe80::/10", // link-local
	// reserved (unallocated space, CPython _reserved_networks)
	"::/8",
	"100::/8",
	"200::/7",
	"400::/6",
	"800::/5",
	"1000::/4",
	"4000::/3",
	"6000::/3",
	"8000::/3",
	"a000::/3",
	"c000::/3",
	"e000::/4",
	"f000::/5",
	"f800::/6",
	"fe00::/9",
	// multicast
	"ff00::/8",
)

// badV6Exceptions: globally reachable holes inside 2001::/23.
var badV6Exceptions = mustParsePrefixes(
	"2001:1::1/128",   // Teredo default ports
	"2001:1::2/128",   // Teredo default ports
	"2001:3::/32",     // AMT
	"2001:4:112::/48", // AS112-v6
	"2001:20::/28",    // ORCHIDv2
	"2001:30::/28",    // Drone Remote ID
)

func mustParsePrefixes(specs ...string) []netip.Prefix {
	ps := make([]netip.Prefix, len(specs))
	for i, s := range specs {
		ps[i] = netip.MustParsePrefix(s)
	}
	return ps
}

func inAny(nets []netip.Prefix, addr netip.Addr) bool {
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}
