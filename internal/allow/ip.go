package allow

import "net/netip"

// BadIP reports whether addr must never be reached by RESOLVING an allowed
// name: private, loopback, link-local,
// multicast, reserved, unspecified or CGNAT ranges — plus, for IPv6, the
// address forms that embed an IPv4 address, judged by the EMBEDDED address:
//
//   - NAT64 (RFC 6052, 64:ff9b::/96): on DNS64 networks public IPv4-only hosts
//     come back this way — unwrap the low 32 bits and recurse.
//   - 6to4 (RFC 3056, 2002::/16): the v6 form looks global, but relays
//     decapsulate to the embedded IPv4 (bits 16..47), which may be
//     loopback/LAN — SSRF via e.g. a 2002:7f00:1:: answer.
//   - Teredo (RFC 4380, 2001:0::/32): deprecated — refuse the whole
//     prefix instead of decoding it.
//
// IPv4-mapped IPv6 addresses receive the full embedded IPv4 policy,
// including CGNAT. The fixed special-use address tables below include
// globally reachable exceptions such as 192.0.0.9/.10 and 2001:1::1.
// Boundary tests keep address classification independent of the host.
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

// badV4Nets covers private, special-use, multicast and reserved IPv4
// ranges. CGNAT is explicit: it must remain blocked even though it is
// neither RFC 1918 private space nor globally reachable.
var badV4Nets = mustParsePrefixes(
	"0.0.0.0/8",       // "this network" + unspecified
	"10.0.0.0/8",      // RFC 1918
	"100.64.0.0/10",   // CGNAT
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

// badV6Nets covers IPv6 special-use, unallocated and multicast ranges.
// Embedded IPv4 forms are handled before these covering ranges.
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
	//                completeness of the covering special-use ranges)
	"3fff::/20", // benchmarking (new registries)
	"fc00::/7",  // unique local
	"fe80::/10", // link-local
	// reserved (unallocated space)
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
