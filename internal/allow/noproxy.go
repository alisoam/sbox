package allow

import (
	"net/netip"
	"strings"
	"unicode"
)

// NoProxy is a parsed $no_proxy list. It decides per-destination whether
// an upstream proxy is bypassed (direct egress); the allowlist still
// applies either way — no_proxy never widens what is reachable.
//
// Routing semantics:
//
//   - entries are separated by commas and/or whitespace; surrounding
//     whitespace is ignored, empty entries dropped;
//   - leading and trailing '*' and '.' characters are ignored (the
//     conventional suffix markers), so "example.com.", "*.example.com"
//     and "example.com" are the same entry;
//   - a "host:port" entry loses its port — it matches any port of that
//     host (curl ignores no_proxy ports; better a working route than an
//     entry that can never match);
//   - IP entries (v4/v6 literals or CIDRs like 10.0.0.0/8, "[::1]/128"
//     after bracket stripping) match LITERAL IP destinations only —
//     no_proxy is a ROUTE hint and never triggers DNS;
//   - name entries match the destination by exact or dot-boundary suffix
//     comparison, like allowlist name entries;
//   - a single "*" matches everything;
//   - entries that are neither valid hostnames nor valid networks are
//     dropped: they could never match.
type NoProxy struct {
	Any   bool
	Names []string
	Nets  []netip.Prefix
}

// ParseNoProxy parses a no_proxy list (comma- and/or whitespace-separated).
func ParseNoProxy(raw string) NoProxy {
	var np NoProxy
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	}) {
		if item == "*" { // catch-all, before any stripping
			np.Any = true
			continue
		}
		if strings.HasPrefix(item, "[") { // [v6] or [v6]:port
			if host, _, ok := strings.Cut(item[1:], "]"); ok {
				item = host
			}
		} else if strings.Count(item, ":") == 1 { // host:port
			if h, p, _ := strings.Cut(item, ":"); isDigits(p) {
				item = h
			}
		}
		item = strings.Trim(item, "*.")
		item = strings.ToLower(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") { // CIDR (host bits masked)
			if w, ok := widenedNetwork(item); ok {
				np.Nets = append(np.Nets, w)
			}
			continue // invalid CIDR: dropped, never a name
		}
		if addr, err := netip.ParseAddr(item); err == nil {
			addr = addr.WithZone("") // zone-blind matching, like the allowlist
			np.Nets = append(np.Nets, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		if !nameRE.MatchString(item) {
			continue // never matches; drop it
		}
		np.Names = append(np.Names, item)
	}
	return np
}

// Matches reports whether the destination host is covered. IP-ness is
// decided by parsing the host: an IP literal is only matched against
// IP/CIDR entries (no_proxy never triggers DNS), a hostname only against
// name entries.
func (np NoProxy) Matches(host string) bool {
	if np.Any {
		return true
	}
	h := strings.ToLower(strings.TrimRight(host, "."))
	if addr, err := netip.ParseAddr(h); err == nil {
		for _, n := range np.Nets {
			if prefixContains(n, addr) {
				return true
			}
		}
		return false
	}
	for _, n := range np.Names {
		if h == n || strings.HasSuffix(h, "."+n) {
			return true
		}
	}
	return false
}

// NoProxyFromEnv reads the no_proxy environment (lowercase wins, like the
// https_proxy fallback: a set-but-empty $no_proxy falls through to
// $NO_PROXY). It returns nil when neither variable carries a value, in
// which case nothing is bypassed.
func NoProxyFromEnv(getenv func(string) string) *NoProxy {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	raw := getenv("no_proxy")
	if raw == "" {
		raw = getenv("NO_PROXY")
	}
	if raw == "" {
		return nil
	}
	np := ParseNoProxy(raw)
	return &np
}
