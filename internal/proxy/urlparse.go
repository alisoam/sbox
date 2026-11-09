package proxy

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// URL parsing preserves sbox's accepted input forms while rejecting ambiguous
// delimiters and non-ASCII ports. Upstream userinfo is percent-decoded as UTF-8.
// net/url uses different acceptance rules, so the parser is explicit here.

// URL errors are replaced by fixed client-facing messages at the call sites.
var errURL = errors.New("invalid URL")

// SplitURL holds the scheme, authority, path and query. Fragments are ignored.
// Hostname, Port, Username and Password interpret the authority on demand.
type SplitURL struct {
	Scheme string
	Netloc string
	Path   string
	Query  string
}

// URLSplit applies these normalization and validation rules:
//
//   - leading C0-and-space is stripped, but NOT trailing (some apps rely
//     on it — WHATWG strips both);
//   - tab/CR/LF are removed EVERYWHERE;
//   - a scheme must start with an ASCII letter and consist of ASCII
//     letters, digits, '+', '-' and '.', and is lowercased;
//   - a netloc (after "//") runs to the first of "/?#";
//   - mismatched brackets, an IPv4 literal in brackets and garbage in
//     brackets are errors; bracketed hosts
//     must be valid IPv6 (or IPvFuture v<hex>.<...>);
//   - a netloc containing characters that NFKC-normalize into "/?#@:"
//     (fullwidth slashes, small commercial at, ...) is an error —
//     spoofed delimiters;
//   - query splits at the first "?", after the fragment was cut.
func URLSplit(url string) (SplitURL, error) {
	var out SplitURL
	// url.lstrip(_WHATWG_C0_CONTROL_OR_SPACE)
	url = strings.TrimLeftFunc(url, func(r rune) bool { return r >= 0 && r <= 0x20 })
	// _UNSAFE_URL_BYTES_TO_REMOVE
	url = strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(url)

	// scheme
	if i := strings.IndexByte(url, ':'); i > 0 && isASCIILetter(url[0]) && allSchemeChars(url[:i]) {
		out.Scheme = strings.ToLower(url[:i])
		url = url[i+1:]
	}
	if strings.HasPrefix(url, "//") {
		netloc, rest := splitNetloc(url)
		out.Netloc, url = netloc, rest
		hasOpen, hasClose := strings.Contains(out.Netloc, "["), strings.Contains(out.Netloc, "]")
		if (hasOpen && !hasClose) || (hasClose && !hasOpen) {
			return out, errURL
		}
		if hasOpen && hasClose {
			if err := checkBracketedNetloc(out.Netloc); err != nil {
				return out, errURL
			}
		}
	}
	// Remove the fragment before splitting the query.
	if i := strings.IndexByte(url, '#'); i >= 0 {
		url = url[:i]
	}
	if i := strings.IndexByte(url, '?'); i >= 0 {
		out.Path, out.Query = url[:i], url[i+1:]
	} else {
		out.Path = url
	}
	if err := checkNetloc(out.Netloc); err != nil {
		return out, errURL
	}
	return out, nil
}

// splitNetloc is _splitnetloc: netloc runs to the earliest of "/?#"
// (start at 2, past the "//").
func splitNetloc(url string) (netloc, rest string) {
	delim := len(url)
	for _, c := range []byte{'/', '?', '#'} {
		if i := strings.IndexByte(url[2:], c); i >= 0 {
			if i+2 < delim {
				delim = i + 2
			}
		}
	}
	return url[2:delim], url[delim:]
}

// checkBracketedNetloc mirrors _check_bracketed_netloc: nothing before
// "[", only ":port" after "]", and the bracketed host must be a valid
// IPv6 literal (or IPvFuture).
func checkBracketedNetloc(netloc string) error {
	hostinfo := netloc
	if i := strings.LastIndexByte(netloc, '@'); i >= 0 {
		hostinfo = netloc[i+1:]
	}
	before, bracketed, hasOpen := strings.Cut(hostinfo, "[")
	if !hasOpen {
		return nil
	}
	if before != "" {
		return errURL
	}
	host, after, _ := strings.Cut(bracketed, "]")
	if after != "" && !strings.HasPrefix(after, ":") {
		return errURL
	}
	if len(host) > 0 && (host[0] == 'v' || host[0] == 'V') {
		if !ipvFutureRE.MatchString(host) {
			return errURL
		}
		return nil
	}
	// ipaddress.ip_address(host): valid IP, but NOT IPv4, in brackets.
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Is4() || !strings.Contains(host, ":") {
		return errURL
	}
	return nil
}

var ipvFutureRE = regexp.MustCompile(`^[vV][a-fA-F0-9]+\..+$`)

// nfkcDangerous are the code points whose NFKC normalization contains one
// of "/?#@:": fullwidth forms, small-form punctuation,
// "a/c"-style abbreviations and the double-question-mark ligatures. A
// netloc containing any of them could smuggle a delimiter past the
// parser after normalization.
var nfkcDangerous = map[rune]bool{
	0x2047: true, // ?? (double question mark)
	0x2048: true, // ?!
	0x2049: true, // !?
	0x2100: true, // a/c
	0x2101: true, // a/s
	0x2105: true, // c/o
	0x2106: true, // c/u
	0x2a74: true, // ::=
	0xfe13: true, // ︓ presentation form colon
	0xfe16: true, // ︖ presentation form question mark
	0xfe55: true, // ︕ small colon
	0xfe56: true, // small question mark
	0xfe5f: true, // small number sign
	0xfe6b: true, // small commercial at
	0xff03: true, // ＃ fullwidth number sign
	0xff0f: true, // ／ fullwidth solidus
	0xff1a: true, // ： fullwidth colon
	0xff1f: true, // ？ fullwidth question mark
	0xff20: true, // ＠ fullwidth commercial at
}

// checkNetloc mirrors _checknetloc: only applies to non-ASCII netlocs;
// any character that NFKC-expands into a delimiter rejects the URL.
func checkNetloc(netloc string) error {
	if netloc == "" || isASCII(netloc) {
		return nil
	}
	for _, r := range netloc {
		if nfkcDangerous[r] {
			return errURL
		}
	}
	return nil
}

// Hostname returns the lowercased host after the last "@", with IPv6 brackets
// removed. An absent authority produces an empty hostname.
func (s SplitURL) Hostname() string {
	hostinfo := s.Netloc
	if i := strings.LastIndexByte(s.Netloc, '@'); i >= 0 {
		hostinfo = s.Netloc[i+1:]
	}
	if _, bracketed, hasOpen := strings.Cut(hostinfo, "["); hasOpen {
		host, _, _ := strings.Cut(bracketed, "]")
		return strings.ToLower(host)
	}
	host, _, _ := strings.Cut(hostinfo, ":")
	return strings.ToLower(host)
}

// Port returns (value, present, error). Empty ports are absent; a present
// port must be ASCII decimal in 0..65535. Callers reject port zero before dial.
func (s SplitURL) Port() (int, bool, error) {
	port := s.portString()
	if port == "" {
		return 0, false, nil
	}
	n, ok := parseURLPort(port)
	if !ok || n > 65535 {
		return 0, false, errURL
	}
	return n, true, nil
}

func (s SplitURL) portString() string {
	hostinfo := s.Netloc
	if i := strings.LastIndexByte(s.Netloc, '@'); i >= 0 {
		hostinfo = s.Netloc[i+1:]
	}
	if _, bracketed, hasOpen := strings.Cut(hostinfo, "["); hasOpen {
		_, rest, _ := strings.Cut(bracketed, "]")
		_, p, _ := strings.Cut(rest, ":")
		return p
	}
	_, p, _ := strings.Cut(hostinfo, ":")
	return p
}

// Username returns userinfo before its first colon, still percent-encoded,
// or an absent value when the authority has no "@".
func (s SplitURL) Username() (string, bool) {
	userinfo, hasAt := cutLast(s.Netloc, "@")
	if !hasAt {
		return "", false
	}
	u, _, _ := strings.Cut(userinfo, ":")
	return u, true
}

// Password returns the part after the first ":" of
// the userinfo, absent when the userinfo has no ":".
func (s SplitURL) Password() (string, bool) {
	userinfo, hasAt := cutLast(s.Netloc, "@")
	if !hasAt {
		return "", false
	}
	_, p, hasColon := strings.Cut(userinfo, ":")
	return p, hasColon
}

// cutLast returns the portion preceding the last separator, if present.
func cutLast(s, sep string) (string, bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, false
	}
	return s[:i], true
}

// parseURLPort accepts ASCII decimal digits, including leading zeros, but
// rejects signs, whitespace, underscores and non-ASCII decimal digits.
func parseURLPort(s string) (int, bool) {
	if s == "" || len(s) > 20 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0, false // absurd; the range check below decides real cases
		}
	}
	return n, true
}

// isDigitsASCII is str.isdigit() restricted to ASCII.
func isDigitsASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

const schemeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-."

func allSchemeChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(schemeChars, rune(s[i])) {
			return false
		}
	}
	return true
}

// unquoteUserinfo decodes percent-escapes as UTF-8, replacing each invalid
// byte with U+FFFD. A plus sign remains a plus sign.
func unquoteUserinfo(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	raw := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			raw = append(raw, hexVal(s[i+1])<<4|hexVal(s[i+2]))
			i += 2
			continue
		}
		raw = append(raw, s[i])
	}
	// UTF-8 decode with per-byte replacement (strings.ToValidUTF8 would
	// coalesce runs of bad bytes instead of replacing each byte separately).
	var b strings.Builder
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(0xFFFD)
			i++
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// ParseHostPort accepts bracketed IPv6 or a host with a trailing port.
// A missing port uses defaultPort. Legacy empty-host and missing-bracket
// spellings are retained here, then rejected by destination validation.
func ParseHostPort(target string, defaultPort int) (string, int, error) {
	if strings.HasPrefix(target, "[") {
		host, rest, _ := strings.Cut(target[1:], "]")
		if host == "" || (rest != "" && !strings.HasPrefix(rest, ":")) {
			return "", 0, fmt.Errorf("bad CONNECT target %q", target)
		}
		if rest == "" {
			return host, defaultPort, nil
		}
		// Port syntax is limited to ASCII decimal digits.
		n, ok := parseURLPort(rest[1:])
		if !ok {
			return "", 0, errParseTarget
		}
		return host, n, nil
	}
	i := strings.LastIndexByte(target, ':')
	if i < 0 || target[:i] == "" {
		return target, defaultPort, nil
	}
	p := target[i+1:]
	if !isDigitsASCII(p) {
		return "", 0, errParseTarget
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, errParseTarget
	}
	return target[:i], n, nil
}

// Callers report a fixed "bad CONNECT target" body on parse failure.
var errParseTarget = errors.New("bad CONNECT target")
