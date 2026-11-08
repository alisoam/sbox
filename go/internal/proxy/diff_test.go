package proxy

// The differential cross-check: identical inputs to this port and to the
// Python reference (the REPO's sbox.py — the spec under port, found by
// oracle.SboxPy() walking up from the test's working directory; an
// older installed ~/.local/bin/sbox.py must never silently take its
// place), outputs compared. This is the scratch zzdiff harness of the
// porting effort, kept as a permanent test — it catches semantic drift
// the unit tables cannot (quirks nobody remembered to pin) for as long
// as sbox.py exists.
//
// Corpus rules, so the comparison stays meaningful:
//
//   - Messages that embed resolver/OS error text are compared by status
//     line only (the texts legitimately differ between runtimes).
//   - Hostname-bearing texts are compared after quote normalization:
//     the port quotes attacker-controlled bytes Go-style (%q) per the
//     invariant checklist, Python uses repr — same guarantee, different
//     quote character.
//
// Everything skips cleanly when python3 or sbox.py is missing
// ($SBOX_PY / $SBOX_PYTHON override), so the suite stays green without
// the oracle.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sbox/internal/allow"
	"sbox/internal/oracle"
)

func requireOracle(t *testing.T) {
	t.Helper()
	if !oracle.Available() {
		t.Skip("differential oracle unavailable: python3 + sbox.py not found (set $SBOX_PY / $SBOX_PYTHON)")
	}
}

// runOracleBatch feeds reqs (JSON-encoded) to a driver evaluating expr
// per request and returns ["OK", value] / ["ERR", message] lines.
func runOracleBatch(t *testing.T, expr string, reqs []any) [][2]any {
	t.Helper()
	var sb strings.Builder
	for _, r := range reqs {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	out, err := oracle.RunBatch(oracle.DriverFor(expr), sb.String())
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	var res [][2]any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var pair [2]any
		if err := json.Unmarshal([]byte(line), &pair); err != nil {
			t.Fatalf("oracle line %q: %v", line, err)
		}
		res = append(res, pair)
	}
	if len(res) != len(reqs) {
		t.Fatalf("oracle returned %d results for %d requests", len(res), len(reqs))
	}
	return res
}

// normQuotes collapses quote-delimited spans so Python repr('x') and Go
// %q("x") compare equal.
var quoteLine = func(s string) string {
	var out []byte
	inQuote := false
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inQuote && (c == '\'' || c == '"') {
			inQuote, q = true, c
			out = append(out, '«')
			continue
		}
		if inQuote {
			if c == '\\' && i+1 < len(s) {
				i++ // skip escaped char
				continue
			}
			if c == q {
				inQuote = false
				out = append(out, '»')
				continue
			}
			continue // quoted content collapses
		}
		out = append(out, c)
	}
	return string(out)
}

// --------------------------------------------------------- parse_hostport ---

func TestDifferentialParseHostPort(t *testing.T) {
	requireOracle(t)
	targets := []string{
		"example.com:8080", "example.com", "example.com:", "example.com:0",
		"example.com:65535", "example.com:65536", "example.com:+80",
		":8080", ":0", "::1", "a:b:c", "a:", ":", "",
		"[::1]:443", "[::1]", "[::1]:", "[::1]:0", "[::1]:abc", "[::1]x",
		"[::1]:70000", "[bad", "[v1.x]:5", "[1.2.3.4]:5",
		"host.example.org:443", "HOST.Example.COM:80", "host.:80",
		"host:0080", "host: 80", "host:8_0",
	}
	type req struct {
		Target  string `json:"target"`
		Default int    `json:"default"`
	}
	reqs := make([]any, len(targets))
	for i, s := range targets {
		reqs[i] = req{s, 80}
	}
	got := runOracleBatch(t, `m.parse_hostport(req["target"], req["default"])`, reqs)
	for i, tc := range targets {
		want := got[i]
		host, port, err := ParseHostPort(tc, 80)
		goKind, goVal := "OK", ""
		if err != nil {
			// Python's error TEXT is the bare ValueError payload
			// (sometimes an internal int() message) — unobservable;
			// only OK/ERR and the parsed value are the contract.
			goKind, goVal = "ERR", "-"
		} else {
			goVal = fmt.Sprint([2]any{host, port})
		}
		pyKind := fmt.Sprint(want[0])
		pyVal := "-"
		if pyKind == "OK" {
			pyVal = fmt.Sprint(want[1])
		}
		if goKind != pyKind || (pyKind == "OK" && goVal != pyVal) {
			t.Errorf("parse_hostport(%q): go=%s %s python=%s %s", tc, goKind, goVal, pyKind, pyVal)
		}
	}
}

// diffEqual compares a Go result pair against the oracle pair, treating
// ERR as equal when the message matches after quote normalization.
func diffEqual(goRes, pyRes any) bool {
	g, _ := goRes.([2]any)
	p, _ := pyRes.([2]any)
	gKind, pKind := fmt.Sprint(g[0]), fmt.Sprint(p[0])
	if gKind != pKind {
		return false
	}
	if gKind == "ERR" {
		return quoteLine(fmt.Sprint(g[1])) == quoteLine(fmt.Sprint(p[1]))
	}
	return fmt.Sprint(g[1]) == fmt.Sprint(p[1])
}

// ---------------------------------------------------------- parse_upstream ---

func TestDifferentialParseUpstream(t *testing.T) {
	requireOracle(t)
	urls := []string{
		"", "p:3128", "p", "proxy.example.com:8080",
		"http://p", "http://p:3128", "http://p/", "http://P:3128/",
		"https://p", "https://p:8443", "socks5://p", "socks5://p:9050",
		"socks5h://p", "socks5h://p:1080", "socks5h://p:1081",
		"gopher://p", "gopher://p:70", "ftp://p",
		"http://u:p@p:3128", "http://u@p", "http://:@p", "http://u:@p",
		"http://%75ser:p%40ss@p", "http://u%3Ap@p",
		"http://[::1]:9050", "http://[::1]", "socks5://[2001:db8::1]:1080",
		"http://[1.2.3.4]/", "http://[bad/",
		"http://p:0", "http://p:65536", "http://p:abc", "http://p:-1",
		"http://p: 80", "http://p:+80", "http://p:8_0",
		"http://", "http://:8080", "://p", "1://p", "1http://x/",
		"http://p\tx/", " http://p/", "http://p\t/",
		"http://p?q", "http://p#f", "http://p/path;q",
		"h", "h:", "http:p:3128",
		"http://p﹫/", "http://p／x/",
	}
	got := runOracleBatch(t, `m.parse_upstream(req, False)`, toAny(urls))
	for i, raw := range urls {
		want := got[i]
		u, err := ParseUpstream(raw, false)
		var mine any
		if err != nil {
			mine = [2]any{"ERR", err.Error()}
		} else if u == nil {
			mine = [2]any{"OK", nil}
		} else {
			mine = [2]any{"OK", upstreamAsDict(u)}
		}
		if !diffEqual(mine, want) {
			t.Errorf("parse_upstream(%q):\n  go   =%v\n  python=%v", raw, mine, want)
		}
	}
}

func upstreamAsDict(u *Upstream) map[string]any {
	d := map[string]any{
		"scheme":     u.Scheme,
		"host":       u.Host,
		"port":       u.Port,
		"user":       nil,
		"pass":       nil,
		"tls_verify": u.TLSVerify,
	}
	if u.User != nil {
		d["user"] = *u.User
	}
	if u.Pass != nil {
		d["pass"] = *u.Pass
	}
	return d
}

func toAny[T any](s []T) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// -------------------------------------------------------- the live proxies ---

// pyProxy is the sbox.py proxy running as a real subprocess, exactly as
// the production launcher starts it (--_proxy SOCK CFG PPID).
type pyProxy struct {
	cmd  *exec.Cmd
	sock string
}

func startPyProxy(t *testing.T, cfgJSON string) *pyProxy {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "p.sock")
	cmd, err := oracle.StartProxy(sock, cfgJSON)
	if err != nil {
		t.Fatalf("start oracle proxy: %v", err)
	}
	if err := oracle.WaitListening(sock, cmd, 5*time.Second); err != nil {
		cmd.Process.Kill()
		t.Fatalf("oracle proxy: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		os.Remove(sock)
		os.Remove(sock + ".cfg")
	})
	return &pyProxy{cmd: cmd, sock: sock}
}

// cfgJSONFor marshals the Go-parsed allow entries into Python's proxy
// config dict — both sides run the SAME semantics by construction.
func cfgJSONFor(allows []allow.Entry, upstream *Upstream) string {
	entries := make([]map[string]any, len(allows))
	for i, e := range allows {
		var port any
		if e.Port != 0 {
			port = e.Port
		}
		entries[i] = map[string]any{"kind": e.Kind, "value": e.Value, "port": port}
	}
	cfg := map[string]any{"allows": entries, "verbose": false}
	if upstream != nil {
		cfg["upstream"] = upstreamAsDict(upstream)
	}
	b, _ := json.Marshal(cfg)
	return string(b)
}

// exchange runs one client session against addr: write everything,
// half-close, read to EOF or deadline.
func exchange(t *testing.T, addr string, writes []byte) []byte {
	return exchangeOpt(t, addr, writes, true)
}

// exchangeOpt with halfClose=false models a client that keeps its write
// side open — used where the ORIGIN ends the conversation (fixed
// responses), so both implementations deliver the response before any
// teardown race can drop it.
func exchangeOpt(t *testing.T, addr string, writes []byte, halfClose bool) []byte {
	t.Helper()
	c, err := net.DialTimeout("unix", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	uc := c.(*net.UnixConn)
	if _, err := uc.Write(writes); err != nil {
		t.Fatalf("write: %v", err)
	}
	if halfClose {
		_ = uc.CloseWrite()
	}
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	var out []byte
	buf := make([]byte, 8192)
	for {
		n, err := uc.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if ee, ok := err.(net.Error); ok && ee.Timeout() {
				return out // no EOF in time; compare what we got
			}
			return out // EOF
		}
	}
}

func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, '\r'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func TestDifferentialProxyProtocol(t *testing.T) {
	requireOracle(t)
	res := &realResolver{}
	allows := []allow.Entry{
		mustEntry(t, "example.com"),
		mustEntry(t, "127.0.0.1"),
		mustEntry(t, "nx.invalid"),
	}
	cfg := Config{Allows: allows, Resolver: res}
	s := startTestProxy(t, cfg)
	py := startPyProxy(t, cfgJSONFor(allows, nil))

	// Origins that need no network: an echo server and a fixed-response
	// server, reachable via the allowed 127.0.0.1 literal entry.
	echo := startOrigin(t, "echo", nil)
	fixedResp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Origin: fixed\r\n\r\nhi")
	fixed := startOrigin(t, "fixed", fixedResp)

	socks := func(atyp byte, host string, port int) []byte { return socksRequest(atyp, host, port) }
	greet := []byte{0x05, 0x01, 0x00}

	cases := []struct {
		name string
		send []byte
		mode string // "exact" | "line" (first line only) | "exact-open" (no client half-close)
	}{
		// --- SOCKS5 wire behavior ---
		{"socks close immediately", nil, "exact"},
		{"socks no no-auth", []byte{0x05, 0x02, 0x01, 0x02}, "exact"},
		{"socks greeting then close", greet, "exact"},
		{"socks truncated methods", []byte{0x05, 0x03, 0x00, 0x01}, "exact"},
		{"socks bad version", append(append([]byte{}, greet...), 0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80), "exact"},
		{"socks atyp unsupported", append(append([]byte{}, greet...), 0x05, 0x01, 0x00, 0x05, 0, 80), "exact"},
		{"socks BIND", append(append([]byte{}, greet...), socks(0x01, "127.0.0.1", 80)...), "exact"},
		{"socks denied name", append(append([]byte{}, greet...), socks(0x03, "denied.example.org", 80)...), "exact"},
		{"socks denied case-insensitive", append(append([]byte{}, greet...), socks(0x03, "Denied.Example.ORG.", 80)...), "exact"},
		{"socks denied v6 literal", append(append([]byte{}, greet...), socks(0x04, "2001:db8::1", 80)...), "exact"},
		{"socks invalid hostname", append(append([]byte{}, greet...), socks(0x03, "bad_host!!", 80)...), "exact"},
		{"socks control-byte hostname", append(append([]byte{}, greet...), socks(0x03, "a\x01b", 80)...), "exact"},
		{"socks hostname too long", append(append([]byte{}, greet...), socks(0x03, strings.Repeat("a.", 127)+"a", 80)...), "exact"},
		{"socks port 0", append(append([]byte{}, greet...), socks(0x03, "example.com", 0)...), "exact"},
		{"socks dns failure", append(append([]byte{}, greet...), socks(0x03, "nx.invalid", 80)...), "exact"},
		{"socks success echo", append(append([]byte{}, greet...), socks(0x01, "127.0.0.1", echo.port())...), "exact"},

		// --- HTTP wire behavior ---
		{"http garbage", []byte("GARBAGE\r\n\r\n"), "exact"},
		{"http bad version", []byte("GET / HTTP 1.1\r\n\r\n"), "exact"},
		{"http method unsupported", []byte("TRACE / HTTP/1.1\r\n\r\n"), "exact"},
		{"http lower-case method", []byte("get http://denied.example.org/ HTTP/1.1\r\n\r\n"), "exact"},
		{"http non-http scheme", []byte("GET ftp://x/ HTTP/1.1\r\n\r\n"), "exact"},
		{"http relative target", []byte("GET /x HTTP/1.1\r\nHost: denied.example.org\r\n\r\n"), "exact"},
		{"http https target", []byte("GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"), "exact"},
		{"http connect denied", []byte("CONNECT denied.example.org:80 HTTP/1.1\r\nHost: x\r\n\r\n"), "exact"},
		{"http connect denied no port", []byte("CONNECT denied.example.org HTTP/1.1\r\n\r\n"), "exact"},
		{"http connect bad target 0", []byte("CONNECT host:0 HTTP/1.1\r\n\r\n"), "exact"},
		{"http connect bad target range", []byte("CONNECT host:65536 HTTP/1.1\r\n\r\n"), "exact"},
		{"http connect bad target brackets", []byte("CONNECT [::1]x:5 HTTP/1.1\r\n\r\n"), "exact"},
		{"http connect empty host port", []byte("CONNECT :80 HTTP/1.1\r\n\r\n"), "line"},
		{"http connect quoted host", []byte("CONNECT b'c:80 HTTP/1.1\r\n\r\n"), "line"},
		{"http connect control host", []byte("CONNECT a\x01b:80 HTTP/1.1\r\n\r\n"), "line"},
		{"http connect dns failure", []byte("CONNECT nx.invalid:80 HTTP/1.1\r\nHost: x\r\n\r\n"), "line"},
		{"http absolute denied", []byte("GET http://denied.example.org/x HTTP/1.1\r\nHost: y\r\n\r\n"), "exact"},
		{"http absolute request-line split", []byte("GET /a b HTTP/1.1\r\nHost: denied.example.org\r\n\r\n"), "exact"},
		{"http connect success fixed", []byte(fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", fixed.port())), "exact-open"},
		{"http absolute success fixed", []byte(fmt.Sprintf("GET http://127.0.0.1:%d/path?q=1 HTTP/1.1\r\nUser-Agent: diff/1\r\n\r\n", fixed.port())), "exact-open"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			halfClose := tc.mode != "exact-open"
			goOut := exchangeOpt(t, s.Addr().String(), tc.send, halfClose)
			pyOut := exchangeOpt(t, py.sock, tc.send, halfClose)
			switch tc.mode {
			case "line":
				if firstLine(goOut) != firstLine(pyOut) {
					t.Errorf("first line:\n  go   = %q\n  py   = %q", firstLine(goOut), firstLine(pyOut))
				}
			default:
				if string(goOut) != string(pyOut) {
					t.Errorf("responses:\n  go   = %q\n  py   = %q", goOut, pyOut)
				}
			}
		})
	}
}

// realResolver delegates to the real resolver, like the Python proxy —
// resolve paths must see the same world on both sides.
type realResolver struct{}

func (realResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// The plain-http one-shot forward, differentially: both proxies forward
// to the SAME recording origin; the bytes the ORIGIN sees (head, exactly
// the declared body, then the half-close) and the client-side response
// must match. This is the anti-smuggling surface — Host rewrite/first,
// hop-by-hop drops, TE/dup-CL/obs-fold/control-byte refusals — pinned
// against the reference implementation, not just the unit tables.
func TestDifferentialPlainHTTPForward(t *testing.T) {
	requireOracle(t)
	allows := []allow.Entry{mustEntry(t, "127.0.0.1")}
	cfg := Config{Allows: allows, Resolver: realResolver{}}
	s := startTestProxy(t, cfg)
	py := startPyProxy(t, cfgJSONFor(allows, nil))
	o := startOrigin(t, "record", nil)

	req := func(format string) []byte {
		return []byte(fmt.Sprintf(format, o.port()))
	}
	cases := []struct {
		name string
		send []byte
	}{
		{"host rewritten and first", req("GET http://127.0.0.1:%d/x?q=1 HTTP/1.1\r\nHost: evil.example.org\r\nUser-Agent: diff/1\r\n\r\n")},
		{"host userinfo never forwarded", req("GET http://u:sekret@127.0.0.1:%d/ HTTP/1.1\r\nHost: x\r\n\r\n")},
		{"hop-by-hop headers dropped", req("GET http://127.0.0.1:%d/ HTTP/1.1\r\nProxy-Connection: keep\r\nProxy-Authorization: Basic x\r\nConnection: keep-alive\r\nKeep-Alive: 1\r\nTE: trailers\r\nTrailer: X\r\nUpgrade: h2c\r\nX-Keep: yes\r\n\r\n")},
		{"obs-fold refused", req("GET http://127.0.0.1:%d/ HTTP/1.1\r\nX-Fold: a\r\n b\r\n\r\n")},
		{"transfer-encoding refused", req("GET http://127.0.0.1:%d/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")},
		{"duplicate content-length refused", req("GET http://127.0.0.1:%d/ HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n")},
		{"embedded CR refused", req("GET http://127.0.0.1:%d/ HTTP/1.1\r\nX-A: a\rb\r\n\r\n")},
		{"request-line control byte refused", []byte(fmt.Sprintf("GET http://127.0.0.1:%d/\x01 HTTP/1.1\r\n\r\n", o.port()))},
		{"body then half-close, pipelined junk dropped", req("POST http://127.0.0.1:%d/ HTTP/1.1\r\nContent-Length: 4\r\nX-A: 1\r\n\r\nabcdGET http://evil.example.org/ HTTP/1.1\r\nHost: evil\r\n\r\n")},
		{"no body half-closes immediately", req("GET http://127.0.0.1:%d/ HTTP/1.1\r\nContent-Length: 0\r\n\r\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			goOut := exchange(t, s.Addr().String(), tc.send)
			goSaw, goHC := o.recorded()
			o.reset()
			pyOut := exchange(t, py.sock, tc.send)
			pySaw, pyHC := o.recorded()
			o.reset()
			if string(goOut) != string(pyOut) {
				t.Errorf("client side:\n  go = %q\n  py = %q", goOut, pyOut)
			}
			if string(goSaw) != string(pySaw) || goHC != pyHC {
				t.Errorf("origin saw:\n  go = %q (half-closed %d)\n  py = %q (half-closed %d)", goSaw, goHC, pySaw, pyHC)
			}
		})
	}
}

// The upstream-chaining differential: both proxies chain through the
// SAME fake upstream; the client side AND the bytes the upstream sees
// must match.
func TestDifferentialUpstreamChaining(t *testing.T) {
	requireOracle(t)

	// wire wires both proxies to chain through the given fake upstream.
	wire := func(t *testing.T, raw string, mutate func(*Upstream)) (*Server, *pyProxy) {
		up, err := ParseUpstream(raw, false)
		if err != nil {
			t.Fatalf("ParseUpstream(%q): %v", raw, err)
		}
		if mutate != nil {
			mutate(up)
		}
		allows := []allow.Entry{mustEntry(t, "127.0.0.1")}
		cfg := Config{Allows: allows, Upstream: up, Resolver: realResolver{}}
		return startTestProxy(t, cfg), startPyProxy(t, cfgJSONFor(allows, up))
	}
	runBoth := func(t *testing.T, s *Server, py *pyProxy, fake *fakeUpstream, req []byte) (goOut, pyOut, goSaw, pySaw []byte) {
		goOut = exchange(t, s.Addr().String(), req)
		goSaw = fake.all()
		fake.mu.Lock()
		fake.saw = nil
		fake.mu.Unlock()
		pyOut = exchange(t, py.sock, req)
		pySaw = fake.all()
		return
	}
	compare := func(t *testing.T, label string, goB, pyB []byte) {
		t.Helper()
		if string(goB) != string(pyB) {
			t.Errorf("%s:\n  go = %q\n  py = %q", label, goB, pyB)
		}
	}

	t.Run("http connect basic auth", func(t *testing.T) {
		fake := startFakeUpstream(t, "http")
		port := fake.ln.Addr().(*net.TCPAddr).Port
		s, py := wire(t, fmt.Sprintf("http://user:pass@127.0.0.1:%d", port), nil)
		req := append([]byte{0x05, 0x01, 0x00}, socksRequest(0x01, "127.0.0.1", 80)...)
		goOut, pyOut, goSaw, pySaw := runBoth(t, s, py, fake, req)
		compare(t, "client side", goOut, pyOut)
		compare(t, "upstream side", goSaw, pySaw)
	})

	t.Run("http connect refused", func(t *testing.T) {
		fake := startFakeUpstream(t, "http")
		fake.refuse = true
		port := fake.ln.Addr().(*net.TCPAddr).Port
		s, py := wire(t, fmt.Sprintf("http://127.0.0.1:%d", port), nil)
		req := []byte("CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: x\r\n\r\n")
		goOut, pyOut, goSaw, pySaw := runBoth(t, s, py, fake, req)
		compare(t, "client side", goOut, pyOut) // full 502 body incl. X-Sbox-Error
		compare(t, "upstream side", goSaw, pySaw)
	})

	t.Run("socks5 rfc1929 auth", func(t *testing.T) {
		fake := startFakeUpstream(t, "socks5")
		fake.allowName = true
		port := fake.ln.Addr().(*net.TCPAddr).Port
		s, py := wire(t, fmt.Sprintf("socks5://u:p@127.0.0.1:%d", port), nil)
		req := append([]byte{0x05, 0x01, 0x00}, socksRequest(0x01, "127.0.0.1", 443)...)
		goOut, pyOut, goSaw, pySaw := runBoth(t, s, py, fake, req)
		compare(t, "client side", goOut, pyOut)
		compare(t, "upstream side", goSaw, pySaw)
	})

	t.Run("socks5 auth refused", func(t *testing.T) {
		fake := startFakeUpstream(t, "socks5") // replies \x01\x01: auth failed
		port := fake.ln.Addr().(*net.TCPAddr).Port
		s, py := wire(t, fmt.Sprintf("socks5://u:p@127.0.0.1:%d", port), nil)
		req := append([]byte{0x05, 0x01, 0x00}, socksRequest(0x01, "127.0.0.1", 443)...)
		goOut, pyOut, _, _ := runBoth(t, s, py, fake, req)
		compare(t, "client side", goOut, pyOut)
	})

	t.Run("denied never reaches upstream", func(t *testing.T) {
		fake := startFakeUpstream(t, "http")
		port := fake.ln.Addr().(*net.TCPAddr).Port
		s, py := wire(t, fmt.Sprintf("http://127.0.0.1:%d", port), nil)
		req := []byte("CONNECT denied.example.org:80 HTTP/1.1\r\nHost: x\r\n\r\n")
		goOut, pyOut, goSaw, pySaw := runBoth(t, s, py, fake, req)
		compare(t, "client side", goOut, pyOut)
		if len(goSaw) != 0 || len(pySaw) != 0 {
			t.Errorf("denied destination reached the upstream: go=%q py=%q", goSaw, pySaw)
		}
	})

	t.Run("https insecure", func(t *testing.T) {
		cert := selfSignedCert(t, "127.0.0.1")
		tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { tlsLn.Close() })
		fake := startFakeUpstream(t, "http") // inner protocol after the handshake
		go func() {
			for {
				c, err := tlsLn.Accept()
				if err != nil {
					return
				}
				go fake.serve(c)
			}
		}()
		port := tlsLn.Addr().(*net.TCPAddr).Port
		s, py := wire(t, fmt.Sprintf("https://127.0.0.1:%d", port), func(u *Upstream) {
			u.TLSVerify = false
		})
		req := append([]byte{0x05, 0x01, 0x00}, socksRequest(0x01, "127.0.0.1", 80)...)
		goOut, pyOut, goSaw, pySaw := runBoth(t, s, py, fake, req)
		compare(t, "client side", goOut, pyOut)
		compare(t, "upstream side", goSaw, pySaw)
	})
}
