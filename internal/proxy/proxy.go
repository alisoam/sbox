// Package proxy is sbox's host-side egress gate: a SOCKS5 + HTTP-CONNECT
// server on a 0600 Unix socket, bound into the sandbox at /run/proxy.sock
// and bridged to 127.0.0.1:1080. It runs in the launcher process, keeping
// upstream credentials in memory. Plain HTTP forwards exactly one request
// per connection (see httpAbsolute).
//
// Security model (default-deny), in this order:
//
//   - A destination is checked against the allowlist BEFORE anything
//     else; hostnames of DENIED destinations are never resolved — there
//     is no DNS side channel.
//   - Allowed names are resolved host-side and the answers are checked
//     with allow.BadIP (SSRF guard); only then does a connection happen
//     (direct, or through the configured upstream).
//   - Anything that looks like a hostname but is not a valid one
//     (embedded NULs, over-long labels, ...) is rejected before the
//     resolver sees it. Attacker-controlled bytes never reach logs or
//     error responses raw: hostnames are %q-quoted, upstream URLs
//     redacted, X-Sbox-Error values sanitized to one printable line.
//   - $no_proxy only picks the ROUTE (direct vs upstream) when chaining;
//     the allowlist applies either way.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"sbox/internal/allow"
)

// DestinationError is a denial/connection failure; Rep is the SOCKS5
// reply code the caller reports.
type DestinationError struct {
	Rep int
	Why string
}

func (e *DestinationError) Error() string { return e.Why }

// SOCKS5 reply codes used (RFC 1928): 1 general failure, 2 connection
// not allowed by ruleset, 4 host unreachable, 5 connection refused, 7
// command not supported, 8 address type not supported.
const (
	repGeneral        = 1
	repNotAllowed     = 2
	repHostUnreach    = 4
	repConnRefused    = 5
	repCmdNotSup      = 7
	repAddrTypeNotSup = 8
)

// Resolver is the resolv surface the proxy needs (satisfied by
// *net.Resolver; tests inject canned answers).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Config holds the destination policy, upstream route, logger and resolver.
type Config struct {
	Allows   []allow.Entry
	Upstream *Upstream      // nil: direct egress
	NoProxy  *allow.NoProxy // nil: never bypass the upstream
	Verbose  bool
	// Logf receives the "sbox-proxy: ..." decision log when Verbose.
	// nil logs to stderr.
	Logf func(msg string)
	// Resolver resolves allowed hostnames host-side. nil uses
	// net.DefaultResolver (pure Go: CGO_ENABLED=0 builds do not consult
	// nsswitch.conf backends like mdns/myhostname).
	Resolver Resolver
}

// Proxy is one configured proxy instance.
type Proxy struct {
	cfg    Config
	closed chan struct{}
}

// New returns a Proxy for cfg.
func New(cfg Config) *Proxy {
	if cfg.Logf == nil {
		if !cfg.Verbose {
			cfg.Logf = func(string) {}
		} else {
			cfg.Logf = func(msg string) { fmt.Fprintf(os.Stderr, "sbox-proxy: %s\n", msg) }
		}
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	return &Proxy{cfg: cfg, closed: make(chan struct{})}
}

func (p *Proxy) logf(format string, args ...any) {
	p.cfg.Logf(fmt.Sprintf(format, args...))
}

// ServeConn detects SOCKS5 (first byte 0x05) or HTTP and dispatches the
// connection. A panicking handler is recovered and logged when verbose;
// one malformed connection must not terminate the launcher.
func (p *Proxy) ServeConn(c net.Conn) {
	defer c.Close()
	defer func() {
		if r := recover(); r != nil {
			if p.cfg.Verbose {
				p.logf("handler panic: %v", r)
			}
		}
	}()
	lr := newLineReader(c)
	first := make([]byte, 1)
	if _, err := io.ReadFull(lr, first); err != nil {
		return // client closed immediately (readiness probe) — fine
	}
	if first[0] == 0x05 {
		p.socks5(c, lr)
	} else {
		p.http(c, lr, first[0])
	}
}

// Server listens on a 0600 Unix socket with one goroutine per connection.
// Close cancels forwarding and closes clients before waiting for handlers.
type Server struct {
	ln        net.Listener
	p         *Proxy
	wg        sync.WaitGroup
	closeOnce sync.Once

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// Listen starts the proxy on a fresh Unix socket at sockPath (removed
// first — a stale socket must not wedge the launch), chmods it 0600
// (only the sandbox may reach it) and serves until Close.
func Listen(sockPath string, cfg Config) (*Server, error) {
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	s := &Server{ln: ln, p: New(cfg), conns: make(map[net.Conn]struct{})}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
			}()
			s.p.ServeConn(c)
		}()
	}
}

// Close stops the listener, cancels forwarding and closes client connections,
// then waits for handlers to finish.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.p.closed)
		err = s.ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
	})
	s.wg.Wait()
	return err
}

// Addr is the socket's address (the path it listens on).
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// ---------------------------------------------------------------- SOCKS5 ---

func socksReply(c net.Conn, rep int) {
	// ver rep rsv atyp=IPv4 addr=0.0.0.0 port=0 (bwrap's placeholder)
	_, _ = c.Write([]byte{0x05, byte(rep), 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func (p *Proxy) socks5(c net.Conn, lr *lineReader) {
	nmethods := make([]byte, 1)
	if _, err := io.ReadFull(lr, nmethods); err != nil {
		return
	}
	methods := make([]byte, int(nmethods[0]))
	if _, err := io.ReadFull(lr, methods); err != nil {
		return
	}
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
		}
	}
	if !hasNoAuth { // only NO-AUTH (the socket is 0600, mode 0)
		_, _ = c.Write([]byte{0x05, 0xff})
		return
	}
	_, _ = c.Write([]byte{0x05, 0x00})

	head := make([]byte, 4) // ver cmd rsv atyp
	if _, err := io.ReadFull(lr, head); err != nil {
		return
	}
	ver, cmd, atyp := head[0], head[1], head[3]
	if ver != 5 {
		return
	}
	var host string
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(lr, b); err != nil {
			return
		}
		host = netip.AddrFrom4([4]byte(b)).String()
	case 0x03:
		n := make([]byte, 1)
		if _, err := io.ReadFull(lr, n); err != nil {
			return
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(lr, b); err != nil {
			return
		}
		for _, ch := range b { // SOCKS domain names must be ASCII.
			if ch >= 0x80 {
				return
			}
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(lr, b); err != nil {
			return
		}
		host = netip.AddrFrom16([16]byte(b)).String()
	default:
		socksReply(c, repAddrTypeNotSup)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(lr, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])

	if cmd != 0x01 { // only CONNECT
		socksReply(c, repCmdNotSup)
		return
	}
	dest, _, err := p.ConnectDestination(host, port)
	if err != nil {
		var de *DestinationError
		if errors.As(err, &de) {
			socksReply(c, de.Rep)
			return
		}
		socksReply(c, repGeneral)
		return
	}
	defer dest.Close()
	socksReply(c, 0)
	tunnel(c, lr, dest)
}

// ------------------------------------------------------------------ HTTP ---

var httpMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true,
	"DELETE": true, "OPTIONS": true, "PATCH": true,
}

func (p *Proxy) http(c net.Conn, lr *lineReader, first byte) {
	line, err := lr.readLine()
	if err != nil {
		return // oversized request line: dropped like any other garbage
	}
	// A control byte in the request line is
	// never a valid request (and would be forwarded inside the target).
	if !lineClean(line) {
		httpError(c, 400, "bad request line\n", "")
		return
	}
	parts := strings.Fields(string(first) + line)
	if len(parts) < 3 || !strings.HasPrefix(strings.ToUpper(parts[2]), "HTTP/") {
		httpError(c, 400, "bad request line\n", "")
		return
	}
	method, target := strings.ToUpper(parts[0]), parts[1]
	switch {
	case method == "CONNECT":
		p.httpConnect(c, lr, target)
	case httpMethods[method]:
		p.httpAbsolute(c, lr, method, target)
	default:
		httpError(c, 400, fmt.Sprintf("method %s not supported\n", method), "")
	}
}

func (p *Proxy) httpConnect(c net.Conn, lr *lineReader, target string) {
	host, port, err := ParseHostPort(target, 443)
	if err != nil {
		httpError(c, 400, "bad CONNECT target\n", "")
		return
	}
	for { // drain request headers up to the blank line
		line, err := lr.readLine()
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" || line == "" {
			break
		}
	}
	dest, _, err := p.ConnectDestination(host, port)
	if err != nil {
		var de *DestinationError
		if errors.As(err, &de) {
			code := 502
			if de.Rep == repNotAllowed {
				code = 403
			}
			httpError(c, code, fmt.Sprintf("%d: %s\n", code, de.Why), de.Why)
			return
		}
		return // unexpected failure: drop the connection, fail closed
	}
	defer dest.Close()
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	tunnel(c, lr, dest)
}

// hopHeaders lists headers that describe
// the client's relationship to the PROXY, not to the origin. Host is
// rewritten from the checked URL and emitted first. Content-Length is NOT
// here — the client's (validated, single) CL header is forwarded in place
// unchanged; Transfer-Encoding is refused while parsing.
var hopHeaders = map[string]bool{
	"proxy-connection":    true,
	"proxy-authorization": true,
	"connection":          true, // we send our own Connection: close
	"keep-alive":          true,
	"te":                  true,
	"trailer":             true,
	"upgrade":             true,
	"host":                true, // rewritten from the checked URL, emitted first
}

// httpAbsolute forwards plain HTTP: exactly ONE request goes
// upstream per connection —
//
//   - the Host header is REWRITTEN from the checked URL (userinfo in
//     the netloc must not reach the origin) and emitted FIRST;
//   - header names must be RFC 9110 tokens; obs-fold continuation lines
//     are refused;
//   - Transfer-Encoding and duplicate Content-Length headers are refused;
//     only one unambiguous Content-Length body is forwarded;
//   - after the body, the origin socket is half-closed
//     (TCPConn.CloseWrite) — a pipelined second request from the
//     sandboxed client can never smuggle its own Host upstream. TLS
//     upstreams cannot half-close.
func (p *Proxy) httpAbsolute(c net.Conn, lr *lineReader, method, target string) {
	sp, err := URLSplit(target)
	host := sp.Hostname()
	// SplitURL.Port validates the URL port: it reports an error
	// for non-numeric or out-of-range values.
	// ":0" parses fine HERE and dies in ConnectDestination as a 502,
	// rather than silently becoming port 80.
	port, hasPort, portErr := sp.Port()
	if !hasPort {
		port = 80
	}
	if err != nil || portErr != nil || !strings.EqualFold(sp.Scheme, "http") || host == "" {
		httpError(c, 400, "only http:// absolute URLs are proxied; https:// must use CONNECT\n", "")
		return
	}

	type header struct{ name, value string }
	var headers []header
	contentLength := int64(-1) // absent
	for {
		line, rerr := lr.readLine()
		if rerr != nil {
			return
		}
		if line == "\r\n" || line == "\n" || line == "" {
			break
		}
		// _line_clean FIRST: embedded \r/NUL/DEL must never be forwarded
		// inside a header value (origin-side parser confusion).
		if !lineClean(line) {
			httpError(c, 400, "malformed headers\n", "")
			return
		}
		if line[0] == ' ' || line[0] == '\t' {
			// obs-fold continuation: deprecated, and the folded value
			// would ride below our injected headers — refuse it
			httpError(c, 400, "obsolete line folding is not accepted\n", "")
			return
		}
		name, value, hasColon := strings.Cut(line, ":")
		// Valid RFC 9110 token names only: "Host : evil" (space before
		// the colon) used to slip through as a forwarded line named
		// "Host " — lenient origins parse it as a SECOND Host header,
		// steering a shared IP to a vhost the allowlist never saw.
		if !hasColon || !isToken(name) {
			httpError(c, 400, "malformed header line\n", "")
			return
		}
		lname := strings.ToLower(name)
		value = strings.TrimSpace(value)
		if lname == "transfer-encoding" {
			// Framed bodies cannot be relayed under the exactly-one-
			// request rule; clients must declare a Content-Length.
			httpError(c, 400, "Transfer-Encoding is not supported; send Content-Length\n", "")
			return
		}
		if lname == "content-length" {
			n, ok := parseContentLength(value)
			if !ok || contentLength != -1 {
				// duplicate/ambiguous CL is the classic smuggling vector
				// (ANY second Content-Length header is refused, even an
				// identical one)
				httpError(c, 400, "ambiguous Content-Length\n", "")
				return
			}
			contentLength = n
		}
		if hopHeaders[lname] {
			continue
		}
		headers = append(headers, header{name, value})
	}

	dest, halfClose, derr := p.ConnectDestination(host, port)
	if derr != nil {
		var de *DestinationError
		if errors.As(derr, &de) {
			code := 502
			if de.Rep == repNotAllowed {
				code = 403
			}
			httpError(c, code, fmt.Sprintf("%d: %s\n", code, de.Why), de.Why)
			return
		}
		return
	}
	defer dest.Close()

	// Host is synthesized from the CHECKED url, never the client's
	// netloc (userinfo!), and emitted first.
	hostHdr := hostHeader(host, port)
	path := sp.Path
	if path == "" {
		path = "/"
	}
	if sp.Query != "" {
		path += "?" + sp.Query
	}
	var head strings.Builder
	fmt.Fprintf(&head, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&head, "Host: %s\r\n", hostHdr)
	for _, h := range headers {
		fmt.Fprintf(&head, "%s: %s\r\n", h.name, h.value)
	}
	head.WriteString("Connection: close\r\n\r\n")
	if _, err := dest.Write([]byte(head.String())); err != nil {
		return
	}
	forwardRequest(c, lr, dest, halfClose, max(contentLength, 0), p.closed)
}

// forwardRequest streams the response while uploading exactly the declared
// body. In particular, an origin's 100 Continue or early rejection must not
// wait for a body the client has not sent. Completion of the response closes
// both connections and joins the upload goroutine, even if the client stalls.
func forwardRequest(c net.Conn, body io.Reader, dest net.Conn, halfClose *net.TCPConn,
	n int64, closed <-chan struct{}) {
	uploadDone := make(chan error, 1)
	responseDone := make(chan struct{}, 1)
	go func() {
		_, err := io.CopyN(dest, body, n)
		if halfClose != nil {
			// The origin may have already sent and closed its response.
			// A failed half-close must not discard those readable bytes.
			_ = halfClose.CloseWrite()
		}
		uploadDone <- err
	}()
	go func() {
		_, _ = io.Copy(c, dest)
		responseDone <- struct{}{}
	}()
	select {
	case err := <-uploadDone:
		if err != nil && halfClose == nil {
			// TLS cannot delimit an incomplete upload with a half-close.
			// Close the transport, but still drain any buffered response
			// before closing the client connection.
			_ = dest.Close()
		}
		// A complete body (including a client half-close) still needs its
		// response. Bytes following the declared body are never forwarded.
		select {
		case <-responseDone:
		case <-closed:
			_ = c.Close()
			_ = dest.Close()
			<-responseDone
		}
		_ = c.Close()
		_ = dest.Close()
	case <-responseDone:
		_ = c.Close()
		_ = dest.Close()
		<-uploadDone
	case <-closed:
		_ = c.Close()
		_ = dest.Close()
		<-uploadDone
		<-responseDone
	}
}

// parseContentLength accepts up to 18 ASCII digits, including leading zeros.
func parseContentLength(s string) (int64, bool) {
	if s == "" || len(s) > 18 {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int64(s[i]-'0')
	}
	return n, true
}

// isToken: RFC 9110 tchar (the name half of a field line).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		default:
			if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
				return false
			}
		}
	}
	return true
}

// lineClean reports whether a request/header line
// holds no control bytes besides the optional CR of its final CRLF (tabs
// pass — legal in field values); DEL is refused with the rest. A bare \r
// anywhere else would be forwarded inside a header value, where it can
// confuse origin-side parsers.
func lineClean(line string) bool {
	body := strings.TrimSuffix(line, "\r\n")
	body = strings.TrimSuffix(body, "\n")
	for i := 0; i < len(body); i++ {
		if (body[i] < 0x20 && body[i] != '\t') || body[i] == 0x7f {
			return false
		}
	}
	return true
}

// hostHeader renders the forwarded Host header from the checked URL:
// IPv6 literals get their brackets back, the port is omitted exactly
// when it is the scheme default (80). Every request gets a rewritten Host.
func hostHeader(host string, port int) string {
	switch {
	case strings.Contains(host, ":"): // IPv6 literal needs its brackets back
		return fmt.Sprintf("[%s]:%d", host, port)
	case port != 80:
		return fmt.Sprintf("%s:%d", host, port)
	default:
		return host
	}
}

func httpError(c net.Conn, code int, text string, reason string) {
	phrase := "Error"
	switch code {
	case 400:
		phrase = "Bad Request"
	case 403:
		phrase = "Forbidden"
	case 502:
		phrase = "Bad Gateway"
	}
	var hdr strings.Builder
	fmt.Fprintf(&hdr, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n", code, phrase, len(text))
	if reason != "" {
		// Reasons can embed attacker-controlled hostnames: keep the
		// header single-line and printable.
		hdr.WriteString("X-Sbox-Error: " + sanitizeReason(reason) + "\r\n")
	}
	_, _ = c.Write([]byte(hdr.String() + "\r\n" + text))
}

func sanitizeReason(reason string) string {
	mapped := strings.Map(func(r rune) rune {
		if r >= 0x20 && r <= 0x7e {
			return r
		}
		return ' '
	}, reason)
	runes := []rune(mapped)
	if len(runes) > 200 {
		runes = runes[:200]
	}
	return string(runes)
}

// ---------------------------------------------------------------- tunnel ---

// tunnel is a bidirectional copy that tears both
// directions down as soon as one ends — no half-close, no lingering.
func tunnel(c net.Conn, cr io.Reader, dest net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(dest, cr)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, dest)
		done <- struct{}{}
	}()
	<-done
	_ = c.Close()
	_ = dest.Close()
	<-done
}

// ------------------------------------------------------------ destination ---

// ConnectDestination is the spec's ordering, made literal:
// allowlist → resolve (SSRF-filtered) → connect (or chain upstream). It
// never resolves a denied name. The second return value is the
// half-closeable TCP connection when one exists (see httpAbsolute).
func (p *Proxy) ConnectDestination(host string, port int) (net.Conn, *net.TCPConn, error) {
	if port < 1 || port > 65535 {
		return nil, nil, &DestinationError{repGeneral, fmt.Sprintf("invalid port %d", port)}
	}
	h := strings.ToLower(strings.TrimRight(host, "."))
	// Scoped literals ("fe80::1%eth0") retain their zone for connect;
	// network matching ignores the zone.
	addr, addrErr := netip.ParseAddr(h)
	if addrErr != nil && !hostnameOK(h) {
		// %q: hostnames come from the sandbox and may contain control
		// bytes — never let them reach the terminal raw.
		return nil, nil, &DestinationError{repHostUnreach, fmt.Sprintf("invalid hostname %q", host)}
	}
	ok, why := allow.DestinationAllowed(p.cfg.Allows, h, port)
	if !ok {
		p.logf("deny  %q:%d — %s", h, port, why)
		return nil, nil, &DestinationError{repNotAllowed, why}
	}

	up := p.cfg.Upstream
	if up != nil && p.cfg.NoProxy != nil && p.cfg.NoProxy.Matches(h) {
		up = nil // no_proxy picks the ROUTE; the allowlist already applied
	}
	if up != nil {
		dest := addr
		if !dest.IsValid() {
			infos, err := p.resolveFiltered(h, port)
			if err != nil {
				return nil, nil, err
			}
			dest = infos[0]
		}
		p.logf("allow %q:%d — via %s upstream %s:%d to %s", h, port, up.Scheme, up.Host, up.Port, dest)
		return p.openUpstream(dest.String(), port)
	}
	if p.cfg.Upstream != nil {
		// no_proxy matched: this destination deliberately goes direct.
		p.logf("allow %q:%d — direct ($no_proxy bypasses the upstream)", h, port)
	}
	if addrErr == nil {
		// Literal IP allowed explicitly: private ranges are intentional.
		p.logf("allow %q:%d — direct (allowed literal IP)", h, port)
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)), ConnectTimeout)
		if err != nil {
			return nil, nil, &DestinationError{repConnRefused,
				fmt.Sprintf("connect to %s:%d failed: %s", addr, port, err)}
		}
		return conn, conn.(*net.TCPConn), nil
	}
	infos, err := p.resolveFiltered(h, port)
	if err != nil {
		return nil, nil, err
	}
	p.logf("allow %q:%d — resolved %s", h, port, joinAddrs(infos))
	var last error
	for _, a := range infos {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(a.String(), strconv.Itoa(port)), ConnectTimeout)
		if err == nil {
			return conn, conn.(*net.TCPConn), nil
		}
		last = err
	}
	return nil, nil, &DestinationError{repConnRefused,
		fmt.Sprintf("connect to %s:%d failed: %s", h, port, last)}
}

// hostnameOK validates resolver input: hostname grammar, total length ≤ 253,
// and labels ≤ 63 bytes. Invalid input never reaches the resolver.
func hostnameOK(h string) bool {
	if !allow.ValidHostname(h) || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) > 63 {
			return false
		}
	}
	return true
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}

// resolveFiltered resolves an ALLOWED name host-side and drops guarded
// answers (allow.BadIP): an allowed name must not become a host/LAN
// SSRF. A !private entry opts that one name out (explicit intent, e.g.
// split-horizon DNS for internal mirrors). Every answer blocked →
// denial (rep 2, it is an allowlist-shaped verdict); no answer at all →
// DNS failure (rep 4).
func (p *Proxy) resolveFiltered(host string, port int) ([]netip.Addr, error) {
	addrs, err := p.cfg.Resolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return nil, &DestinationError{repHostUnreach, fmt.Sprintf("DNS failure for %s: %s", host, err)}
	}
	privateOK := allow.PrivateAllowed(p.cfg.Allows, host, port)
	var good []netip.Addr
	var blocked []string
	for _, a := range addrs {
		if !privateOK && allow.BadIP(a) {
			blocked = append(blocked, a.String())
		} else {
			good = append(good, a)
		}
	}
	if len(blocked) > 0 && len(good) == 0 {
		return nil, &DestinationError{repNotAllowed, fmt.Sprintf(
			"%s resolves only to blocked (private/loopback/link-local) addresses: %s",
			host, strings.Join(blocked, ", "))}
	}
	if len(good) == 0 {
		return nil, &DestinationError{repHostUnreach, fmt.Sprintf("no usable addresses for %s", host)}
	}
	return good, nil
}

// -------------------------------------------------------------- plumbing ---

// lineReader reads \n-terminated lines with a 64 KiB cap: a
// line longer than the limit aborts the connection (the client is not
// a well-behaved HTTP/SOCKS peer). Buffered bytes beyond the current
// line stay available — the tunnel must see them. The cap is enforced
// WHILE reading (ReadSlice, not ReadString): an unterminated request
// can never accumulate more than the bufio buffer in host memory, and
// an EOF tail past the limit is refused too — it used to bypass the
// check entirely.
type lineReader struct {
	r   *bufio.Reader
	eof bool
}

func newLineReader(c net.Conn) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(c, 128*1024)}
}

const maxLine = 64 * 1024

var errLineTooLong = errors.New("line too long")

// readLine returns the next line INCLUDING its terminator; at EOF it
// returns the partial tail (only while it is under the limit).
// errLineTooLong means: give up on this connection silently.
func (lr *lineReader) readLine() (string, error) {
	if lr.eof {
		return "", nil
	}
	var sb strings.Builder
	for {
		chunk, err := lr.r.ReadSlice('\n')
		sb.Write(chunk)
		if sb.Len() > maxLine {
			return "", errLineTooLong
		}
		if err == bufio.ErrBufferFull {
			// No delimiter in the whole buffer: the cap above already
			// failed this line (the buffer is twice maxLine), so this
			// only guards the loop if the buffer size ever changes.
			continue
		}
		if err == io.EOF {
			lr.eof = true
			return sb.String(), nil
		}
		if err != nil {
			return "", err
		}
		return sb.String(), nil
	}
}

// Read implements io.Reader over the same buffer (exact reads for
// SOCKS5/upstream frames).
func (lr *lineReader) Read(p []byte) (int, error) { return lr.r.Read(p) }
