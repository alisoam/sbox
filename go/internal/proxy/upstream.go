package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ConnectTimeout bounds TCP connects AND the upstream handshake (TLS +
// CONNECT/RFC 1929 exchange) — sbox.py's CONNECT_TIMEOUT, one deadline
// for the whole chained setup.
const ConnectTimeout = 15 * time.Second

// upstreamSchemes is sbox.py's UPSTREAM_SCHEMES (socks5h included; it is
// normalized to socks5 at parse time because resolution stays on our
// side, keeping the allowlist and the private-IP guard in force).
const upstreamSchemes = "http, https, socks5, socks5h"

// Upstream is one parsed --upstream URL (Python's parse_upstream dict):
// scheme http/https/socks5 (socks5h normalized), host, port (explicit or
// scheme default), optional percent-decoded credentials and the TLS
// verification flag. The zero value is not valid; use ParseUpstream.
type Upstream struct {
	Scheme    string
	Host      string
	Port      int
	User      *string // nil: no userinfo
	Pass      *string // nil: no password part
	TLSVerify bool
}

// Redacted renders the upstream without credentials for error messages
// and logs (die() output ends up in the terminal and scrollback).
func (u *Upstream) Redacted() string {
	return fmt.Sprintf("%s://%s", u.Scheme, net.JoinHostPort(u.Host, strconv.Itoa(u.Port)))
}

// ParseUpstream ports sbox.py's parse_upstream. raw == "" means "no
// upstream" → (nil, nil). A URL without "://" is http://-prefixed. Every
// failure is an error whose text mirrors the Python die() message
// (minus the "sbox: " prefix the launcher adds).
func ParseUpstream(raw string, insecure bool) (*Upstream, error) {
	if raw == "" {
		return nil, nil
	}
	url := raw
	if !strings.Contains(raw, "://") {
		url = "http://" + raw
	}
	// Error messages echo the redacted URL only: --upstream URLs may
	// carry credentials in the userinfo.
	safe := RedactUserinfo(url)
	sp, err := URLSplit(url)
	if err != nil {
		return nil, fmt.Errorf("cannot parse --upstream URL: %s", safe)
	}
	scheme := strings.ToLower(sp.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	switch scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("unsupported --upstream scheme %q (supported: %s): %s",
			scheme, upstreamSchemes, safe)
	}
	host := sp.Hostname()
	if host == "" {
		return nil, fmt.Errorf("cannot parse --upstream URL: %s", safe)
	}
	def := 80
	switch {
	case scheme == "https":
		def = 443
	case strings.HasPrefix(scheme, "socks5"):
		def = 1080
	}
	port, hasPort, err := sp.Port()
	if err != nil { // non-numeric/out-of-range
		return nil, fmt.Errorf("bad port in --upstream URL: %s", safe)
	}
	if !hasPort {
		port = def
	} else if port < 1 || port > 65535 { // urlsplit allows :0; that is not a port
		return nil, fmt.Errorf("bad port in --upstream URL: %s", safe)
	}
	u := &Upstream{
		// socks5h behaves like socks5 here: resolution stays on our
		// side so the allowlist and the private-IP guard keep applying.
		Scheme:    scheme,
		Host:      host,
		Port:      port,
		TLSVerify: !insecure,
	}
	if scheme == "socks5h" {
		u.Scheme = "socks5"
	}
	if user, ok := sp.Username(); ok {
		dec := pyUnquote(user)
		u.User = &dec
	}
	if pass, ok := sp.Password(); ok {
		dec := pyUnquote(pass)
		u.Pass = &dec
	}
	return u, nil
}

var redactRE = regexp.MustCompile(`//[^/?#]*@`)

// RedactUserinfo removes any userinfo (user[:pass]@) from the URL's
// authority — sbox.py's redact_userinfo, count=1.
func RedactUserinfo(url string) string {
	if loc := redactRE.FindStringIndex(url); loc != nil {
		return url[:loc[0]] + "//" + url[loc[1]:]
	}
	return url
}

// openUpstream establishes a tunnel through u to destIP:destPort (the
// destination always travels as a literal IP — it was resolved and
// checked on OUR side). http/https upstreams get "CONNECT ip:port"
// (with Basic auth when credentials are configured); socks5 upstreams
// the full RFC 1928/1929 exchange. The returned *net.TCPConn (when
// non-nil) supports CloseWrite for the one-shot HTTP forward; TLS
// upstreams cannot half-close (documented exception, same as sbox.py).
func (p *Proxy) openUpstream(destIP string, destPort int) (net.Conn, *net.TCPConn, error) {
	u := p.cfg.Upstream
	// One budget for dial + TLS + CONNECT/RFC 1929 exchange — sbox.py
	// wraps the whole handshake in wait_for(CONNECT_TIMEOUT); a silent
	// upstream must not wedge a connection goroutine forever.
	deadline := time.Now().Add(ConnectTimeout)
	d := &net.Dialer{Deadline: deadline}

	var raw *net.TCPConn
	var conn net.Conn
	if u.Scheme == "https" {
		c, err := d.Dial("tcp", net.JoinHostPort(u.Host, strconv.Itoa(u.Port)))
		if err != nil {
			return nil, nil, p.upstreamErr(err)
		}
		raw = c.(*net.TCPConn)
		tlsConn := tls.Client(raw, &tls.Config{
			ServerName:         u.Host,
			InsecureSkipVerify: !u.TLSVerify, // --upstream-insecure: explicit opt-in
		})
		_ = tlsConn.SetDeadline(deadline)
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			return nil, nil, p.upstreamErr(err)
		}
		conn = tlsConn
	} else {
		c, err := d.Dial("tcp", net.JoinHostPort(u.Host, strconv.Itoa(u.Port)))
		if err != nil {
			return nil, nil, p.upstreamErr(err)
		}
		raw = c.(*net.TCPConn)
		conn = raw
	}

	_ = conn.SetDeadline(deadline) // the exchange is part of the handshake
	br := newLineReader(conn)
	var hsErr error
	if u.Scheme == "http" || u.Scheme == "https" {
		hsErr = p.upstreamHTTPConnect(conn, br, destIP, destPort)
	} else { // socks5
		hsErr = p.upstreamSocks5(conn, br, destIP, destPort)
	}
	if hsErr != nil {
		conn.Close()
		return nil, nil, hsErr
	}
	_ = conn.SetDeadline(time.Time{}) // the tunnel itself is unbounded
	return conn, raw, nil
}

func (p *Proxy) upstreamErr(err error) error {
	u := p.cfg.Upstream
	return &DestinationError{1, fmt.Sprintf("upstream %s://%s:%d failed: %s",
		u.Scheme, u.Host, u.Port, err)}
}

// upstreamHTTPConnect: "CONNECT ip:port HTTP/1.1", optional Basic
// Proxy-Authorization, a 2xx status, then the response headers drained.
func (p *Proxy) upstreamHTTPConnect(conn net.Conn, lr *lineReader, destIP string, destPort int) error {
	u := p.cfg.Upstream
	var req strings.Builder
	fmt.Fprintf(&req, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n", destIP, destPort, destIP, destPort)
	if u.User != nil {
		token := base64.StdEncoding.EncodeToString([]byte(*u.User + ":" + deref(u.Pass)))
		fmt.Fprintf(&req, "Proxy-Authorization: Basic %s\r\n", token)
	}
	req.WriteString("\r\n")
	if _, err := conn.Write([]byte(req.String())); err != nil {
		return p.upstreamErr(err)
	}
	status, err := lr.readLine()
	if err != nil {
		return p.upstreamErr(fmt.Errorf("%s", statusStr(status)))
	}
	parts := strings.Fields(string(status))
	if len(parts) < 2 || !strings.HasPrefix(parts[1], "2") {
		return p.upstreamErr(fmt.Errorf("upstream CONNECT failed: %s", statusStr(status)))
	}
	for { // drain response headers up to the blank line
		line, err := lr.readLine()
		if err != nil || line == "\r\n" || line == "\n" || line == "" {
			break
		}
	}
	return nil
}

func statusStr(line string) string { return strings.TrimSpace(line) }

// upstreamSocks5: method negotiation (NO-AUTH, or username/password when
// credentials are configured), RFC 1929 subnegotiation, then the
// CONNECT request with the destination as a literal-IP address field and
// the bound-address tail of the reply drained.
func (p *Proxy) upstreamSocks5(conn net.Conn, lr *lineReader, destIP string, destPort int) error {
	u := p.cfg.Upstream
	writeAll := func(b []byte) error {
		_, err := conn.Write(b)
		return err
	}
	readN := func(n int) ([]byte, error) {
		buf := make([]byte, n)
		if _, err := io.ReadFull(lr, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}

	greeting := []byte{0x05, 0x01, 0x00}
	if u.User != nil {
		greeting = []byte{0x05, 0x01, 0x02}
	}
	if err := writeAll(greeting); err != nil {
		return p.upstreamErr(err)
	}
	resp, err := readN(2)
	if err != nil {
		return p.upstreamErr(err)
	}
	if resp[0] != 5 {
		return p.upstreamErr(errors.New("upstream is not SOCKS5"))
	}
	switch resp[1] {
	case 0x02:
		user := []byte(deref(u.User))
		pw := []byte(deref(u.Pass))
		if len(user) > 255 || len(pw) > 255 {
			return p.upstreamErr(errors.New("upstream credentials too long"))
		}
		msg := make([]byte, 0, 3+len(user)+len(pw))
		msg = append(msg, 0x01, byte(len(user)))
		msg = append(msg, user...)
		msg = append(msg, byte(len(pw)))
		msg = append(msg, pw...)
		if err := writeAll(msg); err != nil {
			return p.upstreamErr(err)
		}
		auth, err := readN(2)
		if err != nil {
			return p.upstreamErr(err)
		}
		if auth[1] != 0 {
			return p.upstreamErr(errors.New("upstream username/password auth failed"))
		}
	case 0x00:
	default:
		return p.upstreamErr(errors.New("upstream refused our auth methods"))
	}

	addr, err := netip.ParseAddr(destIP)
	if err != nil {
		return p.upstreamErr(err)
	}
	req := []byte{0x05, 0x01, 0x00}
	if addr.Is4() {
		b4 := addr.As4()
		req = append(req, 0x01)
		req = append(req, b4[:]...)
	} else {
		b16 := addr.As16()
		req = append(req, 0x04)
		req = append(req, b16[:]...)
	}
	req = append(req, byte(destPort>>8), byte(destPort))
	if err := writeAll(req); err != nil {
		return p.upstreamErr(err)
	}
	rep, err := readN(4)
	if err != nil {
		return p.upstreamErr(err)
	}
	if rep[1] != 0 {
		return p.upstreamErr(fmt.Errorf("upstream CONNECT failed with reply code %d", rep[1]))
	}
	switch rep[3] { // drain the bound address
	case 0x01:
		_, err = readN(4 + 2)
	case 0x03:
		n, e := readN(1)
		if e != nil {
			err = e
		} else {
			_, err = readN(int(n[0]) + 2)
		}
	case 0x04:
		_, err = readN(16 + 2)
	}
	if err != nil {
		return p.upstreamErr(err)
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
