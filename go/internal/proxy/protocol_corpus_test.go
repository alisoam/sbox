package proxy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestProtocolCorpus(t *testing.T) {
	cfg := testConfig(t, &fakeResolver{err: errors.New("no such host")})
	cfg.Allows = append(cfg.Allows, mustEntry(t, "nx.invalid"))
	s := startTestProxy(t, cfg)
	echo := startOrigin(t, "echo", nil)
	fixedResp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Origin: fixed\r\n\r\nhi")
	fixed := startOrigin(t, "fixed", fixedResp)
	socks := socksRequest
	greet := []byte{0x05, 0x01, 0x00}
	cases := []struct {
		name     string
		send     []byte
		want     string
		keepOpen bool
	}{
		{"socks close immediately", nil, "", false},
		{"socks no no-auth", []byte{0x05, 0x02, 0x01, 0x02}, "\x05\xff", false},
		{"socks greeting then close", greet, "\x05\x00", false},
		{"socks truncated methods", []byte{0x05, 0x03, 0x00, 0x01}, "", false},
		{"socks bad version", append(append([]byte{}, greet...), 0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80), "\x05\x00", false},
		{"socks atyp unsupported", append(append([]byte{}, greet...), 0x05, 0x01, 0x00, 0x05, 0, 80), "\x05\x00\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", false},
		{"socks BIND", append(append([]byte{}, greet...), []byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 80}...), "\x05\x00\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", false},
		{"socks denied name", append(append([]byte{}, greet...), socks(0x03, "denied.example.org", 80)...), "\x05\x00\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00", false},
		{"socks denied case-insensitive", append(append([]byte{}, greet...), socks(0x03, "Denied.Example.ORG.", 80)...), "\x05\x00\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00", false},
		{"socks denied v6 literal", append(append([]byte{}, greet...), socks(0x04, "2001:db8::1", 80)...), "\x05\x00\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00", false},
		{"socks invalid hostname", append(append([]byte{}, greet...), socks(0x03, "bad_host!!", 80)...), "\x05\x00\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00", false},
		{"socks control-byte hostname", append(append([]byte{}, greet...), socks(0x03, "a\x01b", 80)...), "\x05\x00\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00", false},
		{"socks hostname too long", append(append([]byte{}, greet...), socks(0x03, strings.Repeat("a.", 127)+"a", 80)...), "\x05\x00\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00", false},
		{"socks port 0", append(append([]byte{}, greet...), socks(0x03, "example.com", 0)...), "\x05\x00\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00", false},
		{"socks dns failure", append(append([]byte{}, greet...), socks(0x03, "nx.invalid", 80)...), "\x05\x00\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00", false},
		{"socks success echo", append(append([]byte{}, greet...), socks(0x01, "127.0.0.1", echo.port())...), "\x05\x00\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", false},
		{"http garbage", []byte("GARBAGE\r\n\r\n"), "HTTP/1.1 400 Bad Request", false},
		{"http bad version", []byte("GET / HTTP 1.1\r\n\r\n"), "HTTP/1.1 400 Bad Request", false},
		{"http method unsupported", []byte("TRACE / HTTP/1.1\r\n\r\n"), "HTTP/1.1 400 Bad Request", false},
		{"http lower-case method", []byte("get http://denied.example.org/ HTTP/1.1\r\n\r\n"), "HTTP/1.1 403 Forbidden", false},
		{"http non-http scheme", []byte("GET ftp://x/ HTTP/1.1\r\n\r\n"), "HTTP/1.1 400 Bad Request", false},
		{"http relative target", []byte("GET /x HTTP/1.1\r\nHost: denied.example.org\r\n\r\n"), "HTTP/1.1 400 Bad Request", false},
		{"http https target", []byte("GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"), "HTTP/1.1 400 Bad Request", false},
		{"http connect denied", []byte("CONNECT denied.example.org:80 HTTP/1.1\r\nHost: x\r\n\r\n"), "HTTP/1.1 403 Forbidden", false},
		{"http connect denied no port", []byte("CONNECT denied.example.org HTTP/1.1\r\n\r\n"), "HTTP/1.1 403 Forbidden", false},
		{"http connect bad target 0", []byte("CONNECT host:0 HTTP/1.1\r\n\r\n"), "HTTP/1.1 400 Bad Request", false},
		{"http connect bad target range", []byte("CONNECT host:65536 HTTP/1.1\r\n\r\n"), "HTTP/1.1 400 Bad Request", false},
		{"http connect bad target brackets", []byte("CONNECT [::1]x:5 HTTP/1.1\r\n\r\n"), "HTTP/1.1 400 Bad Request", false},
		{"http connect empty host port", []byte("CONNECT :80 HTTP/1.1\r\n\r\n"), "HTTP/1.1 502 Bad Gateway", false},
		{"http connect quoted host", []byte("CONNECT b'c:80 HTTP/1.1\r\n\r\n"), "HTTP/1.1 502 Bad Gateway", false},
		{"http connect control host", []byte("CONNECT a\x01b:80 HTTP/1.1\r\n\r\n"), "HTTP/1.1 400 Bad Request", false},
		{"http connect dns failure", []byte("CONNECT nx.invalid:80 HTTP/1.1\r\nHost: x\r\n\r\n"), "HTTP/1.1 502 Bad Gateway", false},
		{"http absolute denied", []byte("GET http://denied.example.org/x HTTP/1.1\r\nHost: y\r\n\r\n"), "HTTP/1.1 403 Forbidden", false},
		{"http absolute request-line split", []byte("GET /a b HTTP/1.1\r\nHost: denied.example.org\r\n\r\n"), "HTTP/1.1 400 Bad Request", false},
		{"http connect success fixed", []byte(fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", fixed.port())), "HTTP/1.1 200 Connection established\r\n\r\n" + string(fixedResp), true},
		{"http absolute success fixed", []byte(fmt.Sprintf("GET http://127.0.0.1:%d/path?q=1 HTTP/1.1\r\nUser-Agent: diff/1\r\n\r\n", fixed.port())), string(fixedResp), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cl := dialProxy(t, s)
			cl.send(tc.send)
			if !tc.keepOpen {
				_ = cl.c.CloseWrite()
			}
			got := string(cl.readAll())
			if strings.HasPrefix(tc.name, "http") && !tc.keepOpen {
				got = strings.SplitN(got, "\r\n", 2)[0]
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
