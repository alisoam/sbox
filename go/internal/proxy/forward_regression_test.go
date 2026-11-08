package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func readRequestHead(r *bufio.Reader) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil || line == "\r\n" {
			return err
		}
	}
}

func TestUpstreamPreservesGreeting(t *testing.T) {
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			up := startFakeUpstream(t, scheme, func(up *fakeUpstream) {
				up.onConn = func(c net.Conn) {
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					r := bufio.NewReader(c)
					var reply []byte
					if scheme == "http" {
						if err := readRequestHead(r); err != nil {
							return
						}
						reply = []byte("HTTP/1.1 200 Connection established\r\n\r\n")
					} else {
						if _, err := io.CopyN(io.Discard, r, 3); err != nil {
							return
						}
						_, _ = c.Write([]byte{5, 0})
						if _, err := io.CopyN(io.Discard, r, 10); err != nil {
							return
						}
						reply = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
					}
					// One write makes the server-first greeting available during
					// the handshake read. Reading the raw socket would lose it.
					_, _ = c.Write(append(reply, []byte("SSH-2.0-test\r\n")...))
					_, _ = io.Copy(c, r)
				}
			})
			cfg := upstreamConfig(t, fmt.Sprintf("%s://127.0.0.1:%d", scheme, lnPort(up.ln)),
				&fakeResolver{})
			c, _, err := New(cfg).ConnectDestination("127.0.0.1", 22)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			got := make([]byte, len("SSH-2.0-test\r\n"))
			if _, err := io.ReadFull(c, got); err != nil || string(got) != "SSH-2.0-test\r\n" {
				t.Fatalf("greeting = %q, error = %v", got, err)
			}
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(c, got[:4]); err != nil || string(got[:4]) != "ping" {
				t.Fatalf("echo after greeting = %q, error = %v", got[:4], err)
			}
		})
	}
}

func TestForwardRequestContinue(t *testing.T) {
	client, downstream := net.Pipe()
	origin, destination := net.Pipe()
	for _, c := range []net.Conn{client, downstream, origin, destination} {
		t.Cleanup(func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	}
	done := make(chan struct{})
	go func() {
		forwardRequest(downstream, downstream, destination, nil, 4, nil)
		close(done)
	}()
	originDone := make(chan error, 1)
	const interim = "HTTP/1.1 100 Continue\r\n\r\n"
	const final = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
	go func() {
		defer origin.Close()
		if _, err := io.WriteString(origin, interim); err != nil {
			originDone <- err
			return
		}
		body := make([]byte, 4)
		if _, err := io.ReadFull(origin, body); err != nil {
			originDone <- err
			return
		}
		if string(body) != "body" {
			originDone <- fmt.Errorf("body = %q", body)
			return
		}
		_, err := io.WriteString(origin, final)
		originDone <- err
	}()
	buf := make([]byte, len(interim))
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != interim {
		t.Fatalf("interim response before body = %q, error = %v", buf, err)
	}
	if _, err := io.WriteString(client, "body"); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil || string(got) != final {
		t.Fatalf("final response = %q, error = %v", got, err)
	}
	if err := <-originDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwarder did not finish")
	}
}

func TestHTTPExpectContinue(t *testing.T) {
	originDone := make(chan error, 1)
	const interim = "HTTP/1.1 100 Continue\r\n\r\n"
	const final = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
	origin := startFakeUpstream(t, "http", func(origin *fakeUpstream) {
		origin.onConn = func(c net.Conn) {
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			r := bufio.NewReader(c)
			if err := readRequestHead(r); err != nil {
				originDone <- err
				return
			}
			if _, err := io.WriteString(c, interim); err != nil {
				originDone <- err
				return
			}
			body := make([]byte, 4)
			if _, err := io.ReadFull(r, body); err != nil {
				originDone <- err
				return
			}
			if string(body) != "body" {
				originDone <- fmt.Errorf("body = %q", body)
				return
			}
			_, err := io.WriteString(c, final)
			originDone <- err
		}
	})
	s := startTestProxy(t, testConfig(t, &fakeResolver{}))
	cl := dialProxy(t, s)
	cl.send([]byte(fmt.Sprintf("POST http://127.0.0.1:%d/ HTTP/1.1\r\n"+
		"Expect: 100-continue\r\nContent-Length: 4\r\n\r\n", lnPort(origin.ln))))
	if got := string(cl.readN(len(interim))); got != interim {
		t.Fatalf("interim response before body = %q", got)
	}
	cl.send([]byte("body"))
	if got := string(cl.readAll()); got != final {
		t.Fatalf("final response = %q", got)
	}
	if err := <-originDone; err != nil {
		t.Fatal(err)
	}
}

func TestForwardRequestEarlyRejection(t *testing.T) {
	client, downstream := net.Pipe()
	origin, destination := net.Pipe()
	for _, c := range []net.Conn{client, downstream, origin, destination} {
		t.Cleanup(func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	}
	done := make(chan struct{})
	go func() {
		forwardRequest(downstream, downstream, destination, nil, 1<<20, nil)
		close(done)
	}()
	const response = "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n"
	go func() {
		_, _ = io.WriteString(origin, response)
		origin.Close()
	}()
	got, err := io.ReadAll(client)
	if err != nil || string(got) != response {
		t.Fatalf("early rejection = %q, error = %v", got, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("upload goroutine remained blocked after the response")
	}
}

func TestForwardRequestHalfCloseFailure(t *testing.T) {
	client, downstream := net.Pipe()
	origin, destination := net.Pipe()
	for _, c := range []net.Conn{client, downstream, origin, destination} {
		t.Cleanup(func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	}
	// An uninitialized TCPConn deterministically rejects CloseWrite. That
	// advisory error must not close the client or discard the response.
	halfClose := new(net.TCPConn)
	if err := halfClose.CloseWrite(); err == nil {
		t.Fatal("test requires a failing half-close")
	}
	done := make(chan struct{})
	go func() {
		forwardRequest(downstream, downstream, destination, halfClose, 0, nil)
		close(done)
	}()
	const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
	go func() {
		_, _ = io.WriteString(origin, response)
		origin.Close()
	}()
	got, err := io.ReadAll(client)
	if err != nil || string(got) != response {
		t.Fatalf("response after failed half-close = %q, error = %v", got, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwarder did not finish")
	}
}

func TestForwardRequestShutdown(t *testing.T) {
	for _, length := range []int64{0, 1024} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			client, downstream := net.Pipe()
			origin, destination := net.Pipe()
			for _, c := range []net.Conn{client, downstream, origin, destination} {
				t.Cleanup(func() { c.Close() })
			}
			closed := make(chan struct{})
			done := make(chan struct{})
			go func() {
				forwardRequest(downstream, downstream, destination, nil, length, closed)
				close(done)
			}()
			close(closed)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("shutdown waited on a silent client or origin")
			}
		})
	}
}

func TestHTTPForwardHeaderCorpus(t *testing.T) {
	cases := []struct{ name, target, headers, wantHeaders string }{
		{"userinfo", "http://u:sekret@127.0.0.1:%d/", "Host: evil\r\n", ""},
		{"hop headers", "http://127.0.0.1:%d/", "Proxy-Connection: keep\r\n" +
			"Proxy-Authorization: Basic x\r\nConnection: keep-alive\r\nKeep-Alive: 1\r\n" +
			"TE: trailers\r\nTrailer: X\r\nUpgrade: h2c\r\nX-Keep: yes\r\n", "X-Keep: yes\r\n"},
		{"empty body", "http://127.0.0.1:%d/", "Content-Length: 0\r\n", "Content-Length: 0\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := startOrigin(t, "record", nil)
			s := startTestProxy(t, testConfig(t, &fakeResolver{}))
			target := fmt.Sprintf(tc.target, o.port())
			httpExchange(t, s, "GET "+target+" HTTP/1.1\r\n"+tc.headers+"\r\n")
			got, halfClosed := o.recorded()
			want := fmt.Sprintf("GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n", o.port()) +
				tc.wantHeaders + "Connection: close\r\n\r\n"
			if string(got) != want || halfClosed != 1 {
				t.Errorf("origin saw %q, half-closes=%d; want %q, one half-close", got, halfClosed, want)
			}
		})
	}
	t.Run("request line control", func(t *testing.T) {
		s := startTestProxy(t, testConfig(t, &fakeResolver{}))
		got := httpExchange(t, s, "GET http://example.com/\x01 HTTP/1.1\r\n\r\n")
		if !strings.Contains(string(got), "400 Bad Request") ||
			!strings.HasSuffix(string(got), "bad request line\n") {
			t.Errorf("control byte response = %q", got)
		}
	})
}

func TestUpstreamRefusalCorpus(t *testing.T) {
	t.Run("socks authentication refused", func(t *testing.T) {
		up := startFakeUpstream(t, "socks5")
		cfg := upstreamConfig(t, fmt.Sprintf("socks5://u:p@127.0.0.1:%d", lnPort(up.ln)),
			&fakeResolver{})
		cl := dialProxy(t, startTestProxy(t, cfg))
		if replyCode(cl.socksRoundtrip(socksRequest(1, "127.0.0.1", 443))) != repGeneral {
			t.Fatal("failed authentication did not reject the tunnel")
		}
	})
	t.Run("denied never reaches upstream", func(t *testing.T) {
		up := startFakeUpstream(t, "http")
		cfg := upstreamConfig(t, fmt.Sprintf("http://127.0.0.1:%d", lnPort(up.ln)), &fakeResolver{})
		s := startTestProxy(t, cfg)
		got := httpExchange(t, s, "CONNECT denied.example.org:80 HTTP/1.1\r\n\r\n")
		if !strings.HasPrefix(string(got), "HTTP/1.1 403 Forbidden\r\n") {
			t.Errorf("denial = %q", got)
		}
		up.mu.Lock()
		defer up.mu.Unlock()
		if up.conns != 0 {
			t.Errorf("denied destination opened %d upstream connections", up.conns)
		}
	})
}
