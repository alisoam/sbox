package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"sbox/internal/allow"
)

// SelfTest is the fail-closed gate on the REAL socket, before the
// sandbox starts: a non-allowed destination must be refused on both
// SOCKS5 and HTTP CONNECT (denied names are never resolved, so this
// needs no network). errf receives the advisory note (Python's err());
// every failure is a returned error with sbox.py's message (Python
// die()s — the launcher prints and exits).
func SelfTest(sockPath string, allows []allow.Entry, errf func(string)) error {
	if errf == nil {
		errf = func(string) {}
	}
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	name := "sbox-selftest-" + hex.EncodeToString(buf) + ".invalid"
	if ok, _ := allow.DestinationAllowed(allows, name, 80); ok {
		errf("note: allowlist covers the self-test destination; skipping enforcement check")
		return nil
	}

	// SOCKS5: expect REP=2 (not allowed)
	s, err := dialUnixDeadline(sockPath, 5*time.Second)
	if err != nil {
		return selfTestTalkErr(err)
	}
	if _, err := s.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return selfTestTalkErr(err)
	}
	greet := make([]byte, 2)
	if _, err := ioReadFull(s, greet); err != nil || greet[0] != 0x05 || greet[1] != 0x00 {
		return fmt.Errorf("self-test: bad SOCKS5 greeting on the proxy socket")
	}
	host := []byte(name)
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	req = append(req, byte(80>>8), byte(80))
	if _, err := s.Write(req); err != nil {
		return selfTestTalkErr(err)
	}
	rep := make([]byte, 64)
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, rerr := s.Read(rep)
	if rerr != nil {
		n = 0
	}
	if n < 2 || rep[1] != 0x02 {
		reply := "eof"
		if n >= 2 {
			reply = fmt.Sprintf("%02x%02x", rep[0], rep[1])
		} else if n == 1 {
			reply = fmt.Sprintf("%02x", rep[0])
		}
		return fmt.Errorf("self-test: SOCKS5 denial not enforced (reply=%s) — failing closed", reply)
	}
	_ = s.Close()

	// HTTP CONNECT: expect 403
	s, err = dialUnixDeadline(sockPath, 5*time.Second)
	if err != nil {
		return selfTestTalkErr(err)
	}
	reqLine := fmt.Sprintf("CONNECT %s:80 HTTP/1.1\r\nHost: %s\r\n\r\n", name, name)
	if _, err := s.Write([]byte(reqLine)); err != nil {
		return selfTestTalkErr(err)
	}
	status := make([]byte, 128)
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, rerr = s.Read(status)
	if rerr != nil {
		n = 0
	}
	if !strings.HasPrefix(string(status[:n]), "HTTP/1.1 403") {
		first := "<eof>"
		if n > 0 {
			line := strings.SplitN(string(status[:n]), "\r\n", 2)[0]
			if len(line) > 40 {
				line = line[:40]
			}
			first = line
		}
		return fmt.Errorf("self-test: HTTP denial not enforced (%q) — failing closed", first)
	}
	_ = s.Close()
	return nil
}

func selfTestTalkErr(err error) error {
	return fmt.Errorf("self-test: cannot talk to the proxy (%v) — failing closed", err)
}

func dialUnixDeadline(path string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", path, timeout)
}

func ioReadFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
