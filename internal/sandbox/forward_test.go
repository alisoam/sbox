package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"sbox/internal/cliutil"
)

func tcpListener(t *testing.T, network, addr string) *net.TCPListener {
	t.Helper()
	l, err := net.Listen(network, addr)
	if network == "tcp6" && (errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)) {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l.(*net.TCPListener)
}

// Run the actual bridge and host relay without requiring user namespaces.
// Translate only the mount paths, as both processes see the same filesystem.
func TestForwardStreams(t *testing.T) {
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("socat unavailable")
	}
	for _, tc := range []struct{ network, address string }{
		{"tcp4", "127.0.0.1:0"}, {"tcp6", "[::1]:0"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			echo := tcpListener(t, tc.network, tc.address)
			server := echo.Addr().(*net.TCPAddr).AddrPort()
			reserved := tcpListener(t, tc.network, tc.address)
			remote := reserved.Addr().(*net.TCPAddr).AddrPort()
			local := tcpListener(t, tc.network, tc.address)
			published := local.Addr().(*net.TCPAddr).AddrPort()
			local.Close()
			reserved.Close()

			work := t.TempDir()
			plans := []forwardPlan{
				planForward(work, 0, cliutil.Forward{Listen: published, Target: remote}, false),
				planForward(work, 1, cliutil.Forward{Remote: true, Listen: remote, Target: server}, false),
			}
			if !plans[0].mount.RW || plans[1].mount.RW {
				t.Fatal("unexpected relay mount modes")
			}
			g, err := reserveForwards(plans)
			if err != nil {
				t.Fatal(err)
			}
			// The supervisor starts serving only after a successful
			// spawn; the relay logic is identical from here on.
			g.start()
			defer g.close()
			script := awaitForward
			for _, p := range plans {
				script += strings.ReplaceAll(p.bridge, p.mount.Dst, p.mount.Src)
			}
			// Keep the group leader alive until cleanup, like the sandbox's PID 1.
			cmd := exec.Command("/bin/sh", "-c", script+"echo ready; read line")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				cmd.Wait()
			}()
			stdout.(*os.File).SetReadDeadline(time.Now().Add(6 * time.Second))
			line := make([]byte, len("ready\n"))
			if _, err := io.ReadFull(stdout, line); err != nil || string(line) != "ready\n" {
				t.Fatalf("bridge startup: %q, %v", line, err)
			}

			const request = "request\x00after NUL"
			go func() {
				c, err := echo.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(4 * time.Second))
				data, err := io.ReadAll(c)
				if err == nil && string(data) == request {
					time.Sleep(600 * time.Millisecond) // beyond socat's default half-close timeout
					c.Write(bytes.Repeat(data, 4096))
				}
			}()
			c, err := net.DialTimeout(tc.network, published.String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(c, request); err != nil {
				t.Fatal(err)
			}
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, bytes.Repeat([]byte(request), 4096)) {
				t.Fatalf("reply after half-close: %d bytes, %v", len(got), err)
			}
		})
	}
}

func TestForwardRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	symlink := filepath.Join(dir, "relay.sock")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if c, err := dialForward(context.Background(), "unix", symlink); err == nil {
		c.Close()
		t.Fatal("followed a sandbox-created symlink")
	}
}

func TestForwardStartupRollback(t *testing.T) {
	first := tcpListener(t, "tcp4", "127.0.0.1:0")
	busy := tcpListener(t, "tcp4", "127.0.0.1:0")
	rule := cliutil.Forward{Listen: first.Addr().(*net.TCPAddr).AddrPort(), Target: busy.Addr().(*net.TCPAddr).AddrPort()}
	first.Close()
	p := planForward("", 0, rule, true)
	if p.mount.Src != "" || p.bridge != "" {
		t.Fatal("shared network requires only the host TCP relay")
	}
	if g, err := reserveForwards([]forwardPlan{p, {listen: p.target, target: p.listen}}); err == nil {
		g.close()
		t.Fatal("forward started on an occupied port")
	}
	tcpListener(t, "tcp4", p.listen.address)
}

func TestRemoteForwardOccupied(t *testing.T) {
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("socat unavailable")
	}
	busy := tcpListener(t, "tcp4", "127.0.0.1:0").Addr().(*net.TCPAddr).AddrPort()
	p := planForward(t.TempDir(), 0, cliutil.Forward{Remote: true, Listen: busy, Target: busy}, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/bin/sh", "-c", awaitForward+p.bridge+"echo PAYLOAD").CombinedOutput()
	if err == nil || ctx.Err() != nil || !bytes.Contains(output, []byte("could not start")) || bytes.Contains(output, []byte("PAYLOAD")) {
		t.Fatalf("occupied remote listener: %v, %s", err, output)
	}
}

// ParseCLI refuses these for CLI runs; BuildSpec backstops programmatic Options
// (tests, future callers) so no spec can plan a self-dialing relay farm.
func TestBuildSpecRejectsForwardLoops(t *testing.T) {
	root := t.TempDir()
	sand, sock := filepath.Join(root, "sand"), filepath.Join(root, "sock")
	pair := []cliutil.Forward{
		{Listen: netip.MustParseAddrPort("127.0.0.1:8080"), Target: netip.MustParseAddrPort("127.0.0.1:9090")},
		{Listen: netip.MustParseAddrPort("127.0.0.1:9090"), Target: netip.MustParseAddrPort("127.0.0.1:8080")},
	}
	if _, err := BuildSpec(&cliutil.Options{Net: true, Forwards: pair}, root, sand, sock, root,
		nil, nil, "", "", nil, nil); err == nil || !strings.Contains(err.Error(), "forwarding loop") {
		t.Fatalf("shared-network pair: err = %v", err)
	}
	// The same rules stay legal without --net: two -L rules dial inside the
	// sandbox while both listeners sit on the host.
	spec, err := BuildSpec(&cliutil.Options{Forwards: pair}, root, sand, sock, root,
		nil, nil, "", "", nil, nil)
	if err != nil {
		t.Fatalf("isolated two -L rules must not loop: %v", err)
	}
	if len(spec.forwards) != 2 {
		t.Fatalf("planned %d forwards, want 2", len(spec.forwards))
	}
}

// scriptedListener hands out queued errors before delegating to a real
// listener, driving serve's accept-error handling.
type scriptedListener struct {
	net.Listener
	errs chan error
}

func (s *scriptedListener) Accept() (net.Conn, error) {
	select {
	case err := <-s.errs:
		return nil, err
	default:
		return s.Listener.Accept()
	}
}

func acceptErrno(errno syscall.Errno) error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", errno)}
}

func newTestGroup(t *testing.T) *forwardGroup {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	g := &forwardGroup{ctx: ctx, cancel: cancel, streamCap: forwardStreamLimit}
	t.Cleanup(g.close)
	return g
}

// A recoverable accept error (descriptor shortage, routing conditions, or
// any other transient failure) must not kill the forward: the port stays
// bound and serving resumes once it clears.
func TestForwardAcceptRetries(t *testing.T) {
	echo := tcpListener(t, "tcp4", "127.0.0.1:0")
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	front := tcpListener(t, "tcp4", "127.0.0.1:0")
	scripted := &scriptedListener{Listener: front, errs: make(chan error, 3)}
	scripted.errs <- acceptErrno(syscall.EMFILE)
	scripted.errs <- acceptErrno(syscall.ENETUNREACH)
	scripted.errs <- errors.New("bogus accept failure") // not an errno: retried too

	g := newTestGroup(t)
	go g.serve(scripted, tcpEndpoint(echo.Addr().(*net.TCPAddr).AddrPort()))

	c, err := net.DialTimeout("tcp4", front.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "resume"); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("resume"))
	if _, err := io.ReadFull(c, reply); err != nil || string(reply) != "resume" {
		t.Fatalf("forward did not resume after recoverable accept errors: %q, %v", reply, err)
	}
}

// Only a closed listener (teardown) ends the serve loop.
func TestForwardAcceptCloseStops(t *testing.T) {
	front := tcpListener(t, "tcp4", "127.0.0.1:0")
	target := tcpEndpoint(front.Addr().(*net.TCPAddr).AddrPort())
	g := newTestGroup(t)
	done := make(chan struct{})
	go func() { g.serve(front, target); close(done) }()
	time.Sleep(50 * time.Millisecond) // let the loop park in Accept
	front.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serve loop survived a closed listener")
	}
}

// Each forward admits streams against its OWN pool: a forward parked at its
// cap (a held first hop) must not block a different forward. With one shared
// pool, the first hops of a multi-rule chain (client → forward A → payload
// service → forward B → destination) could occupy every slot while their
// downstream hops waited for admission that could never come.
func TestForwardStreamsIndependentPools(t *testing.T) {
	// hold: reads until EOF and only then answers, so a client that stays
	// open keeps its stream — and its forward's only slot — held forever.
	hold := tcpListener(t, "tcp4", "127.0.0.1:0")
	go func() {
		for {
			c, err := hold.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				data, err := io.ReadAll(c)
				if err != nil {
					return
				}
				time.Sleep(400 * time.Millisecond)
				c.Write(data)
			}()
		}
	}()
	echo := tcpListener(t, "tcp4", "127.0.0.1:0")
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	frontA := tcpListener(t, "tcp4", "127.0.0.1:0")
	frontB := tcpListener(t, "tcp4", "127.0.0.1:0")
	g := newTestGroup(t)
	g.streamCap = 1 // one stream per forward
	go g.serve(frontA, tcpEndpoint(hold.Addr().(*net.TCPAddr).AddrPort()))
	go g.serve(frontB, tcpEndpoint(echo.Addr().(*net.TCPAddr).AddrPort()))

	// Forward A: one held stream fills A's pool for good.
	a, err := net.DialTimeout("tcp4", frontA.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := io.WriteString(a, "held"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) // A's only slot is now held

	// Forward B must round-trip immediately despite A being parked.
	b, err := net.DialTimeout("tcp4", frontB.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(b, "free"); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("free"))
	if _, err := io.ReadFull(b, reply); err != nil || string(reply) != "free" {
		t.Fatalf("a forward at its cap blocked another forward: %q, %v", reply, err)
	}
}

// A single forward bounds its concurrent streams: with a per-forward cap of
// one, a second client is accepted but held WITHOUT a slot and only flows
// once the first stream ends (any further clients stay in the kernel
// backlog behind it).
func TestForwardStreamLimit(t *testing.T) {
	// hold: answers only after the client half-closes, then lingers, so
	// the first stream verifiably holds its slot.
	hold := tcpListener(t, "tcp4", "127.0.0.1:0")
	go func() {
		for {
			c, err := hold.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				data, err := io.ReadAll(c)
				if err != nil {
					return
				}
				time.Sleep(400 * time.Millisecond)
				c.Write(data)
			}()
		}
	}()
	front := tcpListener(t, "tcp4", "127.0.0.1:0")
	g := newTestGroup(t)
	g.streamCap = 1
	go g.serve(front, tcpEndpoint(hold.Addr().(*net.TCPAddr).AddrPort()))

	a, err := net.DialTimeout("tcp4", front.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := io.WriteString(a, "first"); err != nil {
		t.Fatal(err)
	}
	if err := a.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) // the first stream now holds the only slot

	b, err := net.DialTimeout("tcp4", front.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := io.WriteString(b, "second"); err != nil {
		t.Fatal(err)
	}
	if err := b.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := b.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	early := make([]byte, 6)
	if n, err := b.Read(early); err == nil {
		t.Fatalf("second stream relayed while the only slot was held: %q", early[:n])
	}
	b.SetReadDeadline(time.Now().Add(6 * time.Second))
	if got, _ := io.ReadAll(a); string(got) != "first" {
		t.Fatalf("first stream: %q", got)
	}
	if got, err := io.ReadAll(b); err != nil || string(got) != "second" {
		t.Fatalf("second stream never resumed: %q, %v", got, err)
	}
}

// The readiness check reads socket-table columns into shell variables
// (state, num, ino, ...); its subshell isolation keeps those from
// overwriting same-named --env values the payload must inherit.
func TestForwardReadinessPreservesEnv(t *testing.T) {
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("socat unavailable")
	}
	work := t.TempDir()
	p := planForward(work, 0, cliutil.Forward{
		Listen: netip.MustParseAddrPort("127.0.0.1:18080"),
		Target: netip.MustParseAddrPort("127.0.0.1:1"),
	}, false)
	if err := os.MkdirAll(p.mount.Src, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "state=keep num=keep ino=keep link=keep inode=keep fd=keep\n" +
		"export state num ino link inode fd\n" +
		awaitForward + strings.ReplaceAll(p.bridge, p.mount.Dst, p.mount.Src) +
		`[ "$state:$num:$ino:$link:$inode:$fd" = keep:keep:keep:keep:keep:keep ] && echo KEPT
kill "$!" 2>/dev/null
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/sh", "-c", script).CombinedOutput()
	if ctx.Err() != nil || err != nil || !bytes.Contains(out, []byte("KEPT")) {
		t.Fatalf("readiness check clobbered environment values: %v, %s", err, out)
	}
}

// workItem waits for a file the supervisor created inside $WORK.
func workItem(t *testing.T, root, name string) string {
	t.Helper()
	pattern := filepath.Join(root, "tmp", "sbox.*", name)
	deadline := time.Now().Add(5 * time.Second)
	for {
		m, _ := filepath.Glob(pattern)
		if len(m) > 0 {
			return m[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared under %s", name, pattern)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The reserved forward listeners stay silent until the sandbox reports
// readiness through the FIFO: the byte opens the gate, an exit before the
// signal never does, and silence past the deadline fails the launch.
func TestSupervisorForwardGate(t *testing.T) {
	echo := tcpListener(t, "tcp4", "127.0.0.1:0")
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	remote := func() cliutil.Forward {
		// Isolated -R: the reserved host listener is the $WORK Unix
		// socket and the relay dials the echo server host-side, so the
		// gate is observable without any in-sandbox help.
		return cliutil.Forward{
			Remote: true,
			Listen: netip.MustParseAddrPort("127.0.0.1:19999"),
			Target: echo.Addr().(*net.TCPAddr).AddrPort(),
		}
	}

	t.Run("ready opens the gate", func(t *testing.T) {
		sup, fp, root := newTestSupervisor(t)
		fp.bin = writeShim(t, filepath.Join(root, "linger"), "sleep 2\nexit 42")
		sup.Opts.Forwards = []cliutil.Forward{remote()}
		rcCh := make(chan int, 1)
		go func() { rcCh <- sup.Run() }()
		sock := workItem(t, root, "forward-0")
		fifo := workItem(t, root, forwardReadyName)

		c, err := net.DialTimeout("unix", sock, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write([]byte("gate")); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		if n, err := c.Read(make([]byte, 8)); err == nil {
			t.Fatalf("forward served before the readiness signal: %q", make([]byte, n))
		}
		// The bridge's signal: one byte into the FIFO.
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		w.Close()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		reply := make([]byte, 4)
		if _, err := io.ReadFull(c, reply); err != nil || string(reply) != "gate" {
			t.Fatalf("forward did not start on the readiness signal: %q, %v", reply, err)
		}
		if rc := <-rcCh; rc != 42 {
			t.Fatalf("rc = %d, want 42", rc)
		}
	})

	t.Run("exit before ready never serves", func(t *testing.T) {
		sup, _, _ := newTestSupervisor(t) // default shim exits 42 at once
		sup.Opts.Forwards = []cliutil.Forward{remote()}
		var notes []string
		sup.Warn = func(w string) { notes = append(notes, w) }
		// The gate must consume the exit and return 42 — not hang for
		// forwardReadyWait, and never call forwards.start().
		if rc := sup.Run(); rc != 42 {
			t.Fatalf("rc = %d, want 42", rc)
		}
		found := false
		for _, n := range notes {
			if strings.Contains(n, "exited before its forwards were ready") {
				found = true
			}
		}
		if !found {
			t.Errorf("no exit-before-ready note: %v", notes)
		}
	})

	t.Run("fast success without readiness fails", func(t *testing.T) {
		sup, fp, root := newTestSupervisor(t)
		fp.bin = writeShim(t, filepath.Join(root, "quick"), "exit 0\n")
		sup.Opts.Forwards = []cliutil.Forward{remote()}
		var notes []string
		sup.Warn = func(w string) { notes = append(notes, w) }
		// The bridge always signals before exec'ing the payload, so a
		// payload exit without the byte means startup failed — a zero
		// exit must be coerced, never reported as success with forwards
		// that never started.
		if rc := sup.Run(); rc != 1 {
			t.Fatalf("rc = %d, want 1", rc)
		}
		found := false
		for _, n := range notes {
			if strings.Contains(n, "exited before its forwards were ready") {
				found = true
			}
		}
		if !found {
			t.Errorf("no exit-before-ready note: %v", notes)
		}
	})

	t.Run("signal raced by exit still succeeds", func(t *testing.T) {
		// The bridge signals a breath before exec'ing the payload, so the
		// byte routinely still sits in the FIFO when a fast payload's
		// exit lands. The gate must resolve the reader's pending report
		// (cancel, then take the final word) instead of guessing: the
		// genuine zero exit survives, and forwards never start on a dead
		// child. Iterate to shake both interleavings.
		for i := 0; i < 15; i++ {
			sup, fp, root := newTestSupervisor(t)
			body := fmt.Sprintf(
				"f=$(ls -d %s 2>/dev/null | head -n 1); echo ok >\"$f\"; exit 0",
				filepath.Join(root, "tmp", "sbox.*", forwardReadyName))
			fp.bin = writeShim(t, filepath.Join(root, "signal"), body)
			sup.Opts.Forwards = []cliutil.Forward{remote()}
			if rc := sup.Run(); rc != 0 {
				t.Fatalf("iteration %d: rc = %d, want 0 (successful run misreported)", i, rc)
			}
		}
	})

	t.Run("silence fails closed", func(t *testing.T) {
		oldWait := forwardReadyWait
		forwardReadyWait = 200 * time.Millisecond
		defer func() { forwardReadyWait = oldWait }()
		sup, fp, root := newTestSupervisor(t)
		fp.bin = writeShim(t, filepath.Join(root, "linger"), "sleep 5\nexit 42")
		sup.Opts.Forwards = []cliutil.Forward{remote()}
		var notes []string
		sup.Warn = func(w string) { notes = append(notes, w) }
		if rc := sup.Run(); rc != 1 {
			t.Fatalf("rc = %d, want 1", rc)
		}
		found := false
		for _, n := range notes {
			if strings.Contains(n, "never reported forward readiness") {
				found = true
			}
		}
		if !found {
			t.Errorf("no readiness-timeout note: %v", notes)
		}
	})
}
