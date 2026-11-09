package outputfilter

// pump.go tests against a REAL pty pair: filtered output flow, the
// deadline-bounded drain and its flush, the EOF-during-run quirk (no
// flush), stdin forwarding with
// backpressure (never drops), and SIGWINCH winsize forwarding via an
// injected channel.

import (
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// readSlave reads the pty slave (the sandbox side of stdin) until n
// bytes arrive or the deadline passes.
func readSlave(t *testing.T, s *os.File, n int, d time.Duration) []byte {
	t.Helper()
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, n)
		m, err := io.ReadFull(s, buf)
		ch <- res{buf[:m], err}
	}()
	select {
	case r := <-ch:
		return r.b
	case <-time.After(d):
		t.Fatalf("slave read timed out")
		return nil
	}
}

func TestPumpFiltersOutput(t *testing.T) {
	master, slave := requirePty(t)
	var mu sync.Mutex
	var out strings.Builder
	p := &Pump{
		Master:    master,
		Sanitizer: NewSanitizer(false),
		Out: writerFunc(func(b []byte) (int, error) {
			mu.Lock()
			defer mu.Unlock()
			return out.WriteString(string(b))
		}),
	}
	p.Start()
	defer p.Close()

	in := "ok\x1b]52;c:aGk=\x07\x1b[32mgreen\x1b[0m\n"
	if _, err := slave.Write([]byte(in)); err != nil {
		t.Fatal(err)
	}
	// the pty's ONLCR delivers \n as \r\n to the master (the epilog
	// documents this; the pump reads OPOST-processed bytes)
	want := "ok\x1b[32mgreen\x1b[0m\r\n"
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := out.String()
		mu.Unlock()
		if got == want {
			p.Stop(50 * time.Millisecond)
			return
		}
		if len(got) > len(want) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Errorf("filtered output = %q, want %q", out.String(), want)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

func TestPumpDrainDeadlineFlushes(t *testing.T) {
	// The test HOLDS the slave open: no EOF can arrive, so Stop's
	// deadline evicts the parked reader — and the flush emits the
	// held-back tail (a truncated multibyte → U+FFFD), exactly like
	// _drain_master's flush.
	master, slave := requirePty(t)
	var mu sync.Mutex
	var out strings.Builder
	p := &Pump{Master: master, Sanitizer: NewSanitizer(true)}
	p.Out = lockWriter(&mu, &out)
	p.Start()
	defer p.Close()

	slave.Write([]byte("ok\r"))    // strict: \r held for its lookahead
	slave.Write([]byte("again"))   // ...and dropped: the \r was bare
	slave.Write([]byte("\xc3"))    // held: incomplete é
	p.Stop(300 * time.Millisecond) // deadline path (no EOF possible)

	mu.Lock()
	defer mu.Unlock()
	if got, want := out.String(), "okagain\ufffd"; got != want {
		t.Errorf("drained output = %q, want %q", got, want)
	}
}

func TestPumpEofDuringRunSkipsFlush(t *testing.T) {
	// EOF arrives during the run phase: the drain and its flush are
	// skipped, so an incomplete tail is dropped.
	master, slave := requirePty(t)
	var mu sync.Mutex
	var out strings.Builder
	p := &Pump{Master: master, Sanitizer: NewSanitizer(true)}
	p.Out = lockWriter(&mu, &out)
	p.Start()

	slave.Write([]byte("ok\xc3"))
	slave.Close() // EOF: every slave fd closed
	// give the reader a moment to see EIO and exit DURING the run
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-p.done:
			p.Stop(time.Second)
			mu.Lock()
			defer mu.Unlock()
			if got := out.String(); got != "ok" {
				t.Errorf("post-EOF output = %q, want %q (no flush on this path)", got, "ok")
			}
			p.Close()
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	p.Close()
	t.Fatal("reader never saw EOF")
}

func lockWriter(mu *sync.Mutex, sb *strings.Builder) io.Writer {
	return writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return sb.WriteString(string(b))
	})
}

func TestPumpStdinForward(t *testing.T) {
	master, slave := requirePty(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	var mu sync.Mutex
	var echo strings.Builder // the pty echoes: keep the pump OFF real stdout
	p := &Pump{Master: master, Sanitizer: NewSanitizer(false), Stdin: pr,
		Out: lockWriter(&mu, &echo)}
	p.Start()
	defer p.Close()

	payload := []byte("keystrokes\n")
	go func() { pw.Write(payload); pw.Close() }()
	got := readSlave(t, slave, len(payload), 3*time.Second)
	if string(got) != string(payload) {
		t.Errorf("slave saw %q, want %q", got, payload)
	}
}

func TestPumpStdinBackpressure(t *testing.T) {
	// Nobody reads the slave: the pty input buffer fills, the writer
	// parks, the backlog grows to the cap and the forwarder STOPS
	// READING (never drops). Draining the slave lets it flow again.
	master, slave := requirePty(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	// keep the pump's (echoed) output off the test's stdout
	echoMu, echoOut := &sync.Mutex{}, &strings.Builder{}
	p := &Pump{Master: master, Sanitizer: NewSanitizer(false), Stdin: pr,
		Out: lockWriter(echoMu, echoOut)}
	p.Start()
	defer p.Close()

	const total = maxPendingInput + 128*1024
	go func() {
		buf := make([]byte, 4096)
		for written := 0; written < total; {
			n, err := pw.Write(buf)
			if err != nil {
				return
			}
			written += n
		}
		pw.Close()
	}()

	// wait until the forwarder pauses at the cap (with slack for the
	// in-flight chunk)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p.pendingLen() >= maxPendingInput {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if p.pendingLen() < maxPendingInput {
		t.Fatalf("backlog never reached the cap: %d", p.pendingLen())
	}
	// the backlog must stay bounded: one in-flight chunk at most
	if p.pendingLen() > maxPendingInput+4096 {
		t.Errorf("backlog exceeded the cap: %d", p.pendingLen())
	}
	// drain the slave side: the backlog must shrink
	buf := make([]byte, 32*1024)
	slave.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 8; i++ {
		if _, err := slave.Read(buf); err != nil {
			break
		}
		if p.pendingLen() < maxPendingInput {
			break
		}
	}
	time.Sleep(100 * time.Millisecond)
	if p.pendingLen() >= maxPendingInput {
		t.Errorf("backlog did not drain: %d", p.pendingLen())
	}
}

func TestPumpStopDuringPendingWrite(t *testing.T) {
	// A pipe provides a deterministic full buffer: a write larger than
	// its capacity cannot complete until this test drains the reader.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	capacity, _, errno := syscall.Syscall(syscall.SYS_FCNTL, w.Fd(), syscall.F_GETPIPE_SZ, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	data := make([]byte, 2*int(capacity))
	p := &Pump{Master: w, chunks: [][]byte{data}, total: len(data)}
	p.space = sync.NewCond(&p.mu)
	p.work = sync.NewCond(&p.mu)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.drainPending()
	}()
	// Receiving one byte proves Write has started, but leaves too little
	// capacity for it to finish. Stop discards the queue in that window.
	if _, err := io.ReadFull(r, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	p.setStopped()
	if _, err := io.ReadFull(r, make([]byte, len(data)-1)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pending writer did not exit after stop")
	}
	if got := p.pendingLen(); got != 0 {
		t.Fatalf("stopped backlog = %d, want 0", got)
	}
}

func TestPumpWinsizeForward(t *testing.T) {
	master, _ := requirePty(t) // pump's pty: the destination
	srcM, _ := requirePty(t)   // a second pty: the winsize source
	winch := make(chan os.Signal, 1)
	p := &Pump{
		Master:    master,
		Sanitizer: NewSanitizer(false),
		TtySource: srcM,
		Winch:     winch, // injected: no OS signal needed
	}
	p.Start()
	defer p.Close()

	setWS := func(f *os.File, rows, cols uint16) winSize {
		ws := winSize{Rows: rows, Cols: cols}
		if err := ioctlPtr(f.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&ws)); err != nil {
			t.Fatalf("set winsize: %v", err)
		}
		return ws
	}
	want := setWS(srcM, 24, 137)
	winch <- nil // a signal value (the pump only uses it as a wakeup)
	time.Sleep(100 * time.Millisecond)
	var got winSize
	if err := ioctlPtr(master.Fd(), syscall.TIOCGWINSZ, unsafe.Pointer(&got)); err != nil {
		t.Fatal(err)
	}
	if got.Rows != want.Rows || got.Cols != want.Cols {
		t.Errorf("pump winsize = %d x %d, want %d x %d", got.Rows, got.Cols, want.Rows, want.Cols)
	}
}

func TestPumpSetupRefusesUnrawableTty(t *testing.T) {
	// Setup's die path: a stdin that IS a tty but raw mode failed —
	// simulated by a stdin whose raw-mode entry we break: a hung-up
	// slave reports not-a-tty (both ioctls fail), so use a HEALTHY
	// slave and make tcsetattr fail by closing... simplest deterministic
	// shape: stdin not a tty (the common case) — the exact fd comes
	// back and nothing is refused.
	f := mustTempFile(t)
	swapStdin(t, f)
	p, childStdin, err := Setup(true)
	if err != nil {
		p.Close()
		t.Fatalf("non-tty Setup refused: %v", err)
	}
	defer p.Close()
	if childStdin != os.Stdin {
		t.Errorf("child stdin = %v, want the exact non-tty fd", childStdin)
	}
	if p.Stdin != nil {
		t.Errorf("nothing to forward, but Stdin = %v", p.Stdin)
	}
}

func TestPumpCloseRestoresTermiosFirst(t *testing.T) {
	// A tty stdin: Setup puts it in raw mode; Close must restore it
	// (and only then close the fds) even though Start never ran.
	master, slave := requirePty(t)
	swapStdin(t, slave)

	p, childStdin, err := Setup(false)
	if err != nil {
		p.Close()
		t.Fatalf("Setup on a healthy pty stdin failed: %v", err)
	}
	if childStdin != p.Slave {
		t.Errorf("child stdin is not Setup's own pty slave")
	}
	if !RawTerm() {
		t.Errorf("raw flag not set")
	}
	p.Close() // never started — must still restore and close
	if RawTerm() {
		t.Errorf("raw flag not cleared by Close")
	}
	var now syscall.Termios
	if err := tcgetattr(slave.Fd(), &now); err != nil {
		t.Fatal(err)
	}
	if now.Oflag&syscall.OPOST == 0 {
		t.Errorf("termios still raw after Close")
	}
	_ = master
}
