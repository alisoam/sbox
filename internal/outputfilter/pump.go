// The --filter-output pump: master→sanitizer→stdout, the raw host tty→master
// with backpressure instead of drops, SIGWINCH→TIOCSWINSZ, and the
// bounded post-exit drain. Teardown order is load-bearing: termios
// restore FIRST (the rest can block for seconds and a raw terminal is
// unusable meanwhile), then the winch channel, then the fds.

package outputfilter

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// maxPendingInput caps the backlog of stdin bytes the sandbox is not
// reading: the pty buffer is small, the pump never blocks the OUTPUT
// direction, so the host-side buffer must stay bounded. At the cap the
// pump backpressures (stops reading the tty until the sandbox drains
// some) instead of dropping bytes.
const maxPendingInput = 262144

// Pump drives one --filter-output run. Construct via Setup (which owns
// the pty/raw-mode/child-stdin decisions), wire the returned childStdin
// plus Pump.Slave into the sandbox spawn, then Start after the spawn,
// Stop when the sandbox exits, Close in the teardown. All methods are
// safe on a never-started Pump (an early-exit path between Setup and
// Start still gets the termios restored and the fds closed).
type Pump struct {
	// Master is the host-side pty end feeding the sanitizer. Opened
	// O_NONBLOCK (poller-registered): reads park in the runtime
	// poller, so a read deadline evicts the parked reader — that is
	// how the bounded drain stops.
	Master *os.File
	// Slave is the sandbox's ONLY stdio. The parent closes its copy
	// right after the spawn (else the host holds EOF away from the
	// pump).
	Slave *os.File
	// Sanitizer filters master bytes; nil ⇒ a default Sanitizer.
	Sanitizer *Sanitizer
	// Stdin is the host tty put in raw mode (nil ⇒ nothing forwarded:
	// non-tty stdin is inherited by the sandbox directly, exactly and
	// unfiltered — see FilterChildStdin).
	Stdin *os.File
	// TtySource is the winsize source for SIGWINCH forwards (nil ⇒
	// resizes are dropped; the initial copy still happens in Setup
	// when a host tty exists).
	TtySource *os.File
	// Winch optionally supplies the resize signal channel; nil ⇒ the
	// pump arms its own signal.Notify(SIGWINCH) at Start and Stops it
	// at Close, restoring the previous disposition.
	Winch <-chan os.Signal
	// Out receives the filtered output; nil ⇒ EmitFiltered (stdout).

	Out io.Writer

	// raw-mode state owned by Close (restore FIRST).
	rawFD  *os.File
	saved  *syscall.Termios
	setRaw bool

	mu      sync.Mutex
	space   *sync.Cond // forwarder waits here: pending at the cap
	work    *sync.Cond // writer waits here: pending empty
	chunks  [][]byte   // pending stdin bytes, in order
	total   int        // sum of len(chunks) — the cap counter
	stopped bool
	started bool

	ioMu      sync.RWMutex // serializes CopyWinsize against the fd teardown
	quit      chan struct{}
	done      chan struct{} // closed when the master reader exits
	draining  atomic.Bool   // Stop() entered: reader flushes on exit
	stdinDup  *os.File      // dup of Stdin the forwarder reads
	selfWinch chan os.Signal
	closeOnce sync.Once
}

// Setup is the --filter-output block of run_sandbox just before the
// spawn: allocate the pty (fail closed — without a pty there is no
// host-side filtering, so refuse to run rather than pass output
// through raw), build the sanitizer (--strict-crlf is a --filter-output
// mode), copy the initial winsize, put a usable host stdin tty in raw
// mode, and decide what the sandbox gets as stdin. The returned Pump
// owns the master/slave pair and the raw-mode restore (Close); even on
// error a non-nil Pump comes back for exactly that cleanup.
func Setup(strictCr bool) (p *Pump, childStdin *os.File, err error) {
	master, slave, err := OpenPty()
	if err != nil {
		return nil, nil, fmt.Errorf(
			"--filter-output: cannot allocate a pty (%v) — refusing to run unfiltered", err)
	}
	p = &Pump{Master: master, Slave: slave, Sanitizer: NewSanitizer(strictCr)}
	p.TtySource = HostTTY()
	if p.TtySource != nil {
		CopyWinsize(p.TtySource, master) // initial size for the pair
	}
	// Forward ONLY a real (raw-mode) tty through the pty — the pump
	// reads exactly that fd. Every other stdin shape is resolved by
	// FilterChildStdin: the exact non-tty fd stdin wraps (byte-exact
	// inherit — routing it through the pty would feed it to the
	// slave's CANONICAL line discipline: 4095-byte line truncation,
	// ^D/^U/^W/^V/^R editing, ICRNL, ISIG), and a LOUD REFUSAL for a
	// tty raw mode could not tame (never hand the host terminal fd
	// over unfiltered).
	p.rawFD, p.saved = EnterRawMode()
	p.Stdin = p.rawFD
	childStdin, err = FilterChildStdin(slave, p.rawFD)
	if err != nil {
		return p, nil, err
	}
	return p, childStdin, nil
}

// Start spawns the pump goroutines. Call once, right after the spawn
// (SIGWINCH is armed only once the sandbox exists).
func (p *Pump) Start() {
	if p.started {
		return
	}
	p.started = true
	p.space = sync.NewCond(&p.mu)
	p.work = sync.NewCond(&p.mu)
	p.done = make(chan struct{})
	p.quit = make(chan struct{})
	if p.Sanitizer == nil {
		p.Sanitizer = NewSanitizer(false)
	}

	// master → sanitizer → stdout. EOF (EIO: every slave fd closed)
	// ends the reader; the drain-tail flush runs HERE — on the reader
	// goroutine — so it can never interleave with an in-flight Feed.
	go func() {
		defer close(p.done)
		buf := make([]byte, 65536)
		for {
			n, err := p.Master.Read(buf)
			if n > 0 {
				p.emit(p.Sanitizer.Feed(buf[:n]))
			}
			if err != nil {
				if p.draining.Load() {
					p.emit(p.Sanitizer.Flush())
				}
				return
			}
		}
	}()

	if p.Stdin != nil {
		// Read the host tty through a dup: fd 0 itself must stay
		// untouched (flags AND lifetime belong to the invoking shell).
		n, _, e := syscall.Syscall(syscall.SYS_DUP, p.Stdin.Fd(), 0, 0)
		if e == 0 {
			p.stdinDup = os.NewFile(n, "sbox-stdin")
			go p.forward()
			go p.drainPending()
		}
		// A failed dup leaves no forwarding — the sandbox simply sees
		// no keystrokes; nothing unfiltered can leak either way.

	}

	winch := p.Winch
	if winch == nil {
		p.selfWinch = make(chan os.Signal, 1)
		signal.Notify(p.selfWinch, syscall.SIGWINCH)
		winch = p.selfWinch
	}
	go func() {
		for {
			select {
			case <-p.quit:
				return
			case _, ok := <-winch:
				if !ok {
					return
				}
				p.ioMu.RLock() // never race the teardown's closes
				if p.TtySource != nil && p.Master != nil {
					CopyWinsize(p.TtySource, p.Master)
				}
				p.ioMu.RUnlock()
			}
		}
	}()
}

// Stop ends the run phase and drains the master: after the sandbox
// exited, final output may still be
// in flight (--die-with-parent runs the payload a beat later), but a
// daemonized child can hold the slave open forever — so the drain is
// bounded. The deadline evicts the parked master read (poller
// deadline); the reader then flushes the sanitizer on its way out.
// If EOF already happened during the run, the drain and its flush
// are skipped; an incomplete tail is dropped.
func (p *Pump) Stop(drain time.Duration) {
	if !p.started {
		return
	}
	p.setStopped()
	p.draining.Store(true)
	timer := time.AfterFunc(drain, func() {
		_ = p.Master.SetReadDeadline(time.Unix(0, 1)) // evict the parked read
	})
	<-p.done
	timer.Stop()
}

// Close tears down --filter-output: restore the host terminal FIRST, clear the raw
// diagnostic flag, release SIGWINCH, wake and drop the pending stdin
// backlog, then close the fds (closing the master evicts the parked
// reader/writer through the runtime poller). Idempotent.
func (p *Pump) Close() {
	p.closeOnce.Do(func() {
		// Restore the host terminal FIRST: the rest of the teardown can
		// block for seconds and a raw terminal is unusable meanwhile.
		RestoreTermios(p.rawFD, p.saved)
		SetRawTerm(false)
		if p.selfWinch != nil {
			signal.Stop(p.selfWinch)
		}
		p.setStopped()
		p.ioMu.Lock() // the winch forwarder's ioctls end before a close
		defer p.ioMu.Unlock()
		if p.quit != nil {
			close(p.quit) // wake the winch forwarder (nil ⇒ never started)
		}
		if p.stdinDup != nil {
			_ = p.stdinDup.Close()
		}
		if p.Slave != nil {
			_ = p.Slave.Close()
		}
		if p.Master != nil {
			_ = p.Master.Close() // evicts the parked reader/writer
		}
	})
}

func (p *Pump) emit(text string) {
	if text == "" {
		return
	}
	if p.Out != nil {
		_, _ = io.WriteString(p.Out, text) // closed output: keep supervising
		return
	}
	EmitFiltered(text)
}

func (p *Pump) setStopped() {
	p.mu.Lock()
	p.stopped = true
	p.chunks = nil
	p.total = 0
	space, work := p.space, p.work
	p.mu.Unlock()
	if space != nil {
		space.Broadcast()
	}
	if work != nil {
		work.Broadcast()
	}
}

// forward is the stdin side of the pump: read the raw host tty, park
// at the backlog cap (backpressure, not drops — the tty stays
// readable, we just read again once the sandbox drained some), hand
// each chunk to the writer. Stops when stopped.
func (p *Pump) forward() {
	buf := make([]byte, 4096)
	for {
		p.mu.Lock()
		for p.total >= maxPendingInput && !p.stopped {
			p.space.Wait()
		}
		stopped := p.stopped
		p.mu.Unlock()
		if stopped {
			return
		}
		n, err := p.stdinDup.Read(buf)
		if n > 0 {
			// copy: buf is reused, and the writer must own the bytes
			cp := make([]byte, n)
			copy(cp, buf[:n])
			if !p.push(cp) {
				return
			}
		}
		if err != nil {
			// Host tty closed. Only a real tty is forwarded, and a
			// raw-mode tty read does not EOF — this is the
			// dead/detached-terminal corner; just stop forwarding.
			return
		}
	}
}

func (p *Pump) push(chunk []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return false
	}
	p.chunks = append(p.chunks, chunk)
	p.total += len(chunk)
	if p.work != nil {
		p.work.Signal()
	}
	return true
}

// drainPending writes the backlog into the pty master. A full pty
// buffer parks the write in the runtime poller — the backpressure the
// forwarder sees — and a dead master (EIO: every slave fd closed)
// drops the backlog.
func (p *Pump) drainPending() {
	for {
		p.mu.Lock()
		for len(p.chunks) == 0 && !p.stopped {
			p.work.Wait()
		}
		if len(p.chunks) == 0 {
			p.mu.Unlock()
			return // stopped
		}
		head := p.chunks[0]
		p.mu.Unlock()

		n, err := p.Master.Write(head)

		p.mu.Lock()
		// Stop may have discarded the queue while Write was blocked on
		// the slave. Its in-flight bytes need no further bookkeeping.
		if p.stopped {
			p.mu.Unlock()
			return
		}
		if n > 0 {
			p.chunks[0] = head[n:]
			p.total -= n
			if len(p.chunks[0]) == 0 {
				p.chunks = p.chunks[1:]
			}
		}
		if err != nil {
			p.chunks = nil
			p.total = 0
		}
		below := p.total < maxPendingInput
		p.mu.Unlock()
		if below && p.space != nil {
			p.space.Broadcast()
		}
	}
}

// pendingLen is the current stdin backlog (test hook).
func (p *Pump) pendingLen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.total
}
