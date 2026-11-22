package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"sbox/internal/bindpolicy"
	"sbox/internal/cliutil"
)

// Check for a listening socket owned by this socat before starting the payload.
// A connect probe would open a spurious connection to the user's service and
// could mistake an unrelated process on an occupied port for our listener.
// await_forward must run inside a subshell (`( await_forward ... ) || exit 1`):
// its read scratch variables (state, uid, timeout, ...) would otherwise
// overwrite same-named shell variables imported from the environment — an
// explicit --env timeout=... would hand the payload a /proc/net field — and
// only the subshell wrapper propagates the failure without polluting the
// bridge shell that later execs the payload.
const awaitForward = `forward_ready() {
    for fd in /proc/"$1"/fd/*; do
        [ -S "$fd" ] || continue
        link=$(readlink "$fd") || continue
        inode=${link#socket:\[}; inode=${inode%\]}
        case "$2" in
            unix) while read -r num refs proto flags type state ino rest; do
                [ "$ino" = "$inode" ] && [ "$flags" = 00010000 ] && return 0
            done < /proc/net/unix ;;
            *) while read -r slot local peer state queues timers retr uid timeout ino rest; do
                [ "$ino" = "$inode" ] && [ "$state" = 0A ] && return 0
            done < "/proc/net/$2" ;;
        esac
    done
    return 1
}
await_forward() {
    i=0
    until forward_ready "$1" "$2"; do
        if ! kill -0 "$1" 2>/dev/null || [ "$i" -ge 50 ]; then
            echo "sbox: could not start $3" >&2
            return 1
        fi
        i=$((i+1))
        sleep 0.05
    done
}
`

// forwardStreamLimit bounds the CONCURRENT STREAMS each forward admits:
// every stream holds an accepted connection plus a dial (and a transient pin
// fd for Unix targets), and the launcher shares one descriptor budget with
// the proxy and the supervisor — an unbounded relay can exhaust it and take
// every other launcher duty down with it. The budget is PER FORWARD, not
// global: a legal chain relays through several rules (client → forward A →
// payload service → forward B → destination), and with one shared pool the
// first hops could occupy every slot while waiting for downstream hops that
// can then never be admitted — a classic admission deadlock. Loop
// validation guarantees no forward's dial can land on any forward's
// listener, so the streams of one forward never depend on one another, and
// a per-forward pool cannot deadlock a chain. The cap counts ACCEPTED
// connections: an idle listener consumes nothing, and a listener at its cap
// holds at most ONE accepted client while it waits for a slot — later
// clients stay in the kernel backlog.
const forwardStreamLimit = 64

// Accept-retry pacing: accept failures short of a closed listener back off
// exponentially from forwardAcceptBackoff up to forwardAcceptMaxBackoff.
const (
	forwardAcceptBackoff    = 25 * time.Millisecond
	forwardAcceptMaxBackoff = time.Second
)

// ForwardReadyPath is the in-sandbox FIFO the bridge writes one byte to once
// its startup — mounts, namespaces and every socat listener — is up. The
// supervisor gates forward serving on that signal (see watchForwardReady).
const ForwardReadyPath = "/run/sbox-ready"

// forwardReadyName is the FIFO's name under the launcher's $WORK.
const forwardReadyName = "forward-ready"

// forwardReadyLine is appended to the bridge AFTER the socat readiness
// checks: a listener startup that failed (occupied port) must never report
// the sandbox ready. The write is MANDATORY: a bridge that cannot signal
// (missing or broken FIFO) exits before exec'ing the payload — the command
// must never run, let alone do work, with inactive forwards. The
// supervisor observes exit-before-ready and fails the run.
const forwardReadyLine = "echo ok >" + ForwardReadyPath + " || exit 1\n"

// forwardReadyWait bounds how long the supervisor waits for the readiness
// byte after spawn (a var so tests can shorten it).
var forwardReadyWait = 10 * time.Second

// forwardReportWait bounds the wait for the reader's FINAL report after
// cancel: closing the descriptor unblocks a parked read at once, so this
// deadline only guards a reader wedged by an internal fault.
const forwardReportWait = 2 * time.Second

// makeForwardReady creates the readiness FIFO before spawn; the bridge's
// write finds it already in place.
func makeForwardReady(work string) error {
	return syscall.Mkfifo(filepath.Join(work, forwardReadyName), 0o600)
}

// watchForwardReady hands the supervisor direct ownership of the FIFO's
// ends, as two SEPARATE descriptors opened before spawn. The read side
// opens O_RDONLY|O_NONBLOCK (the open never blocks); the standing writer
// then opens against that reader and keeps the FIFO open for the bridge's
// write. cancel closes ONLY the writer: a read parked when cancel arrives
// still delivers a byte the bridge already wrote before it sees EOF —
// closing the read end itself could abort that read and fail a launch that
// had actually signaled. False (no byte) means startup never completed or
// the FIFO could not be opened; the caller fails closed.
func watchForwardReady(work string) (ready <-chan bool, cancel func()) {
	ch := make(chan bool, 1)
	path := filepath.Join(work, forwardReadyName)
	r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		ch <- false
		return ch, func() {}
	}
	w, err := os.OpenFile(path, os.O_WRONLY, 0) // the reader exists: opens at once
	if err != nil {
		r.Close()
		ch <- false
		return ch, func() {}
	}
	go func() {
		defer r.Close()
		n, _ := r.Read(make([]byte, 1))
		ch <- n == 1
	}()
	return ch, func() { w.Close() }
}

type forwardGroup struct {
	ctx       context.Context
	cancel    context.CancelFunc
	listeners []net.Listener
	targets   []forwardEndpoint
	streamCap int // per-forward stream cap; 0 means forwardStreamLimit
	wg        sync.WaitGroup
}

func (g *forwardGroup) close() {
	g.cancel()
	for _, l := range g.listeners {
		l.Close()
	}
	g.wg.Wait()
}

type forwardEndpoint struct {
	network string
	address string
}

func tcpEndpoint(ap netip.AddrPort) forwardEndpoint {
	network := "tcp6"
	if ap.Addr().Is4() {
		network = "tcp4"
	}
	return forwardEndpoint{network, ap.String()}
}

type forwardPlan struct {
	listen, target forwardEndpoint // host half of the relay
	mount          Mount
	bridge         string
}

func planForward(work string, index int, f cliutil.Forward, shareNet bool) forwardPlan {
	listen, target := tcpEndpoint(f.Listen), tcpEndpoint(f.Target)
	if shareNet {
		// Both TCP endpoints already live in the host namespace.
		return forwardPlan{listen: listen, target: target}
	}
	name := fmt.Sprintf("forward-%d", index)
	mount := Mount{Src: filepath.Join(work, name), Dst: "/run/" + name}
	var innerListen, innerTarget, table string
	if f.Remote {
		ip := f.Listen.Addr().String()
		table = "tcp"
		if f.Listen.Addr().Is6() {
			ip = "[" + ip + "]"
			table = "tcp6"
		}
		innerListen = fmt.Sprintf("%s-LISTEN:%d,bind=%s,reuseaddr,fork", strings.ToUpper(listen.network), f.Listen.Port(), ip)
		if f.Listen.Addr().Is6() {
			innerListen += ",ipv6only=1"
		}
		innerTarget = "UNIX-CONNECT:" + mount.Dst
		listen = forwardEndpoint{"unix", mount.Src}
	} else {
		// Give socat its own empty directory for the listener socket. The
		// launcher pins the resulting socket before every dial (see dialForward).
		mount.RW = true
		innerListen = "UNIX-LISTEN:" + mount.Dst + "/relay.sock,fork"
		innerTarget = strings.ToUpper(target.network) + ":" + target.address
		target = forwardEndpoint{"unix", filepath.Join(mount.Src, "relay.sock")}
		table = "unix"
	}
	// Only generated paths, parsed IP literals and integers enter the shell.
	// socat normally truncates delayed replies 0.5 s after a TCP half-close.
	// The readiness check runs in a subshell so its scratch variables (state,
	// uid, timeout, ...) can never overwrite --env values; `|| exit 1`
	// propagates a failed startup to the bridge shell (PID 1).
	bridge := fmt.Sprintf("socat -t3600 '%s' '%s' &\n( await_forward $! %s 'forward %s to %s' ) || exit 1\n",
		innerListen, innerTarget, table, f.Listen, f.Target)
	return forwardPlan{listen: listen, target: target, mount: mount, bridge: bridge}
}

// reserveForwards binds EVERY listener and creates the writable relay
// directories before anything serves: a later rule whose port is occupied
// fails here, with earlier listeners still silent. Serving starts only via
// start, after the backend has spawned successfully — a launch that fails
// after the first rule bound must never have forwarded a byte (with --net an
// early rule could already reach a live host service during that window).
func reserveForwards(plans []forwardPlan) (*forwardGroup, error) {
	ctx, cancel := context.WithCancel(context.Background())
	g := &forwardGroup{ctx: ctx, cancel: cancel, streamCap: forwardStreamLimit}
	for _, p := range plans {
		if p.mount.RW {
			if err := os.Mkdir(p.mount.Src, 0o700); err != nil {
				g.close()
				return nil, err
			}
		}
		listener, err := net.Listen(p.listen.network, p.listen.address)
		if err != nil {
			g.close()
			return nil, fmt.Errorf("cannot start forward: %w", err)
		}
		g.listeners = append(g.listeners, listener)
		g.targets = append(g.targets, p.target)
	}
	return g, nil
}

// start begins accepting on every reserved listener. Idempotent, so a
// supervisor that retries cannot double-serve one port.
func (g *forwardGroup) start() {
	for i := range g.listeners {
		listener, target := g.listeners[i], g.targets[i]
		g.wg.Go(func() { g.serve(listener, target) })
	}
}

// streamLimit is this group's per-forward admission cap.
func (g *forwardGroup) streamLimit() int {
	if g.streamCap > 0 {
		return g.streamCap
	}
	return forwardStreamLimit
}

func (g *forwardGroup) serve(listener net.Listener, target forwardEndpoint) {
	// Each forward admits streams against its OWN pool: a global pool let
	// the first hops of a multi-rule chain occupy every slot while their
	// downstream hops waited for admission that could never come.
	sem := make(chan struct{}, g.streamLimit())
	backoff := forwardAcceptBackoff
	for {
		in, err := listener.Accept()
		if err != nil {
			if !g.retryAccept(err, &backoff) {
				return
			}
			continue
		}
		backoff = forwardAcceptBackoff
		// The slot is taken only once a client is ACCEPTED, never before:
		// an idle listener must not eat its forward's pool. While waiting
		// this loop holds exactly one accepted connection; more queue in
		// the kernel backlog behind it.
		select {
		case sem <- struct{}{}:
		case <-g.ctx.Done():
			in.Close()
			return
		}
		g.wg.Go(func() {
			defer func() { <-sem }()
			g.relay(in, target)
		})
	}
}

// retryAccept paces the serve loop through ANY accept failure short of a
// closed listener or group shutdown: descriptor shortages (EMFILE/ENFILE),
// lost buffers (ENOBUFS/ENOMEM), aborted, timed-out or protocol-broken
// pending connections (ECONNABORTED/ETIMEDOUT/EPROTO), firewall denials
// (EPERM) and routing conditions (ENETUNREACH/EHOSTUNREACH) are transient
// under the kernel's contract — the port stays bound and the relay MUST
// resume serving once the condition clears instead of dying silently for
// the rest of the run. Enumeration is deliberately avoided: an error not
// foreseen here is retried too, bounded by the backoff cap; only teardown
// (net.ErrClosed / a canceled group) ends the loop.
func (g *forwardGroup) retryAccept(err error, backoff *time.Duration) bool {
	if g.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	select {
	case <-g.ctx.Done():
	case <-time.After(*backoff):
	}
	*backoff *= 2
	if *backoff > forwardAcceptMaxBackoff {
		*backoff = forwardAcceptMaxBackoff
	}
	return true
}

func (g *forwardGroup) relay(in net.Conn, target forwardEndpoint) {
	defer in.Close()
	out, err := dialForward(g.ctx, target.network, target.address)
	if err != nil {
		return
	}
	defer out.Close()
	stop := context.AfterFunc(g.ctx, func() { in.Close(); out.Close() })
	defer stop()
	done := make(chan struct{})
	go func() { forwardStream(out, in); close(done) }()
	forwardStream(in, out)
	<-done
}

func dialForward(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "unix" {
		pin, err := bindpolicy.OpenPathPinned(address)
		if err != nil {
			return nil, err
		}
		defer pin.Close()
		info, err := pin.Stat()
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("forward endpoint is not a socket")
		}
		address = fmt.Sprintf("/proc/self/fd/%d", pin.Fd())
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, network, address)
}

func forwardStream(dst, src net.Conn) {
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		src.Close()
		return
	}
	// Both TCPConn and UnixConn implement CloseWrite.
	dst.(interface{ CloseWrite() error }).CloseWrite()
}
