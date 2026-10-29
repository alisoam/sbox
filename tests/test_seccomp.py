#!/usr/bin/env python3
"""Seccomp tests for sbox.py.

The syscall tables are hand-typed, and a wrong number fails *silently*:
the filter loads fine and denies the wrong syscall (or nothing at all).
These tests pin the table down in three layers, mirroring the proxy
self-test philosophy:

  1. test_syscall_table_matches_reference — every table entry vs
     authoritative references: kernel headers (unistd_64.h /
     asm-generic/unistd.h), `scmp_sys_resolver -a ARCH NAME`, `ausyscall`.
  2. test_filter_runtime_probe — install the real generated cBPF filter in
     a forked child (PR_SET_NO_NEW_PRIVS + PR_SET_SECCOMP — no bwrap, no
     root needed) and probe the deny-list end to end on the native arch.
     (In production bwrap installs the same bytes via --add-seccomp-fd /
     --seccomp right before exec'ing the payload — the runtime self-probe
     the old in-sandbox helper used to do lives on here instead.)
  3. test_sandbox_end_to_end_probe — the whole sbox.py pipeline, exactly
     like:
       sbox.py -- python3 -c "... l.syscall(<unshare_nr>, 0) ..."  # -1 1
     plus a Seccomp:2 check over every process inside the sandbox.

Run without any dependencies:   python3 tests/test_seccomp.py
or under pytest, if installed:  pytest tests/

Tests SKIP (never fail) when a reference source or a capability (bwrap,
user namespaces, seccomp) is unavailable on this machine.
"""
import ctypes
import errno as _errno
import json
import os
import platform
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import sbox  # noqa: E402

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

EPERM = _errno.EPERM
ENOSYS = _errno.ENOSYS


def _kernel_version():
    m = re.match(r"(\d+)\.(\d+)", os.uname().release)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


# ---------------------------------------------------------------- layer 1 ---

# Kernel uapi headers shipped by linux-libc-dev; the sources of truth for
# syscall numbers. x86_64 has its own table; aarch64/riscv64 use asm-generic.
HEADER_CANDIDATES = {
    "x86_64": (
        "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
        "/usr/include/asm/unistd_64.h",
    ),
    "aarch64": ("/usr/include/asm-generic/unistd.h",),
    "riscv64": ("/usr/include/asm-generic/unistd.h",),
}


def _header_numbers(arch):
    for path in HEADER_CANDIDATES.get(arch, ()):
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        return {m.group(1): int(m.group(2))
                for m in re.finditer(r"^#define\s+__NR_([a-z0-9_]+)\s+(\d+)",
                                     text, re.MULTILINE)}, f"kernel header {path}"
    return None, None


def _scmp_sys_resolver(arch, name):
    tool = shutil.which("scmp_sys_resolver")
    if not tool:
        return None, None
    r = subprocess.run([tool, "-a", arch, name], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip().isdigit():
        return int(r.stdout.strip()), "scmp_sys_resolver"
    return None, None


def _ausyscall(arch, name):
    tool = shutil.which("ausyscall")
    if not tool:
        return None, None
    r = subprocess.run([tool, arch, name], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip().isdigit():
        return int(r.stdout.strip()), "ausyscall"
    return None, None


def _reference_number(arch, name):
    """(number, source) from the first reference that knows `name`, or None."""
    for source in (_header_numbers, lambda a, n: _scmp_sys_resolver(a, n),
                   lambda a, n: _ausyscall(a, n)):
        if source is _header_numbers:
            table, desc = _header_numbers(arch)
            if table is None:
                continue
            if name in table:
                return table[name], desc
        else:
            number, desc = source(arch, name)
            if number is not None:
                return number, desc
    return None, None


def test_syscall_table_matches_reference():
    for arch in sorted(sbox.SECCOMP_SYSCALLS):
        resolved, missing = 0, []
        for name, have in sorted(sbox.SECCOMP_SYSCALLS[arch].items()):
            ref = _reference_number(arch, name)
            if ref is None:
                missing.append(name)
                continue
            resolved += 1
            number, source = ref
            assert have == number, (
                f"{arch}/{name}: sbox says {have}, {source} says {number}")
        if not resolved:
            raise unittest.SkipTest(
                f"{arch}: no reference available (install kernel headers, "
                f"libseccomp's scmp_sys_resolver or auditd's ausyscall)")
        if missing:
            print(f"  note: {arch}: no reference for: {', '.join(missing)}")


# ---------------------------------------------------------------- layer 2 ---


def _install_filter(bpf):
    """Install a raw cBPF program via prctl in the calling process."""
    class SockFilter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]

    libc = ctypes.CDLL(None, use_errno=True)
    prog = SockFprog(len(bpf) // 8, (SockFilter * (len(bpf) // 8)).from_buffer_copy(bpf))
    libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        return ctypes.get_errno()
    return 0


def test_filter_runtime_probe():
    """Install the real filter in a forked child and probe what it denies.

    Probes are harmless no-ops with distinguishable unfiltered errors;
    every expectation encodes a number that was once wrong here.
    """
    bpf = sbox.build_seccomp_bpf()
    if bpf is None:
        raise unittest.SkipTest(f"no seccomp table for {platform.machine()}")
    nr = sbox.SECCOMP_SYSCALLS[sbox.seccomp_machine()]
    kver = _kernel_version()

    rfd, wfd = os.pipe()  # rfd: non-tty fd for the TIOCSTI probe
    cr, cw = os.pipe()    # results channel
    pid = os.fork()
    if pid == 0:
        os.close(cr)
        try:
            install_errno = _install_filter(bpf)
            if install_errno:
                os.write(cw, json.dumps({"install_error": install_errno}).encode())
                os._exit(0)
            libc = ctypes.CDLL(None, use_errno=True)
            libc.syscall.restype = ctypes.c_long

            def probe(label, n, *args, expect_errno):
                ctypes.set_errno(0)
                rc = libc.syscall(n, *args)
                e = ctypes.get_errno()
                return {"label": label, "rc": rc, "errno": e,
                        "ok": rc == -1 and e == expect_errno}

            def probe_fn(label, fn, expect_errno):
                ctypes.set_errno(0)
                rc = fn()
                e = ctypes.get_errno()
                return {"label": label, "rc": rc, "errno": e,
                        "ok": rc == -1 and e == expect_errno}

            # Ground truth via the C library's name->number wrappers: this
            # catches a table entry that filters the WRONG syscall (the
            # raw-number probes below cannot — they test our own number).
            results = [
                # unshare(0) succeeds (rc==0) when the table has the wrong
                # number — exactly the regression that shipped here.
                probe_fn("unshare(0) denied EPERM (libc wrapper)",
                         lambda: libc.unshare(0), EPERM),
                # Non-tty fd: unfiltered this is ENOTTY, filtered EPERM.
                probe_fn("ioctl(TIOCSTI) denied EPERM (libc wrapper)",
                         lambda: libc.ioctl(rfd, sbox.TIOCSTI,
                                            ctypes.c_char_p(b"x")), EPERM),
            ]
            # Filter<->table consistency for syscalls without libc wrappers:
            results.append(probe("bpf(0,...) denied EPERM", nr["bpf"], 0,
                                 None, 0, expect_errno=EPERM))
            # ptrace(PTRACE_ATTACH, pid=0): unfiltered ESRCH, filtered EPERM
            # (glibc wrapper => name->number ground truth for the new entry).
            results.append(probe_fn("ptrace(ATTACH,0) denied EPERM",
                                    lambda: libc.ptrace(16, 0, 0, 0),
                                    EPERM))
            results.append(probe("process_vm_readv(0,...) denied EPERM",
                                 nr["process_vm_readv"], 0, None, 0,
                                 None, 0, 0, expect_errno=EPERM))
            # The kernel takes ioctl's cmd as an unsigned int — upper 32
            # bits of the register are ignored — so a request with junk in
            # the high word is still TIOCSTI to the kernel. The filter must
            # compare the low word only (a high-word==0 check was a bypass:
            # 0x1_0000_5412 fell through to ALLOW and executed as TIOCSTI).
            results.append(probe("ioctl(0x1_0000_5412) denied EPERM",
                                 nr["ioctl"], rfd,
                                 ctypes.c_ulong(0x100000000 | sbox.TIOCSTI),
                                 0, expect_errno=EPERM))
            # socket() family gate: AF_VSOCK (netns bypass in VM guests)
            # and AF_PACKET must be refused; AF_UNIX/AF_INET still work.
            # glibc socket() wrapper = name->number ground truth.
            results.append(probe_fn("socket(AF_VSOCK) denied EPERM",
                                    lambda: libc.socket(40, 1, 0), EPERM))
            results.append(probe_fn("socket(AF_PACKET) denied EPERM",
                                    lambda: libc.socket(17, 1, 0), EPERM))
            vsock_fd = libc.socket(2, 1, 0)  # AF_INET must still work
            results.append({"label": "control socket(AF_INET) allowed",
                            "rc": vsock_fd, "errno": ctypes.get_errno(),
                            "ok": vsock_fd >= 0})
            if vsock_fd >= 0:
                os.close(vsock_fd)
            # personality(0) is PER_LINUX, a harmless no-op that returns 0
            # unfiltered — EPERM here proves the new deny entry fires
            # (glibc wrapper => ground truth for the number).
            results.append(probe_fn("personality(0) denied EPERM",
                                    lambda: libc.personality(0), EPERM))
            # Newer deny entries (each once shipped wrong somewhere):
            # vmsplice(pipe_w, NULL, 0, 0) is rc==0 unfiltered (zero
            # segments) — EPERM under the filter (glibc wrapper => ground
            # truth for the number).
            if hasattr(libc, "vmsplice"):
                results.append(probe_fn("vmsplice(0 segs) denied EPERM",
                                        lambda: libc.vmsplice(wfd, None, 0, 0),
                                        EPERM))
            # filter<->table consistency for the remaining new names
            # (ground truth for their NUMBERS comes from layer 1; these
            # raw-number probes catch a mismatch between table and BPF).
            for name in ("syslog", "name_to_handle_at", "quotactl",
                         "fanotify_init", "vmsplice", "fspick"):
                results.append(probe(f"{name}(0,...) denied EPERM", nr[name],
                                     0, 0, 0, 0, expect_errno=EPERM))
            if kver >= (5, 3):
                # Unfiltered clone3(NULL, 0) is EINVAL; filtered ENOSYS.
                results.append(probe("clone3(NULL,0) ENOSYS", nr["clone3"],
                                     None, 0, expect_errno=ENOSYS))
            if kver >= (5, 1):
                # Unfiltered io_uring_setup(0, NULL) is EINVAL; filtered ENOSYS.
                results.append(probe("io_uring_setup(0,NULL) ENOSYS",
                                     nr["io_uring_setup"], 0, None,
                                     expect_errno=ENOSYS))
            # Control: an unlisted syscall must keep working (deny-list!).
            ctypes.set_errno(0)
            rc = libc.write(wfd, b"x", 1)  # read end (rfd) is ours: succeeds
            results.append({"label": "control write() allowed",
                            "rc": rc, "errno": ctypes.get_errno(), "ok": rc == 1})
            os.write(cw, json.dumps(results).encode())
        except BaseException as e:  # child must always report
            os.write(cw, json.dumps([{"label": "child crashed", "ok": False,
                                      "detail": repr(e)}]).encode())
        finally:
            os._exit(0)
    os.close(rfd), os.close(cw)
    os.waitpid(pid, 0)
    os.close(wfd)
    report = json.loads(os.read(cr, 1 << 16))
    os.close(cr)

    if isinstance(report, dict) and "install_error" in report:
        raise unittest.SkipTest(
            f"cannot load seccomp filters here (prctl errno {report['install_error']})")
    failures = [r for r in report if not r["ok"]]
    assert not failures, "filter misbehaves: " + "; ".join(
        f"{r.get('label')} (rc={r.get('rc')}, errno={r.get('errno')}, "
        f"detail={r.get('detail')})" for r in failures)

    # x32 syscalls (same AUDIT_ARCH_X86_64, bit 0x40000000 set in the
    # number) must be KILLED, not silently allowed by the exact-number
    # rules. A killed child cannot report back, so the parent checks for
    # death-by-SIGSYS on the wait status.
    if sbox.seccomp_machine() == "x86_64":
        r2, w2 = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r2)
            try:
                if _install_filter(bpf):
                    os.write(w2, b"install")
                    os._exit(0)
                libc = ctypes.CDLL(None, use_errno=True)
                libc.syscall.restype = ctypes.c_long
                libc.syscall(ctypes.c_long(0x40000000 | nr["ioctl"]), 0, 0, 0)
                os.write(w2, b"survived")  # reached only if not killed
            except BaseException:
                pass
            os._exit(0)
        os.close(w2)
        _, status = os.waitpid(pid, 0)
        msg = os.read(r2, 64)
        os.close(r2)
        if msg == b"install":
            raise unittest.SkipTest("cannot load seccomp filters here")
        assert msg == b"" and os.WIFSIGNALED(status) and \
            os.WTERMSIG(status) == signal.SIGSYS, (
                f"x32 syscall (nr|0x40000000) not killed: msg={msg!r}, "
                f"exit status={status:#x}")


# ---------------------------------------------------------------- layer 3 ---


def test_tables_structurally_consistent():
    archs = sorted(sbox.SECCOMP_SYSCALLS)
    assert "x86_64" in archs and "aarch64" in archs
    # riscv64 shares the asm-generic table (same object, not a copy that can
    # drift).
    assert sbox.SECCOMP_SYSCALLS["riscv64"] is sbox.SECCOMP_SYSCALLS["aarch64"]
    keysets = {tuple(sorted(sbox.SECCOMP_SYSCALLS[a])) for a in archs}
    assert len(keysets) == 1, f"arch tables disagree on entries: {keysets}"
    names = set(keysets.pop())
    # Every name the BPF builder references must exist in every table...
    for req in sbox.SECCOMP_FAKE_MISSING + sbox.SECCOMP_EPERM + (
            "clone", "ioctl", "socket"):
        assert req in names, f"{req!r} missing from SECCOMP_SYSCALLS"
    # ...and the BPF must actually build for every supported arch.
    for arch in archs:
        bpf = sbox.build_seccomp_bpf(machine=arch)
        assert bpf and len(bpf) % 8 == 0, f"{arch}: bad BPF program"
        insns = [struct.unpack("<HBBI", bpf[i:i + 8])
                 for i in range(0, len(bpf), 8)]
        # The x32 kill rule (x86_64 only): JSET nr,0x40000000 -> RET KILL.
        x32 = [i for i, (c, _jt, _jf, k) in enumerate(insns)
               if c == sbox._BPF_JSET_K and k == 0x40000000]
        if arch == "x86_64":
            assert x32, "x86_64: missing x32 kill rule (JSET 0x40000000)"
            target = insns[x32[0] + 1 + insns[x32[0]][1]]
            assert (target[0] == sbox._BPF_RET_K
                    and target[3] == sbox._SECCOMP_RET_KILL_PROCESS), (
                f"x32 rule must jump to RET KILL_PROCESS, got {target}")
        else:
            assert not x32, f"{arch}: unexpected x32 kill rule"
        # The socket-family gate must exist: JEQ socket_nr followed by a
        # load of args[0] and one allow-jump per family in SOCKET_FAMILIES.
        nr = sbox.SECCOMP_SYSCALLS[arch]
        gate = [i for i, (c, _jt, _jf, k) in enumerate(insns)
                if c == sbox._BPF_JEQ_K and k == nr["socket"]]
        assert gate, f"{arch}: missing socket() rule"
        i = gate[0]
        assert insns[i + 1] == (sbox._BPF_LD_W_ABS, 0, 0, 16), (
            f"{arch}: socket rule must load args[0] (domain) next")
        fams = [insns[j][3] for j in range(i + 2, i + 2 + len(sbox.SOCKET_FAMILIES))]
        assert sorted(fams) == sorted(sbox.SOCKET_FAMILIES), (
            f"{arch}: socket families {fams} != {sbox.SOCKET_FAMILIES}")


def test_bwrap_inner_runs_command_under_filter():
    """Regression guard for the bridge bypass: the inner script must end in
    a plain exec and never interpolate anything seccomp-related — bwrap
    installs the filter BEFORE exec'ing /bin/sh (assembled in run_sandbox),
    so the filter covers the shell, the socat bridge and the command (the
    command becomes the bridge's parent, and Yama scope 1 allows
    ptrace//proc/<pid>/mem against your own descendants, so nothing
    unfiltered may remain below it). Runs from a scratch cwd so the
    automatic cwd mount does not depend on where the runner started."""
    import argparse
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        oldcwd = os.getcwd()
        os.chdir(tmp)
        try:
            opts = argparse.Namespace(net=False, home=False, gui=False, ssh_agent=False,
                                      ro_cwd=False, bind=[], ro_bind=[])
            for net in (False, True):
                opts.net = net
                bw, inner, _dups = sbox.build_bwrap(
                    opts, "/tmp/sbox-test-sand", "/tmp/sbox-test-sock",
                    os.environ["HOME"], [], None, None)
                assert inner.endswith('exec "$@"\n'), f"net={net}: inner must end in a plain exec"
                assert "sbox-seccomp" not in inner and "seccomp" not in inner, (
                    f"net={net}: something seccomp-related interpolated into the "
                    "shell script — the filter must be handed to bwrap itself "
                    "(--add-seccomp-fd), not installed from inside the sandbox")
        finally:
            os.chdir(oldcwd)


def _sandbox_python3():
    """A python3 that exists inside the sandbox: the RESOLVED interpreter
    (only /usr, /bin, ... are mounted there — $HOME/.pyenv/bin/python or
    an activated venv's ~/venv/bin/python is a tmpfs path inside, even
    when it symlinks to /usr/bin/python3.x). Only needed by the END-TO-END
    probe below (production no longer needs python3 in the sandbox at
    all — bwrap installs the filter itself)."""
    for cand in (sys.executable, "/usr/bin/python3", "/bin/python3", "/usr/bin/python"):
        if not cand:
            continue
        try:
            real = os.path.realpath(cand)
        except OSError:
            continue
        if os.path.isfile(real) and real.startswith(("/usr/", "/bin/")):
            return real
    return None


def test_sandbox_end_to_end_probe():
    """The user-facing probe: through a real sbox sandbox, unshare(0) must
    print '-1 1' (rc -1, errno EPERM), and EVERY process inside the sandbox
    must report Seccomp: 2 in /proc — including the socat bridge (the
    unfiltered-bridge ptrace bypass is exactly what this catches). The
    run also carries a pinned -b bind and a --bind-socket socket: the
    payload must see NO fd whose target is a bound source (bwrap closes
    --bind-fd fds after mounting — a leftover O_PATH fd is the runc
    CVE-2024-21626 escape), and the socket must arrive mounted, proving
    bwrap accepts a non-directory O_PATH fd for --ro-bind-fd on this
    machine."""
    if not shutil.which("bwrap") or not shutil.which("socat"):
        raise unittest.SkipTest("bwrap/socat not installed")
    machine = sbox.seccomp_machine()
    if machine not in sbox.SECCOMP_SYSCALLS:
        raise unittest.SkipTest(f"no seccomp table for {machine}")
    py = _sandbox_python3()
    if py is None:
        raise unittest.SkipTest("no python3 available inside the sandbox")
    unshare_nr = sbox.SECCOMP_SYSCALLS[machine]["unshare"]
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        # the -b dir must be socket-free (the scan would refuse it — that
        # is the feature); the socket lives in its own dir and travels
        # through --bind-socket's read-only pin
        bindsrc = os.path.realpath(os.path.join(tmp, "binddir"))
        os.makedirs(bindsrc)
        sockpath = os.path.join(tmp, "sockdir", "probe.sock")
        os.makedirs(os.path.dirname(sockpath))
        keeper = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # keep it alive
        keeper.bind(sockpath)
        code = (
            "import ctypes,os,stat,sys\n"
            "l=ctypes.CDLL(None,use_errno=True)\n"
            "l.syscall.restype=ctypes.c_long\n"
            f"r=l.syscall({unshare_nr},0)\n"
            "unf=[]\n"
            "leak=[]\n"
            "for p in os.listdir('/proc'):\n"
            "    if not p.isdigit(): continue\n"
            "    try: st=open(f'/proc/{p}/status').read()\n"
            "    except OSError: continue\n"
            "    try: sc=[x for x in st.splitlines() if x.startswith('Seccomp:')][0].split()[1]\n"
            "    except IndexError: continue\n"
            "    if sc!='2': unf.append(p)\n"
            "for f in os.listdir('/proc/self/fd'):\n"
            "    try: t=os.readlink(f'/proc/self/fd/{f}')\n"
            "    except OSError: continue\n"
            f"    if t in ({bindsrc!r},{sockpath!r}): leak.append((f,t))\n"
            f"sock_ok=os.path.exists({sockpath!r}) and stat.S_ISSOCK(os.stat({sockpath!r}).st_mode)\n"
            f"dir_ok=os.path.isdir({bindsrc!r})\n"
            "print(r, ctypes.get_errno(), unf, leak, sock_ok, dir_ok)\n"
            "sys.exit(0 if (r==-1 and ctypes.get_errno()==1 and not unf and "
            "not leak and sock_ok and dir_ok) else 1)\n"
        )
        try:
            r = subprocess.run(
                [sys.executable, os.path.join(HERE, "..", "sbox.py"),
                 "-b", bindsrc, "--bind-socket", sockpath,
                 "--", py, "-c", code],
                capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            raise AssertionError("sbox.py run timed out")
        finally:
            keeper.close()
        if "No permissions to create a new namespace" in r.stderr:
            raise unittest.SkipTest("this container forbids user namespaces "
                                    "(bwrap unusable) — run on a real host")
        assert r.returncode == 0, f"sandboxed probe failed:\n{r.stdout}\n{r.stderr}"
        out = r.stdout.strip().splitlines()[-1]
        assert out.startswith("-1 1") and out.endswith("[] [] True True"), (
            f"unexpected probe output (want '-1 1 [] [] True True'): {r.stdout!r}")


def test_seccomp_fd_args_and_fail_closed():
    """The fail-closed handoff: seccomp_fd_args self-probes the compiled
    filter (fork + prctl install + libc unshare(0) must be EPERM — see
    test_seccomp_selfprobe in test_sandbox.py), writes the exact bytes of
    build_seccomp_bpf() into the pipe and names the bwrap option; a bwrap
    without seccomp support (or an unsupported machine) is a hard exit,
    never a warning-and-run-unfiltered."""
    if sbox.build_seccomp_bpf() is None:
        raise unittest.SkipTest(f"no seccomp table for {platform.machine()}")
    try:
        opt, r = sbox.seccomp_fd_args({"seccomp": "--add-seccomp-fd"}, verbose=False)
    except SystemExit:
        raise unittest.SkipTest(
            "cannot install seccomp filters here (the launch-time self-probe "
            "would fail too — sbox.py refuses to run on this machine)")
    assert opt == "--add-seccomp-fd"
    try:
        data = b""
        while True:
            chunk = os.read(r, 65536)
            if not chunk:
                break
            data += chunk
        assert data == sbox.build_seccomp_bpf(), "fd must carry the raw cBPF"
        assert len(data) % 8 == 0  # bwrap rejects anything else
    finally:
        os.close(r)
    opt, r = sbox.seccomp_fd_args({"seccomp": "--seccomp"}, verbose=False)
    assert opt == "--seccomp"
    os.close(r)
    # no seccomp capability at all -> die (fail-closed), not warn
    try:
        sbox.seccomp_fd_args({"seccomp": None}, verbose=False)
    except SystemExit:
        pass
    else:
        raise AssertionError("bwrap without seccomp support must be fatal")
    try:
        sbox.seccomp_fd_args({}, verbose=False)
    except SystemExit:
        pass
    else:
        raise AssertionError("unknown bwrap capabilities must be fatal")


def test_require_seccomp_flag_removed():
    """The old --require-seccomp fail-open patch is gone: fail-closed is
    now the only behavior, so the flag no longer exists (unknown options
    make argparse exit 2 — loud, never silent)."""
    r = subprocess.run(
        [sys.executable, os.path.join(HERE, "..", "sbox.py"),
         "--require-seccomp", "--", "/bin/true"],
        capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "require-seccomp" in r.stderr, (
        f"rc={r.returncode}, stderr={r.stderr!r}")


# ------------------------------------------------------- bpf interpreter ---

def _run_bpf(bpf, audit_arch, nr, args=()):
    """Tiny cBPF interpreter for the four opcodes build_seccomp_bpf emits
    (LD_W_ABS, JEQ_K, JSET_K, RET_K). Header cross-checks validate the
    syscall numbers; only this validates the control flow — stale-register
    fall-throughs, wrong jump targets, forgotten rule blocks."""
    data = (struct.pack("<II", nr & 0xFFFFFFFF, audit_arch)
            + struct.pack("<Q", 0)  # instruction_pointer
            + b"".join(struct.pack("<Q", a & 0xFFFFFFFFFFFFFFFF) for a in args))
    prog = [struct.unpack("<HBBI", bpf[i:i + 8])
            for i in range(0, len(bpf), 8)]
    pc, A = 0, 0
    for _ in range(4096):  # any real run terminates in a few steps
        assert 0 <= pc < len(prog), "interpreter: pc out of range"
        code, jt, jf, k = prog[pc]
        if code == sbox._BPF_LD_W_ABS:
            A = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif code == sbox._BPF_JEQ_K:
            pc += (jt if A == k else jf) + 1
        elif code == sbox._BPF_JSET_K:
            pc += (jt if A & k else jf) + 1
        elif code == sbox._BPF_RET_K:
            return k
        else:
            raise AssertionError(f"interpreter: unhandled opcode {code:#x}")
    raise AssertionError("interpreter: program did not terminate")


_ALLOW = sbox._SECCOMP_RET_ALLOW
_EPERM = sbox._SECCOMP_RET_ERRNO | _errno.EPERM
_ENOSYS = sbox._SECCOMP_RET_ERRNO | _errno.ENOSYS
_KILL = sbox._SECCOMP_RET_KILL_PROCESS


def test_bpf_interpreter_golden_cases():
    for arch in ("x86_64", "aarch64"):
        bpf = sbox.build_seccomp_bpf(machine=arch)
        nr = sbox.SECCOMP_SYSCALLS[arch]
        aa = sbox.SECCOMP_AUDIT_ARCH[arch]
        cases = [
            ("ioctl", [3, 0x5412], _EPERM),               # TIOCSTI
            ("ioctl", [3, 0x541C], _EPERM),               # TIOCLINUX
            ("ioctl", [3, 0x100000000 | 0x5412], _EPERM),  # high word ignored
            # The regression that shipped in the socket-gate revision: the
            # ioctl block used to fall through with the cmd still in A, so
            # an ioctl whose cmd equals the socket() syscall number entered
            # the family gate and got EPERM for any fd.
            ("ioctl", [3, nr["socket"]], _ALLOW),
            ("ioctl", [3, 0], _ALLOW),                    # ordinary ioctl
            ("clone", [0x10000000], _EPERM),              # CLONE_NEWUSER
            ("clone", [0x00010000], _ALLOW),              # CLONE_THREAD
            ("clone", [0], _ALLOW),                       # plain fork
            ("clone", [0x10000000 | 0x10000], _EPERM),    # NEWUSER | THREAD
            ("socket", [40], _EPERM),                     # AF_VSOCK
            ("socket", [17], _EPERM),                     # AF_PACKET
            ("socket", [1], _ALLOW),                      # AF_UNIX
            ("socket", [2], _ALLOW),                      # AF_INET
            ("socket", [10], _ALLOW),                     # AF_INET6
            ("socket", [16], _ALLOW),                     # AF_NETLINK
            ("clone3", [], _ENOSYS),
            ("io_uring_setup", [0], _ENOSYS),
            ("unshare", [0], _EPERM),
            ("bpf", [0], _EPERM),
            ("mount", [0], _EPERM),
            ("personality", [0], _EPERM),
            ("open_tree", [0], _EPERM),
            ("mount_setattr", [0], _EPERM),
            # the newer deny entries (numbers were each mistyped once in
            # draft: vmsplice 316!=278, fanotify_init 290!=262)
            ("syslog", [0], _EPERM),
            ("name_to_handle_at", [0], _EPERM),
            ("quotactl", [0], _EPERM),
            ("fanotify_init", [0], _EPERM),
            ("vmsplice", [0], _EPERM),
            ("fspick", [0], _EPERM),              # the missing new-mount-API entry
        ]
        # An unlisted syscall (read: x86_64=0, generic=63) must stay allowed.
        unlisted = 0 if arch == "x86_64" else 63
        cases.append((unlisted, [0, 0, 0], _ALLOW))
        for name, args, want in cases:
            syscall_nr = nr[name] if isinstance(name, str) else name
            got = _run_bpf(bpf, aa, syscall_nr, args)
            assert got == want, f"{arch} {name!r}{args}: got {got:#010x}, want {want:#010x}"
        # x32 (nr bit 30 set) is killed — x86_64 only, only it has an x32
        # ABI. Foreign-arch calls are killed on every arch.
        if arch == "x86_64":
            assert _run_bpf(bpf, aa, 0x40000000 | unlisted, []) == _KILL
        assert _run_bpf(bpf, aa ^ 1, unlisted, []) == _KILL


# ----------------------------------------------------------------- runner ---


def _main():
    import traceback
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = skipped = 0
    for name, fn in tests:
        try:
            fn()
        except unittest.SkipTest as e:
            skipped += 1
            print(f"SKIP  {name}: {e}")
        except Exception:
            failed += 1
            print(f"FAIL  {name}")
            traceback.print_exc()
        else:
            print(f"PASS  {name}")
    total = len(tests)
    print(f"\n{total} tests: {total - failed - skipped} passed, "
          f"{skipped} skipped, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
