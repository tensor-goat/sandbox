#!/usr/bin/env python3
"""
Comprehensive test suite for sandbox.py

Run:  python3 test_sandbox.py
      python3 test_sandbox.py -v          # verbose
      python3 test_sandbox.py TestPledge  # run one group

Since SECCOMP filters are irreversible, every enforcement test forks a
child process that applies the filter, runs the check, and exits.  The
parent inspects the exit code to determine pass/fail.

Tests are grouped by subsystem:

  TestCapabilities     — kernel feature detection
  TestBPFBuilder       — BPF program generation (no enforcement)
  TestFluentAPI        — Sandbox builder methods (no enforcement)
  TestProfiles         — built-in profile loading and validation
  TestDescribe         — describe() output formatting
  TestConstructor      — constructor variants and error handling
  TestPledge           — SECCOMP enforcement (forked children)
  TestPledgeArgFilter  — argument-level filtering
  TestPledgeNarrowing  — progressive privilege dropping
  TestPledgePenalty    — kill vs eperm penalties
  TestSandboxRun       — Sandbox.run() method
  TestSandboxEnter     — Sandbox.enter() context manager
  TestEnclave          — fork+pledge enclave pattern
  TestConvenienceAPI   — pledge() and unveil() standalone functions
  TestCLI              — command-line interface via subprocess
"""

import json
import os
import signal
import socket
import struct
import subprocess
import sys
import textwrap
import unittest

# Ensure we import from the local directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sandbox import (
    Sandbox, Profile, PROFILES, Capabilities,
    PROMISE_SYSCALLS, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_ERRNO,
    SECCOMP_RET_ALLOW, AUDIT_ARCH, NR,
    _BPFBuilder, _SF_SZ, _nr, _is_dynamic_elf,
    _perms_to_ll, _LL_READ, _LL_WRITE, _LL_EXEC, _LL_CREATE,
    pledge, unveil,
)

SANDBOX_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "sandbox.py")


# ═══════════════════════════════════════════════════════════════════════
# Helper: run a check in an isolated child process
# ═══════════════════════════════════════════════════════════════════════

def _fork_test(fn, *args, expect_signal=None):
    """Fork a child, run fn(*args), return (exit_code, was_signaled, signum).

    The child calls fn(*args).  If fn returns without raising, the child
    exits 0.  If fn raises OSError (EPERM), exits 1.  Any other exception
    exits 2.

    If expect_signal is set, the caller expects the child to die from
    that signal rather than exiting normally.
    """
    pid = os.fork()
    if pid == 0:
        # Child
        try:
            fn(*args)
            os._exit(0)
        except PermissionError:
            os._exit(1)
        except OSError as e:
            if e.errno == 1:  # EPERM
                os._exit(1)
            os._exit(2)
        except SystemExit as e:
            os._exit(e.code if isinstance(e.code, int) else 2)
        except Exception:
            os._exit(2)
    # Parent
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return (-1, True, os.WTERMSIG(status))
    return (os.WEXITSTATUS(status), False, 0)


def _pledged_check(promises, fn, *args):
    """Fork, pledge, run fn, return exit code."""
    def _inner():
        from sandbox import pledge as _pledge
        _pledge(promises)
        fn(*args)
    return _fork_test(_inner)


# ═══════════════════════════════════════════════════════════════════════
# Test: Capabilities
# ═══════════════════════════════════════════════════════════════════════

class TestCapabilities(unittest.TestCase):
    """Kernel capability detection."""

    def test_has_seccomp_returns_bool(self):
        self.assertIsInstance(Capabilities.has_seccomp(), bool)

    def test_has_landlock_returns_bool(self):
        self.assertIsInstance(Capabilities.has_landlock(), bool)

    def test_has_overlayfs_returns_bool(self):
        self.assertIsInstance(Capabilities.has_overlayfs(), bool)

    def test_has_pid_ns_returns_bool(self):
        self.assertIsInstance(Capabilities.has_pid_ns(), bool)

    def test_is_root_returns_bool(self):
        self.assertIsInstance(Capabilities.is_root(), bool)

    def test_landlock_abi_returns_int(self):
        abi = Capabilities.landlock_abi()
        self.assertIsInstance(abi, int)
        self.assertGreaterEqual(abi, 0)

    def test_summary_is_string(self):
        s = Capabilities.summary()
        self.assertIsInstance(s, str)
        self.assertIn("kernel:", s)
        self.assertIn("seccomp:", s)
        self.assertIn("landlock:", s)

    def test_seccomp_available_on_modern_linux(self):
        # This test suite only makes sense on Linux
        self.assertTrue(Capabilities.has_seccomp(),
                        "seccomp BPF should be available on any modern Linux")


# ═══════════════════════════════════════════════════════════════════════
# Test: BPF Builder
# ═══════════════════════════════════════════════════════════════════════

class TestBPFBuilder(unittest.TestCase):
    """BPF program generation — no enforcement, just bytecode checks."""

    def _build(self, promises: str) -> bytes:
        return _BPFBuilder(set(promises.split())).build()

    def _insn_count(self, prog: bytes) -> int:
        return len(prog) // _SF_SZ

    def test_empty_promises_produces_valid_program(self):
        prog = self._build("")
        # Must have at least: arch check (3 insns) + load nr + deny
        self.assertGreaterEqual(self._insn_count(prog), 5)

    def test_stdio_produces_program(self):
        prog = self._build("stdio")
        n = self._insn_count(prog)
        self.assertGreater(n, 50, "stdio should allow many syscalls")
        self.assertLess(n, 4096, "must fit in BPF limit")

    def test_all_promises_produces_valid_program(self):
        all_p = " ".join(PROMISE_SYSCALLS.keys())
        prog = self._build(all_p)
        n = self._insn_count(prog)
        self.assertGreater(n, 100)
        self.assertLess(n, 4096)

    def test_program_is_multiple_of_8_bytes(self):
        for promises in ["stdio", "stdio rpath", "stdio inet dns"]:
            prog = self._build(promises)
            self.assertEqual(len(prog) % _SF_SZ, 0,
                             f"program for '{promises}' not aligned")

    def test_program_starts_with_arch_check(self):
        prog = self._build("stdio")
        # First instruction loads arch field (offset 4)
        code, jt, jf, k = struct.unpack("=HBBI", prog[:8])
        self.assertEqual(k, 4, "first insn should load arch (offset 4)")

    def test_program_contains_audit_arch(self):
        prog = self._build("stdio")
        # Second instruction compares against AUDIT_ARCH
        _, _, _, k = struct.unpack("=HBBI", prog[8:16])
        self.assertEqual(k, AUDIT_ARCH)

    def test_program_ends_with_deny(self):
        prog = self._build("stdio rpath")
        # Last instruction is RET with the penalty value
        code, jt, jf, k = struct.unpack("=HBBI", prog[-8:])
        # BPF_RET | BPF_K = 0x06
        self.assertEqual(code, 0x06)

    def test_more_promises_more_instructions(self):
        n1 = self._insn_count(self._build("stdio"))
        n2 = self._insn_count(self._build("stdio rpath"))
        n3 = self._insn_count(self._build("stdio rpath inet dns"))
        self.assertLess(n1, n2)
        self.assertLess(n2, n3)

    def test_kill_penalty(self):
        prog = _BPFBuilder({"stdio"}, SECCOMP_RET_KILL_PROCESS).build()
        _, _, _, k = struct.unpack("=HBBI", prog[-8:])
        # Penalty has EPERM (1) OR'd in as the data field
        self.assertEqual(k & 0xFFFF0000, SECCOMP_RET_KILL_PROCESS)

    def test_eperm_penalty(self):
        prog = _BPFBuilder({"stdio"}, SECCOMP_RET_ERRNO).build()
        _, _, _, k = struct.unpack("=HBBI", prog[-8:])
        # Should be SECCOMP_RET_ERRNO | EPERM
        self.assertEqual(k & 0xFFFF0000, SECCOMP_RET_ERRNO)
        self.assertEqual(k & 0xFFFF, 1)  # EPERM = 1


# ═══════════════════════════════════════════════════════════════════════
# Test: Fluent API
# ═══════════════════════════════════════════════════════════════════════

class TestFluentAPI(unittest.TestCase):
    """Sandbox fluent builder — no enforcement, just state checks."""

    def test_allow_adds_promises(self):
        sb = Sandbox().allow("stdio rpath")
        self.assertEqual(sb._promises, {"stdio", "rpath"})

    def test_allow_is_additive(self):
        sb = Sandbox().allow("stdio").allow("rpath").allow("inet")
        self.assertEqual(sb._promises, {"stdio", "rpath", "inet"})

    def test_deny_removes_promises(self):
        sb = Sandbox().allow("stdio rpath inet").deny("inet")
        self.assertEqual(sb._promises, {"stdio", "rpath"})

    def test_deny_nonexistent_is_noop(self):
        sb = Sandbox().allow("stdio").deny("inet")
        self.assertEqual(sb._promises, {"stdio"})

    def test_see_adds_paths(self):
        sb = Sandbox().see("/etc", "r").see("/tmp", "rwc")
        self.assertEqual(len(sb._paths), 2)
        self.assertIn(("/etc", "r"), sb._paths)
        self.assertIn(("/tmp", "rwc"), sb._paths)

    def test_hide_adds_masks(self):
        sb = Sandbox().hide(".ssh", ".gnupg")
        self.assertEqual(sb._ns_cfg["masks"], {".ssh", ".gnupg"})

    def test_private_tmp_sets_flag(self):
        sb = Sandbox().private_tmp()
        self.assertTrue(sb._ns_cfg["private_tmp"])
        self.assertTrue(sb._use_ns)

    def test_overlay_home_sets_flag(self):
        sb = Sandbox().overlay_home()
        self.assertTrue(sb._ns_cfg["overlay_home"])
        self.assertTrue(sb._use_ns)

    def test_empty_home_sets_flag(self):
        sb = Sandbox().empty_home()
        self.assertTrue(sb._ns_cfg["empty_home"])
        self.assertTrue(sb._use_ns)

    def test_readonly_root_sets_flag(self):
        sb = Sandbox().readonly_root()
        self.assertTrue(sb._ns_cfg["readonly_root"])
        self.assertTrue(sb._use_ns)

    def test_grant_dir_accumulates(self):
        sb = Sandbox().grant_dir("/a", "/b").grant_dir("/c")
        self.assertEqual(sb._ns_cfg["grant_dirs"], ["/a", "/b", "/c"])

    def test_kill_on_violation_sets_penalty(self):
        sb = Sandbox().kill_on_violation()
        self.assertEqual(sb._penalty, SECCOMP_RET_KILL_PROCESS)

    def test_chaining_returns_self(self):
        sb = Sandbox()
        result = sb.allow("stdio").see("/etc", "r").private_tmp()
        self.assertIs(result, sb)

    def test_default_no_namespace(self):
        sb = Sandbox().allow("stdio rpath")
        self.assertFalse(sb._use_ns)


# ═══════════════════════════════════════════════════════════════════════
# Test: Profiles
# ═══════════════════════════════════════════════════════════════════════

class TestProfiles(unittest.TestCase):
    """Built-in profile loading and validation."""

    def test_all_profiles_exist(self):
        expected = {"strict", "readonly", "netclient", "worker",
                    "claude", "codex", "untrusted"}
        self.assertEqual(set(PROFILES.keys()), expected)

    def test_from_profile_loads(self):
        for name in PROFILES:
            sb = Sandbox.from_profile(name)
            self.assertIsInstance(sb, Sandbox)
            self.assertTrue(len(sb._promises) > 0,
                            f"profile '{name}' has no promises")

    def test_from_profile_unknown_raises(self):
        with self.assertRaises(ValueError):
            Sandbox.from_profile("nonexistent")

    def test_constructor_profile_kwarg(self):
        sb = Sandbox(profile="strict")
        self.assertEqual(sb._promises, {"stdio"})

    def test_strict_is_minimal(self):
        sb = Sandbox.from_profile("strict")
        self.assertEqual(sb._promises, {"stdio"})
        self.assertEqual(sb._paths, [])

    def test_claude_has_network(self):
        sb = Sandbox.from_profile("claude")
        self.assertIn("inet", sb._promises)
        self.assertIn("dns", sb._promises)

    def test_claude_has_masks(self):
        sb = Sandbox.from_profile("claude")
        self.assertIn(".ssh", sb._ns_cfg["masks"])
        self.assertIn(".gnupg", sb._ns_cfg["masks"])

    def test_untrusted_blocks_network(self):
        sb = Sandbox.from_profile("untrusted")
        self.assertNotIn("inet", sb._promises)
        self.assertNotIn("dns", sb._promises)

    def test_untrusted_has_empty_home(self):
        sb = Sandbox.from_profile("untrusted")
        self.assertTrue(sb._ns_cfg["empty_home"])

    def test_worker_has_tmppath(self):
        sb = Sandbox.from_profile("worker")
        self.assertIn("tmppath", sb._promises)
        self.assertIn(("/tmp", "rwc"), sb._paths)

    def test_profile_allows_additional_promises(self):
        sb = Sandbox.from_profile("strict").allow("rpath")
        self.assertIn("rpath", sb._promises)
        self.assertIn("stdio", sb._promises)

    def test_all_profiles_have_description(self):
        for name, p in PROFILES.items():
            self.assertTrue(len(p.description) > 10,
                            f"profile '{name}' needs a description")

    def test_all_profiles_have_valid_promises(self):
        for name, p in PROFILES.items():
            for promise in p.promises.split():
                self.assertIn(promise, PROMISE_SYSCALLS,
                              f"profile '{name}' has unknown promise '{promise}'")


# ═══════════════════════════════════════════════════════════════════════
# Test: Describe
# ═══════════════════════════════════════════════════════════════════════

class TestDescribe(unittest.TestCase):
    """describe() output formatting."""

    def test_describe_includes_promises(self):
        desc = Sandbox().allow("stdio rpath").describe()
        self.assertIn("promises:", desc)
        self.assertIn("stdio", desc)
        self.assertIn("rpath", desc)

    def test_describe_includes_paths(self):
        desc = Sandbox().see("/etc", "r").see("/tmp", "rwc").describe()
        self.assertIn("/etc", desc)
        self.assertIn("/tmp", desc)
        self.assertIn("rwc", desc)

    def test_describe_includes_penalty(self):
        desc = Sandbox().allow("stdio").describe()
        self.assertIn("penalty:", desc)
        self.assertIn("eperm", desc)

    def test_describe_kill_penalty(self):
        desc = Sandbox().allow("stdio").kill_on_violation().describe()
        self.assertIn("kill", desc)

    def test_describe_namespace_features(self):
        desc = Sandbox().private_tmp().overlay_home().describe()
        self.assertIn("private /tmp", desc)
        self.assertIn("overlay home", desc)

    def test_describe_masks(self):
        desc = Sandbox().hide(".ssh", ".aws").describe()
        self.assertIn(".ssh", desc)
        self.assertIn(".aws", desc)

    def test_describe_profile(self):
        desc = Sandbox.from_profile("claude").describe()
        self.assertIn("inet", desc)
        self.assertIn(".ssh", desc)
        self.assertIn("overlay home", desc)

    def test_describe_empty_sandbox(self):
        desc = Sandbox().describe()
        self.assertIn("penalty:", desc)


# ═══════════════════════════════════════════════════════════════════════
# Test: Constructor
# ═══════════════════════════════════════════════════════════════════════

class TestConstructor(unittest.TestCase):
    """Constructor variants and error handling."""

    def test_empty_constructor(self):
        sb = Sandbox()
        self.assertEqual(sb._promises, set())
        self.assertEqual(sb._paths, [])

    def test_promises_kwarg(self):
        sb = Sandbox(promises="stdio rpath")
        self.assertEqual(sb._promises, {"stdio", "rpath"})

    def test_paths_kwarg(self):
        sb = Sandbox(paths={"/etc": "r", "/tmp": "rwc"})
        self.assertIn(("/etc", "r"), sb._paths)
        self.assertIn(("/tmp", "rwc"), sb._paths)

    def test_penalty_kwarg_kill(self):
        sb = Sandbox(penalty="kill")
        self.assertEqual(sb._penalty, SECCOMP_RET_KILL_PROCESS)

    def test_penalty_kwarg_eperm(self):
        sb = Sandbox(penalty="eperm")
        self.assertEqual(sb._penalty, SECCOMP_RET_ERRNO)

    def test_profile_kwarg(self):
        sb = Sandbox(profile="strict")
        self.assertEqual(sb._promises, {"stdio"})

    def test_unknown_profile_raises(self):
        with self.assertRaises(ValueError):
            Sandbox(profile="does_not_exist")

    def test_run_no_command_raises(self):
        with self.assertRaises(ValueError):
            Sandbox().run([])


# ═══════════════════════════════════════════════════════════════════════
# Test: Promise / Syscall tables
# ═══════════════════════════════════════════════════════════════════════

class TestSyscallTables(unittest.TestCase):
    """Syscall number tables and promise definitions."""

    def test_nr_table_not_empty(self):
        self.assertGreater(len(NR), 100)

    def test_critical_syscalls_present(self):
        for sc in ["read", "write", "close", "exit_group", "mmap",
                    "openat", "socket", "fork", "execve", "clone"]:
            self.assertGreaterEqual(_nr(sc), 0,
                                   f"syscall '{sc}' missing from NR table")

    def test_all_promise_syscalls_resolvable(self):
        """Every syscall name in every promise should be in the NR table
        or be a known alias that doesn't exist as a standalone syscall
        on this architecture (e.g. send/recv on x86_64)."""
        # These are multiplexed through other syscalls on some archs
        arch_absent = {"send", "recv", "getpgrp", "alarm"}
        for promise, syscalls in PROMISE_SYSCALLS.items():
            for sc in syscalls:
                if sc in arch_absent:
                    continue
                self.assertIn(sc, NR,
                              f"'{sc}' in promise '{promise}' not in NR table")

    def test_stdio_includes_basics(self):
        stdio = PROMISE_SYSCALLS["stdio"]
        for sc in ["read", "write", "close", "exit", "exit_group",
                    "brk", "mmap", "futex"]:
            self.assertIn(sc, stdio, f"stdio should include '{sc}'")

    def test_rpath_includes_open(self):
        self.assertIn("openat", PROMISE_SYSCALLS["rpath"])

    def test_inet_includes_socket(self):
        self.assertIn("socket", PROMISE_SYSCALLS["inet"])

    def test_exec_includes_execve(self):
        self.assertIn("execve", PROMISE_SYSCALLS["exec"])


# ═══════════════════════════════════════════════════════════════════════
# Test: Pledge enforcement (SECCOMP)
# ═══════════════════════════════════════════════════════════════════════

class TestPledge(unittest.TestCase):
    """SECCOMP BPF enforcement — each test forks a child."""

    def _check(self, promises, fn, *args, should_work=True):
        """Run fn under pledge in a forked child."""
        code, signaled, sig = _pledged_check(promises, fn, *args)
        if should_work:
            self.assertEqual(code, 0,
                             f"should succeed under '{promises}' but "
                             f"got exit={code} signaled={signaled}")
        else:
            self.assertNotEqual(code, 0,
                                f"should fail under '{promises}' but succeeded")

    # ── stdio ──

    def test_stdio_allows_write_stdout(self):
        self._check("stdio", lambda: os.write(1, b""))

    def test_stdio_allows_read_stdin(self):
        # read 0 bytes from a pipe (not stdin, which may block)
        def fn():
            r, w = os.pipe()
            os.close(w)
            os.read(r, 1)
            os.close(r)
        self._check("stdio", fn)

    def test_stdio_allows_getpid(self):
        self._check("stdio", os.getpid)

    def test_stdio_allows_close(self):
        def fn():
            fd = os.dup(1)
            os.close(fd)
        self._check("stdio", fn)

    def test_stdio_blocks_open(self):
        self._check("stdio", lambda: open("/etc/hostname"),
                    should_work=False)

    def test_stdio_blocks_socket(self):
        self._check("stdio",
                    lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    should_work=False)

    def test_stdio_blocks_fork(self):
        self._check("stdio", os.fork, should_work=False)

    # ── rpath ──

    def test_rpath_allows_open_rdonly(self):
        self._check("stdio rpath",
                    lambda: open("/etc/hostname").close())

    def test_rpath_blocks_open_wronly(self):
        self._check("stdio rpath",
                    lambda: open("/tmp/_sandbox_test_rpath", "w"),
                    should_work=False)

    def test_rpath_blocks_socket(self):
        self._check("stdio rpath",
                    lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    should_work=False)

    def test_rpath_blocks_fork(self):
        self._check("stdio rpath", os.fork, should_work=False)

    def test_rpath_allows_stat(self):
        self._check("stdio rpath", lambda: os.stat("/etc/hostname"))

    def test_rpath_allows_getcwd(self):
        self._check("stdio rpath", os.getcwd)

    # ── wpath ──

    def test_wpath_allows_write(self):
        def fn():
            fd = os.open("/tmp/_sandbox_test_w",
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(fd, b"hello")
            os.close(fd)
        # Need cpath for O_CREAT too
        self._check("stdio rpath wpath cpath", fn)

    # ── inet ──

    def test_inet_allows_ipv4_socket(self):
        def fn():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.close()
        self._check("stdio inet", fn)

    def test_inet_allows_ipv6_socket(self):
        def fn():
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.close()
        self._check("stdio inet", fn)

    def test_inet_blocks_unix_socket(self):
        self._check("stdio inet",
                    lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM),
                    should_work=False)

    # ── unix ──

    def test_unix_allows_unix_socket(self):
        def fn():
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.close()
        self._check("stdio unix", fn)

    def test_unix_blocks_inet_socket(self):
        self._check("stdio unix",
                    lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    should_work=False)

    # ── proc ──

    def test_proc_allows_fork(self):
        def fn():
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            os.waitpid(pid, 0)
        self._check("stdio proc", fn)

    # ── exec ──

    def test_exec_allows_execve(self):
        def fn():
            pid = os.fork()
            if pid == 0:
                os.execv("/bin/true", ["/bin/true"])
            _, st = os.waitpid(pid, 0)
            if not os.WIFEXITED(st) or os.WEXITSTATUS(st) != 0:
                raise RuntimeError("execve failed")
        self._check("stdio proc exec rpath prot_exec", fn)


# ═══════════════════════════════════════════════════════════════════════
# Test: Argument-level filtering
# ═══════════════════════════════════════════════════════════════════════

class TestPledgeArgFilter(unittest.TestCase):
    """Tests for syscalls with argument-level BPF filtering."""

    def _check(self, promises, fn, should_work=True):
        code, _, _ = _pledged_check(promises, fn)
        if should_work:
            self.assertEqual(code, 0)
        else:
            self.assertNotEqual(code, 0)

    def test_ioctl_fionread_allowed_by_stdio(self):
        """stdio allows ioctl(FIONREAD)."""
        def fn():
            import array
            r, w = os.pipe()
            buf = array.array("i", [0])
            # Use fcntl.ioctl with a buffer to avoid exceptions
            import fcntl
            fcntl.ioctl(r, 0x541B, buf)  # FIONREAD
            os.close(r); os.close(w)
        self._check("stdio", fn)

    def test_fcntl_getfl_allowed_by_stdio(self):
        """stdio allows fcntl(F_GETFL)."""
        import fcntl
        def fn():
            r, w = os.pipe()
            fcntl.fcntl(r, 3)  # F_GETFL
            os.close(r); os.close(w)
        self._check("stdio", fn)

    def test_open_rdonly_needs_rpath(self):
        """open(O_RDONLY) blocked without rpath."""
        self._check("stdio",
                    lambda: open("/etc/hostname").close(),
                    should_work=False)

    def test_open_rdonly_with_rpath(self):
        """open(O_RDONLY) allowed with rpath."""
        self._check("stdio rpath",
                    lambda: open("/etc/hostname").close())

    def test_socket_af_inet_needs_inet(self):
        """socket(AF_INET) blocked without inet."""
        self._check("stdio rpath",
                    lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    should_work=False)

    def test_socket_af_inet_with_inet(self):
        """socket(AF_INET) allowed with inet."""
        def fn():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.close()
        self._check("stdio inet", fn)


# ═══════════════════════════════════════════════════════════════════════
# Test: Pledge narrowing
# ═══════════════════════════════════════════════════════════════════════

class TestPledgeNarrowing(unittest.TestCase):
    """Progressive privilege dropping."""

    def test_narrow_rpath_to_stdio(self):
        """pledge("stdio rpath") then pledge("stdio") should block reads."""
        def fn():
            from sandbox import pledge as _pledge
            _pledge("stdio rpath")
            open("/etc/hostname").close()  # should work
            _pledge("stdio")
            open("/etc/hostname").close()  # should fail
        code, _, _ = _fork_test(fn)
        self.assertEqual(code, 1, "narrowed pledge should block open")

    def test_narrow_inet_to_stdio(self):
        """After narrowing, sockets should be blocked."""
        def fn():
            from sandbox import pledge as _pledge
            _pledge("stdio rpath inet")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.close()
            _pledge("stdio rpath")
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        code, _, _ = _fork_test(fn)
        self.assertEqual(code, 1)

    def test_three_phase_narrowing(self):
        """stdio rpath inet → stdio inet → stdio."""
        def fn():
            from sandbox import pledge as _pledge
            _pledge("stdio rpath inet")
            open("/etc/hostname").close()  # ok

            _pledge("stdio inet")
            try:
                open("/etc/hostname")
                os._exit(10)  # should not reach
            except OSError:
                pass  # good, rpath removed

            _pledge("stdio")
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                os._exit(11)  # should not reach
            except OSError:
                pass  # good, inet removed

        code, _, _ = _fork_test(fn)
        self.assertEqual(code, 0)


# ═══════════════════════════════════════════════════════════════════════
# Test: Kill penalty
# ═══════════════════════════════════════════════════════════════════════

class TestPledgePenalty(unittest.TestCase):
    """Kill penalty vs EPERM."""

    def test_kill_penalty_sends_signal(self):
        """With kill penalty, violation should kill the process."""
        def fn():
            from sandbox import _install_seccomp, _BPFBuilder
            bpf = _BPFBuilder({"stdio"}, SECCOMP_RET_KILL_PROCESS).build()
            _install_seccomp(bpf)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        code, signaled, sig = _fork_test(fn)
        self.assertTrue(signaled or code >= 128,
                        "kill penalty should terminate with signal")

    def test_eperm_penalty_returns_error(self):
        """With EPERM penalty, violation should raise OSError."""
        def fn():
            from sandbox import _install_seccomp, _BPFBuilder
            bpf = _BPFBuilder({"stdio"}, SECCOMP_RET_ERRNO).build()
            _install_seccomp(bpf)
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                os._exit(10)  # should not reach
            except OSError:
                os._exit(0)  # got EPERM, good
        code, signaled, _ = _fork_test(fn)
        self.assertFalse(signaled, "eperm should not kill")
        self.assertEqual(code, 0, "should catch OSError(EPERM)")


# ═══════════════════════════════════════════════════════════════════════
# Test: Sandbox.run()
# ═══════════════════════════════════════════════════════════════════════

class TestSandboxRun(unittest.TestCase):
    """Sandbox.run() — fork + sandbox + exec."""

    def test_run_ls(self):
        code = Sandbox(promises="stdio rpath").run(["/bin/ls", "/etc/hostname"])
        self.assertEqual(code, 0)

    def test_run_true(self):
        code = Sandbox(promises="stdio").run(["/bin/true"])
        self.assertEqual(code, 0)

    def test_run_false(self):
        code = Sandbox(promises="stdio").run(["/bin/false"])
        self.assertNotEqual(code, 0)

    def test_run_blocks_socket_in_child(self):
        code = Sandbox(promises="stdio rpath").run(
            ["python3", "-c", "import socket; socket.socket()"])
        self.assertNotEqual(code, 0)

    def test_run_blocks_fork_in_child(self):
        code = Sandbox(promises="stdio rpath").run(
            ["python3", "-c", "import os; os.fork()"])
        self.assertNotEqual(code, 0)

    def test_run_allows_network_with_inet(self):
        """With inet+dns, importing socket and creating one should work."""
        code = Sandbox(promises="stdio rpath inet dns").run(
            ["python3", "-c",
             "import socket; s=socket.socket(); s.close()"])
        self.assertEqual(code, 0)

    def test_run_nonexistent_command(self):
        code = Sandbox(promises="stdio").run(["/nonexistent/binary"])
        self.assertNotEqual(code, 0)

    def test_run_finds_path(self):
        code = Sandbox(promises="stdio rpath").run(["ls", "/etc/hostname"])
        self.assertEqual(code, 0)

    def test_run_profile_readonly(self):
        code = Sandbox.from_profile("readonly").run(
            ["/bin/ls", "/etc/hostname"])
        self.assertEqual(code, 0)

    def test_run_empty_argv_raises(self):
        with self.assertRaises(ValueError):
            Sandbox().run([])


# ═══════════════════════════════════════════════════════════════════════
# Test: Sandbox.enter() context manager
# ═══════════════════════════════════════════════════════════════════════

class TestSandboxEnter(unittest.TestCase):
    """Sandbox.enter() context manager — tests in forked children."""

    def _enter_check(self, sb, fn, should_work=True):
        def inner():
            with sb.enter():
                fn()
        code, signaled, _ = _fork_test(inner)
        if should_work:
            self.assertEqual(code, 0, "should work inside entered sandbox")
        else:
            self.assertNotEqual(code, 0, "should fail inside entered sandbox")

    def test_enter_allows_pledged_ops(self):
        self._enter_check(
            Sandbox().allow("stdio rpath"),
            lambda: open("/etc/hostname").close())

    def test_enter_blocks_unpledged_ops(self):
        self._enter_check(
            Sandbox().allow("stdio rpath"),
            lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            should_work=False)

    def test_enter_blocks_fork(self):
        self._enter_check(
            Sandbox().allow("stdio rpath"),
            os.fork,
            should_work=False)

    def test_enter_blocks_write(self):
        self._enter_check(
            Sandbox().allow("stdio rpath"),
            lambda: open("/tmp/_sandbox_enter_test", "w"),
            should_work=False)


# ═══════════════════════════════════════════════════════════════════════
# Test: Enclave pattern (fork + pledge)
# ═══════════════════════════════════════════════════════════════════════

class TestEnclave(unittest.TestCase):
    """Fork+pledge enclave pattern for sandboxing untrusted code."""

    def _enclave_run(self, code_str: str, data: dict) -> dict:
        """Run code_str in a pledged child, return result dict."""
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            with Sandbox().allow("stdio").enter():
                ns = {"data": data}
                try:
                    exec(code_str, ns)
                    os.write(w, json.dumps(
                        {"ok": ns.get("output")}).encode())
                except Exception as e:
                    os.write(w, json.dumps(
                        {"error": type(e).__name__}).encode())
            os._exit(0)
        os.close(w)
        buf = b""
        while True:
            chunk = os.read(r, 4096)
            if not chunk: break
            buf += chunk
        os.close(r)
        os.waitpid(pid, 0)
        return json.loads(buf)

    def test_safe_computation(self):
        r = self._enclave_run('output = sum(data["n"])', {"n": [1,2,3]})
        self.assertEqual(r, {"ok": 6})

    def test_socket_blocked(self):
        r = self._enclave_run(
            'import socket; socket.socket()', {})
        self.assertEqual(r["error"], "PermissionError")

    def test_file_write_blocked(self):
        r = self._enclave_run(
            'open("/tmp/pwned", "w")', {})
        self.assertEqual(r["error"], "PermissionError")

    def test_file_read_blocked(self):
        r = self._enclave_run(
            'open("/etc/hostname")', {})
        self.assertEqual(r["error"], "PermissionError")

    def test_fork_blocked(self):
        r = self._enclave_run('import os; os.fork()', {})
        self.assertIn(r["error"], ("PermissionError", "OSError"))

    def test_exec_blocked(self):
        r = self._enclave_run(
            'import os; os.execv("/bin/true", ["/bin/true"])', {})
        self.assertIn(r["error"], ("PermissionError", "OSError"))

    def test_complex_computation(self):
        r = self._enclave_run(textwrap.dedent('''\
            import math
            output = {
                "pi": round(math.pi, 5),
                "sqrt2": round(math.sqrt(2), 5),
                "factorial10": math.factorial(10),
            }
        '''), {})
        self.assertEqual(r["ok"]["factorial10"], 3628800)
        self.assertAlmostEqual(r["ok"]["pi"], 3.14159, places=4)


# ═══════════════════════════════════════════════════════════════════════
# Test: Convenience API (pledge/unveil standalone functions)
# ═══════════════════════════════════════════════════════════════════════

class TestConvenienceAPI(unittest.TestCase):
    """pledge() and unveil() standalone functions."""

    def test_pledge_unknown_promise_raises(self):
        def fn():
            from sandbox import pledge as _pledge
            _pledge("stdio bogus_promise")
        code, _, _ = _fork_test(fn)
        self.assertNotEqual(code, 0)

    def test_pledge_enforces(self):
        def fn():
            from sandbox import pledge as _pledge
            _pledge("stdio rpath")
            open("/etc/hostname").close()  # should work
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # should fail
        code, _, _ = _fork_test(fn)
        self.assertEqual(code, 1, "socket should fail after pledge")

    def test_unveil_mismatched_args_raises(self):
        """unveil(path, None) should raise ValueError."""
        def fn():
            from sandbox import unveil as _unveil
            _unveil("/etc", None)
        code, _, _ = _fork_test(fn)
        self.assertEqual(code, 2, "should raise ValueError (exit 2)")

    def test_unveil_graceful_on_old_kernel(self):
        """If Landlock unavailable, unveil(None, None) after adding rules
        should raise OSError, not crash."""
        if Capabilities.has_landlock():
            self.skipTest("Landlock is available — can't test failure path")
        def fn():
            from sandbox import unveil as _unveil
            _unveil("/tmp", "r")
            try:
                _unveil(None, None)
                os._exit(10)  # shouldn't reach if no landlock
            except OSError:
                os._exit(0)  # expected
        code, _, _ = _fork_test(fn)
        self.assertEqual(code, 0)


# ═══════════════════════════════════════════════════════════════════════
# Test: ELF detection
# ═══════════════════════════════════════════════════════════════════════

class TestELFDetection(unittest.TestCase):
    """Dynamic ELF detection for auto-adding prot_exec."""

    def test_bin_ls_is_dynamic(self):
        self.assertTrue(_is_dynamic_elf("/bin/ls"))

    def test_bin_sh_is_dynamic(self):
        self.assertTrue(_is_dynamic_elf("/bin/sh"))

    def test_nonexistent_defaults_dynamic(self):
        # Safety default: assume dynamic if we can't read
        self.assertTrue(_is_dynamic_elf("/nonexistent/path"))

    def test_text_file_is_not_elf(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py",
                                         delete=False) as f:
            f.write("#!/usr/bin/env python3\nprint('hello')\n")
            path = f.name
        try:
            self.assertFalse(_is_dynamic_elf(path))
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════
# Test: Landlock helpers
# ═══════════════════════════════════════════════════════════════════════

class TestLandlockHelpers(unittest.TestCase):
    """Permission string → Landlock access bit conversion."""

    def test_read_permission(self):
        access = _perms_to_ll("r", is_dir=True)
        self.assertTrue(access & _LL_READ)
        self.assertFalse(access & _LL_WRITE)

    def test_write_permission(self):
        access = _perms_to_ll("w", is_dir=False)
        self.assertTrue(access & _LL_WRITE)
        self.assertFalse(access & _LL_EXEC)

    def test_exec_permission(self):
        access = _perms_to_ll("x", is_dir=False)
        self.assertTrue(access & _LL_EXEC)

    def test_create_on_dir(self):
        access = _perms_to_ll("c", is_dir=True)
        self.assertTrue(access & _LL_CREATE)

    def test_create_on_file_ignored(self):
        # c on a non-directory should produce 0 for create bits
        access = _perms_to_ll("c", is_dir=False)
        self.assertFalse(access & _LL_CREATE)

    def test_combined_permissions(self):
        access = _perms_to_ll("rwxc", is_dir=True)
        self.assertTrue(access & _LL_READ)
        self.assertTrue(access & _LL_WRITE)
        self.assertTrue(access & _LL_EXEC)
        self.assertTrue(access & _LL_CREATE)

    def test_unknown_permission_raises(self):
        with self.assertRaises(ValueError):
            _perms_to_ll("z", is_dir=False)

    def test_empty_permission(self):
        access = _perms_to_ll("", is_dir=False)
        self.assertEqual(access, 0)


# ═══════════════════════════════════════════════════════════════════════
# Test: CLI (via subprocess)
# ═══════════════════════════════════════════════════════════════════════

class TestCLI(unittest.TestCase):
    """Command-line interface via subprocess."""

    def _run_cli(self, *args, check=True) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, SANDBOX_PY] + list(args),
            capture_output=True, text=True, timeout=30)

    def test_cli_test(self):
        r = self._run_cli("test")
        self.assertEqual(r.returncode, 0)
        self.assertIn("kernel:", r.stdout)
        self.assertIn("seccomp:", r.stdout)
        self.assertIn("landlock:", r.stdout)

    def test_cli_profiles(self):
        r = self._run_cli("profiles")
        self.assertEqual(r.returncode, 0)
        self.assertIn("strict", r.stdout)
        self.assertIn("claude", r.stdout)
        self.assertIn("untrusted", r.stdout)

    def test_cli_describe_strict(self):
        r = self._run_cli("describe", "strict")
        self.assertEqual(r.returncode, 0)
        self.assertIn("stdio", r.stdout)
        self.assertIn("penalty:", r.stdout)

    def test_cli_describe_claude(self):
        r = self._run_cli("describe", "claude")
        self.assertEqual(r.returncode, 0)
        self.assertIn("inet", r.stdout)
        self.assertIn(".ssh", r.stdout)
        self.assertIn("overlay home", r.stdout)

    def test_cli_describe_all_profiles(self):
        for name in PROFILES:
            r = self._run_cli("describe", name)
            self.assertEqual(r.returncode, 0,
                             f"describe {name} failed: {r.stderr}")

    def test_cli_run_ls(self):
        r = self._run_cli("run", "-p", "stdio rpath", "--", "/bin/ls",
                          "/etc/hostname")
        self.assertEqual(r.returncode, 0)
        self.assertIn("/etc/hostname", r.stdout)

    def test_cli_run_true(self):
        r = self._run_cli("run", "-p", "stdio", "--", "/bin/true")
        self.assertEqual(r.returncode, 0)

    def test_cli_run_false(self):
        r = self._run_cli("run", "-p", "stdio", "--", "/bin/false")
        self.assertNotEqual(r.returncode, 0)

    def test_cli_run_blocks_socket(self):
        r = self._run_cli("run", "-p", "stdio rpath", "--",
                          "python3", "-c", "import socket; socket.socket()")
        self.assertNotEqual(r.returncode, 0)

    def test_cli_run_profile_readonly(self):
        r = self._run_cli("run", "--profile", "readonly", "--",
                          "/bin/ls", "/etc/hostname")
        self.assertEqual(r.returncode, 0)

    def test_cli_run_penalty_kill(self):
        r = self._run_cli("run", "--penalty", "kill", "-p", "stdio rpath",
                          "--", "python3", "-c",
                          "import socket; socket.socket()")
        self.assertNotEqual(r.returncode, 0)
        # Should die from SIGSYS (signal 31), exit = 128+31 = 159
        # or the shell may report differently

    def test_cli_run_no_command(self):
        r = self._run_cli("run")
        self.assertNotEqual(r.returncode, 0)

    def test_cli_no_subcommand_shows_help(self):
        r = self._run_cli()
        self.assertNotEqual(r.returncode, 0)

    def test_cli_run_with_unveil_flag(self):
        """Test -v flag with Landlock enforcement.

        When Landlock is active, a dynamically linked binary needs access
        to its shared libraries.  We unveil the necessary paths so the
        command can actually load and run.
        """
        args = ["run", "-p", "stdio rpath",
                "-v", "/etc", "-v", "rx:/usr", "-v", "rx:/lib",
                "-v", "rx:/lib64", "-v", "rx:/bin",
                "--", "/bin/ls", "/etc/hostname"]
        r = self._run_cli(*args)
        self.assertEqual(r.returncode, 0,
                         f"stdout={r.stdout!r} stderr={r.stderr!r}")

    def test_cli_run_with_perm_unveil_flag(self):
        """Test -v PERM:PATH style flag with Landlock enforcement."""
        args = ["run", "-p", "stdio rpath",
                "-v", "rwc:/tmp", "-v", "/etc",
                "-v", "rx:/usr", "-v", "rx:/lib", "-v", "rx:/lib64",
                "-v", "rx:/bin",
                "--", "/bin/ls", "/etc/hostname"]
        r = self._run_cli(*args)
        self.assertEqual(r.returncode, 0,
                         f"stdout={r.stdout!r} stderr={r.stderr!r}")

    def test_cli_unveil_blocks_unlisted_paths(self):
        """When Landlock is active, paths not unveiled should be blocked."""
        if not Capabilities.has_landlock():
            self.skipTest("Landlock not available")
        # Unveil only /usr and /lib (for the binary to load) but NOT /etc
        args = ["run", "-p", "stdio rpath",
                "-v", "rx:/usr", "-v", "rx:/lib", "-v", "rx:/lib64",
                "-v", "rx:/bin",
                "--", "/bin/cat", "/etc/hostname"]
        r = self._run_cli(*args)
        # cat should fail because /etc is not unveiled
        self.assertNotEqual(r.returncode, 0)

    def test_cli_run_with_no_unveil_flag(self):
        """Test -V flag disables unveil."""
        r = self._run_cli("run", "-V", "-p", "stdio rpath",
                          "--", "/bin/ls", "/etc/hostname")
        self.assertEqual(r.returncode, 0)


# ═══════════════════════════════════════════════════════════════════════
# Test: Edge cases and integration
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):
    """Miscellaneous edge cases."""

    def test_multiple_run_calls(self):
        """Sandbox object can be used for multiple run() calls."""
        sb = Sandbox(promises="stdio rpath")
        c1 = sb.run(["/bin/true"])
        c2 = sb.run(["/bin/true"])
        self.assertEqual(c1, 0)
        self.assertEqual(c2, 0)

    def test_run_preserves_parent(self):
        """run() should not sandbox the parent process."""
        sb = Sandbox(promises="stdio")
        sb.run(["/bin/true"])
        # Parent should still be able to do everything
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.close()
        f = open("/etc/hostname")
        f.close()

    def test_describe_is_idempotent(self):
        sb = Sandbox().allow("stdio rpath").see("/etc", "r")
        d1 = sb.describe()
        d2 = sb.describe()
        self.assertEqual(d1, d2)

    def test_large_promise_set(self):
        """All promises together should still produce a valid BPF."""
        all_p = " ".join(PROMISE_SYSCALLS.keys())
        sb = Sandbox(promises=all_p)
        # Should not raise
        desc = sb.describe()
        self.assertIn("stdio", desc)

    def test_run_inherits_env(self):
        """Child should inherit environment variables."""
        os.environ["_SANDBOX_TEST_VAR"] = "hello42"
        code = Sandbox(promises="stdio rpath").run(
            ["python3", "-c",
             "import os,sys; "
             "sys.exit(0 if os.environ.get('_SANDBOX_TEST_VAR')=='hello42' "
             "else 1)"])
        del os.environ["_SANDBOX_TEST_VAR"]
        self.assertEqual(code, 0)


# ═══════════════════════════════════════════════════════════════════════
# Test: Unveil enforcement (Landlock)
# ═══════════════════════════════════════════════════════════════════════

class TestUnveil(unittest.TestCase):
    """Landlock enforcement — each test forks a child.

    These tests are skipped if Landlock is not available (kernel < 5.13).
    """

    def setUp(self):
        if not Capabilities.has_landlock():
            self.skipTest("Landlock not available")

    def _unveil_check(self, rules: list[tuple[str, str]], fn,
                      should_work=True):
        """Fork, install Landlock rules, run fn, check result."""
        def inner():
            from sandbox import _install_landlock
            _install_landlock(rules)
            fn()
        code, signaled, _ = _fork_test(inner)
        if should_work:
            self.assertEqual(code, 0,
                             f"should succeed with {rules} but got exit={code}")
        else:
            self.assertNotEqual(code, 0,
                                f"should fail with {rules} but succeeded")

    def test_unveil_allows_read(self):
        """Unveiled path with 'r' allows reading."""
        self._unveil_check(
            [("/etc", "r")],
            lambda: open("/etc/hostname").close())

    def test_unveil_blocks_unmentioned_path(self):
        """Path not mentioned in any rule is blocked."""
        self._unveil_check(
            [("/usr", "r")],
            lambda: open("/etc/hostname").close(),
            should_work=False)

    def test_unveil_blocks_write_on_readonly(self):
        """Path unveiled with 'r' blocks writing."""
        import tempfile
        self._unveil_check(
            [("/tmp", "r"), ("/usr", "r"), ("/lib", "r")],
            lambda: open("/tmp/_sandbox_unveil_test", "w"),
            should_work=False)

    def test_unveil_allows_write(self):
        """Path unveiled with 'rw' allows writing."""
        def fn():
            p = "/tmp/_sandbox_unveil_test_rw"
            with open(p, "w") as f:
                f.write("test")
            os.unlink(p)
        self._unveil_check(
            [("/tmp", "rwc")],
            fn)

    def test_unveil_dir_covers_children(self):
        """Unveiling a directory covers files underneath it."""
        self._unveil_check(
            [("/etc", "r")],
            lambda: open("/etc/hostname").close())

    def test_unveil_multiple_paths(self):
        """Multiple unveiled paths all accessible."""
        def fn():
            open("/etc/hostname").close()
            os.listdir("/usr/lib")
        self._unveil_check(
            [("/etc", "r"), ("/usr", "r")],
            fn)

    def test_unveil_via_sandbox_run(self):
        """Sandbox.run() with .see() enforces Landlock."""
        sb = Sandbox(promises="stdio rpath") \
            .see("/etc", "r") \
            .see("/usr", "rx") \
            .see("/lib", "rx") \
            .see("/lib64", "rx") \
            .see("/bin", "rx")
        code = sb.run(["/bin/cat", "/etc/hostname"])
        self.assertEqual(code, 0)

    def test_unveil_via_sandbox_blocks(self):
        """Sandbox.run() with .see() blocks non-unveiled paths."""
        sb = Sandbox(promises="stdio rpath") \
            .see("/usr", "rx") \
            .see("/lib", "rx") \
            .see("/lib64", "rx") \
            .see("/bin", "rx")
        # /etc is NOT unveiled, so cat should fail
        code = sb.run(["/bin/cat", "/etc/hostname"])
        self.assertNotEqual(code, 0)

    def test_unveil_enter_enforces(self):
        """Sandbox.enter() with .see() enforces Landlock."""
        def fn():
            with Sandbox().allow("stdio rpath").see("/etc", "r").enter():
                open("/etc/hostname").close()
                # /tmp not unveiled — should fail
                open("/tmp/_sb_enter_unveil_test", "w")
        code, _, _ = _fork_test(fn)
        self.assertNotEqual(code, 0)


# ═══════════════════════════════════════════════════════════════════════
# Test: Combined pledge + unveil
# ═══════════════════════════════════════════════════════════════════════

class TestCombined(unittest.TestCase):
    """Tests that verify pledge and unveil work together."""

    def test_pledge_and_unveil_both_enforce(self):
        """Both layers enforce independently."""
        if not Capabilities.has_landlock():
            self.skipTest("Landlock not available")

        def fn():
            from sandbox import pledge as _pledge, _install_landlock
            # Unveil allows /etc read, blocks /tmp
            _install_landlock([("/etc", "r")])
            # Pledge allows rpath but not inet
            _pledge("stdio rpath")

            # Should work: unveiled + pledged
            open("/etc/hostname").close()

            # Should fail: unveiled but not pledged (socket)
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                os._exit(10)  # pledge should block
            except OSError:
                pass

            # Should fail: pledged but not unveiled
            try:
                open("/tmp/_combined_test")
                os._exit(11)  # landlock should block
            except OSError:
                pass

        code, _, _ = _fork_test(fn)
        self.assertEqual(code, 0)

    def test_sandbox_class_applies_both(self):
        """Sandbox with .allow() and .see() applies both layers."""
        if not Capabilities.has_landlock():
            self.skipTest("Landlock not available")

        def fn():
            with Sandbox() \
                .allow("stdio rpath") \
                .see("/etc", "r") \
                .enter():
                # Read unveiled path — works
                open("/etc/hostname").close()
                # Socket — pledge blocks
                try:
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    os._exit(10)
                except OSError:
                    pass
                # Read non-unveiled — landlock blocks
                try:
                    open("/tmp/_combined_sb_test")
                    os._exit(11)
                except OSError:
                    pass

        code, _, _ = _fork_test(fn)
        self.assertEqual(code, 0)


# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Print capabilities summary before running tests
    print("=" * 60)
    print("sandbox.py test suite")
    print("=" * 60)
    print(Capabilities.summary())
    print("=" * 60)
    print()
    unittest.main(verbosity=2)