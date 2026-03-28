#!/usr/bin/env python3
"""
sandbox — Unified Linux sandboxing for AI agents and untrusted code

Combines three kernel enforcement layers into one clean API:

  Layer 1: SECCOMP BPF  — controls which OPERATIONS are allowed (pledge)
  Layer 2: Landlock LSM  — controls which PATHS are accessible  (unveil)
  Layer 3: Namespaces    — isolates the process's VIEW of the system (jail)

Each layer is optional and auto-detected based on kernel capabilities.
Unprivileged by default; root unlocks namespace features.

Library usage:
    from sandbox import Sandbox

    with Sandbox() \\
        .allow("stdio rpath inet dns") \\
        .see("/etc", "r") \\
        .see("/tmp", "rwc") \\
        .enter():
        # sandboxed code here
        ...

    # Or run an external command
    Sandbox().allow("stdio rpath").run(["ls", "-la"])

CLI usage:
    sandbox run -p "stdio rpath" -- ls -la
    sandbox run --profile claude -- claude
    sandbox test

Requires: Linux, Python >= 3.10.  No dependencies beyond ctypes.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import errno
import fnmatch
import grp
import os
import platform
import pwd
import re
import shutil
import signal
import struct
import sys
import textwrap
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional, Any

# ═══════════════════════════════════════════════════════════════════════
# Architecture detection
# ═══════════════════════════════════════════════════════════════════════

_machine = platform.machine()
if _machine in ("x86_64", "amd64"):
    AUDIT_ARCH = 0xC000003E
    _arch = "x86_64"
elif _machine in ("aarch64", "arm64"):
    AUDIT_ARCH = 0xC00000B7
    _arch = "aarch64"
else:
    AUDIT_ARCH = 0
    _arch = _machine

# ═══════════════════════════════════════════════════════════════════════
# Syscall number tables
# ═══════════════════════════════════════════════════════════════════════

if _arch == "x86_64":
    NR = {
        "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4,
        "fstat": 5, "lstat": 6, "poll": 7, "lseek": 8, "mmap": 9,
        "mprotect": 10, "munmap": 11, "brk": 12, "rt_sigaction": 13,
        "rt_sigprocmask": 14, "rt_sigreturn": 15, "ioctl": 16,
        "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20,
        "access": 21, "pipe": 22, "select": 23, "sched_yield": 24,
        "mremap": 25, "msync": 26, "madvise": 28, "dup": 32,
        "dup2": 33, "nanosleep": 35, "getitimer": 36, "alarm": 37,
        "setitimer": 38, "getpid": 39, "sendfile": 40, "socket": 41,
        "connect": 42, "accept": 43, "sendto": 44, "recvfrom": 45,
        "sendmsg": 46, "recvmsg": 47, "shutdown": 48, "bind": 49,
        "listen": 50, "getsockname": 51, "getpeername": 52,
        "socketpair": 53, "setsockopt": 54, "getsockopt": 55,
        "clone": 56, "fork": 57, "vfork": 58, "execve": 59,
        "exit": 60, "wait4": 61, "kill": 62, "uname": 63,
        "fcntl": 72, "flock": 73, "fsync": 74, "fdatasync": 75,
        "truncate": 76, "ftruncate": 77, "getdents": 78,
        "getcwd": 79, "chdir": 80, "fchdir": 81, "rename": 82,
        "mkdir": 83, "rmdir": 84, "creat": 85, "link": 86,
        "unlink": 87, "symlink": 88, "readlink": 89, "chmod": 90,
        "fchmod": 91, "chown": 92, "fchown": 93, "lchown": 94,
        "umask": 95, "gettimeofday": 96, "getrlimit": 97,
        "getrusage": 98, "getuid": 102, "getgid": 104,
        "setuid": 105, "setgid": 106, "geteuid": 107,
        "getegid": 108, "setpgid": 109, "getppid": 110,
        "getpgrp": 111, "setsid": 112, "setreuid": 113,
        "setregid": 114, "getgroups": 115, "setgroups": 116,
        "setresuid": 117, "getresuid": 118, "setresgid": 119,
        "getresgid": 120, "getpgid": 121, "setfsuid": 122,
        "setfsgid": 123, "getsid": 124, "sigpending": 127,
        "rt_sigtimedwait": 128, "sigsuspend": 130,
        "sigaltstack": 131, "utime": 132, "mknod": 133,
        "statfs": 137, "fstatfs": 138,
        "getpriority": 140, "setpriority": 141,
        "sched_setparam": 142, "sched_getparam": 143,
        "sched_setscheduler": 144, "sched_getscheduler": 145,
        "sched_get_priority_max": 146, "sched_get_priority_min": 147,
        "mlock": 149, "munlock": 150, "prctl": 157, "arch_prctl": 158,
        "setrlimit": 160, "chroot": 161, "sync": 162,
        "mount": 165, "umount2": 166,
        "gettid": 186, "futex": 202, "getdents64": 217,
        "set_tid_address": 218, "clock_gettime": 228,
        "clock_getres": 229, "clock_nanosleep": 230,
        "exit_group": 231, "epoll_wait": 232, "epoll_ctl": 233,
        "openat": 257, "mkdirat": 258, "mknodat": 259,
        "fchownat": 260, "futimesat": 261, "fstatat": 262,
        "unlinkat": 263, "renameat": 264, "linkat": 265,
        "symlinkat": 266, "readlinkat": 267, "fchmodat": 268,
        "faccessat": 269, "pselect6": 270, "ppoll": 271,
        "splice": 275, "tee": 276, "utimensat": 280,
        "accept4": 288, "epoll_create1": 291, "dup3": 292,
        "pipe2": 293, "preadv": 295, "pwritev": 296,
        "recvmmsg": 299, "prlimit64": 302, "sendmmsg": 307,
        "renameat2": 316, "getrandom": 318,
        "execveat": 322, "copy_file_range": 326,
        "preadv2": 327, "pwritev2": 328,
        "statx": 332, "rseq": 334, "close_range": 436,
        "faccessat2": 439,
    }
elif _arch == "aarch64":
    NR = {
        "read": 63, "write": 64, "close": 57, "fstat": 80,
        "lseek": 62, "mmap": 222, "mprotect": 226, "munmap": 215,
        "brk": 214, "rt_sigaction": 134, "rt_sigprocmask": 135,
        "rt_sigreturn": 139, "ioctl": 29,
        "pread64": 67, "pwrite64": 68, "readv": 65, "writev": 66,
        "sched_yield": 124, "msync": 227, "madvise": 233,
        "dup": 23, "dup3": 24, "nanosleep": 101,
        "getitimer": 102, "setitimer": 103,
        "getpid": 172, "sendfile": 71, "socket": 198,
        "connect": 203, "accept": 202, "sendto": 206,
        "recvfrom": 207, "sendmsg": 211, "recvmsg": 212,
        "shutdown": 210, "bind": 200, "listen": 201,
        "getsockname": 204, "getpeername": 205, "socketpair": 199,
        "setsockopt": 208, "getsockopt": 209,
        "clone": 220, "execve": 221,
        "exit": 93, "wait4": 260, "kill": 129,
        "uname": 160, "fcntl": 25, "flock": 32,
        "fsync": 82, "fdatasync": 83, "truncate": 45,
        "ftruncate": 46, "getcwd": 17, "chdir": 49, "fchdir": 50,
        "fchmod": 52, "fchown": 55, "umask": 166,
        "getuid": 174, "getgid": 176, "geteuid": 175,
        "getegid": 177, "setpgid": 154, "getppid": 173,
        "setsid": 157, "setreuid": 145, "setregid": 143,
        "getgroups": 158, "setgroups": 159,
        "setresuid": 147, "getresuid": 148, "setresgid": 149,
        "getresgid": 150, "getpgid": 155, "setfsuid": 151,
        "setfsgid": 152, "getsid": 156, "sigaltstack": 132,
        "statfs": 43, "fstatfs": 44,
        "getpriority": 141, "setpriority": 140,
        "sched_setparam": 118, "sched_getparam": 121,
        "sched_setscheduler": 119, "sched_getscheduler": 120,
        "sched_get_priority_max": 125, "sched_get_priority_min": 126,
        "prctl": 167, "gettimeofday": 169,
        "setuid": 146, "setgid": 144,
        "gettid": 178, "futex": 98, "set_tid_address": 96,
        "clock_gettime": 113, "clock_getres": 114,
        "clock_nanosleep": 115, "exit_group": 94,
        "openat": 56, "mkdirat": 34, "mknodat": 33,
        "fchownat": 54, "fstatat": 79,
        "unlinkat": 35, "renameat": 38, "linkat": 37,
        "symlinkat": 36, "readlinkat": 78, "fchmodat": 53,
        "faccessat": 48, "ppoll": 73,
        "splice": 76, "tee": 77, "utimensat": 88,
        "pipe2": 59, "preadv": 69, "pwritev": 70,
        "accept4": 242, "prlimit64": 261,
        "renameat2": 276, "getrandom": 278,
        "execveat": 281, "copy_file_range": 285,
        "preadv2": 286, "pwritev2": 287,
        "statx": 291, "rseq": 293, "close_range": 436,
        "faccessat2": 439, "getdents64": 61,
        "mremap": 216, "getrusage": 165,
        "sigsuspend": 133, "rt_sigtimedwait": 137,
    }
else:
    NR = {}


def _nr(name: str) -> int:
    return NR.get(name, -1)


# ═══════════════════════════════════════════════════════════════════════
# libc handle
# ═══════════════════════════════════════════════════════════════════════

_libc: Optional[ctypes.CDLL] = None

def _get_libc() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    return _libc


def _raw_syscall(nr: int, *args) -> int:
    libc = _get_libc()
    libc.syscall.restype = ctypes.c_long
    cargs = [ctypes.c_long(a) if isinstance(a, int) else a for a in args]
    return libc.syscall(ctypes.c_long(nr), *cargs)


def _syscall(nr: int, *args, name: str = "syscall") -> int:
    ret = _raw_syscall(nr, *args)
    if ret == -1:
        e = ctypes.get_errno()
        raise OSError(e, f"{name}: {os.strerror(e)}")
    return ret


def _prctl(opt: int, a2: int = 0, a3: int = 0,
           a4: int = 0, a5: int = 0) -> int:
    libc = _get_libc()
    libc.prctl.restype = ctypes.c_int
    libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    ret = libc.prctl(opt, a2, a3, a4, a5)
    if ret < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"prctl({opt}): {os.strerror(e)}")
    return ret


def _mount(src: Optional[str], tgt: str, fstype: Optional[str],
           flags: int, data: Optional[str] = None) -> None:
    libc = _get_libc()
    s = src.encode() if src else None
    t = tgt.encode()
    f = fstype.encode() if fstype else None
    d = data.encode() if data else None
    ret = libc.mount(s, t, f, ctypes.c_ulong(flags), d)
    if ret != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"mount({src!r},{tgt!r}): {os.strerror(e)}")


def _umount2(tgt: str, flags: int = 0) -> None:
    libc = _get_libc()
    ret = libc.umount2(tgt.encode(), flags)
    if ret != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"umount2({tgt!r}): {os.strerror(e)}")


def _unshare(flags: int) -> None:
    libc = _get_libc()
    if libc.unshare(flags) != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"unshare(0x{flags:x}): {os.strerror(e)}")


# ═══════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════

# mount flags
MS_RDONLY = 0x0001; MS_NOSUID = 0x0002; MS_NODEV = 0x0004
MS_REMOUNT = 0x0020; MS_BIND = 0x1000; MS_REC = 0x4000
MS_PRIVATE = 1 << 18; MNT_DETACH = 2

# clone/unshare
CLONE_NEWNS = 0x00020000; CLONE_NEWPID = 0x20000000

# open
O_PATH = 0o10000000; O_CLOEXEC = 0o2000000; O_NOFOLLOW = 0o400000
O_DIRECTORY = 0o200000; O_RDONLY = 0; O_WRONLY = 1; O_RDWR = 2
O_CREAT = 0o100; O_ACCMODE = 3

# prctl
PR_SET_NO_NEW_PRIVS = 38; PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# BPF
BPF_LD = 0x00; BPF_ALU = 0x04; BPF_JMP = 0x05; BPF_RET = 0x06
BPF_W = 0x00; BPF_ABS = 0x20; BPF_K = 0x00
BPF_AND = 0x50; BPF_JEQ = 0x10
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_DATA = 0x0000FFFF

# seccomp_data offsets
OFF_NR = 0; OFF_ARCH = 4; OFF_ARGS = 16

def _off_arg(n: int) -> int: return OFF_ARGS + n * 8
def _off_arg_hi(n: int) -> int: return OFF_ARGS + n * 8 + 4

_SF_FMT = "=HBBI"; _SF_SZ = 8
def BPF_STMT(code: int, k: int) -> bytes:
    return struct.pack(_SF_FMT, code, 0, 0, k & 0xFFFFFFFF)
def BPF_JUMP(code: int, k: int, jt: int, jf: int) -> bytes:
    return struct.pack(_SF_FMT, code, jt, jf, k & 0xFFFFFFFF)

# Socket/ioctl/fcntl constants for argument filtering
AF_INET = 2; AF_INET6 = 10; AF_UNIX = 1
PROT_EXEC = 4
FIONREAD = 0x541B; FIONBIO = 0x5421; FIOCLEX = 0x5451; FIONCLEX = 0x5450
TIOCGWINSZ = 0x5413; TCGETS = 0x5401; TCSETS = 0x5402
TCSETSW = 0x5403; TCSETSF = 0x5404
F_GETFD = 1; F_SETFD = 2; F_GETFL = 3; F_SETFL = 4
F_GETLK = 5; F_SETLK = 6; F_SETLKW = 7; F_DUPFD_CLOEXEC = 1030

# Landlock
SYS_landlock_create_ruleset = 444
SYS_landlock_add_rule = 445
SYS_landlock_restrict_self = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15

_LL_READ = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
_LL_WRITE = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE
_LL_EXEC = LANDLOCK_ACCESS_FS_EXECUTE
_LL_CREATE = (LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR |
              LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_MAKE_SOCK |
              LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_CHAR |
              LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_REMOVE_FILE |
              LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REFER)
_LL_ALL_V1 = (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
              LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
              LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
              LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
              LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
              LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
              LANDLOCK_ACCESS_FS_MAKE_SYM)


# ═══════════════════════════════════════════════════════════════════════
# Kernel capability detection
# ═══════════════════════════════════════════════════════════════════════

def _parse_kver() -> tuple[int, int, int]:
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", platform.release())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else (0,0,0)

KERNEL_VERSION = _parse_kver()


class Capabilities:
    """Probe kernel capabilities at runtime."""

    _cache: dict[str, Any] = {}

    @classmethod
    def _probe(cls, name: str) -> bool:
        nr = NR.get("prctl")
        if nr is None:
            return False
        nr2 = {
            "seccomp": None,  # test via prctl
            "landlock": SYS_landlock_create_ruleset,
        }.get(name)
        if name == "seccomp":
            try:
                _prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                return True
            except OSError:
                return False
        if nr2:
            ret = _raw_syscall(nr2, -1)
            return ret == -1 and ctypes.get_errno() != errno.ENOSYS
        return False

    @classmethod
    def has_seccomp(cls) -> bool:
        if "seccomp" not in cls._cache:
            cls._cache["seccomp"] = cls._probe("seccomp")
        return cls._cache["seccomp"]

    @classmethod
    def has_landlock(cls) -> bool:
        if "landlock" not in cls._cache:
            cls._cache["landlock"] = cls._probe("landlock")
        return cls._cache["landlock"]

    @classmethod
    def landlock_abi(cls) -> int:
        if "ll_abi" not in cls._cache:
            try:
                cls._cache["ll_abi"] = _syscall(
                    SYS_landlock_create_ruleset, 0, 0,
                    LANDLOCK_CREATE_RULESET_VERSION,
                    name="landlock_create_ruleset")
            except OSError:
                cls._cache["ll_abi"] = 0
        return cls._cache["ll_abi"]

    @classmethod
    def has_overlayfs(cls) -> bool:
        if "overlayfs" not in cls._cache:
            try:
                with open("/proc/filesystems") as f:
                    cls._cache["overlayfs"] = any("overlay" in l for l in f)
            except OSError:
                cls._cache["overlayfs"] = False
        return cls._cache["overlayfs"]

    @classmethod
    def has_pid_ns(cls) -> bool:
        if "pid_ns" not in cls._cache:
            cls._cache["pid_ns"] = os.path.exists("/proc/self/ns/pid")
        return cls._cache["pid_ns"]

    @classmethod
    def is_root(cls) -> bool:
        return os.geteuid() == 0

    @classmethod
    def summary(cls) -> str:
        kv = ".".join(str(x) for x in KERNEL_VERSION)
        abi = cls.landlock_abi()
        return "\n".join([
            f"kernel:      {kv} / {_arch}",
            f"seccomp:     {'yes' if cls.has_seccomp() else 'no'}",
            f"landlock:    {'ABI v' + str(abi) if abi else 'no'} (needs >= 5.13)",
            f"overlayfs:   {'yes' if cls.has_overlayfs() else 'no'}",
            f"pid ns:      {'yes' if cls.has_pid_ns() else 'no'}",
            f"root:        {'yes' if cls.is_root() else 'no'}",
            f"namespaces:  {'available' if cls.is_root() else 'needs root'}",
        ])


# ═══════════════════════════════════════════════════════════════════════
# Promise → syscall mapping
# ═══════════════════════════════════════════════════════════════════════

PROMISE_SYSCALLS: dict[str, set[str]] = {
    "stdio": {
        "exit", "exit_group", "close", "close_range",
        "dup", "dup2", "dup3", "fchdir",
        "fstat", "fstatat", "fsync", "fdatasync", "ftruncate",
        "getdents", "getdents64",
        "getegid", "geteuid", "getgid", "getgroups", "getuid",
        "getitimer", "setitimer",
        "getpgid", "getpgrp", "getpid", "getppid",
        "getresgid", "getresuid", "getrlimit", "getsid", "gettid",
        "gettimeofday", "getrandom",
        "clock_gettime", "clock_getres", "clock_nanosleep", "nanosleep",
        "lseek", "brk", "futex", "sched_yield", "mremap",
        "madvise", "mmap", "mprotect", "msync", "munmap", "rseq",
        "pipe", "pipe2",
        "read", "readv", "pread64", "preadv", "preadv2",
        "write", "writev", "pwrite64", "pwritev", "pwritev2",
        "recv", "recvfrom", "send", "sendto",
        "select", "pselect6", "poll", "ppoll",
        "epoll_wait", "epoll_ctl", "epoll_create1",
        "shutdown", "socketpair",
        "sigaltstack", "sigpending",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "rt_sigtimedwait", "sigsuspend",
        "umask", "uname", "set_tid_address", "arch_prctl", "prctl",
        "ioctl", "fcntl", "wait4",
        "splice", "tee", "copy_file_range", "sendfile", "getrusage",
    },
    "rpath": {
        "chdir", "getcwd", "open", "openat",
        "stat", "fstat", "lstat", "fstatat", "statx",
        "access", "faccessat", "faccessat2",
        "readlink", "readlinkat", "statfs", "fstatfs",
        "getdents", "getdents64",
    },
    "wpath": {
        "getcwd", "open", "openat",
        "stat", "fstat", "lstat", "fstatat", "statx",
        "access", "faccessat", "faccessat2",
        "readlink", "readlinkat",
        "chmod", "fchmod", "fchmodat", "utimensat", "futimesat", "utime",
    },
    "cpath": {
        "open", "openat", "rename", "renameat", "renameat2",
        "link", "linkat", "symlink", "symlinkat",
        "unlink", "unlinkat", "rmdir", "mkdir", "mkdirat", "creat",
    },
    "dpath": {"mknod", "mknodat"},
    "chown": {"chown", "fchown", "lchown", "fchownat"},
    "flock": {"flock", "fcntl"},
    "fattr": {"chmod", "fchmod", "fchmodat", "utime", "utimensat", "futimesat"},
    "tty": {"ioctl"},
    "inet": {
        "socket", "listen", "bind", "connect", "accept", "accept4",
        "getpeername", "getsockname", "setsockopt", "getsockopt",
        "sendto", "sendmsg", "recvfrom", "recvmsg",
    },
    "unix": {
        "socket", "listen", "bind", "connect", "accept", "accept4",
        "getpeername", "getsockname", "setsockopt", "getsockopt",
        "sendto", "sendmsg", "recvfrom", "recvmsg",
    },
    "dns": {"socket", "sendto", "recvfrom", "connect", "bind"},
    "proc": {
        "fork", "vfork", "clone", "kill", "wait4",
        "getpriority", "setpriority", "prlimit64", "setrlimit",
        "setpgid", "setsid", "sched_yield",
        "sched_getscheduler", "sched_setscheduler",
        "sched_get_priority_min", "sched_get_priority_max",
        "sched_getparam", "sched_setparam",
    },
    "thread": {"clone", "futex", "set_tid_address", "mmap", "mprotect",
               "getpid", "gettid"},
    "id": {
        "setuid", "setreuid", "setresuid", "setgid", "setregid",
        "setresgid", "setgroups", "setfsuid", "setfsgid",
        "prlimit64", "setrlimit", "getpriority", "setpriority",
    },
    "exec": {"execve", "execveat"},
    "prot_exec": {"mmap", "mprotect"},
    "recvfd": {"recvmsg"},
    "sendfd": {"sendmsg"},
    "tmppath": {"unlink", "unlinkat", "lstat", "fstatat", "statx"},
    "vminfo": set(),
}

_FILTERED = {"open", "openat", "socket", "ioctl", "fcntl",
             "mmap", "mprotect", "sendto", "clone"}


# ═══════════════════════════════════════════════════════════════════════
# BPF builder (pledge engine)
# ═══════════════════════════════════════════════════════════════════════

class _BPFBuilder:
    def __init__(self, promises: set[str],
                 penalty: int = SECCOMP_RET_ERRNO):
        self.promises = promises
        self.penalty = penalty | (errno.EPERM & SECCOMP_RET_DATA)
        self._insns: list[bytes] = []

    def _emit(self, i: bytes): self._insns.append(i)

    def _allow(self, nr: int):
        if nr < 0: return
        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1))
        self._emit(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

    def _load_nr(self):
        self._emit(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR))

    def build(self) -> bytes:
        self._insns.clear()
        # Arch check
        self._emit(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH))
        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0))
        self._emit(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))
        self._load_nr()

        allowed: set[int] = set()
        filtered: dict[str, set[str]] = {}
        for p in self.promises:
            for sc in PROMISE_SYSCALLS.get(p, set()):
                nr = _nr(sc)
                if nr < 0: continue
                if sc in _FILTERED:
                    filtered.setdefault(sc, set()).add(p)
                else:
                    allowed.add(nr)

        for nr in sorted(allowed):
            self._allow(nr)
        self._emit_filtered(filtered)
        self._emit(BPF_STMT(BPF_RET | BPF_K, self.penalty))
        return b"".join(self._insns)

    def _emit_filtered(self, filt: dict[str, set[str]]):
        for sc, ai in [("open", 1), ("openat", 2)]:
            if sc in filt:
                nr = _nr(sc)
                if nr >= 0: self._emit_open(nr, ai, filt[sc])
        if "socket" in filt:
            nr = _nr("socket")
            if nr >= 0: self._emit_socket(nr, filt["socket"])
        if "ioctl" in filt:
            nr = _nr("ioctl")
            if nr >= 0: self._emit_ioctl(nr, filt["ioctl"])
        if "fcntl" in filt:
            nr = _nr("fcntl")
            if nr >= 0: self._emit_fcntl(nr, filt["fcntl"])
        for sc in ("mmap", "mprotect"):
            if sc in filt:
                nr = _nr(sc)
                if nr >= 0: self._emit_prot(nr, filt[sc])
        if "sendto" in filt:
            nr = _nr("sendto")
            if nr >= 0:
                if filt["sendto"] <= {"stdio", "dns"}:
                    self._emit_sendto_null(nr)
                else:
                    self._allow(nr)
        if "clone" in filt:
            nr = _nr("clone")
            if nr >= 0: self._allow(nr)

    def _sub_block(self, nr: int, checks: list[bytes]):
        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, len(checks)))
        for c in checks: self._emit(c)
        self._load_nr()

    def _emit_open(self, nr: int, arg: int, promises: set[str]):
        rdonly = "rpath" in promises or "stdio" in promises
        wronly = "wpath" in promises
        creat = "cpath" in promises
        if rdonly and wronly and creat:
            self._allow(nr); return
        sub = [BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(arg)),
               BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_ACCMODE)]
        if rdonly:
            sub += [BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDONLY, 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)]
        if wronly:
            sub += [BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_WRONLY, 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
                    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDWR, 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)]
        if creat:
            sub += [BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(arg)),
                    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_CREAT),
                    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_CREAT, 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)]
        self._sub_block(nr, sub)

    def _emit_socket(self, nr: int, promises: set[str]):
        inet = "inet" in promises or "dns" in promises
        unix = "unix" in promises
        sub = [BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(0))]
        if inet:
            sub += [BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
                    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)]
        if unix:
            sub += [BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)]
        self._sub_block(nr, sub)

    def _emit_ioctl(self, nr: int, promises: set[str]):
        cmds = []
        if "stdio" in promises: cmds += [FIONREAD, FIONBIO, FIOCLEX, FIONCLEX]
        if "tty" in promises: cmds += [TIOCGWINSZ, TCGETS, TCSETS, TCSETSW, TCSETSF]
        sub = [BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(1))]
        for c in cmds:
            sub += [BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, c, 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)]
        self._sub_block(nr, sub)

    def _emit_fcntl(self, nr: int, promises: set[str]):
        cmds = []
        if "stdio" in promises: cmds += [F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_DUPFD_CLOEXEC]
        if "flock" in promises: cmds += [F_GETLK, F_SETLK, F_SETLKW]
        sub = [BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(1))]
        for c in cmds:
            sub += [BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, c, 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)]
        self._sub_block(nr, sub)

    def _emit_prot(self, nr: int, promises: set[str]):
        if "prot_exec" in promises or "thread" in promises:
            self._allow(nr); return
        sub = [BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(2)),
               BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_EXEC),
               BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
               BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)]
        self._sub_block(nr, sub)

    def _emit_sendto_null(self, nr: int):
        sub = [BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(4)),
               BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3),
               BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg_hi(4)),
               BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
               BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)]
        self._sub_block(nr, sub)


# ═══════════════════════════════════════════════════════════════════════
# ctypes structures
# ═══════════════════════════════════════════════════════════════════════

class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

class _LLRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64),
                ("handled_access_net", ctypes.c_uint64)]

class _LLPathBeneath(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64),
                ("parent_fd", ctypes.c_int32)]
    _pack_ = 1


# ═══════════════════════════════════════════════════════════════════════
# Low-level enforcement functions
# ═══════════════════════════════════════════════════════════════════════

def _install_seccomp(bpf_prog: bytes) -> None:
    n = len(bpf_prog) // _SF_SZ
    buf = ctypes.create_string_buffer(bpf_prog)
    prog = _SockFprog()
    prog.len = n
    prog.filter = ctypes.cast(buf, ctypes.c_void_p).value
    _prctl(PR_SET_NO_NEW_PRIVS, 1)
    libc = _get_libc()
    libc.syscall.restype = ctypes.c_long
    ret = libc.syscall(
        ctypes.c_long(NR["prctl"]),
        ctypes.c_long(PR_SET_SECCOMP),
        ctypes.c_long(SECCOMP_MODE_FILTER),
        ctypes.byref(prog), ctypes.c_long(0), ctypes.c_long(0))
    if ret < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"seccomp install: {os.strerror(e)}")


def _ll_access_mask(abi: int) -> int:
    mask = _LL_ALL_V1
    if abi >= 2: mask |= LANDLOCK_ACCESS_FS_REFER
    if abi >= 3: mask |= LANDLOCK_ACCESS_FS_TRUNCATE
    if abi >= 4: mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV
    return mask


def _perms_to_ll(perms: str, is_dir: bool) -> int:
    access = 0
    for ch in perms:
        if ch == "r": access |= _LL_READ
        elif ch == "w": access |= _LL_WRITE
        elif ch == "x": access |= _LL_EXEC
        elif ch == "c" and is_dir: access |= _LL_CREATE
        elif ch != "c":
            raise ValueError(f"unknown unveil permission '{ch}'")
    return access


def _install_landlock(rules: list[tuple[str, str]]) -> None:
    abi = Capabilities.landlock_abi()
    if abi == 0:
        raise OSError(errno.ENOSYS, "Landlock not supported (kernel < 5.13)")
    handled = _ll_access_mask(abi)
    attr = _LLRulesetAttr()
    attr.handled_access_fs = handled
    fd = _syscall(SYS_landlock_create_ruleset,
                  ctypes.byref(attr), ctypes.sizeof(attr), 0,
                  name="landlock_create_ruleset")
    try:
        for path, perms in rules:
            real = os.path.realpath(path)
            is_dir = os.path.isdir(real)
            pfd = os.open(real, O_PATH | O_CLOEXEC)
            try:
                pb = _LLPathBeneath()
                pb.allowed_access = _perms_to_ll(perms, is_dir) & handled
                pb.parent_fd = pfd
                _syscall(SYS_landlock_add_rule, fd,
                         LANDLOCK_RULE_PATH_BENEATH,
                         ctypes.byref(pb), 0,
                         name="landlock_add_rule")
            finally:
                os.close(pfd)
        _prctl(PR_SET_NO_NEW_PRIVS, 1)
        _syscall(SYS_landlock_restrict_self, fd, 0,
                 name="landlock_restrict_self")
    finally:
        os.close(fd)


def _is_dynamic_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            if f.read(4) != b"\x7fELF": return False
            f.seek(4)
            is_64 = f.read(1)[0] == 2
            if is_64:
                f.seek(32); phoff = int.from_bytes(f.read(8), "little")
                f.seek(54); phsz = int.from_bytes(f.read(2), "little")
                phnum = int.from_bytes(f.read(2), "little")
            else:
                f.seek(28); phoff = int.from_bytes(f.read(4), "little")
                f.seek(42); phsz = int.from_bytes(f.read(2), "little")
                phnum = int.from_bytes(f.read(2), "little")
            for i in range(phnum):
                f.seek(phoff + i * phsz)
                if int.from_bytes(f.read(4), "little") == 3:  # PT_INTERP
                    return True
            return False
    except (OSError, IndexError, ValueError):
        return True  # assume dynamic (safer)


def _parse_mountinfo() -> list[str]:
    mps = []
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 5: mps.append(parts[4])
    except FileNotFoundError: pass
    mps.sort()
    return mps


# ═══════════════════════════════════════════════════════════════════════
# Namespace helpers (Layer 3 — requires root)
# ═══════════════════════════════════════════════════════════════════════

def _setup_overlay_home(homepath: str, storagedir: str,
                        name: str = "default",
                        masks: Optional[set[str]] = None) -> None:
    changes = os.path.join(storagedir, f"{name}.changes")
    work = os.path.join(storagedir, f"{name}.work")
    for d in (changes, work):
        os.makedirs(d, mode=0o700, exist_ok=True)
    if masks:
        for mf in masks:
            mp = os.path.join(changes, mf)
            os.makedirs(os.path.dirname(mp), mode=0o700, exist_ok=True)
            try:
                os.mknod(mp, 0o600 | 0o020000, os.makedev(0, 0))
            except FileExistsError: pass
    data = f"lowerdir={homepath},upperdir={changes},workdir={work}"
    _mount("overlay", homepath, "overlay", 0, data)


def _setup_private_tmp(uid: int, gid: int) -> None:
    tmpdir = f"/run/sandbox/{os.environ.get('USER', 'user')}/tmp"
    os.makedirs(tmpdir, mode=0o1777, exist_ok=True)
    os.chown(tmpdir, uid, gid)
    try:
        _mount("sandbox-tmp", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV,
               "mode=1777")
    except OSError:
        _mount(tmpdir, "/tmp", None, MS_BIND)
    try:
        _mount("/tmp", "/var/tmp", None, MS_BIND)
    except OSError: pass


def _setup_namespace(cfg: dict) -> None:
    """Set up mount namespace (root-only layer)."""
    _unshare(CLONE_NEWNS)
    _mount(None, "/", None, MS_REC | MS_PRIVATE)

    uid = os.getuid()
    gid = os.getgid()

    if cfg.get("private_tmp", True):
        _setup_private_tmp(uid, gid)

    if cfg.get("overlay_home"):
        home = os.path.expanduser("~")
        storage = cfg.get("storage", os.path.join(home, ".sandbox"))
        os.makedirs(storage, mode=0o700, exist_ok=True)
        _setup_overlay_home(home, storage,
                            cfg.get("jail_name", "default"),
                            cfg.get("masks"))

    if cfg.get("empty_home"):
        home = os.path.expanduser("~")
        storage = cfg.get("storage", os.path.join(home, ".sandbox"))
        priv_home = os.path.join(storage,
                                 cfg.get("jail_name", "default") + ".home")
        os.makedirs(priv_home, mode=0o700, exist_ok=True)
        os.chown(priv_home, uid, gid)
        _mount(priv_home, home, None, MS_BIND)

    if cfg.get("readonly_root", True):
        for mp in sorted(_parse_mountinfo(), reverse=True):
            try:
                _mount(None, mp, None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC)
            except OSError: pass

    for d in cfg.get("grant_dirs", []):
        if os.path.isdir(d):
            try:
                _mount(d, d, None, MS_BIND)
                _mount(None, d, None, MS_BIND | MS_REMOUNT)
            except OSError: pass


# ═══════════════════════════════════════════════════════════════════════
# Built-in profiles
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class Profile:
    """A named sandbox configuration."""
    name: str
    description: str
    promises: str
    paths: dict[str, str] = field(default_factory=dict)
    # namespace options (root only)
    private_tmp: bool = True
    overlay_home: bool = False
    empty_home: bool = False
    readonly_root: bool = True
    masks: set[str] = field(default_factory=set)
    grant_dirs: list[str] = field(default_factory=list)
    grant_cwd: bool = True


PROFILES: dict[str, Profile] = {
    "strict": Profile(
        name="strict",
        description="Maximum lockdown — stdio only, no files, no network",
        promises="stdio",
    ),
    "readonly": Profile(
        name="readonly",
        description="Read filesystem, write stdout only",
        promises="stdio rpath tty",
    ),
    "netclient": Profile(
        name="netclient",
        description="Network client — can read files and connect out, "
                    "but cannot write to disk or spawn processes",
        promises="stdio rpath inet dns tty",
    ),
    "worker": Profile(
        name="worker",
        description="Computation worker — stdio + temp files, no network",
        promises="stdio rpath wpath cpath tmppath",
        paths={"/tmp": "rwc"},
    ),
    "claude": Profile(
        name="claude",
        description="Claude Code — read/write cwd, network, "
                    "private home, no access to ~/.ssh etc.",
        promises="stdio rpath wpath cpath fattr inet dns unix "
                 "proc exec prot_exec tty thread tmppath",
        paths={
            "/usr": "rx", "/lib": "r", "/lib64": "r",
            "/etc": "r", "/tmp": "rwc", "/var/tmp": "rwc",
            "/dev/null": "rw", "/dev/urandom": "r",
            "/proc": "r",
        },
        grant_cwd=True,
        overlay_home=True,
        private_tmp=True,
        masks={".ssh", ".gnupg", ".aws", ".config/gcloud",
               ".kube", ".docker", ".netrc"},
    ),
    "codex": Profile(
        name="codex",
        description="OpenAI Codex / similar — similar to claude",
        promises="stdio rpath wpath cpath fattr inet dns unix "
                 "proc exec prot_exec tty thread tmppath",
        paths={
            "/usr": "rx", "/lib": "r", "/lib64": "r",
            "/etc": "r", "/tmp": "rwc",
        },
        grant_cwd=True,
        overlay_home=True,
        private_tmp=True,
        masks={".ssh", ".gnupg", ".aws", ".netrc"},
    ),
    "untrusted": Profile(
        name="untrusted",
        description="Run untrusted binaries — read-only root, "
                    "empty home, private tmp, network blocked",
        promises="stdio rpath wpath cpath exec prot_exec proc "
                 "tty tmppath thread",
        paths={
            "/usr": "rx", "/lib": "r", "/lib64": "r",
            "/etc": "r", "/tmp": "rwc",
        },
        empty_home=True,
        private_tmp=True,
    ),
}


# ═══════════════════════════════════════════════════════════════════════
# The Sandbox class — the main public API
# ═══════════════════════════════════════════════════════════════════════

class Sandbox:
    """
    Unified Linux sandbox combining SECCOMP BPF, Landlock, and namespaces.

    Usage:
        # Fluent builder
        sb = Sandbox().allow("stdio rpath").see("/etc", "r")
        sb.run(["ls", "-la"])

        # Context manager for self-sandboxing
        with Sandbox().allow("stdio rpath inet").enter():
            do_network_stuff()

        # From a profile
        Sandbox.from_profile("claude").run(["claude"])

        # Keyword constructor
        Sandbox(promises="stdio rpath",
                paths={"/data": "r", "/tmp": "rwc"}).run(["my_tool"])
    """

    def __init__(self, promises: str = "",
                 paths: Optional[dict[str, str]] = None,
                 penalty: str = "eperm",
                 profile: Optional[str] = None):
        if profile:
            p = PROFILES.get(profile)
            if not p:
                raise ValueError(
                    f"unknown profile '{profile}' "
                    f"(available: {', '.join(PROFILES)})")
            self._promises: set[str] = set(p.promises.split()) if p.promises else set()
            self._paths: list[tuple[str, str]] = list(p.paths.items())
            self._ns_cfg = {
                "private_tmp": p.private_tmp,
                "overlay_home": p.overlay_home,
                "empty_home": p.empty_home,
                "readonly_root": p.readonly_root,
                "masks": p.masks,
                "grant_dirs": list(p.grant_dirs),
                "grant_cwd": p.grant_cwd,
                "jail_name": p.name,
            }
        else:
            self._promises = set(promises.split()) if promises else set()
            self._paths = list((paths or {}).items())
            self._ns_cfg: dict[str, Any] = {
                "private_tmp": False, "overlay_home": False,
                "empty_home": False, "readonly_root": False,
                "masks": set(), "grant_dirs": [], "grant_cwd": True,
            }

        self._penalty = (SECCOMP_RET_KILL_PROCESS if penalty == "kill"
                         else SECCOMP_RET_ERRNO)
        self._use_ns = False

    # ── Fluent builder methods ──

    def allow(self, promises: str) -> Sandbox:
        """Add pledge promises (space-separated)."""
        self._promises |= set(promises.split())
        return self

    def deny(self, promises: str) -> Sandbox:
        """Remove pledge promises."""
        self._promises -= set(promises.split())
        return self

    def see(self, path: str, perms: str = "r") -> Sandbox:
        """Unveil a path with permissions (r/w/x/c)."""
        self._paths.append((path, perms))
        return self

    def hide(self, *patterns: str) -> Sandbox:
        """Add mask patterns for overlay home (namespace mode)."""
        self._ns_cfg["masks"] |= set(patterns)
        return self

    def private_tmp(self, enabled: bool = True) -> Sandbox:
        """Use a private /tmp (namespace mode, needs root)."""
        self._ns_cfg["private_tmp"] = enabled
        self._use_ns = True
        return self

    def overlay_home(self, enabled: bool = True) -> Sandbox:
        """Copy-on-write home directory (namespace mode, needs root)."""
        self._ns_cfg["overlay_home"] = enabled
        self._use_ns = True
        return self

    def empty_home(self, enabled: bool = True) -> Sandbox:
        """Empty home directory (namespace mode, needs root)."""
        self._ns_cfg["empty_home"] = enabled
        self._use_ns = True
        return self

    def readonly_root(self, enabled: bool = True) -> Sandbox:
        """Make root filesystem read-only (namespace mode, needs root)."""
        self._ns_cfg["readonly_root"] = enabled
        self._use_ns = True
        return self

    def grant_dir(self, *dirs: str) -> Sandbox:
        """Grant read-write access to directories (namespace mode)."""
        self._ns_cfg["grant_dirs"].extend(dirs)
        self._use_ns = True
        return self

    def kill_on_violation(self) -> Sandbox:
        """Kill the process on violation instead of EPERM."""
        self._penalty = SECCOMP_RET_KILL_PROCESS
        return self

    # ── Profile constructor ──

    @classmethod
    def from_profile(cls, name: str) -> Sandbox:
        """Create a Sandbox from a built-in profile."""
        return cls(profile=name)

    # ── Enforcement ──

    def _enforce_pledge(self) -> None:
        """Install SECCOMP BPF filter."""
        if not self._promises or not Capabilities.has_seccomp():
            return
        if AUDIT_ARCH == 0:
            _warn(f"unsupported arch {_arch}, skipping seccomp")
            return
        bpf = _BPFBuilder(self._promises, self._penalty).build()
        n = len(bpf) // _SF_SZ
        if n > 4096:
            raise ValueError(f"BPF too large ({n} insns)")
        _install_seccomp(bpf)

    def _enforce_unveil(self) -> None:
        """Install Landlock rules."""
        if not self._paths:
            return
        if not Capabilities.has_landlock():
            _warn("Landlock not available, skipping path restrictions")
            return
        _install_landlock(self._paths)

    def _enforce_namespace(self) -> None:
        """Set up mount namespace (root only)."""
        if not self._use_ns:
            return
        if not Capabilities.is_root():
            _warn("namespace features need root, skipping "
                  "(overlay home, private tmp, etc.)")
            return
        # Add cwd to grant_dirs if requested
        if self._ns_cfg.get("grant_cwd"):
            cwd = str(Path.cwd().resolve())
            if cwd not in self._ns_cfg.get("grant_dirs", []):
                self._ns_cfg.setdefault("grant_dirs", []).append(cwd)
        _setup_namespace(self._ns_cfg)

    def _enforce_all(self) -> None:
        """Apply all three layers in order."""
        # Layer 3 first (namespace changes the filesystem view)
        self._enforce_namespace()
        # Layer 2 (Landlock restricts paths within that view)
        self._enforce_unveil()
        # Layer 1 last (SECCOMP restricts syscalls)
        self._enforce_pledge()

    # ── Execution modes ──

    @contextmanager
    def enter(self):
        """Context manager: sandbox the current process.

        WARNING: This is irreversible — restrictions persist after
        the context manager exits.  The context manager form is
        provided for code clarity, not for temporary sandboxing.
        Fork first if you need the parent to remain unsandboxed.
        """
        self._enforce_all()
        yield self

    def run(self, argv: list[str]) -> int:
        """Fork, sandbox the child, exec the command, return exit code."""
        if not argv:
            raise ValueError("sandbox.run: no command specified")

        cmd = argv[0]
        if "/" not in cmd:
            resolved = shutil.which(cmd)
            if resolved:
                cmd = resolved

        # Auto-add exec promises for the CLI wrapper path
        promises = set(self._promises)
        auto = []
        if "exec" not in promises:
            promises.add("exec"); auto.append("exec")
        if "rpath" not in promises:
            promises.add("rpath"); auto.append("rpath")
        if "prot_exec" not in promises and _is_dynamic_elf(cmd):
            promises.add("prot_exec"); auto.append("prot_exec")
        if auto:
            _info(f"auto-added: {' '.join(auto)}")
        self._promises = promises

        # Fork
        pid = os.fork()
        if pid == 0:
            try:
                self._enforce_all()
                os.execv(cmd, argv)
            except Exception as e:
                print(f"sandbox: {e}", file=sys.stderr)
                os._exit(127)

        # Parent: wait
        while True:
            try:
                _, status = os.waitpid(pid, 0)
            except ChildProcessError:
                return 1
            except InterruptedError:
                continue
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            if os.WIFSIGNALED(status):
                return 128 + os.WTERMSIG(status)

    def describe(self) -> str:
        """Return a human-readable description of the sandbox config."""
        lines = []
        if self._promises:
            lines.append(f"promises:   {' '.join(sorted(self._promises))}")
        if self._paths:
            lines.append("paths:")
            for p, perm in self._paths:
                lines.append(f"  {perm:4s}  {p}")
        ns_features = []
        if self._ns_cfg.get("private_tmp"): ns_features.append("private /tmp")
        if self._ns_cfg.get("overlay_home"): ns_features.append("overlay home")
        if self._ns_cfg.get("empty_home"): ns_features.append("empty home")
        if self._ns_cfg.get("readonly_root"): ns_features.append("read-only root")
        if ns_features:
            lines.append(f"namespace:  {', '.join(ns_features)}"
                         + (" (needs root)" if not Capabilities.is_root() else ""))
        masks = self._ns_cfg.get("masks")
        if masks:
            lines.append(f"masks:      {', '.join(sorted(masks))}")
        penalty = "kill" if self._penalty == SECCOMP_RET_KILL_PROCESS else "eperm"
        lines.append(f"penalty:    {penalty}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
# Convenience functions (pledge/unveil compatible API)
# ═══════════════════════════════════════════════════════════════════════

def pledge(promises: str) -> None:
    """OpenBSD pledge(2) compatible — restrict syscalls."""
    if not Capabilities.has_seccomp():
        raise OSError(errno.ENOSYS, "seccomp not available")
    for p in promises.split():
        if p not in PROMISE_SYSCALLS:
            raise ValueError(f"unknown promise '{p}'")
    bpf = _BPFBuilder(set(promises.split())).build()
    _install_seccomp(bpf)


_unveil_rules: list[tuple[str, str]] = []
_unveil_committed = False

def unveil(path: Optional[str] = None,
           permissions: Optional[str] = None) -> None:
    """OpenBSD unveil(2) compatible — restrict filesystem paths."""
    global _unveil_committed
    if path is None and permissions is None:
        if _unveil_committed: return
        if not _unveil_rules: return
        _install_landlock(_unveil_rules)
        _unveil_committed = True
    elif path is not None and permissions is not None:
        if _unveil_committed:
            raise OSError(errno.EPERM, "unveil already committed")
        _unveil_rules.append((path, permissions))
    else:
        raise ValueError("both path and permissions must be None or strings")


# ═══════════════════════════════════════════════════════════════════════
# Utility
# ═══════════════════════════════════════════════════════════════════════

def _warn(msg: str):
    print(f"sandbox: {msg}", file=sys.stderr)

def _info(msg: str):
    print(f"sandbox: {msg}", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════

def _cli_main() -> None:
    parser = argparse.ArgumentParser(
        prog="sandbox",
        description="Unified Linux sandboxing for AI agents and untrusted code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # ── sandbox run ──
    run_p = sub.add_parser("run", help="Run a command in a sandbox",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        examples:
          sandbox run -p "stdio rpath" -- ls -la
          sandbox run --profile claude -- claude
          sandbox run -p "stdio rpath wpath" -v rwc:. -- bash
          sandbox run -p "stdio rpath" -v /etc -v /usr -- cat /etc/hostname
        """))
    run_p.add_argument("-p", "--promises", default="",
                       help="pledge promises (space-separated)")
    run_p.add_argument("--profile", choices=list(PROFILES),
                       help="use a built-in profile")
    run_p.add_argument("-v", "--unveil", action="append", default=[],
                       metavar="[PERM:]PATH",
                       help="unveil PATH (default perm: r). Repeatable.")
    run_p.add_argument("-V", "--no-unveil", action="store_true",
                       help="disable path restrictions")
    run_p.add_argument("--penalty", choices=["eperm", "kill"],
                       default="eperm")
    run_p.add_argument("--private-tmp", action="store_true",
                       help="private /tmp (needs root)")
    run_p.add_argument("--overlay-home", action="store_true",
                       help="copy-on-write home (needs root)")
    run_p.add_argument("--empty-home", action="store_true",
                       help="empty home directory (needs root)")
    run_p.add_argument("--readonly-root", action="store_true",
                       help="read-only root fs (needs root)")
    run_p.add_argument("-d", "--dir", action="append", default=[],
                       help="grant rw dir (namespace mode)")
    run_p.add_argument("--mask", action="append", default=[],
                       help="mask file in overlay home")
    run_p.add_argument("argv", nargs="*", metavar="cmd",
                       help="command to run")

    # ── sandbox test ──
    sub.add_parser("test", help="Show kernel capabilities")

    # ── sandbox profiles ──
    sub.add_parser("profiles", help="List built-in profiles")

    # ── sandbox describe ──
    desc_p = sub.add_parser("describe", help="Show what a profile does")
    desc_p.add_argument("profile_name", choices=list(PROFILES))

    args = parser.parse_args()

    if args.command == "test":
        print(Capabilities.summary())
        sys.exit(0)

    if args.command == "profiles":
        for name, p in PROFILES.items():
            print(f"  {name:12s}  {p.description}")
        sys.exit(0)

    if args.command == "describe":
        sb = Sandbox.from_profile(args.profile_name)
        print(sb.describe())
        sys.exit(0)

    if args.command == "run":
        if not args.argv and not args.profile:
            run_p.error("no command specified (use -- cmd args...)")

        if args.profile:
            sb = Sandbox.from_profile(args.profile)
            if args.promises:
                sb.allow(args.promises)
        else:
            sb = Sandbox(promises=args.promises, penalty=args.penalty)

        # Unveil flags
        if not args.no_unveil:
            for vspec in args.unveil:
                if ":" in vspec and len(vspec.split(":", 1)[0]) <= 4:
                    perms, path = vspec.split(":", 1)
                else:
                    perms, path = "r", vspec
                sb.see(path, perms)

        # Namespace flags
        if args.private_tmp: sb.private_tmp()
        if args.overlay_home: sb.overlay_home()
        if args.empty_home: sb.empty_home()
        if args.readonly_root: sb.readonly_root()
        for d in args.dir: sb.grant_dir(d)
        for m in args.mask: sb.hide(m)

        code = sb.run(args.argv)
        sys.exit(code)

    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    _cli_main()
