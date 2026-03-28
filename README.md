# sandbox

<p align="center">
  <img src="sandbox.png" alt="Choke that app" width="400">
</p>
<p align="center">
<b>Three layers of Linux sandboxing in one Python file</b>
</p>

```python
from sandbox import Sandbox

Sandbox() \
    .allow("stdio rpath") \
    .see("/data", "r") \
    .run(["my-agent"])
```

No C compiler. No pip install. No root required. Just drop `sandbox.py` into your project.

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3: Namespaces    private /tmp, overlay home, PID isolation│
│  Layer 2: Landlock      /data=read  /tmp=write  everything else=hidden │
│  Layer 1: SECCOMP BPF   stdio ✓  rpath ✓  inet ✗  fork ✗  exec ✗      │
└─────────────────────────────────────────────────────────────────┘
  Each layer is optional. Each auto-detects. Each degrades gracefully.
```

---

## Table of Contents

- [Install](#install)
- [Three Ways to Use It](#three-ways-to-use-it)
- [CLI Reference](#cli-reference)
- [Library API](#library-api)
  - [Sandbox Class](#sandbox-class)
  - [Fluent Builder Methods](#fluent-builder-methods)
  - [pledge() and unveil()](#pledge-and-unveil)
- [Built-in Profiles](#built-in-profiles)
- [The Three Layers](#the-three-layers)
- [Promise Reference](#promise-reference)
- [Path Permission Reference](#path-permission-reference)
- [Examples](#examples)
  - [Sandbox an AI Agent](#sandbox-an-ai-agent)
  - [Read-Only Data Pipeline](#read-only-data-pipeline)
  - [Network Client With No Disk Access](#network-client-with-no-disk-access)
  - [Progressive Privilege Dropping](#progressive-privilege-dropping)
  - [Untrusted Plugin Runner](#untrusted-plugin-runner)
  - [AI Code Execution Enclave](#ai-code-execution-enclave)
  - [Full Three-Layer Sandbox](#full-three-layer-sandbox)
  - [Custom Profile for Your Tool](#custom-profile-for-your-tool)
  - [Build System Sandbox](#build-system-sandbox)
  - [Self-Sandboxing Server](#self-sandboxing-server)
- [CLI Examples](#cli-examples)
- [How It Works](#how-it-works)
- [Kernel Compatibility](#kernel-compatibility)
- [Caveats](#caveats)
- [Requirements](#requirements)

---

## Install

```bash
# That's it. One file, zero dependencies.
curl -O https://raw.githubusercontent.com/tensor-goat/sandbox/main/sandbox.py

# Verify it works on your kernel:
python3 sandbox.py test
```

Output on a modern system:

```
kernel:      6.8.0 / x86_64
seccomp:     yes
landlock:    ABI v4 (needs >= 5.13)
overlayfs:   yes
pid ns:      yes
root:        no
namespaces:  needs root
```

---

## Three Ways to Use It

### 1. Command-line wrapper

```bash
# Run ls with only stdio + read permissions
sandbox run -p "stdio rpath" -- ls -la

# Use a built-in profile for Claude Code
sandbox run --profile claude -- claude

# Restrict both operations AND paths
sandbox run -p "stdio rpath" -v /etc -v /usr -- cat /etc/hostname
```

### 2. Python library (fluent builder)

```python
from sandbox import Sandbox

# Build, configure, run
Sandbox() \
    .allow("stdio rpath wpath cpath") \
    .see("/data", "r") \
    .see("/output", "rwc") \
    .run(["process_data", "--input", "/data/in.csv"])
```

### 3. Python library (self-sandboxing)

```python
from sandbox import Sandbox

# Everything after enter() is restricted — irreversibly
with Sandbox().allow("stdio rpath").enter():
    config = open("/etc/myapp.conf").read()
    # socket.socket()  → PermissionError
    # os.fork()        → PermissionError
    # open("x", "w")   → PermissionError
```

---

## CLI Reference

```
sandbox test                                  # show kernel capabilities
sandbox profiles                              # list built-in profiles
sandbox describe <profile>                    # show what a profile does
sandbox run [flags] -- command [args...]       # run a sandboxed command
```

### `sandbox run` flags

| Flag | Description |
|------|-------------|
| `-p PROMISES` | Pledge promises (space-separated) |
| `--profile NAME` | Use a built-in profile |
| `-v [PERM:]PATH` | Unveil a path (default perm: `r`). Repeatable. |
| `-V` | Disable path restrictions (pledge only) |
| `--penalty eperm\|kill` | EPERM on violation (default) or kill process |
| `--private-tmp` | Private /tmp directory (needs root) |
| `--overlay-home` | Copy-on-write home directory (needs root) |
| `--empty-home` | Empty home directory (needs root) |
| `--readonly-root` | Read-only root filesystem (needs root) |
| `-d DIR` | Grant read-write access to DIR (needs root) |
| `--mask FILE` | Hide FILE in overlay home (needs root) |

---

## Library API

### Sandbox Class

```python
from sandbox import Sandbox

# Constructor
sb = Sandbox(
    promises="stdio rpath",         # pledge promises
    paths={"/data": "r"},           # unveil rules
    penalty="eperm",                # or "kill"
    profile="claude",               # use a built-in profile
)

# Execution
sb.run(["command", "arg1"])          # fork + sandbox + exec → exit code
with sb.enter():                     # sandbox current process (irreversible)
    ...

# Introspection
print(sb.describe())                 # human-readable summary

# Profile constructor
sb = Sandbox.from_profile("claude")
```

### Fluent Builder Methods

Every method returns `self`, so you can chain them:

```python
sb = Sandbox() \
    .allow("stdio rpath inet dns") \       # add promises
    .deny("dns") \                          # remove a promise
    .see("/etc", "r") \                     # unveil path (read)
    .see("/tmp", "rwc") \                   # unveil path (read+write+create)
    .hide(".ssh", ".gnupg") \               # mask files in overlay home
    .private_tmp() \                        # namespace: private /tmp
    .overlay_home() \                       # namespace: copy-on-write home
    .empty_home() \                         # namespace: empty home
    .readonly_root() \                      # namespace: read-only /
    .grant_dir("/workspace") \              # namespace: rw directory
    .kill_on_violation()                    # kill instead of EPERM
```

| Method | Layer | Needs root? | Description |
|--------|-------|-------------|-------------|
| `.allow(promises)` | SECCOMP | No | Add pledge promise categories |
| `.deny(promises)` | SECCOMP | No | Remove promise categories |
| `.see(path, perms)` | Landlock | No | Unveil a path with permissions |
| `.hide(*patterns)` | Namespace | Yes | Mask files in overlay home |
| `.private_tmp()` | Namespace | Yes | Isolated /tmp |
| `.overlay_home()` | Namespace | Yes | Copy-on-write home directory |
| `.empty_home()` | Namespace | Yes | Start with empty home |
| `.readonly_root()` | Namespace | Yes | Read-only root filesystem |
| `.grant_dir(*dirs)` | Namespace | Yes | Read-write access to specific dirs |
| `.kill_on_violation()` | SECCOMP | No | Kill process on violation |

### pledge() and unveil()

For code that just wants the OpenBSD-compatible API:

```python
from sandbox import pledge, unveil

unveil("/etc",  "r")        # can read /etc
unveil("/tmp",  "rwc")      # can read/write/create in /tmp
unveil(None,    None)        # everything else disappears

pledge("stdio rpath wpath")  # no network, no fork, no exec

open("/etc/hostname").read()        # ✓
open("/tmp/out.txt", "w").write("") # ✓
open("/home/user/.ssh/id_rsa")      # ✗ EACCES — not unveiled
import socket; socket.socket()      # ✗ EPERM  — no inet promise
os.fork()                           # ✗ EPERM  — no proc promise
```

---

## Built-in Profiles

```bash
$ sandbox profiles
  strict        Maximum lockdown — stdio only, no files, no network
  readonly      Read filesystem, write stdout only
  netclient     Network client — can read files and connect out, but cannot write to disk
  worker        Computation worker — stdio + temp files, no network
  claude        Claude Code — read/write cwd, network, private home, no ~/.ssh etc.
  codex         OpenAI Codex / similar — similar to claude
  untrusted     Run untrusted binaries — read-only root, empty home, network blocked
```

```bash
$ sandbox describe claude
promises:   cpath dns exec fattr inet proc prot_exec rpath stdio thread tmppath tty unix wpath
paths:
  rx    /usr
  r     /lib
  r     /lib64
  r     /etc
  rwc   /tmp
  rwc   /var/tmp
  rw    /dev/null
  r     /dev/urandom
  r     /proc
namespace:  private /tmp, overlay home, read-only root
masks:      .aws, .config/gcloud, .docker, .gnupg, .kube, .netrc, .ssh
penalty:    eperm
```

Profiles combine all three layers with settings tuned for each use case. When run without root, namespace features (overlay home, private /tmp) are skipped with a warning — the SECCOMP and Landlock layers still enforce.

---

## The Three Layers

sandbox combines three independent kernel mechanisms. Each addresses a different dimension of isolation:

### Layer 1: SECCOMP BPF — What can the process DO?

Controls which system calls are allowed. Implemented via pledge promises.

```python
.allow("stdio rpath")        # read files and do basic I/O
.allow("inet dns")           # add network access
.deny("proc")                # cannot fork
```

Available on kernel ≥ 3.5. No root required.

### Layer 2: Landlock LSM — What can the process SEE?

Controls which filesystem paths are accessible. Implemented via unveil rules.

```python
.see("/etc", "r")            # read-only access to /etc
.see("/tmp", "rwc")          # full access to /tmp
# everything else → EACCES
```

Available on kernel ≥ 5.13. No root required.

### Layer 3: Linux Namespaces — What does the process THINK exists?

Changes the process's entire view of the system. Overlay home directories, private /tmp, read-only root filesystem, PID isolation.

```python
.overlay_home()              # copy-on-write home
.private_tmp()               # isolated /tmp
.readonly_root()             # read-only /
.hide(".ssh", ".gnupg")      # files vanish from home
```

Requires root (or `CAP_SYS_ADMIN`). Gracefully skipped when running as a normal user.

### Why three layers?

Defense in depth. If an attacker escapes the namespace (kernel bug in overlayfs), Landlock still blocks the path. If they bypass Landlock (leaked file descriptor), SECCOMP still blocks them from opening sockets or forking.

| Attack | Namespace blocks? | Landlock blocks? | SECCOMP blocks? |
|--------|:-:|:-:|:-:|
| Read ~/.ssh/id_rsa | ✓ file hidden by overlay | ✓ path not unveiled | — |
| Open a network socket | — | — | ✓ no inet promise |
| Fork a bitcoin miner | — | — | ✓ no proc promise |
| Write to /etc/passwd | ✓ root is read-only | ✓ /etc not unveiled for write | ✓ no wpath promise |
| Mount a new filesystem | ✓ separate namespace | — | ✓ no mount syscall |
| Read /proc/1/environ | ✓ private PID ns | ✓ /proc not unveiled | — |

---

## Promise Reference

| Promise | What it allows |
|---------|---------------|
| `stdio` | read, write, close, pipe, poll, mmap (no PROT_EXEC), brk, futex, clocks, signals, dup, getrandom, exit |
| `rpath` | open(O_RDONLY), stat, access, readlink, getcwd, chdir, getdents |
| `wpath` | open(O_WRONLY/O_RDWR), chmod, utimensat |
| `cpath` | open(O_CREAT), mkdir, rmdir, unlink, rename, link, symlink |
| `dpath` | mknod (device nodes) |
| `chown` | chown, fchown, lchown |
| `flock` | flock, fcntl(F_GETLK/F_SETLK) |
| `fattr` | chmod, utime, utimensat |
| `tty` | ioctl(TIOCGWINSZ/TCGETS/TCSETS*) |
| `inet` | socket(AF_INET/AF_INET6), bind, listen, connect, accept, send*, recv* |
| `unix` | socket(AF_UNIX) + same ops as inet |
| `dns` | socket(AF_INET) + sendto, recvfrom, connect (restricted) |
| `proc` | fork, vfork, clone, kill, wait4, setpgid, sched_* |
| `thread` | clone (threads), futex, mmap with PROT_EXEC |
| `exec` | execve, execveat |
| `prot_exec` | PROT_EXEC in mmap/mprotect (dynamic linking, JIT) |
| `id` | setuid, setgid, setgroups, setfsuid |
| `recvfd` | recvmsg (SCM_RIGHTS) |
| `sendfd` | sendmsg (SCM_RIGHTS) |
| `tmppath` | unlink, lstat (temp file cleanup) |
| `vminfo` | /proc system info paths |

---

## Path Permission Reference

| Char | Operations | Landlock rights |
|------|-----------|----------------|
| `r` | Read files, list directories | READ_FILE, READ_DIR |
| `w` | Write to files, truncate | WRITE_FILE, TRUNCATE |
| `x` | Execute files | EXECUTE |
| `c` | Create/remove files and directories | MAKE_*, REMOVE_*, REFER |

Common combinations: `"r"` (config dirs), `"rw"` (logs), `"rx"` (/usr/bin), `"rwc"` (working dirs, /tmp).

---

## Examples

### Sandbox an AI Agent

```bash
# Quick: use the built-in claude profile
sandbox run --profile claude -- claude

# Or build your own policy
sandbox run \
    -p "stdio rpath wpath cpath inet dns exec prot_exec proc tty thread" \
    -v rx:/usr -v r:/etc -v rwc:/tmp -v rwc:. \
    --overlay-home --private-tmp \
    --mask .ssh --mask .gnupg --mask .aws \
    -- claude
```

```python
# Same thing from Python
Sandbox.from_profile("claude").run(["claude"])
```

### Read-Only Data Pipeline

```python
from sandbox import Sandbox

# Process CSV files — cannot modify or delete anything
exit_code = Sandbox() \
    .allow("stdio rpath") \
    .see("/data", "r") \
    .run(["python3", "process.py", "/data/input.csv"])
```

### Network Client With No Disk Access

```python
import socket, ssl
from sandbox import Sandbox

context = ssl.create_default_context()

with Sandbox().allow("stdio rpath inet dns").enter():
    sock = socket.create_connection(("api.example.com", 443))
    ssock = context.wrap_socket(sock, server_hostname="api.example.com")
    ssock.sendall(b"GET /data HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
    print(ssock.recv(4096).decode())

    # open("/tmp/exfil.txt", "w")  → PermissionError
    # os.fork()                    → PermissionError
```

### Progressive Privilege Dropping

```python
from sandbox import pledge

# Phase 1: read files + network
pledge("stdio rpath inet dns")
config = open("settings.json").read()

# Phase 2: done with files
pledge("stdio inet")
send_data_to_api(config)

# Phase 3: done with network
pledge("stdio")
print("All done")
```

### Untrusted Plugin Runner

```python
from sandbox import Sandbox
import json, os

def run_plugin(name: str, data: dict) -> dict:
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        plugin = __import__(f"plugins.{name}", fromlist=[name])

        with Sandbox().allow("stdio").enter():
            try:
                result = plugin.process(data)
                os.write(w, json.dumps({"ok": result}).encode())
            except Exception as e:
                os.write(w, json.dumps({"error": str(e)}).encode())
        os._exit(0)

    os.close(w)
    out = b""
    while chunk := os.read(r, 4096): out += chunk
    os.close(r)
    os.waitpid(pid, 0)
    return json.loads(out)

# Plugin can compute but cannot:
#   open files, connect to network, fork, exec, access terminal
```

### AI Code Execution Enclave

```python
from sandbox import Sandbox
import json, os

def safe_exec(code: str, inputs: dict) -> dict:
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        with Sandbox().allow("stdio").enter():
            ns = {"data": inputs}
            try:
                exec(code, ns)
                os.write(w, json.dumps({"output": ns.get("output")}).encode())
            except Exception as e:
                os.write(w, json.dumps({"error": str(e)}).encode())
        os._exit(0)

    os.close(w)
    buf = b""
    while chunk := os.read(r, 4096): buf += chunk
    os.close(r)
    _, st = os.waitpid(pid, 0)
    if os.WIFSIGNALED(st):
        return {"error": f"killed by signal {os.WTERMSIG(st)}"}
    return json.loads(buf)

# Safe computation
r = safe_exec('output = sum(data["n"])', {"n": [1,2,3]})
# → {"output": 6}

# Malicious code gets EPERM on everything
r = safe_exec('import socket; socket.socket()', {})
# → {"error": "[Errno 1] Operation not permitted"}

r = safe_exec('open("/etc/shadow").read()', {})
# → {"error": "[Errno 1] Operation not permitted"}
```

### Full Three-Layer Sandbox

All three layers at maximum strength (requires root for namespace layer):

```python
sb = Sandbox() \
    .allow("stdio rpath wpath cpath") \
    .see("/project/src", "r") \
    .see("/project/build", "rwc") \
    .see("/usr", "rx") \
    .see("/lib", "r") \
    .see("/tmp", "rwc") \
    .overlay_home() \
    .private_tmp() \
    .readonly_root() \
    .grant_dir("/project/build") \
    .hide(".ssh", ".gnupg", ".aws", ".docker") \
    .kill_on_violation()

sb.run(["make", "-j8"])
```

What this creates:
- **Namespace**: overlayfs home (writes go to `.sandbox/default.changes`), private /tmp, read-only root, /project/build granted rw. The process cannot see your real .ssh keys.
- **Landlock**: only /project/src (read), /project/build (full), /usr (execute), /lib (read), /tmp (full) are accessible. Everything else returns EACCES.
- **SECCOMP**: only stdio + filesystem operations allowed. No network, no process spawning beyond the initial exec.

### Custom Profile for Your Tool

```python
from sandbox import Sandbox, Profile, PROFILES

# Register your own profile
PROFILES["my-agent"] = Profile(
    name="my-agent",
    description="My custom AI agent — network + read cwd",
    promises="stdio rpath inet dns tty exec prot_exec proc thread",
    paths={
        "/usr": "rx", "/lib": "r", "/lib64": "r",
        "/etc/ssl": "r", "/etc/resolv.conf": "r",
        "/tmp": "rwc",
    },
    grant_cwd=True,
    overlay_home=True,
    private_tmp=True,
    masks={".ssh", ".gnupg", ".aws", ".netrc", ".env"},
)

# Now usable from CLI and library
Sandbox.from_profile("my-agent").run(["my-agent", "--chat"])
```

### Build System Sandbox

Restrict a compiler to declared inputs and outputs:

```python
from sandbox import Sandbox

def sandboxed_build(sources: list[str], output: str, cmd: list[str]):
    sb = Sandbox() \
        .allow("stdio rpath wpath cpath exec prot_exec proc tmppath thread")

    for src in sources:
        sb.see(src, "r")                 # source: read-only
    sb.see(output, "rwc")                # output: full access
    sb.see("/usr", "rx")                 # compilers
    sb.see("/lib", "r")                  # shared libs
    sb.see("/tmp", "rwc")                # compiler temp files

    return sb.run(cmd)

sandboxed_build(
    sources=["src/", "include/"],
    output="build/",
    cmd=["gcc", "-o", "build/main", "src/main.c"]
)
```

### Self-Sandboxing Server

```python
import socket
from sandbox import Sandbox

# Load everything before sandboxing
import json, mimetypes

with Sandbox() \
    .allow("stdio rpath wpath inet tty") \
    .see("./public", "r") \
    .see("./logs", "rw") \
    .see("/etc/ssl", "r") \
    .see("/usr/lib", "r") \
    .enter():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 8080))
    server.listen(128)

    while True:
        client, addr = server.accept()
        # Can only read from ./public, write to ./logs
        # Cannot exec, fork, or access anything else
        client.close()
```

---

## CLI Examples

```bash
# Basic: read-only ls
sandbox run -p "stdio rpath" -- ls -la /etc/

# With path restrictions
sandbox run -p "stdio rpath" -v /etc -v /usr -- cat /etc/hostname

# With write access to current directory
sandbox run -p "stdio rpath wpath cpath" -v rwc:. -- python3 my_script.py

# Use a profile
sandbox run --profile readonly -- less /var/log/syslog

# Kill on violation (for truly untrusted code)
sandbox run --penalty kill -p "stdio rpath" -- ./untrusted_binary

# Full namespace isolation (requires root)
sudo sandbox run \
    --profile untrusted \
    --overlay-home --private-tmp --readonly-root \
    -d /workspace \
    -- ./agent

# Check what a profile does
sandbox describe claude

# Show what your kernel supports
sandbox test
```

---

## How It Works

```
                    Sandbox()
                       │
          ┌────────────┼────────────┐
          │            │            │
     .allow()      .see()     .overlay_home()
     .deny()                  .private_tmp()
          │            │      .readonly_root()
          │            │            │
          ▼            ▼            ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐
    │ SECCOMP  │ │ Landlock │ │ Mount NS │
    │ BPF      │ │ LSM      │ │          │
    │          │ │          │ │          │
    │ Promise  │ │ Path +   │ │ overlay  │
    │ → syscall│ │ perms →  │ │ bind     │
    │ allow/   │ │ ruleset  │ │ tmpfs    │
    │ deny     │ │          │ │ remount  │
    └────┬─────┘ └────┬─────┘ └────┬─────┘
         │            │            │
         └────────────┼────────────┘
                      │
                      ▼
              ┌──────────────┐
              │    Kernel    │
              │              │
              │  Every       │
              │  syscall:    │
              │   1. ns view │
              │   2. landlock│
              │   3. seccomp │
              │              │
              │  All three   │
              │  must allow  │
              └──────────────┘
```

**SECCOMP BPF** (Layer 1): A `_BPFBuilder` compiles promise strings into BPF bytecode — an array of `sock_filter` structs packed as 8-byte instructions. The program validates the architecture, checks the syscall number, and for filtered syscalls (open, socket, ioctl, mmap, etc.) inspects argument values. Installed via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`.

**Landlock** (Layer 2): Unveil rules are collected, then committed atomically. A ruleset is created with `landlock_create_ruleset`, rules are added with `landlock_add_rule(LANDLOCK_RULE_PATH_BENEATH)` using `O_PATH` file descriptors, and enforced with `landlock_restrict_self`. ABI versions 1–4 are handled, with newer access rights used when available.

**Namespaces** (Layer 3): `unshare(CLONE_NEWNS)` creates a private mount namespace. Within it: overlayfs mounts a copy-on-write layer over home, tmpfs provides a private /tmp, the root is remounted read-only, and specific directories are bind-mounted read-write. Whiteout files mask sensitive dotfiles.

Layers are applied in reverse order (3 → 2 → 1) so that namespaces reshape the filesystem view before Landlock restricts paths within that view, and SECCOMP restricts operations last.

---

## Kernel Compatibility

| Feature | Minimum kernel | Root needed? | Fallback |
|---------|:-:|:-:|---|
| pledge (SECCOMP BPF) | 3.5 | No | None — always available on modern Linux |
| unveil (Landlock) | 5.13 | No | Skipped with warning |
| Private /tmp | 3.8 | Yes | Skipped with warning |
| Overlay home | 3.18 | Yes | Skipped with warning |
| PID namespace | 3.8 | Yes | Skipped with warning |
| Read-only root | 3.8 | Yes | Skipped with warning |
| Landlock ABI v2 (REFER) | 5.19 | No | Silently omitted |
| Landlock ABI v3 (TRUNCATE) | 6.2 | No | Silently omitted |
| Landlock ABI v4 (IOCTL_DEV) | 6.8 | No | Silently omitted |

**Architecture support:** x86_64 and aarch64 (full syscall tables). Other architectures need NR table entries added.

The design philosophy is: **always do the best you can with what's available, never refuse to run.** On a 4.4.0 kernel without root, you still get full SECCOMP enforcement. On a 6.8+ kernel with root, you get all three layers at full strength.

---

## Caveats

**Import before sandboxing.** Python's `import` opens files and loads shared libraries. Do your imports before calling `pledge()`, `unveil()`, or `.enter()`.

```python
# ✓ Correct
import json, csv, socket
from sandbox import Sandbox
with Sandbox().allow("stdio").enter(): ...

# ✗ Wrong — import triggers blocked operations
from sandbox import Sandbox
with Sandbox().allow("stdio").enter():
    import json  # PermissionError
```

**Self-sandboxing is irreversible.** The `.enter()` context manager and `pledge()` function permanently restrict the current process. The context manager syntax is for code clarity, not for temporary sandboxing. Fork first if the parent must remain free.

**`.run()` forks automatically.** The `.run()` method forks a child, sandboxes it, and execs. The parent is never sandboxed. This is the safe default for wrapping external commands.

**Namespace features need root.** `.overlay_home()`, `.private_tmp()`, `.readonly_root()`, and `.grant_dir()` require root or `CAP_SYS_ADMIN`. Without root, they are skipped with a warning — the other two layers still enforce.

**Landlock commits are batched.** Unlike OpenBSD where each `unveil()` takes immediate effect, on Linux rules are collected and only enforced when you call `unveil(None, None)` (or when `.enter()` / `.run()` commits them).

**Cumulative filters.** Each `pledge()` installs an additional SECCOMP filter. Each Landlock commit creates a new domain. The kernel takes the most restrictive result, so you can narrow but never widen.

**glibc internals.** glibc uses `futex`, `rseq`, `mremap` even in single-threaded programs. The `stdio` promise includes these. If something breaks, `strace` will show which syscall got `EPERM`.

---

## Requirements

- **Linux** kernel ≥ 3.5 for pledge, ≥ 5.13 for unveil, root for namespaces
- **Python** ≥ 3.10
- **No root** required for pledge + unveil (the two most useful layers)
- **No dependencies** — pure stdlib + ctypes
- **Single file** — 1,416 lines, just copy `sandbox.py`

---

## License

MIT License
