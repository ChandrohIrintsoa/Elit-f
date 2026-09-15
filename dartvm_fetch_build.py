import re
import glob
import mmap
from collections import deque
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request

GIT_CMD = os.getenv('GIT', 'git')
CMAKE_CMD = os.getenv('CMAKE', 'cmake')
NINJA_CMD = os.getenv('NINJA', 'ninja')

TERMUX_INSTALL_HINT = (
    "pkg install git cmake ninja clang python pkg-config capstone"
    "  &&  pip install pyelftools requests rich"
)
GENERIC_INSTALL_HINT = (
    "Install: git, cmake, ninja, a C++20 compiler (clang/gcc), python3"
    "  then:  pip install -r requirements.txt"
)

TERMUX_USR_BIN = '/data/data/com.termux/files/usr/bin'
TERMUX_HOME_LOCAL_BIN = '/data/data/com.termux/files/home/.local/bin'

def _is_termux_env():
    if os.environ.get('TERMUX_VERSION'):
        return True
    if os.path.isdir('/data/data/com.termux'):
        return True
    prefix = os.environ.get('PREFIX', '')
    return 'com.termux' in prefix

def _tool_search_dirs():
    dirs = []
    prefix = os.environ.get('PREFIX', '')
    if prefix:
        dirs.append(os.path.join(prefix, 'bin'))
    dirs.append(TERMUX_USR_BIN)
    dirs.append(TERMUX_HOME_LOCAL_BIN)
    for pattern in ('/data/data/*/files/usr/bin', '/data/data/*/files/home/.local/bin'):
        dirs.extend(sorted(glob.glob(pattern)))
    dirs.append(os.path.expanduser('~/.local/bin'))
    try:
        import sysconfig
        dirs.append(sysconfig.get_path('scripts'))
        user_base = sysconfig.get_config_var('userbase')
        if user_base:
            dirs.append(os.path.join(user_base, 'bin'))
    except (ImportError, ValueError, KeyError):
        pass
    try:
        import site
        dirs.append(os.path.join(site.getuserbase(), 'bin'))
    except (ImportError, AttributeError):
        pass
    dirs.append(os.path.dirname(os.path.abspath(sys.executable)))
    for mod_name, attr in (('cmake', 'CMAKE_BIN_DIR'), ('ninja', 'BIN_DIR')):
        try:
            mod = __import__(mod_name)
            mod_dir = os.path.dirname(os.path.abspath(getattr(mod, '__file__', '')))
            dirs.append(getattr(mod, attr, '') or os.path.join(mod_dir, 'data', 'bin'))
        except (ImportError, AttributeError, OSError):
            pass
    seen = set()
    unique = []
    for d in dirs:
        if d and d not in seen:
            seen.add(d)
            unique.append(d)
    return unique

def _find_tool(candidates, extra_dirs=()):
    for name in candidates:
        if not name:
            continue
        path = shutil.which(name)
        if path:
            return path
    for d in extra_dirs:
        if not d or not os.path.isdir(d):
            continue
        for name in candidates:
            if not name:
                continue
            p = os.path.join(d, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
    return None

def _rmtree_rw(path, handler):
    try:
        shutil.rmtree(path, onerror=handler)
    except TypeError:
        shutil.rmtree(path, onexc=handler)

def _candidate_names(label):
    if label == 'git':
        return (os.getenv('GIT') or 'git',)
    if label == 'cmake':
        return (os.getenv('CMAKE') or 'cmake', 'cmake3')
    if label == 'ninja':
        return (os.getenv('NINJA') or 'ninja',)
    return (label,)

def _blocked_tool_paths(labels, dirs):
    blocked = []
    for label in labels:
        for name in _candidate_names(label):
            if not name:
                continue
            for d in dirs:
                if not d or not os.path.isdir(d):
                    continue
                p = os.path.join(d, name)
                if os.path.isfile(p) and not os.access(p, os.X_OK) and p not in blocked:
                    blocked.append(p)
    return blocked

def resolve_build_tools():
    global GIT_CMD, CMAKE_CMD, NINJA_CMD
    dirs = _tool_search_dirs()
    git_path = _find_tool(_candidate_names('git'), dirs)
    cmake_path = _find_tool(_candidate_names('cmake'), dirs)
    ninja_path = _find_tool(_candidate_names('ninja'), dirs)
    if git_path:
        GIT_CMD = git_path
    if cmake_path:
        CMAKE_CMD = cmake_path
    if ninja_path:
        NINJA_CMD = ninja_path
    return {'git': git_path, 'cmake': cmake_path, 'ninja': ninja_path}

def _autoinstall_disabled():
    return os.getenv('ELITF_AUTOINSTALL', '').strip().lower() in ('0', 'off', 'false', 'no')

def _pkg_binary():
    dirs = []
    prefix = os.environ.get('PREFIX', '')
    if prefix:
        dirs.append(os.path.join(prefix, 'bin'))
    dirs.append(TERMUX_USR_BIN)
    for d in dirs:
        p = os.path.join(d, 'pkg')
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return shutil.which('pkg')

def _pkg_install(names):
    pkg = _pkg_binary()
    if not pkg:
        return False, 'pkg not found in $PREFIX/bin'
    install_cmd = [pkg, 'install', '-y'] + list(names)
    try:
        proc = subprocess.run(install_cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            subprocess.run([pkg, 'update', '-y'], capture_output=True, text=True)
            proc = subprocess.run(install_cmd, capture_output=True, text=True)
    except OSError as e:
        return False, str(e)
    if proc.returncode == 0:
        return True, 'ok'
    out = (proc.stdout or '') + (proc.stderr or '')
    tail = [line.strip() for line in out.splitlines() if line.strip()]
    return False, (tail[-1] if tail else f'exit code {proc.returncode}')[:200]

def _missing_tools(tools):
    return [label for label in ('git', 'cmake', 'ninja') if tools[label] is None]

def _termux_include_dirs():
    dirs = []
    prefix = os.environ.get('PREFIX', '')
    if prefix:
        dirs.append(os.path.join(prefix, 'include'))
    dirs.append('/data/data/com.termux/files/usr/include')
    return dirs

def _termux_lib_dirs():
    dirs = []
    prefix = os.environ.get('PREFIX', '')
    if prefix:
        dirs.append(os.path.join(prefix, 'lib'))
    dirs.append('/data/data/com.termux/files/usr/lib')
    return dirs

def _capstone_available():
    for d in _termux_include_dirs():
        if (os.path.isfile(os.path.join(d, 'capstone.h'))
                or os.path.isfile(os.path.join(d, 'capstone', 'capstone.h'))):
            for libdir in _termux_lib_dirs():
                if glob.glob(os.path.join(libdir, 'libcapstone.*')):
                    return True
            return False
    return False

def _fmt_available():
    for d in _termux_include_dirs():
        if os.path.isdir(os.path.join(d, 'fmt')):
            return True
    return False

def ensure_native_deps():
    if not _is_termux_env() or _autoinstall_disabled():
        return
    missing = []
    if not _capstone_available():
        missing.append('capstone')
    if not _fmt_available():
        missing.append('fmt')
    if not missing:
        return
    ok, detail = _pkg_install(missing)
    if not ok:
        fallback = ['libcapstone' if name == 'capstone' else name for name in missing]
        ok, detail = _pkg_install(fallback)
    if not _capstone_available():
        raise RuntimeError(
            "Required library capstone not found and automatic install failed"
            f" ({detail}). Install it with: pkg install capstone"
        )

def check_build_tools():
    tools = resolve_build_tools()
    missing = _missing_tools(tools)
    install_note = ''
    if missing and _is_termux_env() and not _autoinstall_disabled():
        pkg_names = list(missing)
        for extra in ('clang', 'pkg-config'):
            if not shutil.which(extra) and extra not in pkg_names:
                pkg_names.append(extra)
        ok, detail = _pkg_install(pkg_names)
        if ok:
            tools = resolve_build_tools()
            missing = _missing_tools(tools)
        else:
            install_note = (
                f"Automatic install via pkg failed: {detail}. "
                "Run the pkg command below manually, then retry "
                "(set ELITF_AUTOINSTALL=0 to disable auto-install). "
            )
    if missing:
        termux = _is_termux_env()
        hint = TERMUX_INSTALL_HINT if termux else GENERIC_INSTALL_HINT
        names = ', '.join(missing)
        path_note = (
            'If already installed, close and reopen Termux '
            'or run: export PATH="$PREFIX/bin:$PATH"'
            if termux else
            'If already installed, verify their directory is in PATH'
        )
        dirs = _tool_search_dirs()
        parts = [
            f"PATH=\"{os.environ.get('PATH', '')}\"",
            f"PREFIX=\"{os.environ.get('PREFIX', '')}\"",
            'searched: ' + (', '.join(dirs) if dirs else 'none'),
        ]
        blocked = _blocked_tool_paths(missing, dirs)
        if blocked:
            parts.append('present but not executable: ' + ', '.join(blocked))
        raise RuntimeError(
            f"Missing required build tool(s): {names}. "
            f"{install_note}"
            f"Resolve with: {hint}. {path_note}. "
            f"Diagnostic [{'; '.join(parts)}]"
        )

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CMAKE_TEMPLATE_FILE = os.path.join(SCRIPT_DIR, 'scripts', 'CMakeLists.txt.dartvm')
CREATE_SRCLIST_FILE = os.path.join(SCRIPT_DIR, 'scripts', 'dartvm_create_srclist.py')
MAKE_VERSION_FILE = os.path.join(SCRIPT_DIR, 'scripts', 'dartvm_make_version.py')

SDK_DIR = os.path.join(SCRIPT_DIR, 'dartsdk')
BUILD_DIR = os.path.join(SCRIPT_DIR, 'build')

# Overridable for censored/slow networks (e.g. set them to a mirror that
# works from your carrier):
#   export ELITF_DART_SDK_GIT=https://git.example.com/mirror/dart-sdk.git
#   export ELITF_DART_SDK_TARBALL=https://mirror.example.net/dart-sdk/{version}.tar.gz
DART_GIT_URL = (os.getenv('ELITF_DART_SDK_GIT')
                or 'https://github.com/dart-lang/sdk.git')
DART_TARBALL_URL = (os.getenv('ELITF_DART_SDK_TARBALL')
                    or 'https://github.com/dart-lang/sdk/archive/refs/tags/{version}.tar.gz')

# Only these paths are needed to build the Dart VM static library.
SPARSE_PATHS = ('runtime', 'tools', 'third_party/double-conversion')


def _emit(log, msg):
    """Route a status line through the UI log panel when available, else print.

    Printing raw text while rich Live redraws breaks the cursor positioning
    and stacks frames on screen (the Termux flood) — so when embedded in the
    UI, every message must go through the captured log panel instead.
    """
    if log:
        log(msg)
    else:
        print(msg)


def _run_captured(cmd, cwd=None, check=True, log=None, desc=''):
    """Run a build command with captured output (safe inside rich Live).

    Only used when a log callback is provided (embedded UI). Fails with the
    stderr tail in the raised error so the cause stays visible.
    """
    if desc and log:
        log(desc)
    try:
        proc = subprocess.run(cmd, cwd=cwd, check=check,
                              capture_output=True, text=True, errors='replace')
    except (subprocess.CalledProcessError, OSError):
        raise
    return proc


def _run_captured_checked(cmd, cwd=None, log=None, desc=''):
    try:
        return _run_captured(cmd, cwd=cwd, check=True, log=log, desc=desc)
    except subprocess.CalledProcessError as e:
        detail = _tail(e.stderr) or _tail(e.stdout)
        raise RuntimeError(
            f"{desc or 'command'} failed (exit {e.returncode})"
            + (f" — {detail}" if detail else '')) from e
    except OSError as e:
        raise RuntimeError(f"{desc or 'command'} could not start: {e}") from e


NINJA_PROGRESS_RE = re.compile(r'^\s*\[\s*(\d+)\s*/\s*(\d+)\s*\]')


def _parse_ninja_line(line):
    """Extract (done, total) from a ninja progress line like `[12/345] Building…`."""
    m = NINJA_PROGRESS_RE.match(line or '')
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def _read_mem_available():
    """Likely-available RAM in bytes, or None when it cannot be determined."""
    total = None
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemAvailable:'):
                    return int(line.split()[1]) * 1024
                if line.startswith('MemTotal:'):
                    total = int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        total = None
    if total:
        return total
    try:
        return os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE')
    except (ValueError, OSError, AttributeError):
        return None


def safe_parallel_jobs(mem_bytes=None, cpu_count=None):
    """Ninja parallelism that will not OOM-kill the device mid-build.

    Heavy Dart VM translation units can eat ~2 GB each with clang -O2;
    on a phone, ninja's default (-j<all cores>) gets the compiler killed
    by the OOM killer and the build then looks frozen forever.
    ELITF_NINJA_JOBS overrides everything.
    """
    env = os.getenv('ELITF_NINJA_JOBS', '').strip()
    if env:
        try:
            j = int(env)
            if j >= 1:
                return j
        except ValueError:
            pass
    if cpu_count is None:
        cpu_count = os.cpu_count() or 4
    if mem_bytes is None:
        mem_bytes = _read_mem_available()
    if not mem_bytes or mem_bytes <= 0:
        return max(1, min(4, cpu_count))
    jobs = int(mem_bytes // (2 * (1 << 30)))
    return max(1, min(jobs, cpu_count, 16))


def _run_streaming(cmd, cwd=None, log=None, on_progress=None, desc='',
                   phase='compile', min_interval=8.0, tail_lines=80):
    """Run a build command and stream its stdout line by line.

    Unlike the fully-captured runs, ninja's `[N/M]` progress lines are parsed
    as they arrive and forwarded to `on_progress(done, total, phase)`, so the
    UI bar advances during a build that can last an hour on a phone. Nothing
    is ever written raw to the tty (rich Live owns the screen): milestone
    lines go through `log`, throttled to at most one every `min_interval`
    seconds and 5% of progress. Failures raise RuntimeError with the output
    tail so the actual error stays visible.
    """
    if desc and log:
        log(desc)
    collected = deque(maxlen=max(10, tail_lines))
    last_emit = [-1e9]
    last_milestone = [-1]
    short_desc = (desc or 'Build').split('(')[0].strip(' …\u2026') or 'Build'
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                errors='replace', bufsize=1)
    except OSError as e:
        raise RuntimeError(f"{desc or 'command'} could not start: {e}") from e
    try:
        for line in proc.stdout:
            line = line.rstrip('\r\n')
            if not line:
                continue
            collected.append(line)
            parsed = _parse_ninja_line(line)
            if parsed:
                done, total = parsed
                if on_progress:
                    try:
                        on_progress(done, total, phase)
                    except Exception:
                        pass
                if log:
                    pct = int(done * 100 / total) if total else 0
                    milestone = pct // 5
                    now = time.monotonic()
                    if (milestone > last_milestone[0]
                            and now - last_emit[0] >= min_interval):
                        last_milestone[0] = milestone
                        last_emit[0] = now
                        log(f"{short_desc}: [{done}/{total}] ({pct}%)")
        proc.wait()
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
    if proc.returncode != 0:
        detail = _tail('\n'.join(collected), 800)
        raise RuntimeError(
            f"{desc or 'command'} failed (exit {proc.returncode})"
            + (f" — {detail}" if detail else ''))
    return proc


def _ninja_command():
    """Ninja invocation bounded by device memory (safe_parallel_jobs)."""
    return [NINJA_CMD, '-j', str(safe_parallel_jobs())]


def _run_ninja_build(builddir, log=None, on_progress=None):
    """Compile the Dart VM with memory-aware parallelism and live progress."""
    jobs = safe_parallel_jobs()
    cpu = os.cpu_count() or 4
    if log:
        if on_progress:
            on_progress(0, 0, 'compile')
        if jobs < cpu and not os.getenv('ELITF_NINJA_JOBS'):
            _emit(log, f"Parallel build limited to -j{jobs} "
                       f"(low device memory; set ELITF_NINJA_JOBS to override)")
        return _run_streaming(_ninja_command(), cwd=builddir, log=log,
                              on_progress=on_progress,
                              desc='Compiling Dart VM (ninja, may take a while)…',
                              phase='compile')
    return subprocess.run(_ninja_command(), cwd=builddir, check=True)


def _tail(text, limit=600):
    """Last `limit` chars of a command output, single line (for error messages)."""
    text = (text or '').strip()
    if not text:
        return ''
    if len(text) > limit:
        text = '… ' + text[-limit:]
    return text.replace('\n', ' | ')


def _git(args, cwd=None, attempts=3, delay=2.0, desc='git', log=None):
    """Run git with captured output and automatic retries.

    On unstable mobile networks (Termux), commands that download data often
    fail once and succeed on retry. Blobs already fetched by a partial clone
    are cached by git, so a retry resumes instead of restarting from zero.
    stdout/stderr are captured so the real cause (network, ref, auth, …)
    ends up in the raised error instead of being lost in the live UI redraw.
    """
    last = None
    for attempt in range(1, max(1, attempts) + 1):
        if log:
            log(f"{desc} (attempt {attempt}/{attempts})…")
        try:
            proc = subprocess.run([GIT_CMD] + list(args), cwd=cwd,
                                  capture_output=True, text=True, errors='replace')
        except FileNotFoundError:
            raise
        if proc.returncode == 0:
            return proc
        detail = _tail(proc.stderr) or _tail(proc.stdout)
        last = RuntimeError(
            f"{desc}: exit {proc.returncode} (attempt {attempt}/{attempts})"
            + (f" — {detail}" if detail else ''))
        if attempt < attempts:
            time.sleep(delay)
            delay = min(delay * 2, 20.0)
    raise last


def _rmtree(path):
    if not os.path.exists(path):
        return

    def remove_readonly(func, p, _):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            pass
        func(p)

    _rmtree_rw(path, remove_readonly)


def _git_clone_sparse(info, clonedir, log=None):
    """Shallow partial clone + sparse checkout: minimal download."""
    _git(['-c', 'advice.detachedHead=false', 'clone', '-b', info.version,
          '--depth', '1', '--filter=blob:none', '--sparse',
          DART_GIT_URL, clonedir],
         attempts=3, desc='git clone (Dart SDK)', log=log)
    # This step lazily fetches ~30 MB of blobs: the most network-sensitive
    # part of the whole fetch. More attempts because it is resumable.
    _git(['sparse-checkout', 'set', *SPARSE_PATHS], cwd=clonedir,
         attempts=4, delay=3.0, desc='git sparse-checkout', log=log)


def _download_with_urllib(url, dest, log=None, attempts=8,
                          on_progress=None, min_interval=3.0):
    """Resumable single-stream download (Range), robust on flaky links.

    A single HTTP stream survives bad mobile networks far better than git's
    chatty fetch protocol; already-received bytes are kept in `<dest>.part`.
    Milestones (`Downloaded 12.3 MB…`) are throttled so a slow link never
    leaves the user staring at a frozen screen, and byte counts are forwarded
    to `on_progress(received, total_or_0, 'download')` for the UI bar.
    """
    part = dest + '.part'
    last = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            start = os.path.getsize(part) if os.path.exists(part) else 0
            received = start
            headers = {'User-Agent': 'Elit-f (dartvm_fetch_build)'}
            if start > 0:
                headers['Range'] = f'bytes={int(start)}-'
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as resp:
                code = getattr(resp, 'status', None) or resp.getcode() or 0
                if start > 0 and code != 206 and log:
                    log('Server ignored resume request; restarting download…')
                try:
                    total = int(resp.headers.get('Content-Length', 0)) + (
                        start if code == 206 else 0)
                except (ValueError, TypeError, AttributeError):
                    total = 0
                last_log_bytes = received
                last_log_time = time.monotonic()
                with open(part, 'ab' if (start > 0 and code == 206) else 'wb') as f:
                    while True:
                        chunk = resp.read(256 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)
                        if on_progress:
                            try:
                                on_progress(received, total, 'download')
                            except Exception:
                                pass
                        now = time.monotonic()
                        if (log and received - last_log_bytes >= (1 << 20)
                                and now - last_log_time >= min_interval):
                            last_log_bytes = received
                            last_log_time = now
                            log(f"Downloaded {received / (1 << 20):.1f} MB…")
            os.replace(part, dest)
            return
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, EOFError) as e:
            last = e
            if log:
                log(f"Download interrupted ({e}); retry {attempt}/{attempts}…")
            time.sleep(min(2.0 * attempt, 10.0))
    raise RuntimeError(f"Download failed after {attempts} attempts: {last}")


def _download_with_curl(url, dest):
    """Last-resort downloader for setups where Python TLS is broken."""
    curl = shutil.which('curl')
    if not curl:
        return False
    part = dest + '.part'
    try:
        proc = subprocess.run(
            [curl, '-L', '--fail', '--retry', '6', '--retry-delay', '3',
             '--retry-all-errors', '-o', part, url],
            capture_output=True, text=True, errors='replace')
    except OSError:
        return False
    if proc.returncode == 0 and os.path.isfile(part) and os.path.getsize(part) > 0:
        os.replace(part, dest)
        return True
    return False


def _download_tarball(info, dest, log=None, on_progress=None):
    url = DART_TARBALL_URL.format(version=info.version)
    if log:
        log(f"Downloading Dart SDK {info.version} archive…")
    try:
        _download_with_urllib(url, dest, log, on_progress=on_progress)
    except (RuntimeError, OSError) as e:
        if log:
            log(f"Python download failed ({_tail(str(e), 160)}); trying curl…")
        if not _download_with_curl(url, dest):
            raise


_TARBALL_SUBDIRS = ('runtime', 'tools', 'third_party/double-conversion')


def _tarball_checkout(info, clonedir, log=None, on_progress=None):
    """Fallback without git: download the tag archive and extract only the
    directories Elit-f compiles against. The archive is cached, so a later
    re-run never downloads it twice."""
    _rmtree(clonedir)
    os.makedirs(SDK_DIR, exist_ok=True)
    dest = os.path.join(SDK_DIR, f'dart-sdk-{info.version}.tar.gz')
    if not os.path.isfile(dest):
        _download_tarball(info, dest, log, on_progress=on_progress)
    if log:
        log("Extracting archive (runtime, tools, double-conversion)…")
    os.makedirs(clonedir, exist_ok=True)
    extracted = 0
    with tarfile.open(dest, 'r:gz') as tf:
        for member in tf:
            parts = member.name.split('/', 1)
            if len(parts) != 2:
                continue  # repository top-level files: not needed for the build
            rel = parts[1]
            if not rel or '..' in rel.split('/'):
                continue
            if not any(rel == p or rel.startswith(p + '/')
                       for p in _TARBALL_SUBDIRS):
                continue
            member.name = rel
            try:
                tf.extract(member, clonedir, filter='data')
            except TypeError:
                tf.extract(member, clonedir)
            extracted += 1
            if on_progress:
                try:
                    on_progress(extracted, 0, 'extract')
                except Exception:
                    pass
            if log and extracted % 400 == 0:
                log(f"Extracted {extracted} files…")
    if extracted == 0:
        raise RuntimeError("Dart SDK archive unreadable or empty: " + dest)
    if not os.path.isfile(os.path.join(clonedir, 'runtime', 'vm', 'version_in.cc')):
        raise RuntimeError("Dart SDK archive incomplete "
                           "(runtime/vm/version_in.cc missing): " + dest)

imp_replace_snippet = """import importlib.util
import importlib.machinery

def load_source(modname, filename):
    loader = importlib.machinery.SourceFileLoader(modname, filename)
    spec = importlib.util.spec_from_file_location(modname, filename, loader=loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module
"""

class DartLibInfo:
    def __init__(self, version: str, os_name: str, arch: str, has_compressed_ptrs=None, snapshot_hash=None):
        if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', version):
            raise ValueError(f'Invalid or undetected Dart version: {version!r}')
        if os_name not in ('android', 'ios') or arch not in ('arm64', 'x64'):
            raise ValueError(f'Unsupported Dart target: {os_name}/{arch}')
        if snapshot_hash is not None and not re.fullmatch(r'[0-9a-f]{32}', snapshot_hash):
            raise ValueError('Invalid snapshot hash')
        self.version = version
        self.os_name = os_name
        self.arch = arch
        self.snapshot_hash = snapshot_hash
        self.has_compressed_ptrs = os_name != 'ios' if has_compressed_ptrs is None else bool(has_compressed_ptrs)
        self.variant_suffix = '' if self.has_compressed_ptrs else '_uncompressed'
        if snapshot_hash:
            self.variant_suffix += '_' + snapshot_hash
        self.lib_name = f'dartvm{version}_{os_name}_{arch}{self.variant_suffix}'

def checkout_dart(info: DartLibInfo, log=None, on_progress=None):
    if on_progress:
        try:
            on_progress(0, 0, 'clone')
        except Exception:
            pass
    clonedir = os.path.join(SDK_DIR, 'v' + info.version + info.variant_suffix)

    version_file = os.path.join(clonedir, 'runtime', 'vm', 'version.cc')
    if os.path.exists(clonedir) and not os.path.exists(version_file):
        _emit(log, 'Delete incomplete clone directory ' + clonedir)
        _rmtree(clonedir)

    if not os.path.exists(clonedir):
        try:
            _git_clone_sparse(info, clonedir, log=log)
        except (RuntimeError, OSError) as git_err:
            # git failed for good (bad network on the blob fetch, old git
            # without sparse-checkout, proxy…): switch to a single-stream
            # archive download which survives flaky mobile links.
            _emit(log, 'git sparse-checkout failed (' + _tail(str(git_err), 200) + ')')
            _emit(log, 'Falling back to direct archive download…')
            try:
                _tarball_checkout(info, clonedir, log=log, on_progress=on_progress)
            except Exception as tar_err:
                raise RuntimeError(
                    f"Cannot fetch Dart SDK {info.version} sources.\n"
                    f"  - git: {git_err}\n"
                    f"  - archive: {tar_err}\n"
                    "Check network connectivity, or point a reachable mirror "
                    "with env vars ELITF_DART_SDK_GIT / ELITF_DART_SDK_TARBALL."
                ) from tar_err
        with os.scandir(clonedir) as it:
            for entry in it:
                if entry.is_file():
                    os.remove(entry.path)

        if info.snapshot_hash is None:

            if sys.version_info[:2] >= (3, 12):
                utils_path = os.path.join(clonedir, "tools", "utils.py")
                if os.path.exists(utils_path):
                    with open(utils_path, "r+") as f:
                        content = f.read()
                        new_content = content.replace("match_against('", "match_against(r'").replace("re.search('", "re.search(r'")
                        if "import imp\n" in new_content:
                            new_content = new_content.replace("import imp\n", imp_replace_snippet).replace("imp.load_source", "load_source")
                        if new_content != content:
                            f.seek(0)
                            f.truncate()
                            f.write(new_content)
            cmd = [sys.executable, 'tools/make_version.py', '--output', 'runtime/vm/version.cc',
                   '--input', 'runtime/vm/version_in.cc']
            if log:
                _run_captured_checked(cmd, cwd=clonedir, log=log,
                                      desc='Generating runtime/vm/version.cc')
            else:
                subprocess.run(cmd, cwd=clonedir, check=True)
        else:
            cmd = [sys.executable, MAKE_VERSION_FILE, clonedir, info.snapshot_hash]
            if log:
                _run_captured_checked(cmd, log=log, desc='Generating runtime/vm/version.cc')
            else:
                subprocess.run(cmd, check=True)

    if sys.platform == 'win32':
        vers = info.version.split('.', 2)
        if (int(vers[0]), int(vers[1])) >= (3, 8):
            with open(os.path.join(clonedir, 'runtime', 'platform', 'unwinding_records.h'), 'r+b') as f:
                mm = mmap.mmap(f.fileno(), 0)
                pos = mm.find(b'\n#if !defined(DART_HOST_OS_WINDOWS) || !defined(HOST_ARCH_ARM64)')
                if pos != -1:
                    mm[pos+36:pos+38] = b'//'
                else:
                    pos = mm.find(b'\nstatic_assert(sizeof(')
                    if pos != -1:
                        mm[pos+1:pos+3] = b'//'
                mm.close()

    return clonedir

def cmake_dart(info: DartLibInfo, target_dir: str, log=None, on_progress=None):

    parts = info.version.split('.')
    if len(parts) < 2:
        raise ValueError(f'Invalid Dart version format: "{info.version}"')
    try:
        major, minor = int(parts[0]), int(parts[1])
    except ValueError:
        raise ValueError(f'Invalid Dart version format: "{info.version}"')
    cpp_std = "20" if (major, minor) >= (3, 11) else "17"

    with open(CMAKE_TEMPLATE_FILE, 'r') as f:
        code = f.read()
    with open(os.path.join(target_dir, 'CMakeLists.txt'), 'w') as f:
        f.write(code.replace('VERSION_PLACE_HOLDER', info.version).replace('CXX_STD_PLACE_HOLDER', cpp_std))

    icu_compat_src = os.path.join(SCRIPT_DIR, 'scripts', 'icu_compat.h')
    if os.path.isfile(icu_compat_src):
        shutil.copy2(icu_compat_src, os.path.join(target_dir, 'icu_compat.h'))

    with open(os.path.join(target_dir, 'Config.cmake.in'), 'w') as f:
        f.write('@PACKAGE_INIT@\n\n')
        f.write('include ( "${CMAKE_CURRENT_LIST_DIR}/dartvmTarget.cmake" )\n\n')

    if log:
        _run_captured_checked([sys.executable, CREATE_SRCLIST_FILE, target_dir],
                              log=log, desc='Listing Dart VM sources')
    else:
        subprocess.run([sys.executable, CREATE_SRCLIST_FILE, target_dir], check=True)

    builddir = os.path.join(BUILD_DIR, info.lib_name)
    cmake_cmd = [CMAKE_CMD, '-GNinja', '-B', builddir,
                 f'-DTARGET_OS={info.os_name}', f'-DTARGET_ARCH={info.arch}',
                 f'-DDARTLIB_SUFFIX={info.variant_suffix}',
                 f'-DCOMPRESSED_PTRS={1 if info.has_compressed_ptrs else 0}',
                 '-DCMAKE_BUILD_TYPE=Release', '--log-level=NOTICE']

    if log:
        # Output captured or streamed so nothing is written to the tty while
        # rich Live owns the screen (raw writes break cursor positioning and
        # stack frames — the Termux flood). The ninja build is STREAMED: its
        # [N/M] lines feed on_progress so the UI bar moves during the compile.
        if on_progress:
            try:
                on_progress(0, 1, 'configure')
            except Exception:
                pass
        _run_captured_checked(cmake_cmd, cwd=target_dir, log=log,
                              desc='Configuring Dart VM build (CMake)')
        _run_ninja_build(builddir, log=log, on_progress=on_progress)
        if on_progress:
            try:
                on_progress(1, 1, 'install')
            except Exception:
                pass
        _run_captured_checked([CMAKE_CMD, '--install', '.'], cwd=builddir, log=log,
                              desc='Installing Dart VM library')
    else:
        subprocess.run(cmake_cmd, cwd=target_dir, check=True)
        subprocess.run(_ninja_command(), cwd=builddir, check=True)
        subprocess.run([CMAKE_CMD, '--install', '.'], cwd=builddir, check=True)

def fetch_and_build(info: DartLibInfo, log=None, on_progress=None):
    check_build_tools()
    outdir = checkout_dart(info, log=log, on_progress=on_progress)
    cmake_dart(info, outdir, log=log, on_progress=on_progress)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: dartvm_fetch_build.py <version> [os_name] [arch] [snapshot_hash]')
        sys.exit(1)
    ver = sys.argv[1]
    os_name = 'android' if len(sys.argv) < 3 else sys.argv[2]
    arch = 'arm64' if len(sys.argv) < 4 else sys.argv[3]
    snapshot_hash = None if len(sys.argv) < 5 else sys.argv[4]
    info = DartLibInfo(ver, os_name, arch, snapshot_hash=snapshot_hash)
    fetch_and_build(info)
