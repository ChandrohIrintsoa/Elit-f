import re
import mmap
import os
import shutil
import stat
import subprocess
import sys

GIT_CMD = os.getenv('GIT', 'git')
CMAKE_CMD = os.getenv('CMAKE', 'cmake')
NINJA_CMD = os.getenv('NINJA', 'ninja')

TERMUX_INSTALL_HINT = (
    "pkg install git cmake ninja clang python pkg-config"
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

def resolve_build_tools():
    global GIT_CMD, CMAKE_CMD, NINJA_CMD
    dirs = _tool_search_dirs()
    cmake_names = ('cmake', 'cmake3')
    ninja_names = ('ninja',)
    env_cmake = os.getenv('CMAKE')
    env_ninja = os.getenv('NINJA')
    if env_cmake:
        cmake_names = (env_cmake,)
    if env_ninja:
        ninja_names = (env_ninja,)
    git_path = _find_tool((os.getenv('GIT') or 'git',), dirs)
    cmake_path = _find_tool(cmake_names, dirs)
    ninja_path = _find_tool(ninja_names, dirs)
    if git_path:
        GIT_CMD = git_path
    if cmake_path:
        CMAKE_CMD = cmake_path
    if ninja_path:
        NINJA_CMD = ninja_path
    return {'git': git_path, 'cmake': cmake_path, 'ninja': ninja_path}

def check_build_tools():
    tools = resolve_build_tools()
    missing = [label for label in ('git', 'cmake', 'ninja') if tools[label] is None]
    if missing:
        hint = TERMUX_INSTALL_HINT if _is_termux_env() else GENERIC_INSTALL_HINT
        names = ', '.join(missing)
        path_note = (
            'If already installed, close and reopen Termux '
            'or run: export PATH="$PREFIX/bin:$PATH"'
            if _is_termux_env() else
            'If already installed, verify their directory is in PATH'
        )
        raise RuntimeError(
            f"Missing required build tool(s): {names}. "
            f"Resolve with: {hint}. {path_note}."
        )

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CMAKE_TEMPLATE_FILE = os.path.join(SCRIPT_DIR, 'scripts', 'CMakeLists.txt.dartvm')
CREATE_SRCLIST_FILE = os.path.join(SCRIPT_DIR, 'scripts', 'dartvm_create_srclist.py')
MAKE_VERSION_FILE = os.path.join(SCRIPT_DIR, 'scripts', 'dartvm_make_version.py')

SDK_DIR = os.path.join(SCRIPT_DIR, 'dartsdk')
BUILD_DIR = os.path.join(SCRIPT_DIR, 'build')

DART_GIT_URL = 'https://github.com/dart-lang/sdk.git'

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

def checkout_dart(info: DartLibInfo):
    clonedir = os.path.join(SDK_DIR, 'v' + info.version + info.variant_suffix)

    version_file = os.path.join(clonedir, 'runtime', 'vm', 'version.cc')
    if os.path.exists(clonedir) and not os.path.exists(version_file):
        print('Delete incomplete clone directory ' + clonedir)
        def remove_readonly(func, path, _):
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            func(path)
        _rmtree_rw(clonedir, remove_readonly)

    if not os.path.exists(clonedir):
        subprocess.run([GIT_CMD, '-c', 'advice.detachedHead=false', 'clone', '-b', info.version,
                        '--depth', '1', '--filter=blob:none', '--sparse', DART_GIT_URL, clonedir], check=True)
        subprocess.run([GIT_CMD, 'sparse-checkout', 'set', 'runtime', 'tools',
                        'third_party/double-conversion'], cwd=clonedir, check=True)
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
            subprocess.run([sys.executable, 'tools/make_version.py', '--output', 'runtime/vm/version.cc',
                            '--input', 'runtime/vm/version_in.cc'], cwd=clonedir, check=True)
        else:

            subprocess.run([sys.executable, MAKE_VERSION_FILE, clonedir, info.snapshot_hash], check=True)

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

def cmake_dart(info: DartLibInfo, target_dir: str):

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

    subprocess.run([sys.executable, CREATE_SRCLIST_FILE, target_dir], check=True)

    builddir = os.path.join(BUILD_DIR, info.lib_name)
    subprocess.run([CMAKE_CMD, '-GNinja', '-B', builddir,
                    f'-DTARGET_OS={info.os_name}', f'-DTARGET_ARCH={info.arch}',
                    f'-DDARTLIB_SUFFIX={info.variant_suffix}',
                    f'-DCOMPRESSED_PTRS={1 if info.has_compressed_ptrs else 0}',
                    '-DCMAKE_BUILD_TYPE=Release', '--log-level=NOTICE'],
                   cwd=target_dir, check=True)

    subprocess.run([NINJA_CMD], cwd=builddir, check=True)
    subprocess.run([CMAKE_CMD, '--install', '.'], cwd=builddir, check=True)

def fetch_and_build(info: DartLibInfo):
    check_build_tools()
    outdir = checkout_dart(info)
    cmake_dart(info, outdir)

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
