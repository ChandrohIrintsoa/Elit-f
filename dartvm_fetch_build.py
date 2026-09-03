
import os
import shutil
import stat
import subprocess
import sys

GIT_CMD = "git"
CMAKE_CMD = os.getenv('CMAKE', 'cmake')
NINJA_CMD = os.getenv('NINJA', 'ninja')

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

dart_versions = {
    "3.0_aa": ["3.0.0", "3.0.1", "3.0.2"],
    "3.0_90": ["3.0.3", "3.0.4", "3.0.5", "3.0.6", "3.0.7"],
    "3.1": ["3.1.0", "3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5"],
    "3.2": ["3.2.0", "3.2.1", "3.2.2", "3.2.3", "3.2.4", "3.2.5", "3.2.6"],
    "3.3": ["3.3.0", "3.3.1", "3.3.2", "3.3.3", "3.3.4"],
    "3.4": ["3.4.0", "3.4.1", "3.4.2", "3.4.3", "3.4.4"],
    "3.5": ["3.5.0", "3.5.1", "3.5.2", "3.5.3", "3.5.4", "3.5.5", "3.5.6"],
    "3.6": ["3.6.0", "3.6.1", "3.6.2", "3.6.3", "3.6.4"],
    "3.7": ["3.7.0", "3.7.1", "3.7.2"],
    "3.8": ["3.8.0", "3.8.1", "3.8.2", "3.8.3", "3.8.4", "3.8.5"],
    "3.9": ["3.9.0", "3.9.1", "3.9.2", "3.9.3", "3.9.4", "3.9.5"],
    "3.10": ["3.10.0", "3.10.1", "3.10.2", "3.10.3", "3.10.4", "3.10.5", "3.10.6", "3.10.7", "3.10.8", "3.10.9"],
    "3.11": ["3.11.0", "3.11.1", "3.11.2", "3.11.3", "3.11.4", "3.11.5", "3.11.6"],
    "3.12": ["3.12.0", "3.12.1", "3.12.2", "3.12.3", "3.12.4", "3.12.5", "3.12.6", "3.12.7", "3.12.8"],
    "3.13": ["3.13.0", "3.13.1", "3.13.2", "3.13.3", "3.13.4", "3.13.5"],
    "3.14": ["3.14.0", "3.14.1", "3.14.2"],
    "3.15": ["3.15.0", "3.15.1"],
    "3.16": ["3.16.0"],
    "3.17": ["3.17.0"],
    "3.18": ["3.18.0"],
}

class DartLibInfo:
    def __init__(self, version: str, os_name: str, arch: str, has_compressed_ptrs=None, snapshot_hash=None):
        self.os_name = os_name
        self.arch = arch
        self.snapshot_hash = snapshot_hash
        if has_compressed_ptrs is None:
            self.has_compressed_ptrs = os_name != 'ios'
        else:
            self.has_compressed_ptrs = has_compressed_ptrs

        bin_dir = os.path.join(SCRIPT_DIR, 'bin')
        if os.path.exists(bin_dir):
            file_name_version = []
            suffixes = [
                '', '_no-analysis', '_ida-fcn', '_no-analysis_ida-fcn',
                '_no-compressed-ptrs', '_no-compressed-ptrs_no-analysis',
                '_no-compressed-ptrs_no-analysis_ida-fcn', '_no-compressed-ptrs_ida-fcn',
            ]
            for file in os.listdir(bin_dir):
                for suffix in suffixes:
                    if file.startswith('elitf_dartvm') and file.endswith(f'{os_name}_{arch}{suffix}'):
                        file_name_version.append(file.split('_')[1].replace('dartvm', ''))

            for _key, versions in dart_versions.items():
                if version in versions and any(v in versions for v in file_name_version):
                    matched_version = next(v for v in file_name_version if v in versions)
                    self.lib_name = f'dartvm{matched_version}_{os_name}_{arch}'
                    self.version = matched_version
                    return

        self.version = version
        self.lib_name = f'dartvm{version}_{os_name}_{arch}'

def checkout_dart(info: DartLibInfo):
    clonedir = os.path.join(SDK_DIR, 'v' + info.version)

    version_file = os.path.join(clonedir, 'runtime', 'vm', 'version.cc')
    if os.path.exists(clonedir) and not os.path.exists(version_file):
        print('Delete incomplete clone directory ' + clonedir)
        def remove_readonly(func, path, _):
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            func(path)
        shutil.rmtree(clonedir, onerror=remove_readonly)

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
                        if r"match_against('^MAJOR (\d+)$', content)" in content and "match_against(r'" not in content:
                            content = content.replace(" ' awk ", " r' awk ").replace("match_against('", "match_against(r'").replace("re.search('", "re.search(r'")
                            if "import imp\n" in content:
                                content = content.replace("import imp\n", imp_replace_snippet).replace("imp.load_source", "load_source")
                            f.seek(0)
                            f.truncate()
                            f.write(content)
            subprocess.run([sys.executable, 'tools/make_version.py', '--output', 'runtime/vm/version.cc',
                            '--input', 'runtime/vm/version_in.cc'], cwd=clonedir, check=True)
        else:

            subprocess.run([sys.executable, MAKE_VERSION_FILE, clonedir, info.snapshot_hash], check=True)

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
                    f'-DCOMPRESSED_PTRS={1 if info.has_compressed_ptrs else 0}',
                    '-DCMAKE_BUILD_TYPE=Release', '--log-level=NOTICE'],
                   cwd=target_dir, check=True)

    subprocess.run([NINJA_CMD], cwd=builddir, check=True)
    subprocess.run([CMAKE_CMD, '--install', '.'], cwd=builddir, check=True)

def fetch_and_build(info: DartLibInfo):
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
