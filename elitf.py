#!/usr/bin/env python3
import argparse
import glob
import mmap
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile

from dartvm_fetch_build import DartLibInfo, resolve_build_tools, ensure_native_deps
from elitf_ui import LogManager, ElitfUI, AUTHOR, HAS_RICH, _is_termux
from elitf_r2 import display_binary_info, r2_unified_analysis, run_r2_custom, R2_PRESETS

_TOOLS = resolve_build_tools()
CMAKE_CMD = _TOOLS['cmake'] or os.getenv('CMAKE', 'cmake')
NINJA_CMD = _TOOLS['ninja'] or os.getenv('NINJA', 'ninja')

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
BIN_DIR = os.path.join(SCRIPT_DIR, 'bin')
PKG_INC_DIR = os.path.join(SCRIPT_DIR, 'packages', 'include')
PKG_LIB_DIR = os.path.join(SCRIPT_DIR, 'packages', 'lib')
BUILD_DIR = os.path.join(SCRIPT_DIR, 'build')

EXPECTED_LIBS = ('libapp.so', 'libflutter.so')

ABI_DIRS = ['lib/arm64-v8a/', 'lib/x86_64/']

def _safe_zip_extract(zf: zipfile.ZipFile, member_name: str, out_dir: str) -> str:
    target_path = os.path.realpath(os.path.join(out_dir, member_name))
    base_dir = os.path.realpath(out_dir) + os.sep
    if not target_path.startswith(base_dir):
        raise ValueError(f"Refusing to extract '{member_name}' outside of '{out_dir}' (path traversal)")
    zf.extract(member_name, out_dir)
    return target_path

def _search_in_file(path: str, needle: bytes) -> bool:
    with open(path, 'rb') as f:
        if os.fstat(f.fileno()).st_size == 0:
            return False
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            return mm.find(needle) != -1

def _parse_major_minor(version: str):
    parts = version.split('.')
    if not parts or not parts[0]:
        return 0, 0
    try:
        major = int(parts[0])
    except ValueError:
        return 0, 0
    if len(parts) < 2:
        return major, 0
    try:
        minor = int(parts[1])
    except ValueError:
        return major, 0
    return major, minor

def validate_two_libs(indir: str):
    if not os.path.isdir(indir):
        raise ValueError(
            f"Input is not a directory containing {EXPECTED_LIBS[0]} and {EXPECTED_LIBS[1]}")

    candidates = []
    for root, dirs, files in os.walk(indir):
        dirs.sort()
        for app, flutter in (EXPECTED_LIBS, ('App', 'Flutter')):
            if app in files and flutter in files:
                candidates.append((os.path.abspath(os.path.join(root, app)),
                                   os.path.abspath(os.path.join(root, flutter))))
    direct = [pair for pair in candidates if os.path.dirname(pair[0]) == os.path.abspath(indir)]
    if direct:
        return direct[0]
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise ValueError('Multiple Flutter library pairs found; select an ABI directory: ' +
                         ', '.join(os.path.dirname(pair[0]) for pair in candidates))
    raise ValueError('No co-located libapp.so/libflutter.so or App/Flutter pair found')

def extract_libs_from_apk(apk_file: str, out_dir: str):
    try:
        with zipfile.ZipFile(apk_file, "r") as zf:
            names = set(zf.namelist())
            app_info = None
            flutter_info = None
            for abi_dir in ABI_DIRS:
                app_path = abi_dir + 'libapp.so'
                flutter_path = abi_dir + 'libflutter.so'
                if app_path in names and flutter_path in names:
                    app_info = zf.getinfo(app_path)
                    flutter_info = zf.getinfo(flutter_path)
                    break
            if app_info is None or flutter_info is None:
                raise ValueError(
                    "Cannot find libapp.so and libflutter.so in the APK "
                    f"(tried: {', '.join(ABI_DIRS)})")
            libapp_path = _safe_zip_extract(zf, app_info.filename, out_dir)
            libflutter_path = _safe_zip_extract(zf, flutter_info.filename, out_dir)
            return libapp_path, libflutter_path
    except zipfile.BadZipFile as e:
        raise ValueError(f"Invalid APK file '{apk_file}': {e}")

def find_compat_macro(dart_version: str, no_analysis: bool, ida_fcn: bool = False):
    macros = []
    include_path = os.path.join(PKG_INC_DIR, f'dartvm{dart_version}')
    vm_path = os.path.join(include_path, 'vm')

    required_files = [
        'class_id.h', 'class_table.h', 'stub_code_list.h',
        'object_store.h', 'object.h', 'thread.h',
    ]
    for required in required_files:
        if not os.path.isfile(os.path.join(vm_path, required)):
            raise FileNotFoundError(
                f"Required Dart header not found: {os.path.join(vm_path, required)}. "
                "Did you run `dartvm_fetch_build.py` to fetch the SDK headers?")

    if _search_in_file(os.path.join(vm_path, 'class_id.h'), b'V(LinkedHashMap)'):
        macros.append('-DOLD_MAP_SET_NAME=1')
        if not _search_in_file(os.path.join(vm_path, 'class_id.h'), b'V(ImmutableLinkedHashMap)'):
            macros.append('-DOLD_MAP_NO_IMMUTABLE=1')
    if not _search_in_file(os.path.join(vm_path, 'class_id.h'), b' kLastInternalOnlyCid '):
        macros.append('-DNO_LAST_INTERNAL_ONLY_CID=1')
    if _search_in_file(os.path.join(vm_path, 'class_id.h'), b'V(TypeRef)'):
        macros.append('-DHAS_TYPE_REF=1')
    major, _ = _parse_major_minor(dart_version)
    if major >= 3 and _search_in_file(os.path.join(vm_path, 'class_id.h'), b'V(RecordType)'):
        macros.append('-DHAS_RECORD_TYPE=1')
    if _search_in_file(os.path.join(vm_path, 'class_table.h'), b'class SharedClassTable {'):
        macros.append('-DHAS_SHARED_CLASS_TABLE=1')

    if not _search_in_file(os.path.join(vm_path, 'stub_code_list.h'), b'V(InitLateStaticField)'):
        macros.append('-DNO_INIT_LATE_STATIC_FIELD=1')

    if not _search_in_file(os.path.join(vm_path, 'object_store.h'),
                           b'build_generic_method_extractor_code)'):
        macros.append('-DNO_METHOD_EXTRACTOR_STUB=1')

    if not _search_in_file(os.path.join(vm_path, 'object.h'), b'AsTruncatedInt64Value()'):
        macros.append('-DUNIFORM_INTEGER_ACCESS=1')

    dart_api_path = os.path.join(include_path, 'include', 'dart_api.h')
    if os.path.isfile(dart_api_path) and _search_in_file(dart_api_path, b'kSnapshotDataAsmSymbol'):
        macros.append('-DBLUTTER_DART_SINGLE_SNAPSHOT=1')


    if _search_in_file(os.path.join(vm_path, 'thread.h'), b'old_marking_stack_block'):
        macros.append('-DOLD_MARKING_STACK_BLOCK=1')

    if ida_fcn:
        macros.append('-DIDA_FCN=1')

    if no_analysis:
        macros.append('-DNO_CODE_ANALYSIS=1')

    return macros

class ElitfInput:
    def __init__(self, libapp_path: str, dart_info: DartLibInfo, outdir: str,
                 rebuild: bool, no_analysis: bool, ida_fcn: bool = False,
                 log_mgr: LogManager = None, create_vs_sln: bool = False):
        self.libapp_path = libapp_path
        self.create_vs_sln = create_vs_sln
        self.dart_info = dart_info
        self.outdir = outdir
        self.rebuild = rebuild
        self.ida_fcn = ida_fcn

        major, minor = _parse_major_minor(dart_info.version)
        if major == 2 and minor < 15:
            if not no_analysis:
                msg = 'Dart version <2.15, force "no-analysis" option'
                if log_mgr:
                    log_mgr.add(msg, 'warn')
                else:
                    print(msg)
            no_analysis = True
        if dart_info.arch != 'arm64' or dart_info.os_name != 'android':
            raise ValueError('The supplied AOT C++ engine supports Android ARM64 only; use --action r2 for other ELF architectures')
        self.no_analysis = no_analysis

        self.name_suffix = ''
        if not dart_info.has_compressed_ptrs:
            self.name_suffix += '_no-compressed-ptrs'
        if no_analysis:
            self.name_suffix += '_no-analysis'
        if ida_fcn:
            self.name_suffix += '_ida-fcn'
        self.bin_name = f'elitf_{dart_info.lib_name}{self.name_suffix}'
        self.bin_file = os.path.join(BIN_DIR, self.bin_name + ('.exe' if sys.platform == 'win32' else ''))

def _proc_output_tail(proc, limit=20):
    text = ((proc.stdout or '') + '\n' + (proc.stderr or ''))
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return lines[-limit:]

def cmake_elitf(elitf_input: ElitfInput, log_mgr: LogManager = None):
    ensure_native_deps()
    builddir = os.path.join(BUILD_DIR, elitf_input.bin_name)
    macros = find_compat_macro(elitf_input.dart_info.version,
                               elitf_input.no_analysis, elitf_input.ida_fcn)
    if log_mgr:
        log_mgr.add(f"Compat macros: {' '.join(macros)}", "info")
    my_env = None
    if platform.system() == 'Darwin':
        mac_ver = int(platform.mac_ver()[0].split('.', 1)[0])
        if mac_ver < 15:
            try:
                llvm_prefix = subprocess.run(['brew', '--prefix', 'llvm@16'], capture_output=True,
                                             check=True).stdout.decode().strip()
                clang_file = os.path.join(llvm_prefix, 'bin', 'clang')
                if os.path.isfile(clang_file):
                    my_env = {**os.environ, 'CC': clang_file, 'CXX': clang_file + '++'}
            except (subprocess.SubprocessError, OSError):
                my_env = None
    cmd = [CMAKE_CMD, '-GNinja', '-B', builddir,
           f'-DDARTLIB={elitf_input.dart_info.lib_name}',
           f'-DNAME_SUFFIX={elitf_input.name_suffix}',
           '-DCMAKE_BUILD_TYPE=Release', '--log-level=NOTICE'] + macros
    if log_mgr:
        log_mgr.add("Running cmake configure...", "info")
    try:
        proc = subprocess.run(cmd, cwd=SCRIPT_DIR, check=False, stdin=subprocess.DEVNULL,
                              env=my_env, capture_output=True, text=True, errors='replace')
    except FileNotFoundError:
        raise RuntimeError(
            f"cmake binary not found ('{CMAKE_CMD}'). Install cmake or set CMAKE env var.")
    if proc.returncode != 0:
        tail = _proc_output_tail(proc)
        if log_mgr:
            for line in tail:
                log_mgr.add(line, "warn")
        raise RuntimeError(
            f"cmake configure failed (exit {proc.returncode}):\n" + '\n'.join(tail))
    if log_mgr:
        log_mgr.add("Running ninja build...", "info")
        log_mgr.step()
    try:
        proc = subprocess.run([NINJA_CMD], cwd=builddir, check=False,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors='replace')
    except FileNotFoundError:
        raise RuntimeError(
            f"ninja binary not found ('{NINJA_CMD}'). Install ninja or set NINJA env var.")
    if proc.returncode != 0:
        tail = _proc_output_tail(proc, 30)
        if log_mgr:
            for line in tail:
                log_mgr.add(line, "warn")
        raise RuntimeError(
            f"ninja build failed (exit {proc.returncode}):\n" + '\n'.join(tail))
    if log_mgr:
        log_mgr.add("Running cmake install...", "info")
        log_mgr.step()
    try:
        proc = subprocess.run([CMAKE_CMD, '--install', '.'], cwd=builddir, check=False,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors='replace')
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"cmake install failed (exit {e.returncode})") from e
    if proc.returncode != 0:
        tail = _proc_output_tail(proc, 15)
        if log_mgr:
            for line in tail:
                log_mgr.add(line, "warn")
        raise RuntimeError(
            f"cmake install failed (exit {proc.returncode}):\n" + '\n'.join(tail))
    if log_mgr:
        log_mgr.step()

def cmake_vs_sln(elitf_input: ElitfInput, log_mgr: LogManager = None):
    macros = find_compat_macro(elitf_input.dart_info.version,
                               elitf_input.no_analysis, elitf_input.ida_fcn)
    if log_mgr:
        log_mgr.add("Generating Visual Studio solution...", "info")
    dbg_output_path = os.path.abspath(os.path.join(elitf_input.outdir, 'out'))
    dbg_cmd_args = f'-i "{elitf_input.libapp_path}" -o "{dbg_output_path}"'
    vscmd_ver = os.getenv('VSCMD_VER')
    if vscmd_ver is None:
        raise RuntimeError('Need to run Elit-f in a Visual Studio Developer console')
    if vscmd_ver.startswith('18.'):
        generator = 'Visual Studio 18 2026'
    elif vscmd_ver.startswith('17.'):
        generator = 'Visual Studio 17 2022'
    else:
        raise RuntimeError(f'Unknown Visual Studio version: {vscmd_ver}')
    subprocess.run([CMAKE_CMD, '-G', generator, '-A', 'x64', '-B', elitf_input.outdir,
                    f'-DDARTLIB={elitf_input.dart_info.lib_name}',
                    f'-DNAME_SUFFIX={elitf_input.name_suffix}',
                    f'-DDBG_CMD:STRING={dbg_cmd_args}']
                   + macros + [SCRIPT_DIR], check=True, stdin=subprocess.DEVNULL)
    dbg_exe_dir = os.path.join(elitf_input.outdir, 'Debug')
    os.makedirs(dbg_exe_dir, exist_ok=True)
    for filename in glob.glob(os.path.join(BIN_DIR, '*.dll')):
        shutil.copy(filename, dbg_exe_dir)

def get_dart_lib_info(libapp_path: str, libflutter_path: str, log_mgr: LogManager = None):
    from extract_dart_info import extract_dart_info
    dart_version, snapshot_hash, flags, arch, os_name = extract_dart_info(libapp_path, libflutter_path)
    msg = f'Dart version: {dart_version}, Snapshot: {snapshot_hash}, Target: {os_name} {arch}'
    if log_mgr:
        log_mgr.add(msg, "info")
    else:
        print(msg)
    has_compressed_ptrs = 'compressed-pointers' in flags
    return dart_version, snapshot_hash, flags, arch, os_name, has_compressed_ptrs

def build_and_run(elitf_input: ElitfInput, log_mgr: LogManager = None):
    if not os.path.isfile(elitf_input.bin_file) or elitf_input.rebuild:
        libfile_variants = [
            os.path.join(PKG_LIB_DIR, 'lib' + elitf_input.dart_info.lib_name + '.a'),
            os.path.join(PKG_LIB_DIR, elitf_input.dart_info.lib_name + '.lib'),
        ]
        dartlib_file = next((p for p in libfile_variants if os.path.isfile(p)), None)
        if dartlib_file is None:
            if log_mgr:
                log_mgr.add(f"Fetching Dart VM {elitf_input.dart_info.version}...", "info")
            try:
                from dartvm_fetch_build import fetch_and_build
                fetch_and_build(elitf_input.dart_info,
                                log=log_mgr.add if log_mgr else None)
            except FileNotFoundError as e:
                missing = os.path.basename(str(getattr(e, 'filename', None) or ''))
                hint = (
                    f"Required build tool not found: '{missing or 'unknown'}'. "
                    "Install git, cmake and ninja (Termux: pkg install git cmake ninja clang capstone; "
                    "other: use your package manager), then retry."
                )
                raise RuntimeError(
                    f"Failed to fetch/build Dart VM {elitf_input.dart_info.version}: {hint}"
                ) from e
            except (subprocess.CalledProcessError, OSError, RuntimeError) as e:
                raise RuntimeError(
                    f"Failed to fetch/build Dart VM {elitf_input.dart_info.version}: {e}. "
                    "Check network connectivity and that 'git', 'cmake' and 'ninja' are installed."
                ) from e
            if log_mgr:
                log_mgr.add(f"Dart VM {elitf_input.dart_info.version} built successfully", "success")
                log_mgr.step()
        elitf_input.rebuild = True
    if elitf_input.create_vs_sln:
        cmake_vs_sln(elitf_input, log_mgr)
        return
    if elitf_input.rebuild:
        if log_mgr:
            log_mgr.add(f"Building Elit-f binary ({elitf_input.bin_name})...", "info")
            log_mgr.step()
        cmake_elitf(elitf_input, log_mgr)
        if not os.path.isfile(elitf_input.bin_file):
            raise RuntimeError("Build complete but cannot find binary: " + elitf_input.bin_file)
        if log_mgr:
            log_mgr.add(f"Binary built: {elitf_input.bin_file}", "success")
            log_mgr.step()
    if log_mgr:
        log_mgr.add(f"Running analysis on {elitf_input.libapp_path}...", "info")
        log_mgr.step()
        result = subprocess.run(
            [elitf_input.bin_file, '-i', elitf_input.libapp_path, '-o', elitf_input.outdir],
            capture_output=True, text=True, errors='replace', stdin=subprocess.DEVNULL)
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                if "null-safety" in line.lower() or "cannot find" in line.lower():
                    log_mgr.add(line, "warn")
                elif line.lower().startswith("error:") or " exception:" in line.lower():
                    log_mgr.add(line, "error")
                else:
                    log_mgr.add(line, "info")
                log_mgr.step()
        if result.returncode != 0:
            if result.stderr:
                log_mgr.add(result.stderr.strip(), "error")
            raise subprocess.CalledProcessError(result.returncode, elitf_input.bin_file)
        log_mgr.add(f"Analysis output: {elitf_input.outdir}", "success")
        log_mgr.step()
    else:
        subprocess.run([elitf_input.bin_file, '-i', elitf_input.libapp_path,
                        '-o', elitf_input.outdir], check=True)

def _analyze_libs(libapp_file, libflutter_file, outdir, rebuild, no_analysis, ida_fcn,
                  ui, log_mgr, vs_sln=False):
    dart_version, snapshot_hash, flags, arch, os_name, has_compressed_ptrs = \
        get_dart_lib_info(libapp_file, libflutter_file, log_mgr)
    if ui is not None:
        ui.metadata = {
            "Dart Version": dart_version,
            "Snapshot Hash": snapshot_hash,
            "Architecture": arch,
            "OS": os_name,
            "Compressed Pointers": "Yes" if has_compressed_ptrs else "No",
            "Null Safety": "Enabled" if 'no-null-safety' not in flags else "Disabled",
            "Auteur": AUTHOR,
        }
    dart_info = DartLibInfo(dart_version, os_name, arch, has_compressed_ptrs, snapshot_hash)
    input_obj = ElitfInput(libapp_file, dart_info, outdir, rebuild, no_analysis,
                           ida_fcn, log_mgr, create_vs_sln=vs_sln)
    build_and_run(input_obj, log_mgr)

def prepare_so_targets(indir, outdir, ui):
    if os.path.isfile(indir) and zipfile.is_zipfile(indir):
        import hashlib
        hasher = hashlib.sha256()
        with open(indir, 'rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                hasher.update(chunk)
        digest = hasher.hexdigest()[:16]
        target_dir = os.path.abspath(os.path.join(outdir, 'inputs', digest))
        has_extracted = False
        if os.path.isdir(target_dir):
            for _root, _dirs, files in os.walk(target_dir):
                if any(f.endswith('.so') for f in files):
                    has_extracted = True
                    break
        if not has_extracted:
            with zipfile.ZipFile(indir) as archive:
                for member in archive.namelist():
                    if member.startswith('lib/') and member.endswith('.so'):
                        _safe_zip_extract(archive, member, target_dir)
        ui.detect_so_files(target_dir)
    elif os.path.isfile(indir):
        # Un fichier .so seul est une cible valide pour --action r2/info
        try:
            size = os.path.getsize(indir)
        except OSError as e:
            raise ValueError(f'Cannot access input file: {indir}') from e
        ui.detected_so = [{"path": os.path.abspath(indir),
                           "name": os.path.basename(indir), "size": size}]
    else:
        ui.detect_so_files(indir)
    return ui.detected_so

def filter_selected_targets(ui, selected):
    """Applique une sélection d'indices aux cibles détectées (option 5)."""
    if selected:
        ui.detected_so = [ui.detected_so[i] for i in selected
                          if 0 <= i < len(ui.detected_so)]
    return ui.detected_so


_CLEANUP_LABELS = {
    'build': 'Compilation C++ (cmake/ninja)',
    'bin': 'Binaires Elit-f compilés',
    'packages': 'Cache SDK Dart VM (headers + libs)',
    'inputs': "Cache d'extraction APK/zip",
    'r2_output': 'Sorties r2 générées',
    'pycache': 'Cache Python',
}


def _dir_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def find_cleanup_targets(project_dir, outdir):
    """Détecte les dossiers compilés et caches supprimables.

    Retourne une liste de dicts {kind, label, path, size} existants.
    """
    items = []
    out_real = os.path.realpath(outdir) if outdir else ''
    fixed = [
        ('build', os.path.join(project_dir, 'build')),
        ('bin', os.path.join(project_dir, 'bin')),
        ('packages', os.path.join(project_dir, 'packages')),
        ('inputs', os.path.join(outdir, 'inputs') if outdir else ''),
        ('r2_output', os.path.join(outdir, 'r2_output') if outdir else ''),
    ]
    for kind, path in fixed:
        if path and os.path.isdir(path):
            items.append({'kind': kind, 'label': _CLEANUP_LABELS[kind],
                          'path': os.path.abspath(path),
                          'size': _dir_size(path)})
    if not os.path.isdir(project_dir):
        return items
    for root, dirs, _files in os.walk(project_dir):
        if out_real and os.path.realpath(root) == out_real:
            dirs[:] = []
            continue
        if '__pycache__' in dirs:
            pyc = os.path.join(root, '__pycache__')
            items.append({'kind': 'pycache', 'label': _CLEANUP_LABELS['pycache'],
                          'path': os.path.abspath(pyc), 'size': _dir_size(pyc)})
            dirs.remove('__pycache__')
    return items


def perform_cleanup(project_dir, outdir, items, picks, log_mgr=None):
    """Supprime les dossiers sélectionnés (garde-fou: uniquement sous
    project_dir ou outdir, jamais les racines elles-mêmes)."""
    project_real = os.path.realpath(project_dir)
    out_real = os.path.realpath(outdir) if outdir else None
    allowed = [project_real + os.sep]
    if out_real:
        allowed.append(out_real + os.sep)
    deleted, freed = [], 0
    for idx in picks:
        item = items[idx]
        path_real = os.path.realpath(item['path'])
        forbidden_roots = {project_real, out_real}
        if path_real in forbidden_roots \
                or not any(path_real.startswith(root) for root in allowed):
            raise ValueError(
                f"Chemin refusé (hors zone autorisée): {item['path']}")
        if not os.path.isdir(path_real):
            continue
        freed += item.get('size', 0) or _dir_size(path_real)
        shutil.rmtree(path_real)
        deleted.append(item['path'])
        if log_mgr:
            log_mgr.add(f"Supprimé: {item['path']}", 'info')
    return deleted, freed


# ---------------------------------------------------------------------------
# Lanceur Termux : taper 'Elit-f' directement dans le terminal
# ---------------------------------------------------------------------------

LAUNCHER_NAMES = ('Elit-f', 'elitf')

LAUNCHER_TEMPLATE = ("""#!/bin/sh
# Lanceur Elit-f — généré par install_launcher
cd "{project_dir}" || exit 1
if command -v python >/dev/null 2>&1; then
    exec python elitf.py "$@"
fi
exec python3 elitf.py "$@"
""")


def _default_launcher_bin_dir():
    prefix = os.environ.get('PREFIX', '')
    if 'com.termux' in prefix or os.path.isdir('/data/data/com.termux'):
        prefix = prefix or '/data/data/com.termux/files/usr'
        return os.path.join(prefix, 'bin')
    return os.path.join(os.path.expanduser('~'), '.local', 'bin')


def install_launcher(project_dir=None, bin_dir=None):
    """Installe les lanceurs 'Elit-f' et 'elitf' (idempotent)."""
    project_dir = os.path.abspath(project_dir or SCRIPT_DIR)
    bin_dir = bin_dir or _default_launcher_bin_dir()
    os.makedirs(bin_dir, exist_ok=True)
    installed = []
    for name in LAUNCHER_NAMES:
        path = os.path.join(bin_dir, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(LAUNCHER_TEMPLATE.format(project_dir=project_dir))
        os.chmod(path, 0o755)
        installed.append(path)
    return installed


def launcher_installed(bin_dir=None):
    bin_dir = bin_dir or _default_launcher_bin_dir()
    return os.path.isfile(os.path.join(bin_dir, 'Elit-f'))


def offer_launcher_install(ui):
    """Propose l'installation du lanceur au premier lancement sur Termux."""
    if not _is_termux() or launcher_installed():
        return
    marker = os.path.join(SCRIPT_DIR, '.elitf_no_launcher')
    if os.path.exists(marker):
        return
    try:
        if not sys.stdout.isatty():
            return
    except (AttributeError, ValueError, OSError):
        return
    ui._print("[bright_cyan]Astuce Termux : lancez Elit-f directement avec la"
              " commande 'Elit-f'.[/]" if ui.console
              else "Astuce Termux : lancez Elit-f directement avec la commande 'Elit-f'.")
    if ui.confirm("Installer le lanceur maintenant ?", default=True):
        try:
            paths = install_launcher()
            ui._print(f"[bright_green]Lanceur installé : {', '.join(paths)}[/]"
                      if ui.console else f"Lanceur installe : {', '.join(paths)}")
            ui._print("Tapez 'Elit-f' (ou 'elitf') pour lancer l'outil."
                      " Si la commande est introuvable, ouvrez un nouveau shell.")
        except OSError as e:
            ui._print(f"Installation du lanceur impossible: {e}")
    else:
        try:
            with open(marker, 'w', encoding='utf-8') as f:
                f.write('installation refusee par l utilisateur\n')
        except OSError:
            pass


def run_flutter_analysis(indir, outdir, rebuild, no_analysis, ida_fcn, ui, log_mgr,
                         vs_sln=False):
    if os.path.isfile(indir) and zipfile.is_zipfile(indir):
        if log_mgr:
            log_mgr.add(f"Extracting APK: {indir}", "info")
            log_mgr.step()
        if vs_sln:
            tmp_dir = os.path.abspath(os.path.join(outdir, 'inputs'))
            libapp_file, libflutter_file = extract_libs_from_apk(indir, tmp_dir)
            return _analyze_libs(libapp_file, libflutter_file, outdir, rebuild,
                                 no_analysis, ida_fcn, ui, log_mgr, vs_sln)
        with tempfile.TemporaryDirectory() as tmp_dir:
            libapp_file, libflutter_file = extract_libs_from_apk(indir, tmp_dir)
            if log_mgr:
                log_mgr.add("APK extracted successfully", "success")
                log_mgr.step()
            _analyze_libs(libapp_file, libflutter_file, outdir, rebuild,
                          no_analysis, ida_fcn, ui, log_mgr, vs_sln)
    else:
        libapp_file, libflutter_file = validate_two_libs(indir)
        _analyze_libs(libapp_file, libflutter_file, outdir, rebuild,
                      no_analysis, ida_fcn, ui, log_mgr, vs_sln)
    if log_mgr:
        log_mgr.add("Flutter/Dart AOT analysis complete", "success")
        log_mgr.step()

def check_dependencies():
    missing = []
    try:
        import elftools
    except ImportError:
        missing.append(('pyelftools', 'pip install pyelftools'))
    try:
        import requests
    except ImportError:
        missing.append(('requests', 'pip install requests'))
    if not HAS_RICH:
        missing.append(('rich', 'pip install rich'))
    return missing

def critical_dependencies_missing(missing):
    return [m for m in missing if m[0] in ('pyelftools', 'requests')]

def run_command(command):
    result = subprocess.run(shlex.split(command) if isinstance(command, str) else command,
                            cwd=SCRIPT_DIR, capture_output=True, text=True, errors='replace',
                            timeout=30, check=True, stdin=subprocess.DEVNULL)
    return result.stdout

def check_for_updates():
    if not os.path.isdir(os.path.join(SCRIPT_DIR, '.git')):
        return
    try:
        run_command(['git', 'fetch'])
        behind = run_command(['git', 'rev-list', '--count', 'HEAD..@{u}'])
        if behind.strip().isdigit() and int(behind):
            print('Elit-f update available. Run git pull --ff-only, then --rebuild.')
    except (OSError, subprocess.SubprocessError):
        return

def main_cli(indir, outdir, rebuild, no_analysis, ida_fcn=False, force_plain=False,
             vs_sln=False):
    ui = ElitfUI(force_plain=force_plain)
    missing = check_dependencies()
    if missing and ui.console:
        from rich.panel import Panel as _Panel
        from rich.style import Style as _Style
        ui.console.print()
        ui.console.print(
            _Panel(
                "\n".join(f"  - {name}  [dim]({cmd})[/]" for name, cmd in missing),
                title="[bold bright_yellow]Dépendances manquantes[/]",
                border_style=_Style(color="bright_yellow")
            ))
    elif missing:
        print("\nDépendances manquantes:")
        for name, cmd in missing:
            print(f"  - {name} ({cmd})")

    if critical_dependencies_missing(missing):
        print("\nAnalyse impossible: installez les dépendances ci-dessus puis relancez.")
        return 1

    os.makedirs(outdir, exist_ok=True)
    try:
        run_flutter_analysis(indir, outdir, rebuild, no_analysis, ida_fcn, ui, None, vs_sln)
    except Exception as exc:
        print(f'ERREUR: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 1
    return 0

def main_interactive(ui, rebuild=False, no_analysis=False, ida_fcn=False,
                     vs_sln=False):
    from rich.rule import Rule as _Rule
    from rich.style import Style as _Style
    from rich.panel import Panel as _Panel
    from rich.prompt import Prompt as _Prompt

    offer_launcher_install(ui)
    ui.display_logo()
    if ui.console:
        ui.console.print(_Rule("[dim]Configuration[/]", style=_Style(dim=True)))
        ui.console.print()
        try:
            indir = _Prompt.ask("  [bold bright_cyan]Répertoire cible / APK[/]",
                                default=ui.indir or "", console=ui.console)
        except (KeyboardInterrupt, EOFError):
            return
    else:
        try:
            indir = input("\n  Repertoire cible / APK: ") or ui.indir
        except (KeyboardInterrupt, EOFError):
            return
    if not indir:
        ui._print("[bold red]Aucun répertoire spécifié.[/]" if ui.console
                  else "Aucun repertoire specifie.")
        return
    indir = os.path.expanduser(indir)
    if ui.console:
        ui.console.print()
        try:
            outdir = _Prompt.ask(
                "  [bold bright_cyan]Répertoire de sortie[/]",
                default=os.path.join(indir, "out") if os.path.isdir(indir) else "./out",
                console=ui.console)
        except (KeyboardInterrupt, EOFError):
            return
    else:
        try:
            outdir = input(f"\n  Repertoire de sortie [{os.path.join(indir, 'out')}]: ") \
                     or os.path.join(indir, "out")
        except (KeyboardInterrupt, EOFError):
            return
    ui.indir = indir
    ui.outdir = os.path.expanduser(outdir)
    outdir = ui.outdir

    is_apk = os.path.isfile(indir) and zipfile.is_zipfile(indir)
    if is_apk:
        ui._print("[bright_cyan]Mode APK détecté.[/]" if ui.console else "Mode APK detecte.")
    elif os.path.isdir(indir):
        ui.detect_so_files(indir)
        ui.display_so_table()
    else:
        ui._print(f"[bold red]Chemin invalide: {indir}[/]" if ui.console
                  else f"Chemin invalide: {indir}")
        return

    missing = check_dependencies()
    if missing:
        if ui.console:
            ui.console.print()
            ui.console.print(_Panel(
                "\n".join(f"  - {name}  [dim]({cmd})[/]" for name, cmd in missing),
                title="[bold bright_yellow]Dépendances manquantes[/]",
                border_style=_Style(color="bright_yellow")))
            ui.console.print("[dim]Dépendances Python :[/]")
            ui.console.print("[dim]  pip install pyelftools requests rich[/]")
            ui.console.print("[dim]Outils système requis pour le build (Dart VM) :[/]")
            ui.console.print("[dim]  Termux: pkg install git cmake ninja clang python pkg-config capstone[/]")
            ui.console.print("[dim]  Debian: sudo apt install git cmake ninja-build clang python3-pip libcapstone-dev[/]")
            ui.console.print("[dim]  macOS : brew install git cmake ninja llvm[/]")
            ui.console.print()
        else:
            print("\nDépendances manquantes:")
            for name, cmd in missing:
                print(f"  - {name} ({cmd})")
            print("Installez les dépendances Python: pip install pyelftools requests rich")
            print("Outils système requis pour le build (Dart VM):")
            print("  Termux: pkg install git cmake ninja clang python pkg-config capstone")
            print("  Debian: sudo apt install git cmake ninja-build clang python3-pip libcapstone-dev")
            print("  macOS : brew install git cmake ninja llvm\n")

    while True:
        indir = ui.indir or indir
        ui._clear()
        ui.display_logo()
        ui.display_metadata()
        ui.display_so_table()
        ui.display_menu()
        choice = ui.get_choice()

        if choice == 0:
            ui._print("[dim]Au revoir.[/]" if ui.console else "Au revoir.")
            break

        if choice in (1, 3, 4):
            if critical_dependencies_missing(check_dependencies()):
                ui._print("[bold red]Analyse impossible: installez pyelftools et requests d'abord.[/]"
                          if ui.console
                          else "Analyse impossible: installez pyelftools et requests d'abord.")
                continue
            os.makedirs(outdir, exist_ok=True)
            ui.log_mgr.clear()
            def work(lm):
                run_flutter_analysis(indir, outdir, rebuild, no_analysis, ida_fcn or choice == 3, ui, lm,
                                     vs_sln)
            try:
                ui.run_with_live_display("Flutter/Dart AOT Analysis", 20, work)
                if ui.console:
                    ui.console.print(_Panel(
                        "[bright_green]Analyse Flutter terminée.[/]",
                        border_style=_Style(color="bright_green")))
            except Exception as e:
                ui._print_error(e)

        elif choice == 2:
            if not ui.detected_so:
                prepare_so_targets(indir, outdir, ui)
            if not ui.detected_so:
                ui._print("[bold yellow]Aucun fichier .so à analyser.[/]" if ui.console
                          else "Aucun fichier .so a analyser.")
                continue
            os.makedirs(outdir, exist_ok=True)
            ui.log_mgr.clear()
            try:
                r2_unified_analysis(ui.detected_so, outdir, ui.log_mgr, ui)
                if ui.console:
                    ui.console.print(_Panel(
                        "[bright_green]Analyse r2 unifiée terminée.[/]",
                        border_style=_Style(color="bright_green")))
            except Exception as e:
                ui._print_error(e)

        elif choice == 5:
            if not ui.detected_so:
                prepare_so_targets(indir, outdir, ui)
            if not ui.detected_so:
                ui._print("[bold yellow]Aucun fichier .so détecté.[/]" if ui.console
                          else "Aucun fichier .so detecte.")
                continue
            os.makedirs(outdir, exist_ok=True)
            info_action = ui.get_info_menu_choice()
            if info_action in ("back", None):
                continue
            if info_action == "display":
                ui.log_mgr.clear()
                def work(lm):
                    display_binary_info(ui.detected_so, outdir, lm)
                try:
                    ui.run_with_live_display("Information binaire",
                                             len(ui.detected_so) * 2, work)
                    if ui.console:
                        ui.console.print(_Panel(
                            "[bright_green]Information binaire affichée.[/]",
                            border_style=_Style(color="bright_green")))
                except Exception as e:
                    ui._print_error(e)
            elif info_action == "change_targets":
                new_indir = ui._prompt_text("Nouveau répertoire cible / APK",
                                            default=ui.indir or indir)
                new_indir = os.path.expanduser((new_indir or "").strip())
                if not new_indir:
                    continue
                previous = ui.detected_so
                try:
                    targets = prepare_so_targets(new_indir, outdir, ui)
                except Exception as e:
                    ui._print_error(e)
                    continue
                ui.indir = new_indir
                if not targets:
                    ui._print("[bold yellow]Aucun .so trouvé — anciennes cibles"
                              " conservées.[/]" if ui.console
                              else "Aucun .so trouve — anciennes cibles conservees.")
                    ui.detected_so = previous
                    continue
                selected = ui.get_target_selection()
                if selected:
                    filter_selected_targets(ui, selected)
                    ui._print(f"[bright_green]{len(ui.detected_so)} cible(s)"
                              " sélectionnée(s).[/]" if ui.console
                              else f"{len(ui.detected_so)} cible(s) selectionnee(s).")
            elif info_action == "cleanup":
                items = find_cleanup_targets(SCRIPT_DIR, outdir)
                picks = ui.get_cleanup_selection(items)
                if not picks:
                    continue
                if not ui.confirm(f"Confirmer la suppression de {len(picks)}"
                                  " dossier(s) ?", default=False):
                    continue
                try:
                    deleted, freed = perform_cleanup(SCRIPT_DIR, outdir,
                                                     items, picks)
                except (ValueError, OSError) as e:
                    ui._print_error(e)
                    continue
                ui._print(f"[bright_green]{len(deleted)} dossier(s) supprimé(s)"
                          f" — {ui._format_size(freed)} libérés.[/]"
                          if ui.console
                          else f"{len(deleted)} dossier(s) supprime(s)"
                               f" — {freed} octets liberes.")

        else:
            ui._print("[bold yellow]Option invalide.[/]" if ui.console else "Option invalide.")

        if ui.console:
            try:
                input("\n  Appuyez sur Entrée pour continuer...")
            except (KeyboardInterrupt, EOFError):
                break

def main_no_flutter(libapp_path: str, dart_version: str, outdir: str,
                    rebuild: bool, no_analysis: bool, ida_fcn: bool = False,
                    vs_sln: bool = False):
    parts = dart_version.split('_', 2)
    if len(parts) != 3:
        sys.exit(f'Invalid dart-version format: "{dart_version}". '
                 'Expected "<version>_<os>_<arch>" (e.g. "3.4.2_android_arm64")')
    version, os_name, arch = parts
    from extract_dart_info import extract_snapshot_hash_flags, extract_elf_arch
    snapshot_hash, flags = extract_snapshot_hash_flags(libapp_path)
    if extract_elf_arch(libapp_path) != arch:
        raise ValueError('Requested architecture does not match libapp')
    dart_info = DartLibInfo(version, os_name, arch, 'compressed-pointers' in flags, snapshot_hash)
    input_obj = ElitfInput(libapp_path, dart_info, outdir, rebuild, no_analysis, ida_fcn,
                           create_vs_sln=vs_sln)
    build_and_run(input_obj)

def main():
    parser = argparse.ArgumentParser(
        prog='Elit-f',
        description='Reversing a flutter application tool '
                    '(needs exactly libapp.so and libflutter.so)')
    parser.add_argument('indir', nargs='?', default=None,
                        help='An apk or a directory that contains exactly both '
                             'libapp.so and libflutter.so')
    parser.add_argument('outdir', nargs='?', default=None, help='An output directory')
    parser.add_argument('--rebuild', action='store_true', default=False,
                        help='Force rebuild the Elit-f executable')
    parser.add_argument('--no-analysis', action='store_true', default=False,
                        help='Do not build with code analysis')
    parser.add_argument('--ida-fcn', action='store_true', default=False,
                        help='Build with IDA function support')
    parser.add_argument('--dart-version',
                        help='Run without libflutter (indir becomes libapp.so path). '
                             'Format: <version>_<os>_<arch>')
    parser.add_argument('--cli', action='store_true', default=False,
                        help='Force CLI mode (no interactive menu)')
    parser.add_argument('--plain', action='store_true', default=False,
                        help='Disable Rich Live animations and use plain streaming '
                             '(recommended on Termux or limited terminals)')
    parser.add_argument('--vs-sln', action='store_true', default=False,
                        help='Generate Visual Studio solution at <outdir> '
                             '(run from a Visual Studio Developer console)')
    parser.add_argument('--nu', action='store_false', default=True,
                        help='Do not check for updates')
    parser.add_argument('--install-launcher', action='store_true', default=False,
                        help="Installer les lanceurs 'Elit-f'/'elitf' (Termux:"
                             " lancement direct via la commande 'Elit-f')")
    parser.add_argument('--action', choices=('flutter', 'r2', 'info'), default='flutter')
    parser.add_argument('--r2-preset', choices=tuple(R2_PRESETS), default='standard')
    parser.add_argument('--generate-only', action='store_true')
    args = parser.parse_args()

    if args.cli and not args.indir:
        parser.error('--cli requires an input path')
    if args.cli and not args.outdir:
        args.outdir = './out'

    if args.nu:
        check_for_updates()

    if args.install_launcher:
        try:
            paths = install_launcher(project_dir=SCRIPT_DIR)
        except OSError as e:
            print(f'ERREUR: installation du lanceur impossible: {e}',
                  file=sys.stderr)
            return 1
        for p in paths:
            print(f"Installé: {p}")
        print("Lancez l'outil en tapant: Elit-f   (ou 'elitf')")
        print("Si la commande est introuvable, ouvrez un nouveau shell Termux.")
        return 0

    if args.action != 'flutter':
        if not args.indir:
            parser.error('--action requires an input path')
        if args.dart_version or args.vs_sln:
            parser.error('--dart-version and --vs-sln require --action flutter')
        outdir = args.outdir or './out'
        ui = ElitfUI(force_plain=True)
        try:
            targets = prepare_so_targets(args.indir, outdir, ui)
            if not targets:
                raise ValueError('No shared libraries found')
            if args.action == 'info':
                display_binary_info(targets, outdir, ui.log_mgr)
            else:
                preset = R2_PRESETS[args.r2_preset]
                run_r2_custom(targets, outdir, preset['analysis_key'],
                              preset['extraction_keys'], ui.log_mgr,
                              execute=not args.generate_only)
            print(ui.log_mgr.get_plain_text())
            return 0
        except Exception as exc:
            print(f'ERREUR: {exc}', file=sys.stderr)
            return 1

    if args.dart_version is not None:
        if not args.indir:
            sys.exit('--dart-version requires indir (libapp.so path)')
        outdir = args.outdir or './out'
        try:
            main_no_flutter(args.indir, args.dart_version, outdir,
                            args.rebuild, args.no_analysis, args.ida_fcn,
                            vs_sln=args.vs_sln)
        except Exception as exc:
            print(f'ERREUR: {exc}', file=sys.stderr)
            return 1
        return 0

    if args.indir and args.outdir:
        if args.cli or not HAS_RICH:
            return main_cli(args.indir, args.outdir, args.rebuild,
                            args.no_analysis, args.ida_fcn,
                            force_plain=args.plain, vs_sln=args.vs_sln) or 0

        ui = ElitfUI(force_plain=args.plain)
        ui.indir = args.indir
        ui.outdir = args.outdir
        main_interactive(ui, args.rebuild, args.no_analysis, args.ida_fcn,
                         vs_sln=args.vs_sln)
        return 0

    if not HAS_RICH:
        print("\n  Elit-f - Flutter/Dart AOT Reversing Engine")
        print(f"  Auteur : {AUTHOR}")
        print("  pip install rich  (pour l'interface complète)\n")
        if not args.indir:
            try:
                args.indir = input("  Repertoire cible / APK: ")
            except (KeyboardInterrupt, EOFError):
                return 0
        if not args.indir:
            return 0
        if not args.outdir:
            try:
                args.outdir = input("  Repertoire de sortie [./out]: ") or "./out"
            except (KeyboardInterrupt, EOFError):
                return 0
        try:
            run_flutter_analysis(args.indir, args.outdir, args.rebuild,
                                 args.no_analysis, args.ida_fcn,
                                 ElitfUI(force_plain=args.plain), None, args.vs_sln)
        except Exception as e:
            print(f"\nERREUR: {type(e).__name__}: {e}")
            return 2
        return 0

    ui = ElitfUI(force_plain=args.plain)
    if args.indir:
        ui.indir = args.indir
    if args.outdir:
        ui.outdir = args.outdir
    main_interactive(ui, args.rebuild, args.no_analysis, args.ida_fcn,
                     vs_sln=args.vs_sln)
    return 0

if __name__ == "__main__":
    sys.exit(main() or 0)
