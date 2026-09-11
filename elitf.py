#!/usr/bin/env python3
import argparse
import glob
import mmap
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile

from dartvm_fetch_build import DartLibInfo
from elitf_ui import LogManager, ElitfUI, AUTHOR, HAS_RICH
from elitf_r2 import display_binary_info, r2_unified_analysis, run_r2_custom, R2_PRESETS

CMAKE_CMD = os.getenv('CMAKE', 'cmake')
NINJA_CMD = os.getenv('NINJA', 'ninja')

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


    major, minor = _parse_major_minor(dart_version)
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

def cmake_elitf(elitf_input: ElitfInput, log_mgr: LogManager = None):
    builddir = os.path.join(BUILD_DIR, elitf_input.bin_name)
    macros = find_compat_macro(elitf_input.dart_info.version,
                               elitf_input.no_analysis, elitf_input.ida_fcn)
    if log_mgr:
        log_mgr.add(f"Compat macros: {' '.join(macros)}", "info")
    my_env = None
    if platform.system() == 'Darwin':
        mac_ver = int(platform.mac_ver()[0].split('.', 1)[0])
        if mac_ver < 15:
            llvm_prefix = subprocess.run(['brew', '--prefix', 'llvm@16'], capture_output=True,
                                         check=True).stdout.decode().strip()
            clang_file = os.path.join(llvm_prefix, 'bin', 'clang')
            my_env = {**os.environ, 'CC': clang_file, 'CXX': clang_file + '++'}
    cmd = [CMAKE_CMD, '-GNinja', '-B', builddir,
           f'-DDARTLIB={elitf_input.dart_info.lib_name}',
           f'-DNAME_SUFFIX={elitf_input.name_suffix}',
           '-DCMAKE_BUILD_TYPE=Release', '--log-level=NOTICE'] + macros
    if log_mgr:
        log_mgr.add("Running cmake configure...", "info")
    try:
        subprocess.run(cmd, cwd=SCRIPT_DIR, check=True, stdin=subprocess.DEVNULL, env=my_env)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"cmake configure failed (exit {e.returncode})") from e
    except FileNotFoundError:
        raise RuntimeError(
            f"cmake binary not found ('{CMAKE_CMD}'). Install cmake or set CMAKE env var.")
    if log_mgr:
        log_mgr.add("Running ninja build...", "info")
        log_mgr.step()
    try:
        subprocess.run([NINJA_CMD], cwd=builddir, check=True, stdin=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"ninja build failed (exit {e.returncode})") from e
    except FileNotFoundError:
        raise RuntimeError(
            f"ninja binary not found ('{NINJA_CMD}'). Install ninja or set NINJA env var.")
    if log_mgr:
        log_mgr.add("Running cmake install...", "info")
        log_mgr.step()
    try:
        subprocess.run([CMAKE_CMD, '--install', '.'], cwd=builddir, check=True,
                       stdin=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"cmake install failed (exit {e.returncode})") from e
    if log_mgr:
        log_mgr.step()

def cmake_vs_sln(elitf_input: ElitfInput, log_mgr: LogManager = None):
    macros = find_compat_macro(elitf_input.dart_info.version,
                               elitf_input.no_analysis, elitf_input.ida_fcn)
    if log_mgr:
        log_mgr.add("Generating Visual Studio solution...", "info")
    dbg_output_path = os.path.abspath(os.path.join(elitf_input.outdir, 'out'))
    dbg_cmd_args = f'-i {elitf_input.libapp_path} -o {dbg_output_path}'
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
                fetch_and_build(elitf_input.dart_info)
            except (subprocess.CalledProcessError, OSError, FileNotFoundError) as e:
                raise RuntimeError(
                    f"Failed to fetch/build Dart VM {elitf_input.dart_info.version}: {e}. "
                    "Check network connectivity and that 'git' is installed.") from e
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
            capture_output=True, text=True, stdin=subprocess.DEVNULL)
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
        with zipfile.ZipFile(indir) as archive:
            for member in archive.namelist():
                if member.startswith('lib/') and member.endswith('.so'):
                    _safe_zip_extract(archive, member, target_dir)
        ui.detect_so_files(target_dir)
    else:
        ui.detect_so_files(indir)
    return ui.detected_so

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
                            cwd=SCRIPT_DIR, capture_output=True, text=True,
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
    ui.outdir = outdir

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
            ui.console.print("[dim]Installez-les avant de lancer une analyse :[/]")
            ui.console.print("[dim]  pkg install python && pip install pyelftools requests rich[/]")
            ui.console.print()
        else:
            print("\nDépendances manquantes:")
            for name, cmd in missing:
                print(f"  - {name} ({cmd})")
            print("Installez-les: pkg install python && pip install pyelftools requests rich\n")

    while True:
        ui._clear()
        ui.display_logo()
        ui.display_metadata()
        ui.display_so_table()
        ui.display_menu()
        choice = ui.get_choice()

        if choice == 0:
            ui._print("[dim]Au revoir.[/]" if ui.console else "Au revoir.")
            break

        if choice == 1:
            if critical_dependencies_missing(check_dependencies()):
                ui._print("[bold red]Analyse impossible: installez pyelftools et requests d'abord.[/]"
                          if ui.console
                          else "Analyse impossible: installez pyelftools et requests d'abord.")
                continue
            os.makedirs(outdir, exist_ok=True)
            ui.log_mgr.clear()
            def work(lm):
                run_flutter_analysis(indir, outdir, rebuild, no_analysis, ida_fcn, ui, lm,
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
            def work(lm):
                r2_unified_analysis(ui.detected_so, outdir, lm, ui)
            try:
                r2_unified_analysis(ui.detected_so, outdir, ui.log_mgr, ui)
                if ui.console:
                    ui.console.print(_Panel(
                        "[bright_green]Analyse r2 unifiée terminée.[/]",
                        border_style=_Style(color="bright_green")))
            except Exception as e:
                ui._print_error(e)

        elif choice == 3:
            ui._print("[bright_cyan]Les scripts IDA sont générés automatiquement lors de l'analyse Flutter (option 1).[/]"
                      if ui.console
                      else "Les scripts IDA sont generes automatiquement lors de l'analyse Flutter (option 1).")

        elif choice == 4:
            ui._print("[bright_cyan]Les scripts Frida sont générés automatiquement lors de l'analyse Flutter (option 1).[/]"
                      if ui.console
                      else "Les scripts Frida sont generes automatiquement lors de l'analyse Flutter (option 1).")

        elif choice == 5:
            if not ui.detected_so:
                prepare_so_targets(indir, outdir, ui)
            if not ui.detected_so:
                ui._print("[bold yellow]Aucun fichier .so détecté.[/]" if ui.console
                          else "Aucun fichier .so detecte.")
                continue
            os.makedirs(outdir, exist_ok=True)
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
    parser.add_argument('--action', choices=('flutter', 'r2', 'info'), default='flutter')
    parser.add_argument('--r2-preset', choices=tuple(R2_PRESETS), default='full')
    parser.add_argument('--generate-only', action='store_true')
    args = parser.parse_args()

    if args.cli and not args.indir:
        parser.error('--cli requires an input path')
    if args.cli and not args.outdir:
        args.outdir = './out'

    if args.nu:
        check_for_updates()

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
