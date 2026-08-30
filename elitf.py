#!/usr/bin/env python3
"""
elitf.py — Point d'entrée d'Elit-f (reversing d'applications Flutter/Dart AOT).

Ce module contient la logique métier (extraction APK, détection version Dart,
macros de compatibilité, build CMake/Ninja, exécution de l'analyseur C++).
L'interface utilisateur (TUI Rich, LogManager) est dans `elitf_ui.py`.
Les fonctions r2 / readelf sont dans `elitf_r2.py`.

Trois modes d'utilisation :
  * Mode interactif (TUI) — défaut si `rich` est installé et qu'aucun indir/outdir
    n'est fourni sur la ligne de commande.
  * Mode CLI one-shot — `python3 elitf.py <indir> <outdir> [--cli]`
    (le flag `--cli` force le mode CLI même avec `rich`).
  * Mode sans libflutter — `python3 elitf.py <libapp.so> --dart-version X.Y.Z_os_arch <outdir>`
"""
import argparse
import mmap
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

from dartvm_fetch_build import DartLibInfo
from elitf_ui import LogManager, ElitfUI, AUTHOR, HAS_RICH, strip_rich_tags
from elitf_r2 import generate_r2_scripts, run_r2_scripts, display_binary_info, r2_unified_analysis

CMAKE_CMD = os.getenv('CMAKE', 'cmake')
NINJA_CMD = os.getenv('NINJA', 'ninja')

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
BIN_DIR = os.path.join(SCRIPT_DIR, 'bin')
PKG_INC_DIR = os.path.join(SCRIPT_DIR, 'packages', 'include')
PKG_LIB_DIR = os.path.join(SCRIPT_DIR, 'packages', 'lib')
BUILD_DIR = os.path.join(SCRIPT_DIR, 'build')

EXPECTED_LIBS = ('libapp.so', 'libflutter.so')

# ABI directories searched (in order) when extracting libs from an APK.
ABI_DIRS = ['lib/arm64-v8a/', 'lib/armeabi-v7a/', 'lib/x86_64/', 'lib/x86/']


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _safe_zip_extract(zf: zipfile.ZipFile, member_name: str, out_dir: str) -> str:
    """Extract `member_name` from `zf` into `out_dir`, protecting against Zip Slip.

    Returns the absolute path of the extracted file.
    """
    target_path = os.path.abspath(os.path.join(out_dir, member_name))
    base_dir = os.path.abspath(out_dir) + os.sep
    if not target_path.startswith(base_dir):
        raise ValueError(f"Refusing to extract '{member_name}' outside of '{out_dir}' (path traversal)")
    zf.extract(member_name, out_dir)
    return target_path


def _search_in_file(path: str, needle: bytes) -> bool:
    """True if `needle` appears in the file at `path` (memory-mapped search)."""
    with open(path, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            return mm.find(needle) != -1


def _parse_major_minor(version: str):
    """Return (major, minor) tuple from a "X.Y.Z" version string.

    Missing minor defaults to 0. Malformed values also return (0, 0).
    """
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


# ---------------------------------------------------------------------------
# Input validation / extraction
# ---------------------------------------------------------------------------
def validate_two_libs(indir: str):
    """Ensure `indir` contains exactly libapp.so and libflutter.so.

    Searches recursively in subdirectories (e.g. lib/arm64-v8a/) so that
    users can point to a parent directory that contains an ABI folder
    structure extracted from an APK.

    Returns a tuple of absolute paths (libapp_path, libflutter_path).
    Raises `ValueError` (rather than sys.exit) so callers can recover.
    """
    if not os.path.isdir(indir):
        raise ValueError(
            f"Input is not a directory containing {EXPECTED_LIBS[0]} and {EXPECTED_LIBS[1]}")

    import glob as globmod

    # First try: direct children (fast path, preserves strict behaviour)
    try:
        so_files = sorted(f for f in os.listdir(indir) if f.endswith('.so'))
    except OSError as e:
        raise ValueError(f"Cannot list directory '{indir}': {e}")

    # If both expected libs found directly, return them (original behaviour)
    expected = sorted(EXPECTED_LIBS)
    if all(f in so_files for f in expected):
        return (os.path.abspath(os.path.join(indir, EXPECTED_LIBS[0])),
                os.path.abspath(os.path.join(indir, EXPECTED_LIBS[1])))

    # Second try: recursive glob to find .so in subdirectories (e.g. lib/arm64-v8a/)
    try:
        all_so = globmod.glob(os.path.join(indir, '**', '*.so'), recursive=True)
    except (PermissionError, OSError):
        all_so = []

    found = {}  # basename -> absolute path
    for p in all_so:
        name = os.path.basename(p)
        if name in EXPECTED_LIBS and name not in found:
            found[name] = os.path.abspath(p)

    missing = [f for f in EXPECTED_LIBS if f not in found]
    if missing:
        raise ValueError(
            f"Missing libraries: {missing}. The Flutter libs must be exactly two: "
            f"{EXPECTED_LIBS[0]} and {EXPECTED_LIBS[1]}")

    return (found[EXPECTED_LIBS[0]], found[EXPECTED_LIBS[1]])


def extract_libs_from_apk(apk_file: str, out_dir: str):
    """Extract libapp.so and libflutter.so from an APK, trying all known ABIs.

    Returns (libapp_path, libflutter_path). Raises `ValueError` if not found.
    """
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


# ---------------------------------------------------------------------------
# Compatibility macros
# ---------------------------------------------------------------------------
def find_compat_macro(dart_version: str, no_analysis: bool, ida_fcn: bool = False):
    """Detect required -D... macros by scanning the installed Dart SDK headers.

    Strictly mirrors the upstream blutter `find_compat_macro()` so that the
    compiled C++ binary is byte-for-byte compatible with the one produced by
    blutter (1=1 output). Any divergence here would compile a different binary
    and break the parity guarantee.
    """
    macros = []
    include_path = os.path.join(PKG_INC_DIR, f'dartvm{dart_version}')
    vm_path = os.path.join(include_path, 'vm')

    required_files = [
        'class_id.h', 'class_table.h', 'stub_code_list.h',
        'object_store.h', 'object.h',
    ]
    for required in required_files:
        if not os.path.isfile(os.path.join(vm_path, required)):
            raise FileNotFoundError(
                f"Required Dart header not found: {os.path.join(vm_path, required)}. "
                "Did you run `dartvm_fetch_build.py` to fetch the SDK headers?")

    # class_id.h
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

    # class_table.h
    if _search_in_file(os.path.join(vm_path, 'class_table.h'), b'class SharedClassTable {'):
        macros.append('-DHAS_SHARED_CLASS_TABLE=1')

    # stub_code_list.h
    if not _search_in_file(os.path.join(vm_path, 'stub_code_list.h'), b'V(InitLateStaticField)'):
        macros.append('-DNO_INIT_LATE_STATIC_FIELD=1')

    # object_store.h
    if not _search_in_file(os.path.join(vm_path, 'object_store.h'),
                           b'build_generic_method_extractor_code)'):
        macros.append('-DNO_METHOD_EXTRACTOR_STUB=1')

    # object.h — UNIFORM_INTEGER_ACCESS is set when AsTruncatedInt64Value is absent.
    # (HtArrayIterator.h then always uses Smi::Value() — see the C++ source.)
    if not _search_in_file(os.path.join(vm_path, 'object.h'), b'AsTruncatedInt64Value()'):
        macros.append('-DUNIFORM_INTEGER_ACCESS=1')

    # OLD_MARKING_STACK_BLOCK: Dart 3.5.0+ split marking_stack_block into old/new
    # https://github.com/worawit/blutter/issues/96#issue-2470674670
    major, _ = _parse_major_minor(dart_version)
    if major >= 3 and _parse_major_minor(dart_version)[1] >= 5:
        macros.append('-DOLD_MARKING_STACK_BLOCK=1')

    if no_analysis:
        macros.append('-DNO_CODE_ANALYSIS=1')
    if ida_fcn:
        macros.append('-DIDA_FCN=1')
    return macros


# ---------------------------------------------------------------------------
# Build & run
# ---------------------------------------------------------------------------
class ElitfInput:
    """Configuration for a single Elit-f execution (libapp + dart_info + outdir)."""
    def __init__(self, libapp_path: str, dart_info: DartLibInfo, outdir: str,
                 rebuild: bool, no_analysis: bool, ida_fcn: bool = False,
                 log_mgr: LogManager = None):
        self.libapp_path = libapp_path
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
        self.no_analysis = no_analysis

        self.name_suffix = ''
        if not dart_info.has_compressed_ptrs:
            self.name_suffix += '_no-compressed-ptrs'
        if no_analysis:
            self.name_suffix += '_no-analysis'
        if ida_fcn:
            self.name_suffix += '_ida-fcn'
        self.bin_name = f'elitf_{dart_info.lib_name}{self.name_suffix}'
        self.bin_file = os.path.join(BIN_DIR, self.bin_name)


def cmake_elitf(elitf_input: ElitfInput, log_mgr: LogManager = None):
    """Configure + build + install the Elit-f binary via CMake/Ninja."""
    builddir = os.path.join(BUILD_DIR, elitf_input.bin_name)
    macros = find_compat_macro(elitf_input.dart_info.version,
                               elitf_input.no_analysis, elitf_input.ida_fcn)
    if log_mgr:
        log_mgr.add(f"Compat macros: {' '.join(macros)}", "info")
    cmd = [CMAKE_CMD, '-GNinja', '-B', builddir,
           f'-DDARTLIB={elitf_input.dart_info.lib_name}',
           f'-DNAME_SUFFIX={elitf_input.name_suffix}',
           '-DCMAKE_BUILD_TYPE=Release', '--log-level=NOTICE'] + macros
    fmt_inc = os.getenv('FMT_INCLUDE_DIR')
    if fmt_inc:
        cmd.append(f'-DFMT_INCLUDE_DIR={fmt_inc}')
    if log_mgr:
        log_mgr.add("Running cmake configure...", "info")
    try:
        subprocess.run(cmd, cwd=SCRIPT_DIR, check=True, stdin=subprocess.DEVNULL)
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


def get_dart_lib_info(libapp_path: str, libflutter_path: str, log_mgr: LogManager = None):
    """Return (dart_version, snapshot_hash, flags, arch, os_name, has_compressed_ptrs)."""
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
    """Build the Elit-f binary if needed, then run it on `elitf_input.libapp_path`."""
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


# ---------------------------------------------------------------------------
# Orchestration helpers (factorized, used by both CLI and TUI)
# ---------------------------------------------------------------------------
def _analyze_libs(libapp_file, libflutter_file, outdir, rebuild, no_analysis, ida_fcn,
                  ui, log_mgr):
    """Common path: extract dart info → build DartLibInfo → build & run Elit-f."""
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
                           ida_fcn, log_mgr)
    build_and_run(input_obj, log_mgr)


def run_flutter_analysis(indir, outdir, rebuild, no_analysis, ida_fcn, ui, log_mgr):
    """Analyze either an APK or a directory containing libapp.so + libflutter.so."""
    if indir.endswith(".apk"):
        if log_mgr:
            log_mgr.add(f"Extracting APK: {indir}", "info")
            log_mgr.step()
        with tempfile.TemporaryDirectory() as tmp_dir:
            libapp_file, libflutter_file = extract_libs_from_apk(indir, tmp_dir)
            if log_mgr:
                log_mgr.add("APK extracted successfully", "success")
                log_mgr.step()
            _analyze_libs(libapp_file, libflutter_file, outdir, rebuild,
                          no_analysis, ida_fcn, ui, log_mgr)
    else:
        libapp_file, libflutter_file = validate_two_libs(indir)
        _analyze_libs(libapp_file, libflutter_file, outdir, rebuild,
                      no_analysis, ida_fcn, ui, log_mgr)
    if log_mgr:
        log_mgr.add("Flutter/Dart AOT analysis complete", "success")
        log_mgr.step()


def check_dependencies():
    """Return list of (name, install_cmd) for each missing Python dependency."""
    missing = []
    try:
        import elftools  # noqa: F401
    except ImportError:
        missing.append(('pyelftools', 'pip install pyelftools'))
    try:
        import requests  # noqa: F401
    except ImportError:
        missing.append(('requests', 'pip install requests'))
    if not HAS_RICH:
        missing.append(('rich', 'pip install rich'))
    return missing


# ---------------------------------------------------------------------------
# CLI mode (one-shot)
# ---------------------------------------------------------------------------
def main_cli(indir, outdir, rebuild, no_analysis, ida_fcn=False, force_plain=False):
    """CLI one-shot mode: show menu once, run the chosen action, exit.

    Args:
        force_plain: if True, disable Rich Live animations even when Rich is
            available — recommended on Termux or any terminal where Live
            refresh doesn't work correctly.
    """
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

    if not HAS_RICH:
        # Minimal fallback: just run the Flutter analysis directly.
        print(f"\n  Auteur : {AUTHOR}")
        print("  Pour l'interface complète, installez: pip install rich\n")
        run_flutter_analysis(indir, outdir, rebuild, no_analysis, ida_fcn, ui, None)
        return

    ui.indir = indir
    ui.outdir = outdir
    ui.display_logo()
    is_apk = indir.endswith(".apk")
    if not is_apk and os.path.isdir(indir):
        ui.detect_so_files(indir)
        ui.display_so_table()
    ui.display_menu()
    choice = ui.get_choice()

    if choice == 0:
        return
    if choice == 1:
        os.makedirs(outdir, exist_ok=True)
        ui.log_mgr.clear()
        def work(lm):
            run_flutter_analysis(indir, outdir, rebuild, no_analysis, ida_fcn, ui, lm)
        try:
            ui.run_with_live_display("Flutter/Dart AOT Analysis", 20, work)
        except Exception as e:
            ui._print_error(e)
            return 1
    elif choice == 2:
        if not ui.detected_so and not is_apk:
            ui.detect_so_files(indir)
        if not ui.detected_so:
            print("No .so files detected")
            return 1
        os.makedirs(outdir, exist_ok=True)
        ui.log_mgr.clear()
        def work(lm):
            r2_unified_analysis(ui.detected_so, outdir, lm, ui)
        try:
            ui.run_with_live_display("Radare2 - Analyse unifiée",
                                     len(ui.detected_so) * 5, work)
        except Exception as e:
            ui._print_error(e)
            return 1
    elif choice == 3:
        print("Les scripts IDA sont générés automatiquement lors de l'analyse Flutter (option 1).")
    elif choice == 4:
        print("Les scripts Frida sont générés automatiquement lors de l'analyse Flutter (option 1).")
    elif choice == 5:
        if not ui.detected_so and not is_apk:
            ui.detect_so_files(indir)
        if not ui.detected_so:
            print("No .so files detected")
            return 1
        os.makedirs(outdir, exist_ok=True)
        ui.log_mgr.clear()
        def work(lm):
            display_binary_info(ui.detected_so, outdir, lm)
        try:
            ui.run_with_live_display("Information binaire",
                                     len(ui.detected_so) * 2, work)
        except Exception as e:
            ui._print_error(e)
            return 1
    else:
        print("Option invalide.")
        return 1
    return 0


# ---------------------------------------------------------------------------
# Interactive TUI mode
# ---------------------------------------------------------------------------
def main_interactive(ui, rebuild=False, no_analysis=False, ida_fcn=False):
    """Interactive menu loop (clears screen + redraws at each iteration)."""
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

    is_apk = indir.endswith(".apk")
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
            os.makedirs(outdir, exist_ok=True)
            ui.log_mgr.clear()
            def work(lm):
                run_flutter_analysis(indir, outdir, rebuild, no_analysis, ida_fcn, ui, lm)
            try:
                ui.run_with_live_display("Flutter/Dart AOT Analysis", 20, work)
                if ui.console:
                    ui.console.print(_Panel(
                        "[bright_green]Analyse Flutter terminée.[/]",
                        border_style=_Style(color="bright_green")))
            except Exception as e:
                ui._print_error(e)

        elif choice == 2:
            if not ui.detected_so and not is_apk:
                ui.detect_so_files(indir)
            if not ui.detected_so:
                ui._print("[bold yellow]Aucun fichier .so à analyser.[/]" if ui.console
                          else "Aucun fichier .so a analyser.")
                continue
            os.makedirs(outdir, exist_ok=True)
            ui.log_mgr.clear()
            def work(lm):
                r2_unified_analysis(ui.detected_so, outdir, lm, ui)
            try:
                ui.run_with_live_display("Radare2 - Analyse unifiée",
                                         len(ui.detected_so) * 5, work)
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
            if not ui.detected_so and not is_apk:
                ui.detect_so_files(indir)
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


# ---------------------------------------------------------------------------
# Mode without libflutter (libapp.so only + user-provided dart version)
# ---------------------------------------------------------------------------
def main_no_flutter(libapp_path: str, dart_version: str, outdir: str,
                    rebuild: bool, no_analysis: bool, ida_fcn: bool = False):
    """Run with libapp.so only, using a user-provided `<version>_<os>_<arch>` string.

    The dart_version string MUST follow the format `<X.Y.Z>_<os>_<arch>` (e.g.
    `3.4.2_android_arm64`). Restored from v1 because the previous version of
    `a/elitf.py` dropped this entry point silently.
    """
    parts = dart_version.split('_')
    if len(parts) != 3:
        sys.exit(f'Invalid dart-version format: "{dart_version}". '
                 'Expected "<version>_<os>_<arch>" (e.g. "3.4.2_android_arm64")')
    version, os_name, arch = parts
    dart_info = DartLibInfo(version, os_name, arch)
    input_obj = ElitfInput(libapp_path, dart_info, outdir, rebuild, no_analysis, ida_fcn)
    build_and_run(input_obj)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
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
    args = parser.parse_args()

    # --dart-version mode: libapp.so + user-provided version (no libflutter needed)
    if args.dart_version is not None:
        if not args.indir:
            sys.exit('--dart-version requires indir (libapp.so path)')
        outdir = args.outdir or './out'
        main_no_flutter(args.indir, args.dart_version, outdir,
                        args.rebuild, args.no_analysis, args.ida_fcn)
        return 0

    # Dispatch logic (B3 fix: --cli is now meaningful):
    #   * indir + outdir + --cli          -> CLI one-shot menu (main_cli)
    #   * indir + outdir (no --cli) + rich -> full interactive TUI (main_interactive)
    #   * indir + outdir (no --cli) + !rich -> CLI one-shot menu (fallback)
    #   * partial or none + rich          -> interactive TUI prompting for missing args
    #   * partial or none + !rich         -> prompt + direct flutter analysis
    if args.indir and args.outdir:
        if args.cli or not HAS_RICH:
            return main_cli(args.indir, args.outdir, args.rebuild,
                            args.no_analysis, args.ida_fcn,
                            force_plain=args.plain) or 0
        # Rich available, no --cli: launch full TUI with indir+outdir preset.
        ui = ElitfUI(force_plain=args.plain)
        ui.indir = args.indir
        ui.outdir = args.outdir
        main_interactive(ui, args.rebuild, args.no_analysis, args.ida_fcn)
        return 0

    # No indir+outdir: prompt interactively.
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
                                 ElitfUI(force_plain=args.plain), None)
        except Exception as e:
            print(f"\nERREUR: {type(e).__name__}: {e}")
            return 2
        return 0

    # Rich available: launch interactive TUI (indir/outdir preset if provided).
    ui = ElitfUI(force_plain=args.plain)
    if args.indir:
        ui.indir = args.indir
    if args.outdir:
        ui.outdir = args.outdir
    main_interactive(ui, args.rebuild, args.no_analysis, args.ida_fcn)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
