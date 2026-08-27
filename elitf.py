#!/usr/bin/env python3
import argparse
import mmap
import os
import platform
import shutil
import subprocess
import sys
import zipfile
import tempfile
import time
import glob as globmod
import threading
from pathlib import Path
from datetime import datetime
from collections import deque
from io import StringIO

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TimeElapsedColumn, MofNCompleteColumn, TaskProgressColumn, DownloadColumn
    from rich.text import Text
    from rich.layout import Layout
    from rich.live import Live
    from rich.prompt import IntPrompt, Confirm, Prompt
    from rich.rule import Rule
    from rich.style import Style
    from rich.align import Align
    from rich import box as rbox
    from rich.columns import Columns
    from rich.tree import Tree
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from dartvm_fetch_build import DartLibInfo

CMAKE_CMD = os.getenv('CMAKE', 'cmake')
NINJA_CMD = os.getenv('NINJA', 'ninja')

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
BIN_DIR = os.path.join(SCRIPT_DIR, 'bin')
PKG_INC_DIR = os.path.join(SCRIPT_DIR, 'packages', 'include')
PKG_LIB_DIR = os.path.join(SCRIPT_DIR, 'packages', 'lib')
BUILD_DIR = os.path.join(SCRIPT_DIR, 'build')

EXPECTED_LIBS = ('libapp.so', 'libflutter.so')

AUTHOR = "𝕴𝖗𝖎𝖓𝖙𝖘𝖔𝖆 𝕮𝖍𝖆𝖓𝖉𝖗𝖔𝖍"

LOGO = (
    "[bold bright_cyan]    ╔═══════════════════════════════════════════════╗[/]\n"
    "    [bold bright_cyan]║[/] [bold bright_white]E[/][bold bright_cyan] L [/][bold bright_white]I[/][bold bright_cyan] T [/][bold bright_white]-[/][bold bright_cyan] F [/][bold bright_cyan]                             ║[/]\n"
    "    [bold bright_cyan]║[/] [dim]Flutter/Dart AOT Reversing Engine[/]       [bold bright_cyan]║[/]\n"
    "    [bold bright_cyan]╠═══════════════════════════════════════════════╣[/]\n"
    "    [bold bright_cyan]║[/] [bright_yellow]◈[/] [bold bright_white]Auteur[/] : [italic bright_magenta]%s[/]   [bold bright_cyan]║[/]\n"
    "    [bold bright_cyan]║[/] [bright_yellow]◈[/] [bold bright_white]Plateforme[/] : [bright_green]%s[/]  [bold bright_cyan]║[/]\n"
    "    [bold bright_cyan]║[/] [bright_yellow]◈[/] [bold bright_white]Date[/] : [bright_green]%s[/]             [bold bright_cyan]║[/]\n"
    "    [bold bright_cyan]╚═══════════════════════════════════════════════╝[/]"
)

R2_SCRIPT_TEMPLATE = r"""e scr.color=0
e scr.utf8=0
e anal.strings=true
e bin.cache=true
e asm.bytes=false
e asm.lines=false
e asm.offset=true
aaa
e log.dest=FILE
afl > __OUTDIR__/__NAME__functions.txt
izz > __OUTDIR__/__NAME__strings.txt
iS > __OUTDIR__/__NAME__sections.txt
ii > __OUTDIR__/__NAME__imports.txt
iE > __OUTDIR__/__NAME__exports.txt
is > __OUTDIR__/__NAME__symbols.txt
ir > __OUTDIR__/__NAME__relocations.txt
ic > __OUTDIR__/__NAME__classes.txt
iI > __OUTDIR__/__NAME__binary_info.txt
ie > __OUTDIR__/__NAME__entrypoints.txt
Ih > __OUTDIR__/__NAME__headers.txt
im > __OUTDIR__/__NAME__memory_map.txt
e log.dest=stderr
f > __OUTDIR__/__NAME__flags.txt
afl~sym\. > __OUTDIR__/__NAME__sym_functions.txt
afl~sub\. > __OUTDIR__/__NAME__sub_functions.txt
aac
aar
afr
aflq~? > __OUTDIR__/__NAME__all_functions_raw.txt
isq~FUNC > __OUTDIR__/__NAME__func_symbols.txt
axt sym.imp.* > __OUTDIR__/__NAME__xrefs_to_imports.txt
iE~* > __OUTDIR__/__NAME__exports_raw.txt
ii~* > __OUTDIR__/__NAME__imports_raw.txt
/w \x00http > __OUTDIR__/__NAME__urls.txt
/w \x00file:// > __OUTDIR__/__NAME__file_urls.txt
/w \x00/content/ > __OUTDIR__/__NAME__content_uris.txt
/w JNI_OnLoad > __OUTDIR__/__NAME__jni.txt
/w Java_ > __OUTDIR__/__NAME__jni_methods.txt
/w registerNatives > __OUTDIR__/__NAME__register_natives.txt
/w /proc/ > __OUTDIR__/__NAME__proc_paths.txt
/w /data/ > __OUTDIR__/__NAME__data_paths.txt
/w /sdcard/ > __OUTDIR__/__NAME__sdcard_paths.txt
/w /system/ > __OUTDIR__/__NAME__system_paths.txt
/w AES > __OUTDIR__/__NAME__crypto_aes.txt
/w RSA > __OUTDIR__/__NAME__crypto_rsa.txt
/w SHA > __OUTDIR__/__NAME__crypto_sha.txt
/w MD5 > __OUTDIR__/__NAME__crypto_md5.txt
/w HMAC > __OUTDIR__/__NAME__crypto_hmac.txt
/w key= > __OUTDIR__/__NAME__key_assignments.txt
/w password > __OUTDIR__/__NAME__passwords.txt
/w secret > __OUTDIR__/__NAME__secrets.txt
/w token > __OUTDIR__/__NAME__tokens.txt
/w api_key > __OUTDIR__/__NAME__api_keys.txt
/w .so > __OUTDIR__/__NAME__so_refs.txt
/w lib/ > __OUTDIR__/__NAME__lib_paths.txt
/w dex > __OUTDIR__/__NAME__dex_refs.txt
/w classes.dex > __OUTDIR__/__NAME__dex_files.txt
/x ff4889e7 > __OUTDIR__/__NAME__x86_hooks.txt
/w SQLite > __OUTDIR__/__NAME__sqlite.txt
/w .db > __OUTDIR__/__NAME__db_refs.txt
/w .sqlite > __OUTDIR__/__NAME__sqlite_refs.txt
/w SharedPreferences > __OUTDIR__/__NAME__shared_prefs.txt
/w encryption > __OUTDIR__/__NAME__encryption.txt
/w decrypt > __OUTDIR__/__NAME__decryption.txt
/w encrypt > __OUTDIR__/__NAME__encrypt_refs.txt
/w BASE64 > __OUTDIR__/__NAME__base64.txt
/w protobuf > __OUTDIR__/__NAME__protobuf.txt
q
"""

R2_DISASM_TEMPLATE = r"""e scr.color=0
e scr.utf8=0
e asm.bytes=true
e asm.lines=true
e asm.offset=true
e asm.cmt.right=true
e asm.cmt.fold=true
e anal.strings=true
e bin.cache=true
aaa
e log.dest=FILE
__FUNCS_BLOCK__
e log.dest=stderr
q
"""

R2_BATCH_TEMPLATE = r"""#!/data/data/com.termux/files/usr/bin/bash
set -e

OUTDIR="__OUTDIR__"
mkdir -p "$OUTDIR/r2_output"

__SCRIPTS_BLOCK__

echo "[✓] Radare2 analysis complete: $OUTDIR/r2_output/"
"""


class LogManager:
    def __init__(self, maxlen=30):
        self.logs = deque(maxlen=maxlen)
        self.lock = threading.Lock()

    def add(self, msg, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            self.logs.append((ts, msg, level))

    def clear(self):
        with self.lock:
            self.logs.clear()

    def get_rich_text(self):
        lines = []
        for ts, msg, level in self.logs:
            if level == "error":
                lines.append(Text(f"  [{ts}] [bold red]✗ {msg}[/]"))
            elif level == "success":
                lines.append(Text(f"  [{ts}] [bold bright_green]✓ {msg}[/]"))
            elif level == "warn":
                lines.append(Text(f"  [{ts}] [bold bright_yellow]⚠ {msg}[/]"))
            elif level == "debug":
                lines.append(Text(f"  [{ts}] [dim]{msg}[/]"))
            else:
                lines.append(Text(f"  [{ts}] [bright_cyan]→ {msg}[/]"))
        if not lines:
            lines.append(Text("  [dim]En attente...[/]"))
        return Text("\n").join(lines)

    def get_plain_text(self):
        lines = []
        for ts, msg, level in self.logs:
            prefix = {"error": "✗", "success": "✓", "warn": "⚠", "debug": "  "}.get(level, "→")
            lines.append(f"  [{ts}] {prefix} {msg}")
        return "\n".join(lines) if lines else "  En attente..."


class ElitfUI:
    def __init__(self):
        self.console = Console() if HAS_RICH else None
        self.log_mgr = LogManager(30)
        self.detected_so = []
        self.dart_info = None
        self.metadata = {}
        self.outdir = ""
        self.indir = ""

    def _print(self, *args, **kwargs):
        if self.console:
            self.console.print(*args, **kwargs)
        else:
            msg = " ".join(str(a) for a in args)
            print(msg)

    def _clear(self):
        os.system('cls' if platform.system() == 'Windows' else 'clear')

    def _panel(self, title, content, style=None, box_style=None):
        if self.console:
            return Panel(content, title=title, border_style=style or Style(color="bright_cyan"), box=box_style or rbox.ROUNDED, padding=(0, 1))
        return None

    def _table(self, title, columns, rows, title_style=None):
        if not self.console:
            return None
        t = Table(title=title, title_style=title_style or Style(color="bright_white", bold=True), box=rbox.SIMPLE, show_header=True, header_style=Style(color="bright_cyan", bold=True), border_style=Style(color="dim"))
        for col_name, col_style in columns:
            t.add_column(col_name, style=col_style or "bright_white")
        for row in rows:
            t.add_row(*[str(c) for c in row])
        return t

    def display_logo(self):
        self._clear()
        logo_text = LOGO % (AUTHOR, platform.system(), datetime.now().strftime("%Y-%m-%d %H:%M"))
        if self.console:
            self.console.print(logo_text)
        else:
            print(f"\n  ELIT-F - Flutter/Dart AOT Reversing Engine")
            print(f"  Auteur : {AUTHOR}")
            print(f"  Plateforme : {platform.system()}")
            print(f"  Date : {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        self.console.print("\n") if self.console else print()

    def detect_so_files(self, directory):
        self.detected_so = []
        if not os.path.isdir(directory):
            return []
        pattern = os.path.join(directory, "**", "*.so")
        files = globmod.glob(pattern, recursive=False)
        files.sort(key=lambda x: os.path.basename(x).lower())
        for f in files:
            size = os.path.getsize(f)
            name = os.path.basename(f)
            self.detected_so.append({"path": os.path.abspath(f), "name": name, "size": size})
        return self.detected_so

    def _format_size(self, size_bytes):
        if size_bytes >= 1024 * 1024 * 1024:
            return f"{size_bytes / (1024*1024*1024):.2f} GB"
        if size_bytes >= 1024 * 1024:
            return f"{size_bytes / (1024*1024):.2f} MB"
        if size_bytes >= 1024:
            return f"{size_bytes / 1024:.2f} KB"
        return f"{size_bytes} B"

    def display_so_table(self):
        if not self.detected_so:
            self._print("[bold bright_yellow]Aucun fichier .so détecté.[/]" if self.console else "Aucun fichier .so detecte.")
            return
        cols = [("#", "bright_cyan"), ("Fichier", "bright_white"), ("Taille", "bright_green"), ("Chemin", "dim")]
        rows = []
        for i, so in enumerate(self.detected_so, 1):
            rows.append((str(i), so["name"], self._format_size(so["size"]), so["path"]))
        t = self._table(" Bibliothèques détectées ", cols, rows)
        if t:
            self.console.print(t)
        else:
            for i, so in enumerate(self.detected_so, 1):
                print(f"  {i}. {so['name']} ({self._format_size(so['size'])})")

    def display_metadata(self):
        if not self.metadata:
            return
        if self.console:
            meta_text = Text()
            for key, val in self.metadata.items():
                meta_text.append(f"  [bold bright_cyan]{key}[/]: {val}\n")
            panel = Panel(meta_text, title=" Métadonnées ", border_style=Style(color="bright_yellow"), box=rbox.ROUNDED, padding=(0, 1))
            self.console.print(panel)
        else:
            print("\n  === Metadonnees ===")
            for key, val in self.metadata.items():
                print(f"  {key}: {val}")

    def display_menu(self):
        if self.console:
            menu_text = Text()
            menu_items = [
                ("1", "Flutter/Dart AOT Analysis", "Analyse complète libapp.so + libflutter.so", "bright_cyan"),
                ("2", "Radare2 - Toutes les lib*.so", "Analyse r2 complète de toutes les .so détectées", "bright_green"),
                ("3", "Radare2 - Sélection ciblée", "Choisir les .so à analyser avec r2", "bright_yellow"),
                ("4", "Générer scripts r2 uniquement", "Générer les scripts r2 sans exécution", "bright_magenta"),
                ("5", "Générer scripts IDA uniquement", "Générer les scripts IDA sans exécution", "blue"),
                ("6", "Générer scripts Frida uniquement", "Générer les scripts Frida sans exécution", "red"),
                ("7", "Information binaire détaillée", "Afficher les infos détaillées des .so", "white"),
                ("0", "Quitter", "", "red"),
            ]
            for num, label, desc, color in menu_items:
                menu_text.append(f"  [" + num + "] ", style=f"bold {color}")
                menu_text.append(f"{label}\n", style="bold bright_white")
                if desc:
                    menu_text.append(f"      {desc}\n", style="dim")
            panel = Panel(menu_text, title=" Menu Principal ", border_style=Style(color="bright_green"), box=rbox.DOUBLE, padding=(0, 1))
            self.console.print(panel)
        else:
            print("\n  === Menu Principal ===")
            print("  [1] Flutter/Dart AOT Analysis")
            print("  [2] Radare2 - Toutes les lib*.so")
            print("  [3] Radare2 - Selection ciblee")
            print("  [4] Generer scripts r2 uniquement")
            print("  [5] Generer scripts IDA uniquement")
            print("  [6] Generer scripts Frida uniquement")
            print("  [7] Information binaire detaillee")
            print("  [0] Quitter")

    def get_choice(self):
        if self.console:
            try:
                choice = IntPrompt.ask("\n  [bold bright_green]Sélection[/]", console=self.console, default=1)
            except (KeyboardInterrupt, EOFError):
                return 0
        else:
            try:
                choice = int(input("\n  Selection: ") or "1")
            except (ValueError, KeyboardInterrupt, EOFError):
                return 0
        return choice

    def get_target_selection(self):
        if not self.detected_so:
            self._print("[bold red]Aucun fichier .so détecté.[/]" if self.console else "Aucun fichier .so detecte.")
            return []
        self.display_so_table()
        if self.console:
            self.console.print("\n  [dim]Entrez les numéros séparés par des virgules (ex: 1,3,5) ou 'all'[/]")
            try:
                raw = Prompt.ask("  [bold bright_green]Cible[/]", default="all", console=self.console)
            except (KeyboardInterrupt, EOFError):
                return []
        else:
            try:
                raw = input("\n  Cible (ex: 1,3,5 ou 'all'): ") or "all"
            except (KeyboardInterrupt, EOFError):
                return []
        if raw.strip().lower() == "all":
            return list(range(len(self.detected_so)))
        indices = []
        for part in raw.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    indices.extend(range(int(start) - 1, int(end)))
                except ValueError:
                    pass
            else:
                try:
                    idx = int(part) - 1
                    if 0 <= idx < len(self.detected_so):
                        indices.append(idx)
                except ValueError:
                    pass
        return sorted(set(indices))

    def run_with_live_display(self, title, steps, work_fn):
        if not self.console or not HAS_RICH:
            return work_fn(self.log_mgr)

        progress = Progress(
            SpinnerColumn(spinner_name="dots", style="bright_cyan"),
            TextColumn("[bold bright_white]{task.description}[/]", table_column=TextColumn(width=40)),
            BarColumn(bar_width=30, bar_style=Style(color="bright_cyan"), complete_style=Style(color="bright_green"), finished_style=Style(color="bright_green"), background_style=Style(color="dim")),
            TaskProgressColumn(text_style=Style(color="bright_white"), table_column=TextColumn(width=6)),
            TimeElapsedColumn(text_style=Style(color="dim")),
            console=self.console,
        )

        log_panel_content = Text("  [dim]En attente...[/]")
        log_panel = Panel(log_panel_content, title=" Opérations en direct ", border_style=Style(color="bright_yellow"), box=rbox.ROUNDED, padding=(0, 0), height=18)

        header_panel = Panel(Text(f"[bold bright_cyan]◆[/] [bold bright_white]{title}[/]", justify="center"), border_style=Style(color="bright_cyan"), box=rbox.ROUNDED)

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="progress", size=5),
            Layout(name="logs", ratio=1),
        )
        layout["header"].update(header_panel)
        layout["progress"].update(progress)
        layout["logs"].update(log_panel)

        result = [None]
        error_holder = [None]

        def update_logs():
            log_panel_content = self.log_mgr.get_rich_text()
            new_panel = Panel(log_panel_content, title=" Opérations en direct ", border_style=Style(color="bright_yellow"), box=rbox.ROUNDED, padding=(0, 0), height=18)
            layout["logs"].update(new_panel)

        def worker():
            try:
                result[0] = work_fn(self.log_mgr)
            except Exception as e:
                error_holder[0] = e
                self.log_mgr.add(str(e), "error")

        thread = threading.Thread(target=worker)
        thread.start()

        with Live(layout, console=self.console, refresh_per_second=4):
            task_id = progress.add_task("Initialisation...", total=steps)
            while thread.is_alive():
                progress.update(task_id, completed=self.log_mgr.logs.__len__() if self.log_mgr.logs else 0)
                update_logs()
                time.sleep(0.25)
            progress.update(task_id, completed=steps)
            update_logs()

        thread.join(timeout=5)

        if error_holder[0]:
            raise error_holder[0]
        return result[0]


class ElitfInput:
    def __init__(self, libapp_path: str, dart_info: DartLibInfo, outdir: str, rebuild: bool, no_analysis: bool, log_mgr: LogManager = None):
        self.libapp_path = libapp_path
        self.dart_info = dart_info
        self.outdir = outdir
        self.rebuild = rebuild
        vers = dart_info.version.split('.', 2)
        if int(vers[0]) == 2 and int(vers[1]) < 15:
            if not no_analysis:
                if log_mgr:
                    log_mgr.add('Dart version <2.15, force "no-analysis" option', 'warn')
                else:
                    print('Dart version <2.15, force "no-analysis" option')
            no_analysis = True
        self.no_analysis = no_analysis
        self.name_suffix = ''
        if not dart_info.has_compressed_ptrs:
            self.name_suffix += '_no-compressed-ptrs'
        if no_analysis:
            self.name_suffix += '_no-analysis'
        self.bin_name = f'elitf_{dart_info.lib_name}{self.name_suffix}'
        self.bin_file = os.path.join(BIN_DIR, self.bin_name)


def validate_two_libs(indir: str):
    if not os.path.isdir(indir):
        sys.exit(f"Input is not a directory containing {EXPECTED_LIBS[0]} and {EXPECTED_LIBS[1]}")
    so_files = sorted(f for f in os.listdir(indir) if f.endswith('.so'))
    expected = sorted(EXPECTED_LIBS)
    missing = [f for f in expected if f not in so_files]
    extra = [f for f in so_files if f not in expected]
    if missing and extra:
        sys.exit(f"Invalid input. Missing libraries: {missing}. Unexpected libraries: {extra}. "
                 f"The Flutter libs must be exactly two: {EXPECTED_LIBS[0]} and {EXPECTED_LIBS[1]}")
    if missing:
        sys.exit(f"Cannot find {' and '.join(missing)}. The Flutter libs must be exactly two: "
                 f"{EXPECTED_LIBS[0]} and {EXPECTED_LIBS[1]}")
    if extra:
        sys.exit(f"Unexpected libraries found: {extra}. The Flutter libs must be exactly two: "
                 f"{EXPECTED_LIBS[0]} and {EXPECTED_LIBS[1]}")
    return os.path.abspath(os.path.join(indir, EXPECTED_LIBS[0])), \
           os.path.abspath(os.path.join(indir, EXPECTED_LIBS[1]))


def extract_libs_from_apk(apk_file: str, out_dir: str):
    with zipfile.ZipFile(apk_file, "r") as zf:
        try:
            app_info = zf.getinfo('lib/arm64-v8a/libapp.so')
            flutter_info = zf.getinfo('lib/arm64-v8a/libflutter.so')
        except Exception:
            sys.exit("Cannot find libapp.so or libflutter.so in the APK")
        zf.extract(app_info, out_dir)
        zf.extract(flutter_info, out_dir)
        return os.path.join(out_dir, app_info.filename), os.path.join(out_dir, flutter_info.filename)


def find_compat_macro(dart_version: str, no_analysis: bool):
    macros = []
    include_path = os.path.join(PKG_INC_DIR, f'dartvm{dart_version}')
    vm_path = os.path.join(include_path, 'vm')
    with open(os.path.join(vm_path, 'class_id.h'), 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        if mm.find(b'V(LinkedHashMap)') != -1:
            macros.append('-DOLD_MAP_SET_NAME=1')
            if mm.find(b'V(ImmutableLinkedHashMap)') == -1:
                macros.append('-DOLD_MAP_NO_IMMUTABLE=1')
        if mm.find(b' kLastInternalOnlyCid ') == -1:
            macros.append('-DNO_LAST_INTERNAL_ONLY_CID=1')
        if mm.find(b'V(TypeRef)') != -1:
            macros.append('-DHAS_TYPE_REF=1')
        if dart_version.startswith('3.') and mm.find(b'V(RecordType)') != -1:
            macros.append('-DHAS_RECORD_TYPE=1')
    with open(os.path.join(vm_path, 'class_table.h'), 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        if mm.find(b'class SharedClassTable {') != -1:
            macros.append('-DHAS_SHARED_CLASS_TABLE=1')
    with open(os.path.join(vm_path, 'stub_code_list.h'), 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        if mm.find(b'V(InitLateStaticField)') == -1:
            macros.append('-DNO_INIT_LATE_STATIC_FIELD=1')
    with open(os.path.join(vm_path, 'object_store.h'), 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        if mm.find(b'build_generic_method_extractor_code)') == -1:
            macros.append('-DNO_METHOD_EXTRACTOR_STUB=1')
    with open(os.path.join(vm_path, 'object.h'), 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        if mm.find(b'AsTruncatedInt64Value()') == -1:
            macros.append('-DUNIFORM_INTEGER_ACCESS=1')
    with open(os.path.join(vm_path, 'thread.h'), 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        if mm.find(b'old_marking_stack_block') == -1:
            macros.append('-DOLD_MARKING_STACK_BLOCK=1')
    if no_analysis:
        macros.append('-DNO_CODE_ANALYSIS=1')
    return macros


def cmake_elitf(input: ElitfInput, log_mgr: LogManager = None):
    builddir = os.path.join(BUILD_DIR, input.bin_name)
    macros = find_compat_macro(input.dart_info.version, input.no_analysis)
    cmd = [CMAKE_CMD, '-GNinja', '-B', builddir,
           f'-DDARTLIB={input.dart_info.lib_name}',
           f'-DNAME_SUFFIX={input.name_suffix}',
           '-DCMAKE_BUILD_TYPE=Release', '--log-level=NOTICE'] + macros
    fmt_inc = os.getenv('FMT_INCLUDE_DIR')
    if fmt_inc:
        cmd.append(f'-DFMT_INCLUDE_DIR={fmt_inc}')
    subprocess.run(cmd, cwd=SCRIPT_DIR, check=True)
    subprocess.run([NINJA_CMD], cwd=builddir, check=True)
    subprocess.run([CMAKE_CMD, '--install', '.'], cwd=builddir, check=True)


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


def build_and_run(input: ElitfInput, log_mgr: LogManager = None):
    if not os.path.isfile(input.bin_file) or input.rebuild:
        libfile_variants = [
            os.path.join(PKG_LIB_DIR, 'lib' + input.dart_info.lib_name + '.a'),
            os.path.join(PKG_LIB_DIR, input.dart_info.lib_name + '.lib'),
        ]
        dartlib_file = next((p for p in libfile_variants if os.path.isfile(p)), None)
        if dartlib_file is None:
            if log_mgr:
                log_mgr.add(f"Fetching Dart VM {input.dart_info.version}...", "info")
            from dartvm_fetch_build import fetch_and_build
            fetch_and_build(input.dart_info)
            if log_mgr:
                log_mgr.add(f"Dart VM {input.dart_info.version} built successfully", "success")
        input.rebuild = True
    if input.rebuild:
        if log_mgr:
            log_mgr.add(f"Building Elit-f binary ({input.bin_name})...", "info")
        cmake_elitf(input, log_mgr)
        assert os.path.isfile(input.bin_file), "Build complete but cannot find binary: " + input.bin_file
        if log_mgr:
            log_mgr.add(f"Binary built: {input.bin_file}", "success")
    if log_mgr:
        log_mgr.add(f"Running analysis on {input.libapp_path}...", "info")
        result = subprocess.run([input.bin_file, '-i', input.libapp_path, '-o', input.outdir],
                               capture_output=True, text=True)
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                if "null-safety" in line.lower() or "cannot find" in line.lower():
                    log_mgr.add(line, "warn")
                elif "error" in line.lower():
                    log_mgr.add(line, "error")
                else:
                    log_mgr.add(line, "info")
        if result.returncode != 0:
            if result.stderr:
                log_mgr.add(result.stderr, "error")
            raise subprocess.CalledProcessError(result.returncode, input.bin_file)
        log_mgr.add(f"Analysis output: {input.outdir}", "success")
    else:
        subprocess.run([input.bin_file, '-i', input.libapp_path, '-o', input.outdir], check=True)


def generate_r2_scripts(so_list, outdir, log_mgr=None):
    r2_out = os.path.join(outdir, "r2_output")
    os.makedirs(r2_out, exist_ok=True)
    generated = []
    batch_lines = []
    for so in so_list:
        name = so["name"].replace(".so", "") + "_"
        script_content = R2_SCRIPT_TEMPLATE.replace("__OUTDIR__", r2_out).replace("__NAME__", name)
        script_path = os.path.join(r2_out, f"r2_{so['name']}.r2")
        with open(script_path, "w") as f:
            f.write(script_content)
        generated.append(script_path)
        if log_mgr:
            log_mgr.add(f"Generated r2 script: r2_{so['name']}.r2", "success")
        abs_so = so["path"]
        batch_lines.append(f'r2 -q -i "{script_path}" "{abs_so}"')
        disasm_funcs = f'aflq~? > "{os.path.join(r2_out, name + "func_list.txt")}"\n'
        disasm_content = R2_DISASM_TEMPLATE.replace("__OUTDIR__", r2_out).replace("__NAME__", name).replace("__FUNCS_BLOCK__", disasm_funcs)
        disasm_path = os.path.join(r2_out, f"r2_{so['name']}_disasm.r2")
        with open(disasm_path, "w") as f:
            f.write(disasm_content)
        if log_mgr:
            log_mgr.add(f"Generated r2 disasm script: r2_{so['name']}_disasm.r2", "success")
    batch_content = R2_BATCH_TEMPLATE.replace("__OUTDIR__", r2_out).replace("__SCRIPTS_BLOCK__", "\n".join(batch_lines))
    batch_path = os.path.join(outdir, "r2_analyze_all.sh")
    with open(batch_path, "w") as f:
        f.write(batch_content)
    os.chmod(batch_path, 0o755)
    if log_mgr:
        log_mgr.add(f"Generated batch script: r2_analyze_all.sh ({len(generated)} .so)", "success")
    return generated


def run_r2_scripts(so_list, outdir, log_mgr=None):
    r2_out = os.path.join(outdir, "r2_output")
    os.makedirs(r2_out, exist_ok=True)
    r2_bin = shutil.which("r2")
    if not r2_bin:
        if log_mgr:
            log_mgr.add("r2 not found. Generating scripts only.", "warn")
        return generate_r2_scripts(so_list, outdir, log_mgr)
    generated = []
    for so in so_list:
        name = so["name"].replace(".so", "") + "_"
        script_content = R2_SCRIPT_TEMPLATE.replace("__OUTDIR__", r2_out).replace("__NAME__", name)
        script_path = os.path.join(r2_out, f"r2_{so['name']}.r2")
        with open(script_path, "w") as f:
            f.write(script_content)
        generated.append(script_path)
        if log_mgr:
            log_mgr.add(f"Analyzing {so['name']} with r2...", "info")
        try:
            result = subprocess.run([r2_bin, "-q", "-i", script_path, so["path"]],
                                   capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                if log_mgr:
                    log_mgr.add(f"r2 analysis complete: {so['name']}", "success")
            else:
                if log_mgr:
                    log_mgr.add(f"r2 error on {so['name']}: {result.stderr[:100]}", "error")
        except subprocess.TimeoutExpired:
            if log_mgr:
                log_mgr.add(f"r2 timeout on {so['name']}", "warn")
        except Exception as e:
            if log_mgr:
                log_mgr.add(f"r2 failed on {so['name']}: {e}", "error")
    if log_mgr:
        log_mgr.add(f"r2 analysis finished: {len(generated)} scripts", "success")
    return generated


def display_binary_info(so_list, outdir, log_mgr=None):
    for so in so_list:
        if log_mgr:
            log_mgr.add(f"Reading info: {so['name']}", "info")
        try:
            result = subprocess.run(["readelf", "-h", "-S", "-l", so["path"]],
                                   capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and log_mgr:
                for line in result.stdout.strip().split("\n")[:20]:
                    log_mgr.add(f"[{so['name']}] {line.strip()}", "debug")
            elif log_mgr:
                log_mgr.add(f"readelf not available for {so['name']}", "warn")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            if log_mgr:
                log_mgr.add(f"Cannot read binary info: {so['name']}", "warn")
    if log_mgr:
        log_mgr.add("Binary info scan complete", "success")


def run_flutter_analysis(indir, outdir, rebuild, no_analysis, ui, log_mgr):
    if indir.endswith(".apk"):
        if log_mgr:
            log_mgr.add(f"Extracting APK: {indir}", "info")
        with tempfile.TemporaryDirectory() as tmp_dir:
            libapp_file, libflutter_file = extract_libs_from_apk(indir, tmp_dir)
            if log_mgr:
                log_mgr.add("APK extracted successfully", "success")
            dart_version, snapshot_hash, flags, arch, os_name, has_compressed_ptrs = get_dart_lib_info(libapp_file, libflutter_file, log_mgr)
            ui.metadata = {
                "Dart Version": dart_version,
                "Snapshot Hash": snapshot_hash,
                "Architecture": arch,
                "OS": os_name,
                "Compressed Pointers": "Yes" if has_compressed_ptrs else "No",
                "Null Safety": "Enabled",
                "Auteur": AUTHOR,
            }
            dart_info = DartLibInfo(dart_version, os_name, arch, has_compressed_ptrs, snapshot_hash)
            input_obj = ElitfInput(libapp_file, dart_info, outdir, rebuild, no_analysis, log_mgr)
            build_and_run(input_obj, log_mgr)
    else:
        libapp_file, libflutter_file = validate_two_libs(indir)
        dart_version, snapshot_hash, flags, arch, os_name, has_compressed_ptrs = get_dart_lib_info(libapp_file, libflutter_file, log_mgr)
        ui.metadata = {
            "Dart Version": dart_version,
            "Snapshot Hash": snapshot_hash,
            "Architecture": arch,
            "OS": os_name,
            "Compressed Pointers": "Yes" if has_compressed_ptrs else "No",
            "Null Safety": "Enabled",
            "Auteur": AUTHOR,
        }
        dart_info = DartLibInfo(dart_version, os_name, arch, has_compressed_ptrs, snapshot_hash)
        input_obj = ElitfInput(libapp_file, dart_info, outdir, rebuild, no_analysis, log_mgr)
        build_and_run(input_obj, log_mgr)
    if log_mgr:
        log_mgr.add("Flutter/Dart AOT analysis complete", "success")


def main_interactive(ui):
    ui.display_logo()
    if ui.console:
        ui.console.print(Rule("[dim]Configuration[/]", style=Style(color="dim")))
    if ui.console:
        ui.console.print()
        try:
            indir = Prompt.ask("  [bold bright_cyan]Répertoire cible / APK[/]", default=ui.indir or "", console=ui.console)
        except (KeyboardInterrupt, EOFError):
            return
    else:
        try:
            indir = input("\n  Repertoire cible / APK: ") or ui.indir
        except (KeyboardInterrupt, EOFError):
            return
    if not indir:
        ui._print("[bold red]Aucun répertoire spécifié.[/]" if ui.console else "Aucun repertoire specifie.")
        return
    if ui.console:
        ui.console.print()
        try:
            outdir = Prompt.ask("  [bold bright_cyan]Répertoire de sortie[/]", default=os.path.join(indir, "out") if os.path.isdir(indir) else "./out", console=ui.console)
        except (KeyboardInterrupt, EOFError):
            return
    else:
        try:
            outdir = input(f"\n  Repertoire de sortie [{os.path.join(indir, 'out')}]: ") or os.path.join(indir, "out")
        except (KeyboardInterrupt, EOFError):
            return
    ui.indir = indir
    ui.outdir = outdir

    is_apk = indir.endswith(".apk")
    if is_apk:
        ui._print("[bright_cyan]Mode APK détecté.[/]" if ui.console else "Mode APK detecte.")
        so_dir = indir
    elif os.path.isdir(indir):
        ui.detect_so_files(indir)
        ui.display_so_table()
        so_dir = indir
    else:
        ui._print(f"[bold red]Chemin invalide: {indir}[/]" if ui.console else f"Chemin invalide: {indir}")
        return

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
        elif choice == 1:
            os.makedirs(outdir, exist_ok=True)
            ui.log_mgr.clear()
            def work(lm):
                run_flutter_analysis(indir, outdir, False, False, ui, lm)
            total_steps = 20
            try:
                ui.run_with_live_display("Flutter/Dart AOT Analysis", total_steps, work)
            except Exception as e:
                ui._print(f"[bold red]Erreur: {e}[/]" if ui.console else f"Erreur: {e}")
            ui._print("")
            if ui.console:
                ui.console.print(Panel("[bright_green]Analyse Flutter terminée.[/]", border_style=Style(color="bright_green")))
        elif choice == 2:
            if not ui.detected_so and not is_apk:
                ui.detect_so_files(indir)
            if not ui.detected_so:
                ui._print("[bold yellow]Aucun fichier .so à analyser.[/]" if ui.console else "Aucun fichier .so a analyser.")
                continue
            os.makedirs(outdir, exist_ok=True)
            ui.log_mgr.clear()
            def work(lm):
                run_r2_scripts(ui.detected_so, outdir, lm)
            total_steps = len(ui.detected_so) * 5
            try:
                ui.run_with_live_display("Radare2 - Analyse complète", total_steps, work)
            except Exception as e:
                ui._print(f"[bold red]Erreur: {e}[/]" if ui.console else f"Erreur: {e}")
            ui._print("")
            if ui.console:
                ui.console.print(Panel(f"[bright_green]Analyse r2 terminée: {len(ui.detected_so)} fichiers .so[/]", border_style=Style(color="bright_green")))
        elif choice == 3:
            if not ui.detected_so and not is_apk:
                ui.detect_so_files(indir)
            if not ui.detected_so:
                ui._print("[bold yellow]Aucun fichier .so à analyser.[/]" if ui.console else "Aucun fichier .so a analyser.")
                continue
            indices = ui.get_target_selection()
            if not indices:
                ui._print("[dim]Aucune cible sélectionnée.[/]" if ui.console else "Aucune cible selectionnee.")
                continue
            selected = [ui.detected_so[i] for i in indices]
            os.makedirs(outdir, exist_ok=True)
            ui.log_mgr.clear()
            def work(lm):
                run_r2_scripts(selected, outdir, lm)
            total_steps = len(selected) * 5
            try:
                ui.run_with_live_display("Radare2 - Analyse ciblée", total_steps, work)
            except Exception as e:
                ui._print(f"[bold red]Erreur: {e}[/]" if ui.console else f"Erreur: {e}")
            ui._print("")
            if ui.console:
                ui.console.print(Panel(f"[bright_green]Analyse r2 ciblée terminée: {len(selected)} fichiers[/]", border_style=Style(color="bright_green")))
        elif choice == 4:
            if not ui.detected_so and not is_apk:
                ui.detect_so_files(indir)
            if not ui.detected_so:
                ui._print("[bold yellow]Aucun fichier .so détecté.[/]" if ui.console else "Aucun fichier .so detecte.")
                continue
            os.makedirs(outdir, exist_ok=True)
            ui.log_mgr.clear()
            def work(lm):
                generate_r2_scripts(ui.detected_so, outdir, lm)
            try:
                ui.run_with_live_display("Génération scripts r2", len(ui.detected_so) * 3, work)
            except Exception as e:
                ui._print(f"[bold red]Erreur: {e}[/]" if ui.console else f"Erreur: {e}")
            ui._print("")
            if ui.console:
                ui.console.print(Panel(f"[bright_green]{len(ui.detected_so)} scripts r2 générés dans {outdir}/r2_output/[/]", border_style=Style(color="bright_green")))
        elif choice == 5:
            ui._print("[bright_cyan]Les scripts IDA sont générés automatiquement lors de l'analyse Flutter (option 1).[/]" if ui.console else "Les scripts IDA sont generes automatiquement lors de l'analyse Flutter (option 1).")
        elif choice == 6:
            ui._print("[bright_cyan]Les scripts Frida sont générés automatiquement lors de l'analyse Flutter (option 1).[/]" if ui.console else "Les scripts Frida sont generes automatiquement lors de l'analyse Flutter (option 1).")
        elif choice == 7:
            if not ui.detected_so and not is_apk:
                ui.detect_so_files(indir)
            if not ui.detected_so:
                ui._print("[bold yellow]Aucun fichier .so détecté.[/]" if ui.console else "Aucun fichier .so detecte.")
                continue
            os.makedirs(outdir, exist_ok=True)
            ui.log_mgr.clear()
            def work(lm):
                display_binary_info(ui.detected_so, outdir, lm)
            try:
                ui.run_with_live_display("Information binaire", len(ui.detected_so) * 2, work)
            except Exception as e:
                ui._print(f"[bold red]Erreur: {e}[/]" if ui.console else f"Erreur: {e}")
        else:
            ui._print("[bold yellow]Option invalide.[/]" if ui.console else "Option invalide.")

        if ui.console:
            try:
                input("\n  Appuyez sur Entrée pour continuer...")
            except (KeyboardInterrupt, EOFError):
                break


def main_cli(indir, outdir, rebuild, no_analysis):
    ui = ElitfUI()
    if not HAS_RICH:
        print(f"\n  Auteur : {AUTHOR}")
        print(f"  Pour l'interface complète, installez: pip install rich\n")
        if indir.endswith(".apk"):
            with tempfile.TemporaryDirectory() as tmp_dir:
                libapp_file, libflutter_file = extract_libs_from_apk(indir, tmp_dir)
                dart_version, snapshot_hash, flags, arch, os_name, has_compressed_ptrs = get_dart_lib_info(libapp_file, libflutter_file)
                dart_info = DartLibInfo(dart_version, os_name, arch, has_compressed_ptrs, snapshot_hash)
                input_obj = ElitfInput(libapp_file, dart_info, outdir, rebuild, no_analysis)
                build_and_run(input_obj)
        else:
            libapp_file, libflutter_file = validate_two_libs(indir)
            dart_version, snapshot_hash, flags, arch, os_name, has_compressed_ptrs = get_dart_lib_info(libapp_file, libflutter_file)
            dart_info = DartLibInfo(dart_version, os_name, arch, has_compressed_ptrs, snapshot_hash)
            input_obj = ElitfInput(libapp_file, dart_info, outdir, rebuild, no_analysis)
            build_and_run(input_obj)
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
    if choice == 1:
        os.makedirs(outdir, exist_ok=True)
        ui.log_mgr.clear()
        def work(lm):
            run_flutter_analysis(indir, outdir, rebuild, no_analysis, ui, lm)
        total_steps = 20
        ui.run_with_live_display("Flutter/Dart AOT Analysis", total_steps, work)
    elif choice in (2, 3):
        if not ui.detected_so and not is_apk:
            ui.detect_so_files(indir)
        if choice == 3:
            indices = ui.get_target_selection()
            if not indices:
                sys.exit(0)
            selected = [ui.detected_so[i] for i in indices]
        else:
            selected = ui.detected_so
        if not selected:
            sys.exit("No .so files to analyze")
        os.makedirs(outdir, exist_ok=True)
        ui.log_mgr.clear()
        def work(lm):
            run_r2_scripts(selected, outdir, lm)
        total_steps = len(selected) * 5
        ui.run_with_live_display("Radare2 Analysis", total_steps, work)
    elif choice == 4:
        if not ui.detected_so and not is_apk:
            ui.detect_so_files(indir)
        os.makedirs(outdir, exist_ok=True)
        generate_r2_scripts(ui.detected_so, outdir)
    else:
        os.makedirs(outdir, exist_ok=True)
        ui.log_mgr.clear()
        def work(lm):
            run_flutter_analysis(indir, outdir, rebuild, no_analysis, ui, lm)
        ui.run_with_live_display("Flutter/Dart AOT Analysis", 20, work)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='Elit-f',
        description='Reversing a flutter application tool (needs exactly libapp.so and libflutter.so)')
    parser.add_argument('indir', nargs='?', default=None, help='An apk or a directory that contains exactly both libapp.so and libflutter.so')
    parser.add_argument('outdir', nargs='?', default=None, help='An output directory')
    parser.add_argument('--rebuild', action='store_true', default=False, help='Force rebuild the Elit-f executable')
    parser.add_argument('--no-analysis', action='store_true', default=False, help='Do not build with code analysis')
    parser.add_argument('--dart-version', help='Run without libflutter (indir becomes libapp.so path)')
    parser.add_argument('--cli', action='store_true', default=False, help='Force CLI mode (no interactive menu)')
    args = parser.parse_args()

    if args.cli and args.indir and args.outdir and args.dart_version is None:
        main_cli(args.indir, args.outdir, args.rebuild, args.no_analysis)
    elif args.indir and args.outdir and args.dart_version is None:
        main_cli(args.indir, args.outdir, args.rebuild, args.no_analysis)
    elif args.dart_version is not None:
        if not args.indir:
            sys.exit('--dart-version requires indir (libapp.so path)')
        parts = args.dart_version.split('_')
        if len(parts) != 3:
            sys.exit(f'Invalid dart-version format: "{args.dart_version}". Expected "<version>_<os>_<arch>"')
        version, os_name, arch = parts
        dart_info = DartLibInfo(version, os_name, arch)
        outdir = args.outdir or './out'
        input_obj = ElitfInput(args.indir, dart_info, outdir, args.rebuild, args.no_analysis)
        build_and_run(input_obj)
    else:
        if not HAS_RICH:
            print("\n  Elit-f - Flutter/Dart AOT Reversing Engine")
            print(f"  Auteur : {AUTHOR}")
            print("  pip install rich  (pour l'interface complète)\n")
            if not args.indir:
                args.indir = input("  Repertoire cible / APK: ")
            if not args.indir:
                sys.exit(0)
            args.outdir = args.outdir or input("  Repertoire de sortie [./out]: ") or "./out"
            if args.indir.endswith(".apk"):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    libapp_file, libflutter_file = extract_libs_from_apk(args.indir, tmp_dir)
                    dart_version, snapshot_hash, flags, arch, os_name, has_compressed_ptrs = get_dart_lib_info(libapp_file, libflutter_file)
                    dart_info = DartLibInfo(dart_version, os_name, arch, has_compressed_ptrs, snapshot_hash)
                    input_obj = ElitfInput(libapp_file, dart_info, args.outdir, args.rebuild, args.no_analysis)
                    build_and_run(input_obj)
            else:
                libapp_file, libflutter_file = validate_two_libs(args.indir)
                dart_version, snapshot_hash, flags, arch, os_name, has_compressed_ptrs = get_dart_lib_info(libapp_file, libflutter_file)
                dart_info = DartLibInfo(dart_version, os_name, arch, has_compressed_ptrs, snapshot_hash)
                input_obj = ElitfInput(libapp_file, dart_info, args.outdir, args.rebuild, args.no_analysis)
                build_and_run(input_obj)
        else:
            ui = ElitfUI()
            if args.indir:
                ui.indir = args.indir
            if args.outdir:
                ui.outdir = args.outdir
            main_interactive(ui)
