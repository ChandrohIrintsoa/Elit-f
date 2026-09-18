#!/usr/bin/env python3
import os
import sys
import re
import platform
import threading
import time
from datetime import datetime
from collections import deque

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TimeElapsedColumn, TaskProgressColumn
    from rich.text import Text
    from rich.columns import Columns
    from rich.layout import Layout
    from rich.live import Live
    from rich.prompt import IntPrompt, Prompt
    from rich.style import Style
    from rich import box as rbox
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

AUTHOR = "𝕴𝖗𝖎𝖓𝖙𝖘𝖔𝖆 𝕮𝖍𝖆𝖓𝖉𝖗𝖔𝖍"

ASCII_LINES = [
    "⠀⠀⠀⣿⣿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⢀⣿⣿⣿⣿⣿⣿⣆⡀⠀⠀⠀⠀⣠⣴⣦⡄⢤⣄⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣷⣷⣶⣶⣿⣿⣿⣿⡀⣽⡿⣶⣦⡀⠀⠀⠀⠀",
    "⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡿⣿⣿⣿⣿⣆⠀⠀⠀",
    "⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣦⠀⠀",
    "⠀⠀⢾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣟⣿⣿⣿⣿⣿⡿⢟⣿⣷⡀",
    "⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣭⣿⣿⣽⣿⣽⣾⣿⣿⣿⠛⠉⠉⠀⢈⣿⣿⡇",
    "⠀⠀⠀⢻⣿⣿⠛⠉⠛⠻⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠡⠤⠄⠁⠀⠀⢻⣿⡇",
    "⠀⠀⠀⠘⣿⣿⠄⠀⠀⠀⠀⠀⣉⠙⠋⢿⣿⣯⠀⠀⠀⠀⠀⠀⣰⣿⣿⡿⡃",
    "⠀⠀⠀⠀⢹⣿⣇⣀⠀⠈⠉⠉⠁⠀⣤⢠⣿⣿⣧⡆⣤⣤⡀⣾⣿⣿⣿⢠⡇",
    "⠀⠀⠀⠀⠀⣿⣿⣿⣷⣤⠄⣀⣴⣧⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⠇",
    "⠀⠀⠀⠀⠀⠸⣿⣯⠉⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⡯⠁⡌⠀",
    "⠀⠀⠀⠀⠀⠀⠙⢿⡄⢿⣿⣿⣿⣿⣿⣎⠙⠻⠛⣁⣼⣿⣿⡿⠛⠁⡸⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠈⢿⡄⠉⣿⡿⣿⣿⣿⣿⣷⣬⣿⡿⠟⠋⢀⣴⡞⠁⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⠀⠀⠀⠀⠉⠉⠋⠉⠉⠁⠀⢀⣴⣿⡿⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⠿⢃⣴⣿⣿⣿⠃⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀",
]

X_COLORS = ["bright_cyan", "bright_magenta", "bright_yellow", "bright_green", "bright_blue"]

def build_x(offset: int = 0):
    art = Text()
    color_idx = offset
    for line in ASCII_LINES:
        for ch in line:
            if ch == "⠀" or ch == " ":
                art.append(ch)
            else:
                color = X_COLORS[color_idx % len(X_COLORS)]
                art.append(ch, style=f"bold {color}")
                color_idx += 1
        art.append("\n")
    return art

def build_y(author: str, platform_name: str, date_str: str) -> "Panel":
    body = Text()
    body.append("◈ ", style="bright_yellow")
    body.append("Auteur", style="bold bright_white")
    body.append(" : ")
    body.append(author, style="italic bright_magenta")
    body.append("\n")
    body.append("◈ ", style="bright_yellow")
    body.append("Plateforme", style="bold bright_white")
    body.append(" : ")
    body.append(platform_name, style="bright_green")
    body.append("\n")
    body.append("◈ ", style="bright_yellow")
    body.append("Date", style="bold bright_white")
    body.append(" : ")
    body.append(date_str, style="bright_green")
    panel = Panel(
        body,
        title="[bold bright_white]E L I T - F[/]",
        title_align="center",
        border_style="bold bright_cyan",
        padding=(1, 2),
    )
    return panel

def build_logo(author: str, platform_name: str, date_str: str, offset: int = 0) -> "Columns":
    x = build_x(offset=offset)
    y = build_y(author, platform_name, date_str)
    return Columns([x, y], align="center", expand=False, padding=(0, 3))

def logo_plain_text(author: str, platform_name: str, date_str: str) -> str:
    lines = list(ASCII_LINES)
    lines.append("")
    lines.append("  E L I T - F   (Flutter/Dart AOT Reversing Engine)")
    lines.append(f"  ◈ Auteur    : {author}")
    lines.append(f"  ◈ Plateforme: {platform_name}")
    lines.append(f"  ◈ Date      : {date_str}")
    return "\n".join(lines)

_RICH_TAG_RE = re.compile(r'(?:\[/?[#a-zA-Z][\w #]*\]|\[/\])')

def strip_rich_tags(text: str) -> str:
    return _RICH_TAG_RE.sub('', str(text))

class LogManager:
    def __init__(self, maxlen=200):
        self.logs = deque(maxlen=maxlen)
        self.pending = None
        self.lock = threading.Lock()
        self.step_count = 0
        self.total_steps = 0
        self.sub_fraction = 0.0
        self.sub_label = ''

    def add(self, msg, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            self.logs.append((ts, msg, level))
            if self.pending is not None:
                self.pending.append((ts, msg, level))

    def begin_stream(self):
        with self.lock:
            self.pending = deque()

    def drain_stream(self, finish=False):
        with self.lock:
            entries = list(self.pending or ())
            self.pending = None if finish else deque()
            return entries

    def clear(self):
        with self.lock:
            self.logs.clear()
            self.step_count = 0
            self.sub_fraction = 0.0
            self.sub_label = ''

    def step(self, count=1):
        with self.lock:
            self.step_count += count

    def set_sub_progress(self, fraction=None, label=''):
        
        with self.lock:
            self.sub_fraction = float(fraction) if fraction is not None else 0.0
            self.sub_label = label or ''

    def get_sub_progress(self):
        with self.lock:
            return (self.sub_fraction, self.sub_label)

    def set_total(self, total):
        with self.lock:
            self.total_steps = total

    def get_rich_text(self):
        from rich.text import Text as RichText
        lines = []
        with self.lock:
            entries = list(self.logs)

        entries = entries[-16:]
        for ts, msg, level in entries:
            if level == "error":
                lines.append(RichText(f"  [{ts}] ", style="dim") + RichText(f"✗ {msg}", style="bold red"))
            elif level == "success":
                lines.append(RichText(f"  [{ts}] ", style="dim") + RichText(f"✓ {msg}", style="bold bright_green"))
            elif level == "warn":
                lines.append(RichText(f"  [{ts}] ", style="dim") + RichText(f"⚠ {msg}", style="bold bright_yellow"))
            elif level == "debug":
                lines.append(RichText(f"  [{ts}] {msg}", style="dim"))
            else:
                lines.append(RichText(f"  [{ts}] ", style="dim") + RichText(f"→ {msg}", style="bright_cyan"))
        if not lines:
            lines.append(RichText("  En attente...", style="dim"))
        result = RichText("")
        for i, line in enumerate(lines):
            if i > 0:
                result.append("\n")
            result.append_text(line)
        return result

    def get_plain_text(self):
        with self.lock:
            entries = list(self.logs)
        lines = []
        for ts, msg, level in entries:
            prefix = {"error": "✗", "success": "✓", "warn": "⚠", "debug": "  "}.get(level, "→")
            lines.append(f"  [{ts}] {prefix} {msg}")
        return "\n".join(lines) if lines else "  En attente..."

def _is_termux() -> bool:
    if os.environ.get('TERMUX_VERSION'):
        return True
    if os.path.isdir('/data/data/com.termux'):
        return True
    prefix = os.environ.get('PREFIX', '')
    if 'com.termux' in prefix:
        return True
    return False

class ElitfUI:
    def __init__(self, force_plain: bool = False):
        self.force_plain = force_plain or not sys.stdout.isatty()
        if HAS_RICH:
            self.console = Console()
        else:
            self.console = None
        self.log_mgr = LogManager(200)
        self.detected_so = []
        self.metadata = {}
        self.outdir = ""
        self.indir = ""

    def _print(self, *args, **kwargs):
        if self.console:
            self.console.print(*args, **kwargs)
        else:
            msg = " ".join(str(a) for a in args)
            print(strip_rich_tags(msg))

    def _print_error(self, e):
        msg = str(e)
        is_missing_tool = (
            isinstance(e, FileNotFoundError)
            or "No such file or directory" in msg
            or "not found" in msg.lower()
            or "Missing required build tool" in msg
        )
        if self.console:
            self.console.print()
            self.console.print(Panel(f"[bold red]Erreur: {type(e).__name__}: {e}[/]",
                                     title="[bright_red]Échec de l'opération[/]",
                                     border_style=Style(color="red")))
            if is_missing_tool:
                self.console.print("[dim]Outils système requis pour le build :[/]")
                self.console.print("[dim]  Termux  : pkg install git cmake ninja clang python pkg-config capstone[/]")
                self.console.print("[dim]             && pip install pyelftools requests rich[/]")
                self.console.print("[dim]  Debian  : sudo apt install git cmake ninja-build clang python3-pip[/]")
                self.console.print("[dim]  macOS   : brew install git cmake ninja llvm[/]")
            else:
                self.console.print("[dim]Dépendances Python :[/]")
                self.console.print("[dim]  pip install pyelftools requests rich[/]")
        else:
            print(f"\nERREUR: {type(e).__name__}: {e}")
            if is_missing_tool:
                print("Outils système requis pour le build:")
                print("  Termux: pkg install git cmake ninja clang python pkg-config capstone && pip install pyelftools requests rich")
                print("  Debian: sudo apt install git cmake ninja-build clang python3-pip")
                print("  macOS : brew install git cmake ninja llvm")
            else:
                print("Dépendances Python:")
                print("  pip install pyelftools requests rich")

    def _clear(self):
        os.system('cls' if platform.system() == 'Windows' else 'clear')

    def _table(self, title, columns, rows, title_style=None):
        if not self.console:
            return None
        t = Table(title=title, title_style=title_style or Style(color="bright_white", bold=True),
                  box=rbox.SIMPLE, show_header=True,
                  header_style=Style(color="bright_cyan", bold=True),
                  border_style=Style(dim=True))
        for col_name, col_style in columns:
            t.add_column(col_name, style=col_style or "bright_white")
        for row in rows:
            t.add_row(*[str(c) for c in row])
        return t

    def display_logo(self):
        self._clear()
        author = AUTHOR
        plat = platform.system()
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        if self.console:
            self.console.print(build_logo(author, plat, date_str))
            self.console.print()
        else:
            print(logo_plain_text(author, plat, date_str))
            print()

    def animate_logo(self, duration_seconds=10.0, interval_ms=150):
        if not self.console or not HAS_RICH or self.force_plain:
            self.display_logo()
            return
        author = AUTHOR
        plat = platform.system()
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        offset = 0
        start = time.monotonic()
        try:
            with Live(
                build_logo(author, plat, date_str, offset=offset),
                console=self.console,
                refresh_per_second=max(1, int(1000 / interval_ms)),
                screen=False,
            ) as live:
                while (time.monotonic() - start) < duration_seconds:
                    time.sleep(interval_ms / 1000)
                    offset += 1
                    live.update(build_logo(author, plat, date_str, offset=offset))
        except KeyboardInterrupt:
            pass

    def detect_so_files(self, directory):
        import glob as globmod
        self.detected_so = []
        if not os.path.isdir(directory):
            return []
        pattern = os.path.join(directory, "**", "*.so")
        try:
            files = globmod.glob(pattern, recursive=True)
        except (PermissionError, OSError):
            files = []
        files.sort(key=lambda x: os.path.basename(x).lower())
        for f in files:
            try:
                size = os.path.getsize(f)
            except OSError:
                continue
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
            self._print("[bold bright_yellow]Aucun fichier .so détecté.[/]" if self.console
                        else "Aucun fichier .so detecte.")
            return
        cols = [("#", "bright_cyan"), ("Fichier", "bright_white"),
                ("Taille", "bright_green"), ("Chemin", "dim")]
        rows = [(str(i), so["name"], self._format_size(so["size"]), so["path"])
                for i, so in enumerate(self.detected_so, 1)]
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
                meta_text.append(f"  {key}", style="bold bright_cyan")
                meta_text.append(f": {val}\n")
            panel = Panel(meta_text, title=" Métadonnées ",
                          border_style=Style(color="bright_yellow"),
                          box=rbox.ROUNDED, padding=(0, 1))
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
                ("2", "Radare2 - Terminal interactif",
                 "Lance le vrai r2 (toutes commandes natives) sur la cible sélectionnée — quit avec 'q'",
                 "bright_green"),
                ("3", "Il2Cpp Analysis (Il2CppInspector)",
                 "dump.cs + symbol map + IDA/Ghidra scripts depuis libil2cpp.so + global-metadata.dat",
                 "blue"),
                ("4", "Analyser et générer les scripts Frida", "Analyse AOT avec exports Frida", "red"),
                ("5", "Information binaire détaillée",
                 "Infos détaillées des .so + changer les cibles / nettoyer"
                 " les caches", "white"),
                ("0", "Quitter", "", "red"),
            ]
            for num, label, desc, color in menu_items:
                menu_text.append("  [" + num + "] ", style=f"bold {color}")
                menu_text.append(f"{label}\n", style="bold bright_white")
                if desc:
                    menu_text.append(f"      {desc}\n", style="dim")
            panel = Panel(menu_text, title=" 𝕸𝖊𝖓𝖚 𝕻𝖗𝖎𝖓𝖈𝖎𝖕𝖆𝖑 ",
                          border_style=Style(color="bright_green"),
                          box=rbox.DOUBLE, padding=(0, 1))
            self.console.print(panel)
        else:
            print("\n  === 𝕸𝖊𝖓𝖚 𝕻𝖗𝖎𝖓𝖈𝖎𝖕𝖆𝖑 ===")
            print("  [1] Flutter/Dart AOT Analysis")
            print("  [2] Radare2 - Terminal interactif (vrai r2 natif)")
            print("  [3] Il2Cpp Analysis (Il2CppInspector: dump.cs + IDA/Ghidra)")
            print("  [4] Analyser et generer les scripts Frida")
            print("  [5] Information binaire detaillee (+ cibles / nettoyage)")
            print("  [0] Quitter")

    def get_choice(self):
        if self.console:
            try:
                choice = IntPrompt.ask("\n  [bold bright_green]Sélection[/]",
                                       console=self.console, default=1)
            except (KeyboardInterrupt, EOFError):
                return 0
        else:
            try:
                choice = int(input("\n  Selection: ") or "1")
            except (ValueError, KeyboardInterrupt, EOFError):
                return 0
        return choice

    def display_r2_submenu(self):
        if self.console:
            from rich.text import Text as _Text
            from rich.panel import Panel as _Panel
            from rich.rule import Rule as _Rule
            from rich.style import Style as _Style

            self.console.print()
            self.console.print(_Rule("[dim]Radare2 — Modes d'analyse[/]",
                                    style=_Style(dim=True)))

            self.console.print()
            preset_text = _Text()
            preset_items = [
                ("1", "Analyse complète", "aaa + toutes les commandes + toute extraction", "bright_green"),
                ("2", "Analyse standard", "aaa + fonctions, strings, imports/exports, xrefs, info", "bright_cyan"),
                ("3", "Analyse rapide", "aa + fonctions, strings, info binaire", "bright_yellow"),
                ("4", "Analyse minimale", "a + liste des fonctions", "bright_magenta"),
                ("5", "Audit sécurité", "aaa + sécurité, réseau, Android, strings", "red"),
            ]
            for num, label, desc, color in preset_items:
                preset_text.append(f"  [{num}] ", style=f"bold {color}")
                preset_text.append(f"{label}\n", style="bold bright_white")
                preset_text.append(f"       {desc}\n", style="dim")
            self.console.print(_Panel(
                preset_text, title=" [A] Presets d'analyse ",
                border_style=Style(color="bright_green"), box=rbox.ROUNDED,
                padding=(0, 1)))

            self.console.print()
            anal_text = _Text()
            anal_items = [
                ("a", "a — Analyse minimale", "", "dim"),
                ("b", "aa — Analyse de base", "", "bright_cyan"),
                ("c", "aaa — Analyse avancée", "", "bright_green"),
                ("d", "Toutes les commandes", "aa+aaa+aac+aar+afr+aae+aaft+aao+aav+aas+aat+aap+aau+ad", "bright_yellow"),
            ]
            for num, label, desc, color in anal_items:
                anal_text.append(f"  [{num}] ", style=f"bold {color}")
                anal_text.append(f"{label}\n", style="bright_white")
                if desc:
                    anal_text.append(f"       {desc}\n", style="dim")
            self.console.print(_Panel(
                anal_text, title=" [B] Niveaux d'analyse ",
                border_style=Style(color="bright_cyan"), box=rbox.ROUNDED,
                padding=(0, 1)))

            self.console.print()
            ext_text = _Text()
            ext_items = [
                ("e", "Fonctions uniquement", "afl, afij, aflq", "bright_cyan"),
                ("f", "Strings uniquement", "iz, izz, izq, izzq", "bright_green"),
                ("g", "Imports / Exports", "ii, iE, is, ir", "bright_yellow"),
                ("h", "Cross-références", "axt, axf (vers/depuis)", "bright_magenta"),
                ("i", "Info binaire", "headers, sections, arch, mémoire", "blue"),
                ("j", "Classes (C++ / Obj-C)", "ic, icq, ic*", "red"),
                ("k", "Sécurité (crypto, tokens)", "AES, RSA, SHA, clés, mots de passe, JWT", "bright_red"),
                ("l", "Réseau (URLs, endpoints)", "HTTP(S), WS, Firebase, cookies, Bearer", "cyan"),
                ("m", "Android (JNI, paths, dex)", "JNI_OnLoad, Java_, registerNatives, paths", "green"),
                ("n", "Bases de données", "SQLite, .db, protobuf", "yellow"),
                ("o", "Hooks (x86)", "Détection inline hooks", "magenta"),
            ]
            for num, label, desc, color in ext_items:
                ext_text.append(f"  [{num}] ", style=f"bold {color}")
                ext_text.append(f"{label}\n", style="bright_white")
                ext_text.append(f"       {desc}\n", style="dim")
            self.console.print(_Panel(
                ext_text, title=" [C] Extraction ciblée (analyse aaa auto) ",
                border_style=Style(color="bright_yellow"), box=rbox.ROUNDED,
                padding=(0, 1)))

            self.console.print()
            write_text = _Text()
            write_items = [
                ("p", "wa — Écriture assembleur", "r2 -w : écrire des instructions asm à une adresse", "bright_red"),
                ("r", "wx — Écriture hexadécimale", "r2 -w : écrire des octets en hex à une adresse", "bright_red"),
                ("s", "w — Écriture string", "r2 -w : écrire une chaîne à une adresse", "bright_red"),
            ]
            for num, label, desc, color in write_items:
                write_text.append(f"  [{num}] ", style=f"bold {color}")
                write_text.append(f"{label}\n", style="bold bright_white")
                write_text.append(f"       {desc}\n", style="dim")
            self.console.print(_Panel(
                write_text, title=" [D] Mode écriture r2 -w (patching) ",
                border_style=Style(color="red"), box=rbox.ROUNDED,
                padding=(0, 1)))

            self.console.print()
            other_text = _Text()
            other_items = [
                ("t", "Personnalisé", "Choisir librement l'analyse + les blocs d'extraction", "bright_cyan"),
                ("u", "Générer scripts sans exécuter", "Créer les .r2 + batch .sh uniquement", "bright_magenta"),
                ("0", "Retour au menu", "", "red"),
            ]
            for num, label, desc, color in other_items:
                other_text.append(f"  [{num}] ", style=f"bold {color}")
                other_text.append(f"{label}\n", style="bold bright_white")
                if desc:
                    other_text.append(f"       {desc}\n", style="dim")
            self.console.print(_Panel(
                other_text, title=" [E] Autres ",
                border_style=Style(color="white"), box=rbox.ROUNDED,
                padding=(0, 1)))
        else:
            print()
            print("  === [A] Presets d'analyse ===")
            print("  [1] Analyse complete (aaa + toute extraction)")
            print("  [2] Analyse standard (aaa + extraction courante)")
            print("  [3] Analyse rapide (aa + extraction basique)")
            print("  [4] Analyse minimale (a + fonctions)")
            print("  [5] Audit securite")
            print()
            print("  === [B] Niveaux d'analyse ===")
            print("  [a] a  — Analyse minimale")
            print("  [b] aa — Analyse de base")
            print("  [c] aaa — Analyse avancee")
            print("  [d] Toutes les commandes d'analyse")
            print()
            print("  === [C] Extraction ciblee (analyse aaa auto) ===")
            print("  [e] Fonctions uniquement")
            print("  [f] Strings uniquement")
            print("  [g] Imports / Exports")
            print("  [h] Cross-references")
            print("  [i] Info binaire (headers, sections, arch)")
            print("  [j] Classes (C++ / Obj-C)")
            print("  [k] Securite (crypto, tokens, secrets)")
            print("  [l] Reseau (URLs, endpoints, auth)")
            print("  [m] Android (JNI, paths, dex)")
            print("  [n] Bases de donnees")
            print("  [o] Hooks (x86)")
            print()
            print("  === [D] Mode ecriture r2 -w (patching) ===")
            print("  [p] wa — Ecriture assembleur")
            print("  [r] wx — Ecriture hexadecimale")
            print("  [s] w  — Ecriture string")
            print()
            print("  === [E] Autres ===")
            print("  [t] Personnalise (choix libre analyse + extraction)")
            print("  [u] Generer scripts sans executer")
            print("  [0] Retour au menu")

    def get_r2_choice(self):
        _PRESET_MAP = {
            "1": "full", "2": "standard", "3": "quick",
            "4": "minimal", "5": "security_audit",
        }
        _ANALYSIS_MAP = {
            "a": "a", "b": "aa", "c": "aaa", "d": "all_anal",
        }
        _EXTRACTION_MAP = {
            "e": "functions", "f": "strings", "g": "imports_exports",
            "h": "xrefs", "i": "binary_info", "j": "classes",
            "k": "security", "l": "network", "m": "android",
            "n": "databases", "o": "hooks",
        }
        _WRITE_MAP = {
            "p": "write_wa", "r": "write_wx", "s": "write_w",
        }
        _OTHER_MAP = {
            "t": "custom", "u": "generate_only", "0": "back",
        }

        prompt_text = "  [bold bright_green]Mode r2[/]"
        if self.console:
            try:
                raw = Prompt.ask(prompt_text, default="1", console=self.console)
            except (KeyboardInterrupt, EOFError):
                return "back"
        else:
            try:
                raw = input("\n  Mode r2 [1]: ") or "1"
            except (KeyboardInterrupt, EOFError):
                return "back"

        raw = raw.strip().lower()

        for mapping in (_PRESET_MAP, _ANALYSIS_MAP, _EXTRACTION_MAP,
                        _WRITE_MAP, _OTHER_MAP):
            if raw in mapping:
                return mapping[raw]

        self._print("[bold yellow]Choix invalide.[/]" if self.console
                    else "Choix invalide.")
        return None

    def display_r2_analysis_picker(self):
        if self.console:
            from rich.text import Text as _Text
            from rich.panel import Panel as _Panel
            text = _Text()
            items = [
                ("1", "a", "Analyse minimale"),
                ("2", "aa", "Analyse de base"),
                ("3", "aaa", "Analyse avancee"),
                ("4", "all_anal", "Toutes les commandes"),
            ]
            for num, key, label in items:
                text.append(f"  [{num}] ", style="bold bright_cyan")
                text.append(f"{key} — {label}\n", style="bright_white")
            self.console.print(_Panel(
                text, title=" Niveau d'analyse ",
                border_style=Style(color="bright_cyan"), box=rbox.ROUNDED,
                padding=(0, 1)))
        else:
            print("\n  === Niveau d'analyse ===")
            print("  [1] a  — Analyse minimale")
            print("  [2] aa — Analyse de base")
            print("  [3] aaa — Analyse avancee")
            print("  [4] Toutes les commandes")

    def get_r2_analysis_choice(self):
        _MAP = {"1": "a", "2": "aa", "3": "aaa", "4": "all_anal"}
        if self.console:
            try:
                raw = Prompt.ask(
                    "  [bold bright_green]Niveau d'analyse[/]",
                    default="3", console=self.console)
            except (KeyboardInterrupt, EOFError):
                return None
        else:
            try:
                raw = input("\n  Niveau d'analyse [3]: ") or "3"
            except (KeyboardInterrupt, EOFError):
                return None
        return _MAP.get(raw.strip(), None)

    def display_r2_extraction_picker(self):
        if self.console:
            from rich.text import Text as _Text
            from rich.panel import Panel as _Panel
            text = _Text()
            items = [
                ("1", "functions", "Fonctions"),
                ("2", "strings", "Strings"),
                ("3", "imports_exports", "Imports/Exports"),
                ("4", "xrefs", "Cross-references"),
                ("5", "binary_info", "Info binaire"),
                ("6", "classes", "Classes"),
                ("7", "security", "Securite"),
                ("8", "network", "Reseau"),
                ("9", "android", "Android"),
                ("a", "databases", "Bases de donnees"),
                ("b", "hooks", "Hooks"),
                ("0", "all", "TOUT sélectionner"),
            ]
            for num, key, label in items:
                text.append(f"  [{num}] ", style="bold bright_yellow")
                text.append(f"{label}\n", style="bright_white")
            text.append("\n  ", style="dim")
            text.append("Saisir les numeros separes par des virgules (ex: 1,3,5)", style="dim")
            self.console.print(_Panel(
                text, title=" Blocs d'extraction ",
                border_style=Style(color="bright_yellow"), box=rbox.ROUNDED,
                padding=(0, 1)))
        else:
            print("\n  === Blocs d'extraction ===")
            print("  [1] Fonctions")
            print("  [2] Strings")
            print("  [3] Imports/Exports")
            print("  [4] Cross-references")
            print("  [5] Info binaire")
            print("  [6] Classes")
            print("  [7] Securite")
            print("  [8] Reseau")
            print("  [9] Android")
            print("  [a] Bases de donnees")
            print("  [b] Hooks")
            print("  [0] TOUT selectionner")
            print("  (numeros separes par virgules, ex: 1,3,5)")

    def get_r2_extraction_choices(self):
        _MAP = {
            "1": "functions", "2": "strings", "3": "imports_exports",
            "4": "xrefs", "5": "binary_info", "6": "classes",
            "7": "security", "8": "network", "9": "android",
            "a": "databases", "b": "hooks",
        }
        if self.console:
            try:
                raw = Prompt.ask(
                    "  [bold bright_green]Extraction[/] (ex: 1,3,5 ou 0 pour tout)",
                    default="0", console=self.console)
            except (KeyboardInterrupt, EOFError):
                return None
        else:
            try:
                raw = input("\n  Extraction [0]: ") or "0"
            except (KeyboardInterrupt, EOFError):
                return None

        raw = raw.strip().lower()
        if raw == "0" or raw.strip().lower() == "all":
            return list(_MAP.values())

        keys = []
        for part in raw.split(","):
            part = part.strip()
            if part in _MAP:
                keys.append(_MAP[part])
        return keys if keys else None

    def get_r2_execute_choice(self):
        if self.console:
            try:
                raw = Prompt.ask(
                    "  [bold bright_green]Exécuter[/] r2 ou [bold bright_magenta]générer[/] uniquement ? (e/g)",
                    default="e", console=self.console)
            except (KeyboardInterrupt, EOFError):
                return True
        else:
            try:
                raw = input("\n  Executer (e) ou generer uniquement (g) [e]: ") or "e"
            except (KeyboardInterrupt, EOFError):
                return True
        return raw.strip().lower() != "g"

    def get_r2_generate_choice(self):
        self.display_r2_submenu()
        choice = self.get_r2_choice()
        if choice == "back" or choice is None:
            return None
        if choice in ("write_wa", "write_wx", "write_w"):
            self._print("[bold yellow]Le mode écriture nécessite l'exécution de r2.[/]"
                        if self.console else "Le mode ecriture necessite l'execution de r2.")
            return None
        if choice == "generate_only":
            return "full"
        if choice == "custom":
            return "full"
        return choice

    def _prompt_text(self, prompt_str, default="", show_default=True):
        if self.console:
            try:
                return Prompt.ask(
                    f"  [bold bright_cyan]{prompt_str}[/]",
                    default=default, console=self.console,
                    show_default=show_default)
            except (KeyboardInterrupt, EOFError):
                return default
        else:
            suffix = f" [{default}]" if (show_default and default) else ""
            try:
                return input(f"\n  {prompt_str}{suffix}: ") or default
            except (KeyboardInterrupt, EOFError):
                return default

    def print_raw(self, text):
        if self.console and not self.force_plain:
            try:
                sys.stdout.write(text + "\n")
                sys.stdout.flush()
            except Exception:
                from rich.text import Text as _RawText
                self.console.print(_RawText(text), soft_wrap=True, overflow="ignore", crop=False)
        else:
            print(text)

    def r2_readline(self, prompt="r2> "):

        if self.console:
            try:
                return self.console.input(
                    f"  [bold bright_green]{prompt}[/] ")
            except (KeyboardInterrupt, EOFError):
                return None
        else:
            try:
                return input(f"\n  {prompt}")
            except (KeyboardInterrupt, EOFError):
                return None

    def confirm(self, question, default=False):

        if self.console:
            try:
                raw = Prompt.ask(f"  [bold bright_yellow]{question}[/]",
                                 choices=("o", "n"),
                                 default="o" if default else "n",
                                 console=self.console, show_choices=True)
                return raw.strip().lower() == "o"
            except (KeyboardInterrupt, EOFError):
                return default
        else:
            hint = "O/n" if default else "o/N"
            try:
                raw = input(f"\n  {question} [{hint}]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                return default
            if not raw:
                return default
            return raw in ("o", "oui", "y", "yes")



    def display_r2_console_menu(self, session=None):
        r2_missing = session is not None and not session.r2_bin
        pptool_path = getattr(session, 'pptool_bin', None) if session else None
        pptool_status = ("disponible" if pptool_path else "non installé") \
            if session else "—"
        if self.console:
            from rich.text import Text as _Text
            from rich.panel import Panel as _Panel
            self.console.print()
            text = _Text()
            items = [
                ("1", "Terminal r2",
                 "Tapez vos commandes r2 librement (et pptool) sur les cibles"
                 " — ex: afl, px 64 @ 0x1000, pdf @ sym.main", "bright_green"),
                ("2", "Catalogue des commandes r2",
                 "Toutes les options r2 par catégories : analyse, info,"
                 " impression, recherche, xrefs, écriture, config…", "bright_cyan"),
                ("3", "Presets d'analyse",
                 "full / standard / quick / minimal / audit sécurité", "bright_yellow"),
                ("4", "Analyse personnalisée",
                 "Choisir le niveau d'analyse + les blocs d'extraction", "bright_magenta"),
                ("5", "Patching (mode écriture r2 -w)",
                 "wa (assembleur) / wx (hex) / w (string) — backup .elitf.bak", "bright_red"),
                ("6", "Générer les scripts sans exécuter",
                 "Créer les .r2 + batch .sh uniquement", "blue"),
                ("0", "Retour au menu", "", "red"),
            ]
            for num, label, desc, color in items:
                text.append(f"  [{num}] ", style=f"bold {color}")
                text.append(f"{label}\n", style="bold bright_white")
                if desc:
                    text.append(f"        {desc}\n", style="dim")
            if r2_missing:
                text.append("\n  [!] r2 introuvable — le terminal et le"
                            " catalogue nécessitent radare2"
                            " (Termux: pkg install radare2)\n", style="bold red")
            text.append(f"\n  pptool: {pptool_status}", style="dim")
            if pptool_path:
                text.append(f"  ({pptool_path})", style="dim")
            text.append("\n", style="dim")
            self.console.print(_Panel(
                text, title=" Console r2 ",
                border_style=Style(color="bright_green"), box=rbox.DOUBLE,
                padding=(0, 1)))
        else:
            print("\n  === Console r2 ===")
            print("  [1] Terminal r2 (+ pptool)")
            print("  [2] Catalogue des commandes r2 (toutes les options)")
            print("  [3] Presets d'analyse")
            print("  [4] Analyse personnalisee")
            print("  [5] Patching (mode ecriture r2 -w)")
            print("  [6] Generer les scripts sans executer")
            print("  [0] Retour au menu")
            if r2_missing:
                print("  [!] r2 introuvable (pkg install radare2)")
            print(f"  pptool: {pptool_status}")

    def get_r2_console_choice(self, session=None):
        self.display_r2_console_menu(session)
        if self.console:
            try:
                raw = Prompt.ask("  [bold bright_green]Console r2[/]",
                                 default="1", console=self.console)
            except (KeyboardInterrupt, EOFError):
                return "back"
        else:
            try:
                raw = input("\n  Console r2 [1]: ") or "1"
            except (KeyboardInterrupt, EOFError):
                return "back"
        raw = raw.strip().lower()
        mapping = {
            "1": "terminal", "2": "catalog",
            "3": "preset", "4": "custom",
            "5": "write", "6": "generate_only", "0": "back",
        }
        if raw in mapping:
            return self._resolve_console_action(mapping[raw])
        self._print("[bold yellow]Choix invalide.[/]" if self.console
                    else "Choix invalide.")
        return None

    def _resolve_console_action(self, action):
 
        if action == "preset":
            presets = [
                ("1", "full", "Analyse complète (aaa + toute extraction)"),
                ("2", "standard", "Analyse standard (aaa + extraction courante)"),
                ("3", "quick", "Analyse rapide (aa + extraction basique)"),
                ("4", "minimal", "Analyse minimale (a + fonctions)"),
                ("5", "security_audit", "Audit sécurité complet"),
            ]
            if self.console:
                from rich.text import Text as _Text
                from rich.panel import Panel as _Panel
                text = _Text()
                for num, key, label in presets:
                    text.append(f"  [{num}] ", style="bold bright_yellow")
                    text.append(f"{label}\n", style="bright_white")
                self.console.print(_Panel(
                    text, title=" Preset d'analyse ",
                    border_style=Style(color="bright_yellow"),
                    box=rbox.ROUNDED, padding=(0, 1)))
            else:
                print("\n  === Preset d'analyse ===")
                for num, _key, label in presets:
                    print(f"  [{num}] {label}")
            try:
                raw = self._prompt_text("Preset", default="2")
            except (KeyboardInterrupt, EOFError):
                return None
            pmap = {n: k for n, k, _ in presets}
            return pmap.get(raw.strip(), None)
        if action == "write":
            writes = [("1", "write_wa", "wa — Écrire des instructions assembleur"),
                      ("2", "write_wx", "wx — Écrire des octets en hexadécimal"),
                      ("3", "write_w", "w — Écrire une chaîne de caractères")]
            if self.console:
                from rich.text import Text as _Text
                from rich.panel import Panel as _Panel
                text = _Text()
                for num, _key, label in writes:
                    text.append(f"  [{num}] ", style="bold bright_red")
                    text.append(f"{label}\n", style="bright_white")
                self.console.print(_Panel(
                    text, title=" Mode écriture r2 -w ",
                    border_style=Style(color="red"), box=rbox.ROUNDED,
                    padding=(0, 1)))
            else:
                print("\n  === Mode ecriture r2 -w ===")
                for num, _key, label in writes:
                    print(f"  [{num}] {label}")
            try:
                raw = self._prompt_text("Commande d'écriture", default="1")
            except (KeyboardInterrupt, EOFError):
                return None
            wmap = {n: k for n, k, _ in writes}
            return wmap.get(raw.strip(), None)
        return action

    # -- Catalogue des commandes r2 ------------------------------------------

    def display_r2_catalog(self):
        from elitf_r2 import R2_TERMINAL_CATALOG
        if self.console:
            from rich.text import Text as _Text
            from rich.panel import Panel as _Panel
            self.console.print()
            text = _Text()
            keys = list(R2_TERMINAL_CATALOG)
            for i, key in enumerate(keys, 1):
                cat = R2_TERMINAL_CATALOG[key]
                text.append(f"  [{i}] ", style="bold bright_cyan")
                text.append(f"{cat['title']}\n", style="bold bright_white")
                text.append(f"        {len(cat['commands'])} commandes\n",
                            style="dim")
            text.append("\n  [0] Retour\n", style="bold red")
            self.console.print(_Panel(
                text, title=" Catalogue r2 — catégories ",
                border_style=Style(color="bright_cyan"), box=rbox.DOUBLE,
                padding=(0, 1)))
        else:
            print("\n  === Catalogue r2 - categories ===")
            for i, key in enumerate(list(R2_TERMINAL_CATALOG), 1):
                print(f"  [{i}] {R2_TERMINAL_CATALOG[key]['title']}")
            print("  [0] Retour")

    def get_r2_catalog_category(self):
        from elitf_r2 import R2_TERMINAL_CATALOG
        self.display_r2_catalog()
        keys = list(R2_TERMINAL_CATALOG)
        if self.console:
            try:
                raw = Prompt.ask("  [bold bright_green]Catégorie[/] (ex: 1"
                                 " ou 1,3 pour plusieurs)",
                                 default="", console=self.console)
            except (KeyboardInterrupt, EOFError):
                return None
        else:
            try:
                raw = input("\n  Categorie [0]: ") or "0"
            except (KeyboardInterrupt, EOFError):
                return None
        raw = raw.strip()
        if raw in ("0", "", "b", "back"):
            return "back"
        if raw.isdigit() and 1 <= int(raw) <= len(keys):
            return keys[int(raw) - 1]
        self._print("[bold yellow]Choix invalide.[/]" if self.console
                    else "Choix invalide.")
        return None

    def display_r2_catalog_commands(self, cat_key):
        from elitf_r2 import R2_TERMINAL_CATALOG
        cat = R2_TERMINAL_CATALOG.get(cat_key)
        if not cat:
            return
        if self.console:
            from rich.text import Text as _Text
            from rich.panel import Panel as _Panel
            self.console.print()
            text = _Text()
            for i, entry in enumerate(cat['commands'], 1):
                label = entry.get('raw') or entry.get('cmd', '')
                text.append(f"  [{i}] ", style="bold bright_yellow")
                text.append(f"{label}\n", style="bold bright_white")
                text.append(f"        {entry['desc']}\n", style="dim")
            text.append("\n  [0] Retour aux catégories\n", style="bold red")
            self.console.print(_Panel(
                text, title=f" Catalogue r2 — {cat['title']} ",
                border_style=Style(color="bright_yellow"), box=rbox.ROUNDED,
                padding=(0, 1)))
        else:
            print(f"\n  === Catalogue r2 - {cat['title']} ===")
            for i, entry in enumerate(cat['commands'], 1):
                label = entry.get('raw') or entry.get('cmd', '')
                print(f"  [{i}] {label} — {entry['desc']}")
            print("  [0] Retour aux categories")

    def get_r2_catalog_command(self, cat_key):
        from elitf_r2 import R2_TERMINAL_CATALOG
        cat = R2_TERMINAL_CATALOG.get(cat_key)
        if not cat:
            return None
        self.display_r2_catalog_commands(cat_key)
        if self.console:
            try:
                raw = Prompt.ask("  [bold bright_green]Commande[/] (numéro)",
                                 default="", console=self.console)
            except (KeyboardInterrupt, EOFError):
                return None
        else:
            try:
                raw = input("\n  Commande [0]: ") or "0"
            except (KeyboardInterrupt, EOFError):
                return None
        raw = raw.strip()
        if raw in ("0", "", "b", "back"):
            return "back"
        if raw.isdigit() and 1 <= int(raw) <= len(cat['commands']):
            return cat['commands'][int(raw) - 1]
        self._print("[bold yellow]Choix invalide.[/]" if self.console
                    else "Choix invalide.")
        return None

    def prompt_r2_command_args(self, entry):

        args = entry.get('args') or []
        if not args:
            return []
        values = []
        label = entry.get('raw') or entry.get('cmd', '')
        self._print(f"[bold bright_cyan]{label}[/] — {entry['desc']}"
                    if self.console else f"{label} — {entry['desc']}")
        for _key, prompt, default in args:
            try:
                val = self._prompt_text(prompt, default=default)
            except (KeyboardInterrupt, EOFError):
                return None
            values.append(val.strip() if val else "")
        return values



    def display_info_menu(self):
        if self.console:
            from rich.text import Text as _Text
            from rich.panel import Panel as _Panel
            self.console.print()
            text = _Text()
            items = [
                ("1", "Afficher les infos détaillées des .so",
                 "readelf -h -S -l sur chaque cible → binary_info.txt", "bright_cyan"),
                ("2", "Changer les cibles à traiter",
                 "Nouveau répertoire / APK + sélection des .so", "bright_yellow"),
                ("3", "Supprimer les dossiers compilés et les caches",
                 "build/, bin/, packages/, out/inputs, out/r2_output,"
                 " __pycache__", "bright_red"),
                ("0", "Retour au menu", "", "red"),
            ]
            for num, label, desc, color in items:
                text.append(f"  [{num}] ", style=f"bold {color}")
                text.append(f"{label}\n", style="bold bright_white")
                if desc:
                    text.append(f"        {desc}\n", style="dim")
            self.console.print(_Panel(
                text, title=" Information binaire détaillée ",
                border_style=Style(color="bright_white"), box=rbox.DOUBLE,
                padding=(0, 1)))
        else:
            print("\n  === Information binaire detaillee ===")
            print("  [1] Afficher les infos detaillees des .so")
            print("  [2] Changer les cibles a traiter")
            print("  [3] Supprimer les dossiers compiles et les caches")
            print("  [0] Retour au menu")

    def get_info_menu_choice(self):
        self.display_info_menu()
        if self.console:
            try:
                raw = Prompt.ask("  [bold bright_green]Info binaire[/]",
                                 default="1", console=self.console)
            except (KeyboardInterrupt, EOFError):
                return "back"
        else:
            try:
                raw = input("\n  Info binaire [1]: ") or "1"
            except (KeyboardInterrupt, EOFError):
                return "back"
        mapping = {"1": "display", "2": "change_targets",
                   "3": "cleanup", "0": "back"}
        choice = mapping.get(raw.strip(), None)
        if choice is None:
            self._print("[bold yellow]Choix invalide.[/]" if self.console
                        else "Choix invalide.")
        return choice

    def display_cleanup_table(self, items):
        cols = [("#", "bright_red"), ("Type", "bright_cyan"),
                ("Dossier", "bright_white"), ("Taille", "bright_green"),
                ("Chemin", "dim")]
        rows = [(str(i), it['kind'], it['label'],
                 self._format_size(it['size']), it['path'])
                for i, it in enumerate(items, 1)]
        t = self._table(" Dossiers compilés / caches détectés ", cols, rows)
        if t:
            self.console.print(t)
        else:
            for i, it in enumerate(items, 1):
                print(f"  {i}. [{it['kind']}] {it['label']}"
                      f" ({self._format_size(it['size'])}) {it['path']}")

    def get_cleanup_selection(self, items):
        """Sélection des dossiers à supprimer. Retourne une liste d'indices
        (0-based) ou None si annulé."""
        if not items:
            self._print("[bright_green]Rien à nettoyer.[/]" if self.console
                        else "Rien a nettoyer.")
            return None
        self.display_cleanup_table(items)
        if self.console:
            self.console.print("\n  [dim]Numéros séparés par des virgules"
                               " (ex: 1,3) ou 'all'[/]")
            try:
                raw = Prompt.ask("  [bold bright_green]Supprimer[/]",
                                 default="", console=self.console)
            except (KeyboardInterrupt, EOFError):
                return None
        else:
            try:
                raw = input("\n  Supprimer (ex: 1,3 / all / vide=annuler): ")
            except (KeyboardInterrupt, EOFError):
                return None
        raw = raw.strip().lower()
        if not raw:
            return None
        if raw == "all":
            return list(range(len(items)))
        picks = []
        for part in raw.split(","):
            part = part.strip()
            if part.isdigit() and 1 <= int(part) <= len(items):
                picks.append(int(part) - 1)
        return sorted(set(picks)) or None

    def get_target_selection(self):
        if not self.detected_so:
            self._print("[bold red]Aucun fichier .so détecté.[/]" if self.console
                        else "Aucun fichier .so detecte.")
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
            if not part:
                continue
            if "-" in part:
                try:
                    start_s, end_s = part.split("-", 1)
                    start, end = int(start_s), int(end_s)
                    if start > end:
                        start, end = end, start
                    indices.extend(range(start - 1, end))
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
            return self._run_plain(title, steps, work_fn, stream_logs=True)

        if self.force_plain:
            return self._run_plain(title, steps, work_fn, stream_logs=True)

        return self._run_live(title, steps, work_fn)

    def _run_plain(self, title, steps, work_fn, stream_logs=True):
        if self.console:
            self.console.print()
            self.console.print(Panel(
                f"[bold bright_cyan]◆[/] [bold bright_white]{title}[/]",
                border_style=Style(color="bright_cyan"), box=rbox.ROUNDED))
            self.console.print()
        else:
            print()
            print(f"=== {title} ===")
            print()

        self.log_mgr.set_total(steps)
        self.log_mgr.step_count = 0

        result = [None]
        error_holder = [None]

        def worker():
            try:
                result[0] = work_fn(self.log_mgr)
            except Exception as e:
                error_holder[0] = e

        thread = threading.Thread(target=worker, daemon=True)
        self.log_mgr.begin_stream()
        thread.start()

        prefix_map = {"error": "✗", "success": "✓", "warn": "⚠", "debug": "  "}
        style_map = {"error": "bold red", "success": "bold bright_green",
                    "warn": "bold bright_yellow", "debug": "dim"}

        while thread.is_alive():
            new_entries = self.log_mgr.drain_stream()
            for ts, msg, level in new_entries:
                prefix = prefix_map.get(level, "→")
                if self.console:
                    style = style_map.get(level, "bright_cyan")
                    self.console.print(f"  [dim][{ts}][/] [{style}]{prefix} {msg}[/]")
                else:
                    clean_msg = strip_rich_tags(str(msg))
                    print(f"  [{ts}] {prefix} {clean_msg}")
            time.sleep(0.2)

        new_entries = self.log_mgr.drain_stream(finish=True)
        for ts, msg, level in new_entries:
            prefix = prefix_map.get(level, "→")
            if self.console:
                style = style_map.get(level, "bright_cyan")
                self.console.print(f"  [dim][{ts}][/] [{style}]{prefix} {msg}[/]")
            else:
                clean_msg = strip_rich_tags(str(msg))
                print(f"  [{ts}] {prefix} {clean_msg}")

        thread.join(timeout=10)

        if self.console:
            self.console.print()
        else:
            print()
        if error_holder[0]:
            raise error_holder[0]
        return result[0]

    @staticmethod
    def _live_layout_sizes(width, height):
        """Dimensionne le Live pour tenir dans la taille réelle du terminal.

        Un layout plus haut (ou plus large) que l'écran ne peut pas être effacé
        par rich : chaque frame se réimprime et inonde l'affichage (bug observé
        sur Termux, notamment avec une police agrandie ou en mode portrait).
        On réduit donc le panneau de logs et les colonnes de progression pour
        que le total reste inférieur à la hauteur de l'écran.
        """
        try:
            width = max(int(width or 0), 20)
            height = max(int(height or 0), 10)
        except (TypeError, ValueError):
            width, height = 80, 24
        header_h, progress_h = 3, 5
        logs_h = max(4, min(18, height - header_h - progress_h - 2))
        fixed_w = 22  # spinner + pourcentage + temps + séparateurs
        avail = max(width - fixed_w, 14)
        desc_w = max(8, min(40, int(avail * 0.45)))
        bar_w = max(6, min(30, avail - desc_w))
        return header_h, progress_h, logs_h, desc_w, bar_w

    @staticmethod
    def compact_progress_label(label, width):
        """Raccourcit un libellé de barre en gardant le compteur visible.

        Sur un écran Termux étroit, tronquer brutalement `label[:width]`
        supprime la partie informative « [17/40] » ou « (12.3 Mo) ». On
        raccourcit donc le préfixe et on conserve le suffixe entre crochets
        ou parenthèses : « Compilation Dart VM… [17/40] » tient en 15 colonnes
        sous la forme « Compil… [17/40] ».
        """
        label = str(label or '')
        try:
            width = int(width)
        except (TypeError, ValueError):
            width = 40
        if width <= 0:
            return ''
        if len(label) <= width:
            return label
        m = re.search(r'\s((\[[^\]]+\])|(\([^)]+\)))\s*$', label)
        suffix, prefix = '', label
        if m:
            suffix = m.group(1)
            prefix = label[:m.start()].rstrip()
        if suffix and width >= len(suffix) + 3:
            keep = width - len(suffix) - 2  # '…' + espace
            return prefix[:max(keep, 1)] + '… ' + suffix
        return prefix[:max(width - 1, 1)] + '…'

    @staticmethod
    def _combined_completed(step_count, sub_fraction, steps, last=0.0):

        try:
            steps = max(int(steps), 1)
        except (TypeError, ValueError):
            steps = 1
        try:
            sc = float(step_count or 0)
        except (TypeError, ValueError):
            sc = 0.0
        frac = float(sub_fraction or 0.0)
        prev = float(last or 0.0)
        return min(max(sc, frac, prev), float(steps))

    def _run_live(self, title, steps, work_fn):
        from rich.table import Column

        if not getattr(self.console, 'is_terminal', False):

            return self._run_plain(title, steps, work_fn, stream_logs=True)

        try:
            w, h = self.console.size.width, self.console.size.height
        except Exception:
            w, h = 80, 24
        header_h, progress_h, logs_h, desc_w, bar_w = \
            self._live_layout_sizes(w, h)

        progress = Progress(
            SpinnerColumn(spinner_name="dots", style="bright_cyan"),
            TextColumn("[bold bright_white]{task.description}[/]",
                       table_column=Column(width=desc_w, no_wrap=False)),
            BarColumn(bar_width=bar_w, style=Style(dim=True),
                      complete_style=Style(color="bright_cyan"),
                      finished_style=Style(color="bright_green")),
            TaskProgressColumn(style=Style(color="bright_white"), table_column=Column(width=6)),
            TimeElapsedColumn(table_column=Column()),
            console=self.console,
        )

        log_panel_content = Text.from_markup("  [dim]En attente...[/]")
        log_panel = Panel(log_panel_content, title=" Elit-f travaille ",
                          border_style=Style(color="bright_yellow"),
                          box=rbox.ROUNDED, padding=(0, 0), height=logs_h)

        header_panel = Panel(Text.from_markup(f"[bold bright_cyan]◆[/] [bold bright_white]{title}[/]", justify="center"),
                             border_style=Style(color="bright_cyan"), box=rbox.ROUNDED)

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=header_h),
            Layout(name="progress", size=progress_h),
            Layout(name="logs", size=logs_h),
        )
        layout["header"].update(header_panel)
        layout["progress"].update(progress)
        layout["logs"].update(log_panel)

        result = [None]
        error_holder = [None]

        self.log_mgr.set_total(steps)
        self.log_mgr.step_count = 0

        def update_logs():
            new_content = self.log_mgr.get_rich_text()
            new_panel = Panel(new_content, title=" Elit-f travaille ",
                              border_style=Style(color="bright_yellow"),
                              box=rbox.ROUNDED, padding=(0, 0), height=logs_h)
            layout["logs"].update(new_panel)

        def worker():
            try:
                result[0] = work_fn(self.log_mgr)
            except Exception as e:
                error_holder[0] = e
                self.log_mgr.add(str(e), "error")

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

        try:
            with Live(layout, console=self.console, refresh_per_second=4,
                      vertical_overflow="crop"):
                task_id = progress.add_task("Initialisation...", total=steps)
                last_completed = 0.0
                while thread.is_alive():
                    frac, label = self.log_mgr.get_sub_progress()
                    last_completed = self._combined_completed(
                        self.log_mgr.step_count, frac, steps, last_completed)
                    if label:
                        progress.update(
                            task_id,
                            description=self.compact_progress_label(label,
                                                                    desc_w))
                    progress.update(task_id, completed=last_completed)
                    update_logs()
                    time.sleep(0.25)
                progress.update(task_id, description="Terminé",
                                completed=steps)
                update_logs()
        finally:
            thread.join(timeout=10)

        if error_holder[0]:
            raise error_holder[0]
        return result[0]
