
import os
import re
import platform
import threading
import time
import sys
from datetime import datetime
from collections import deque

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TimeElapsedColumn, TaskProgressColumn
    from rich.text import Text
    from rich.layout import Layout
    from rich.live import Live
    from rich.prompt import IntPrompt, Prompt
    from rich.rule import Rule
    from rich.style import Style
    from rich import box as rbox
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

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

# Regex to strip Rich markup tags when rich is unavailable.
# Rich markup tags can contain combinations of style names, colors, and modifiers
# separated by spaces (e.g. `[bold bright_cyan on #ff0000]`). The closing tag
# shorthand is `[/]`. We accept any tag starting with a letter or `#` (hex color),
# followed by word chars / spaces / `#` — this is permissive but matches Rich's
# parser for the markup used in this codebase.
_RICH_TAG_RE = re.compile(r'(?:\[/?[#a-zA-Z][\w #]*\]|\[/\])')


def strip_rich_tags(text: str) -> str:
    """Strip Rich markup tags so plain-text fallbacks stay readable.

    Handles both named tags ([bold red]...[/bold red]) and Rich shorthand
    closings ([/]).
    """
    return _RICH_TAG_RE.sub('', str(text))


class LogManager:

    def __init__(self, maxlen=200):
        self.logs = deque(maxlen=maxlen)
        self.lock = threading.Lock()
        self.step_count = 0
        self.total_steps = 0

    def add(self, msg, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            self.logs.append((ts, msg, level))

    def clear(self):
        with self.lock:
            self.logs.clear()
            self.step_count = 0

    def step(self, count=1):
        with self.lock:
            self.step_count += count

    def set_total(self, total):
        with self.lock:
            self.total_steps = total

    def get_rich_text(self):
        from rich.text import Text as RichText
        lines = []
        with self.lock:
            entries = list(self.logs)
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
        # Use RichText("\n").join() — well-defined in Rich Text objects.
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

        self.force_plain = force_plain or _is_termux()
        if HAS_RICH and not self.force_plain:
            self.console = Console()
        else:
            self.console = None
        self.log_mgr = LogManager(200)
        self.detected_so = []
        self.metadata = {}
        self.outdir = ""
        self.indir = ""

    def _print(self, *args, **kwargs):
        if self.console and not self.force_plain:
            self.console.print(*args, **kwargs)
        else:
            msg = " ".join(str(a) for a in args)
            print(strip_rich_tags(msg))

    def _print_error(self, e):
        if self.console:
            self.console.print()
            self.console.print(Panel(f"[bold red]Erreur: {type(e).__name__}: {e}[/]",
                                     title="[bright_red]Échec de l'opération[/]",
                                     border_style=Style(color="red")))
            self.console.print("[dim]Vérifiez que toutes les dépendances sont installées :[/]")
            self.console.print("[dim]  pkg install python  &&  pip install pyelftools requests rich[/]")
        else:
            print(f"\nERREUR: {type(e).__name__}: {e}")
            print("Vérifiez que toutes les dépendances sont installées:")
            print("  pkg install python && pip install pyelftools requests rich")

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
        logo_text = LOGO % (AUTHOR, platform.system(), datetime.now().strftime("%Y-%m-%d %H:%M"))
        if self.console:
            self.console.print(logo_text)
            self.console.print("\n")
        else:
            print(f"\n  ELIT-F - Flutter/Dart AOT Reversing Engine")
            print(f"  Auteur : {AUTHOR}")
            print(f"  Plateforme : {platform.system()}")
            print(f"  Date : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")

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
            panel = Panel(menu_text, title=" Menu Principal ",
                          border_style=Style(color="bright_green"),
                          box=rbox.DOUBLE, padding=(0, 1))
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
        """Run `work_fn(log_mgr)` while reporting progress.

        Three modes:
          * Plain (no Rich): work_fn runs synchronously, logs are NOT streamed
            but `work_fn` itself can `print()` directly.
          * Plain-streaming (Rich installed but on Termux / force_plain):
            work_fn runs in a thread, new log entries are printed in real-time
            via `print()` so the user sees progress without needing Rich Live.
          * Rich Live (default on desktop terminals): full animated TUI with
            progress bar + live log panel.

        The plain-streaming mode exists because Termux (and some CI terminals)
        don't support Rich's cursor-repositioning codes correctly, which causes
        Live frames to stack vertically instead of refreshing in place.
        """
        # Plain fallback when Rich is unavailable OR when the user explicitly
        # asked for plain mode (Termux, --plain, non-TTY output, ...).
        if not self.console or not HAS_RICH:
            return self._run_plain(title, steps, work_fn, stream_logs=True)

        if self.force_plain:
            return self._run_plain(title, steps, work_fn, stream_logs=True)

        return self._run_live(title, steps, work_fn)

    def _run_plain(self, title, steps, work_fn, stream_logs=True):
        """Plain mode: print title, run work_fn in a thread, stream logs as they arrive.

        Used when Rich is unavailable OR when running on terminals (Termux, CI)
        where Rich Live doesn't refresh correctly.
        """
        # Print a header line so the user knows what's running.
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
        thread.start()

        last_count = 0
        prefix_map = {"error": "✗", "success": "✓", "warn": "⚠", "debug": "  "}

        # Stream new log entries as they appear.
        while thread.is_alive():
            with self.log_mgr.lock:
                current_logs = list(self.log_mgr.logs)
            new_entries = current_logs[last_count:]
            for ts, msg, level in new_entries:
                prefix = prefix_map.get(level, "→")
                # In plain mode, strip any Rich markup so the user never sees
                # literal `[bold red]...[/]` tags on stdout.
                clean_msg = strip_rich_tags(str(msg))
                print(f"  [{ts}] {prefix} {clean_msg}")
            last_count = len(current_logs)
            time.sleep(0.2)

        # Print any final logs added after the worker exited.
        with self.log_mgr.lock:
            current_logs = list(self.log_mgr.logs)
        new_entries = current_logs[last_count:]
        for ts, msg, level in new_entries:
            prefix = prefix_map.get(level, "→")
            clean_msg = strip_rich_tags(str(msg))
            print(f"  [{ts}] {prefix} {clean_msg}")

        thread.join(timeout=10)

        print()
        if error_holder[0]:
            raise error_holder[0]
        return result[0]

    def _run_live(self, title, steps, work_fn):
        """Rich Live mode: animated TUI with progress bar + live log panel."""
        from rich.table import Column

        progress = Progress(
            SpinnerColumn(spinner_name="dots", style="bright_cyan"),
            TextColumn("[bold bright_white]{task.description}[/]",
                       table_column=Column(width=40, no_wrap=False)),
            BarColumn(bar_width=30, style=Style(dim=True),
                      complete_style=Style(color="bright_cyan"),
                      finished_style=Style(color="bright_green")),
            TaskProgressColumn(style=Style(color="bright_white"), table_column=Column(width=6)),
            TimeElapsedColumn(table_column=Column()),
            console=self.console,
        )

        log_panel_content = Text("  [dim]En attente...[/]")
        log_panel = Panel(log_panel_content, title=" Opérations en direct ",
                          border_style=Style(color="bright_yellow"),
                          box=rbox.ROUNDED, padding=(0, 0), height=18)

        header_panel = Panel(Text(f"[bold bright_cyan]◆[/] [bold bright_white]{title}[/]", justify="center"),
                             border_style=Style(color="bright_cyan"), box=rbox.ROUNDED)

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

        self.log_mgr.set_total(steps)
        self.log_mgr.step_count = 0

        def update_logs():
            new_content = self.log_mgr.get_rich_text()
            new_panel = Panel(new_content, title=" Opérations en direct ",
                              border_style=Style(color="bright_yellow"),
                              box=rbox.ROUNDED, padding=(0, 0), height=18)
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
            with Live(layout, console=self.console, refresh_per_second=4):
                task_id = progress.add_task("Initialisation...", total=steps)
                while thread.is_alive():
                    completed = min(self.log_mgr.step_count, steps)
                    progress.update(task_id, completed=completed)
                    update_logs()
                    time.sleep(0.25)
                progress.update(task_id, completed=steps)
                update_logs()
        finally:
            # Ensure worker has fully finished before returning so any pending
            # exception is propagated deterministically.
            thread.join(timeout=10)

        if error_holder[0]:
            raise error_holder[0]
        return result[0]
