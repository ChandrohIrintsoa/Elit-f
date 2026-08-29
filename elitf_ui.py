#!/usr/bin/env python3
"""
elitf_ui.py — Composants d'interface utilisateur pour Elit-f.

Contient :
  * `LogManager`        : buffer circulaire thread-safe de logs avec rendu Rich/plaintext.
  * `ElitfUI`           : façade d'affichage (console Rich ou fallback print).
  * Constantes associées (LOGO, AUTHOR) et détection de `rich`.

Ce module est importé paresseusement par `elitf.py` afin que le cœur fonctionnel
(extraction, build, analyse) reste utilisable même si `rich` n'est pas installé.

Notes Termux :
  * Rich ne détecte pas toujours Termux comme un terminal interactif, ce qui
    fait apparaître les balises littéralement et empêche `Live` de rafraîchir
    correctement l'écran (les frames s'empilent au lieu de se remplacer).
  * On détecte donc Termux via la variable d'environnement `TERMUX_VERSION`
    ou la présence du chemin `/data/data/com.termux`, et dans ce cas on force
    `Console(force_terminal=True)` pour l'interprétation des balises, et on
    remplace `Live` par un mode "plain-streaming" qui affiche les logs au fil
    de l'eau via des `print()` simples.
"""
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
    """Thread-safe ring buffer of timestamped log entries.

    Also tracks an explicit `step_count` so progress bars can advance
    based on actual work performed rather than the (capped) buffer length.
    """
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
    """Detect whether we're running inside a Termux environment.

    Termux exposes a `TERMUX_VERSION` env var and installs under
    `/data/data/com.termux/`. Either signal is sufficient.
    """
    if os.environ.get('TERMUX_VERSION'):
        return True
    if os.path.isdir('/data/data/com.termux'):
        return True
    prefix = os.environ.get('PREFIX', '')
    if 'com.termux' in prefix:
        return True
    return False


class ElitfUI:
    """Façade d'affichage Rich avec fallback plain-text.

    `detected_so` est une liste de dicts `{"path", "name", "size"}` peuplée par
    `detect_so_files()`. `metadata` est un dict affiché par `display_metadata()`.
    """
    def __init__(self, force_plain: bool = False):
        """Initialize the UI.

        Args:
            force_plain: if True, don't use Rich Live animations (use plain
                streaming instead). Recommended on Termux or any terminal
                where Live doesn't refresh correctly.

        Note: Even when force_plain is True, we still create a Rich Console
        (with force_terminal=True) so that the logo, menu, panels, and tables
        are rendered with colors and proper formatting. Only the Live
        animation is replaced with plain streaming on Termux.
        """
        # force_plain disables Live animations only, NOT colors/panels/tables.
        # On Termux, Live doesn't refresh correctly (frames stack), so we use
        # _run_plain which streams logs via print() while still using Rich
        # Console for static rendering (logo, menu, panels).
        self.force_plain = force_plain or _is_termux()
        if HAS_RICH:
            # On Termux (or when force_plain is requested), force_terminal=True
            # so Rich interprets markup tags and renders colors even when it
            # can't auto-detect the terminal as interactive.
            self.console = Console(force_terminal=self.force_plain or None)
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
                ("2", "Radare2 - Analyse unifiée", "Sélection cibles + sous-menu r2 (a/aa/aaa/-w/wa/extraits/...)", "bright_green"),
                ("3", "Générer scripts IDA uniquement", "Générer les scripts IDA sans exécution", "blue"),
                ("4", "Générer scripts Frida uniquement", "Générer les scripts Frida sans exécution", "red"),
                ("5", "Information binaire détaillée", "Afficher les infos détaillées des .so", "white"),
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
            print("  [2] Radare2 - Analyse unifiee")
            print("  [3] Generer scripts IDA uniquement")
            print("  [4] Generer scripts Frida uniquement")
            print("  [5] Information binaire detaillee")
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

    # ------------------------------------------------------------------
    #  Radare2 unified sub-menu (remplace les anciennes options [2] + [3])
    # ------------------------------------------------------------------
    def display_r2_submenu(self):
        """Afficher le sous-menu Radare2 avec tous les modes d'analyse."""
        if self.console:
            from rich.text import Text as _Text
            from rich.panel import Panel as _Panel
            from rich.rule import Rule as _Rule
            from rich.style import Style as _Style

            self.console.print()
            self.console.print(_Rule("[dim]Radare2 — Modes d'analyse[/]",
                                    style=_Style(dim=True)))

            # Section A : Presets
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

            # Section B : Niveaux d'analyse
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

            # Section C : Extraction ciblée
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

            # Section D : Mode écriture
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

            # Section E : Autres
            self.console.print()
            other_text = _Text()
            other_items = [
                ("t", "Personnalisé", "Choisir librement l'analyse + les blocs d'extraction", "bright_cyan"),
                ("u", "Générer scripts sans exécuter", "Créer les .r2 + batch .sh uniquement", "bright_magenta"),
                ("0", "Retour au menu principal", "", "red"),
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
            # Mode plain-text
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
            print("  [0] Retour au menu principal")

    def get_r2_choice(self):
        """Obtenir le choix de l'utilisateur dans le sous-menu r2.

        Returns:
            str: la clé du choix ("full", "standard", "a", "aa", "functions", etc.)
                 ou "back" pour retourner.
        """
        # Mapping choix -> clé
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

        # Chercher dans tous les mappings
        for mapping in (_PRESET_MAP, _ANALYSIS_MAP, _EXTRACTION_MAP,
                        _WRITE_MAP, _OTHER_MAP):
            if raw in mapping:
                return mapping[raw]

        # Invité ? Montrer le sous-menu à nouveau
        self._print("[bold yellow]Choix invalide.[/]" if self.console
                    else "Choix invalide.")
        return None

    def display_r2_analysis_picker(self):
        """Afficher le sélecteur de niveau d'analyse (pour le mode personnalisé)."""
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
        """Obtenir le choix du niveau d'analyse personnalisé.

        Returns:
            Clé dans R2_ANALYSIS_LEVELS ou None.
        """
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
        """Afficher le sélecteur de blocs d'extraction (pour le mode personnalisé)."""
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
        """Obtenir les blocs d'extraction sélectionnés.

        Returns:
            Liste de clés dans R2_EXTRACTION_BLOCKS, ou None si annulé.
        """
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
        """Demander si l'on doit exécuter r2 ou juste générer les scripts.

        Returns:
            True pour exécuter, False pour générer uniquement.
        """
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
        """Sous-menu pour le mode 'générer sans exécuter'.

        Returns:
            Clé de preset ou None.
        """
        self.display_r2_submenu()
        choice = self.get_r2_choice()
        if choice == "back" or choice is None:
            return None
        if choice in ("write_wa", "write_wx", "write_w"):
            # Pas de sens en mode génération seule
            self._print("[bold yellow]Le mode écriture nécessite l'exécution de r2.[/]"
                        if self.console else "Le mode ecriture necessite l'execution de r2.")
            return None
        if choice == "generate_only":
            # Récursif — utiliser le preset complet par défaut
            return "full"
        if choice == "custom":
            return "full"  # Simplification pour la génération
        return choice

    def _prompt_text(self, prompt_str, default=""):
        """Demander une chaîne de texte à l'utilisateur.

        Args:
            prompt_str: le prompt à afficher
            default: valeur par défaut

        Returns:
            La chaîne saisie ou la valeur par défaut.
        """
        if self.console:
            try:
                return Prompt.ask(
                    f"  [bold bright_cyan]{prompt_str}[/]",
                    default=default, console=self.console)
            except (KeyboardInterrupt, EOFError):
                return default
        else:
            try:
                return input(f"\n  {prompt_str} [{default}]: ") or default
            except (KeyboardInterrupt, EOFError):
                return default

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

        When self.console is available (Rich installed), we still use it for
        rendering the header panel and log entries with colors — only the
        Live animation is replaced with plain streaming. When self.console is
        None (Rich not installed), we fall back to plain print().
        """
        # Print a header so the user knows what's running.
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
        thread.start()

        last_count = 0
        prefix_map = {"error": "✗", "success": "✓", "warn": "⚠", "debug": "  "}
        style_map = {"error": "bold red", "success": "bold bright_green",
                    "warn": "bold bright_yellow", "debug": "dim"}

        # Stream new log entries as they appear.
        while thread.is_alive():
            with self.log_mgr.lock:
                current_logs = list(self.log_mgr.logs)
            new_entries = current_logs[last_count:]
            for ts, msg, level in new_entries:
                prefix = prefix_map.get(level, "→")
                if self.console:
                    style = style_map.get(level, "bright_cyan")
                    self.console.print(f"  [dim][{ts}][/] [{style}]{prefix} {msg}[/]")
                else:
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

        log_panel_content = Text.from_markup("  [dim]En attente...[/]")
        log_panel = Panel(log_panel_content, title=" Opérations en direct ",
                          border_style=Style(color="bright_yellow"),
                          box=rbox.ROUNDED, padding=(0, 0), height=18)

        header_panel = Panel(Text.from_markup(f"[bold bright_cyan]◆[/] [bold bright_white]{title}[/]", justify="center"),
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
