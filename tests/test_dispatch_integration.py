import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf
import elitf_il2cpp as il2cpp
import elitf_r2 as r2
from elitf_ui import LogManager


class StubUI:
    console = None

    def __init__(self):
        self.printed = []
        self._targets_selection = [0]
        self.log_mgr = LogManager()
        self.indir = None
        self.outdir = None
        self.detected_so = []

    def _print(self, *a, **k):
        self.printed.append(" ".join(str(x) for x in a))

    def _print_error(self, e):
        self.printed.append(f"ERROR: {e}")

    def _clear(self):
        pass

    def display_logo(self):
        pass

    def display_metadata(self):
        pass

    def display_so_table(self):
        pass

    def detect_so_files(self, indir):
        pass

    def display_menu(self):
        pass

    def get_choice(self):
        return self._next_choice()

    def _next_choice(self):
        if not hasattr(self, "_choices"):
            return 0
        if not self._choices:
            return 0
        return self._choices.pop(0)

    def set_choices(self, choices):
        self._choices = list(choices)

    def get_target_selection(self):
        return self._targets_selection

    def run_with_live_display(self, title, steps, work_fn):
        work_fn(LogManager())


def _patch_input_returns_empty():
    return patch("builtins.input", side_effect=["", ""])


class DispatchChoice2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.libapp = self.root / "libapp.so"
        self.libapp.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
        self.outdir = self.root / "out"
        self.outdir.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_choice_2_calls_r2_mini_terminal(self):
        ui = StubUI()
        ui.indir = str(self.root)
        ui.outdir = str(self.outdir)
        ui.detected_so = [{"name": "libapp.so", "path": str(self.libapp)}]
        ui.set_choices([2, 0])

        called = {"count": 0}

        def fake_mini_terminal(so_list, outdir, log_mgr=None, ui=None):
            called["count"] += 1
            return None

        with patch.object(elitf, "r2_mini_terminal", side_effect=fake_mini_terminal):
            with patch.object(elitf, "prepare_so_targets", return_value=ui.detected_so):
                with _patch_input_returns_empty():
                    elitf.main_interactive(ui)

        self.assertEqual(called["count"], 1)


class DispatchChoice3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.outdir = self.root / "out"
        self.outdir.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_choice_3_calls_run_il2cpp_analysis(self):
        ui = StubUI()
        ui.indir = str(self.root)
        ui.outdir = str(self.outdir)
        ui.detected_so = []
        ui.set_choices([3, 0])

        called = {"count": 0}

        def fake_run(indir, outdir, log_mgr=None, ui=None):
            called["count"] += 1
            called["indir"] = indir
            called["outdir"] = outdir
            return str(Path(outdir) / "il2cpp_output")

        with patch.object(elitf, "find_il2cpp_targets",
                          return_value=[("libil2cpp.so", "global-metadata.dat")]):
            with patch.object(elitf, "run_il2cpp_analysis", side_effect=fake_run):
                with _patch_input_returns_empty():
                    elitf.main_interactive(ui)

        self.assertEqual(called["count"], 1)
        self.assertEqual(called["indir"], str(self.root))
        self.assertEqual(called["outdir"], str(self.outdir))

    def test_choice_3_skips_when_no_il2cpp_targets(self):
        ui = StubUI()
        ui.indir = str(self.root)
        ui.outdir = str(self.outdir)
        ui.detected_so = []
        ui.set_choices([3, 0])

        called = {"count": 0}

        def fake_run(indir, outdir, log_mgr=None, ui=None):
            called["count"] += 1
            return None

        import io
        import contextlib
        buf = io.StringIO()
        with patch.object(elitf, "find_il2cpp_targets", return_value=[]):
            with patch.object(elitf, "run_il2cpp_analysis", side_effect=fake_run):
                with _patch_input_returns_empty():
                    with contextlib.redirect_stdout(buf):
                        elitf.main_interactive(ui)

        self.assertEqual(called["count"], 0)
        text = buf.getvalue() + "\n".join(ui.printed)
        self.assertIn("libil2cpp.so", text)


class MenuLabelTests(unittest.TestCase):
    def test_menu_has_mini_terminal_label(self):
        from elitf_ui import ElitfUI
        ui = ElitfUI(force_plain=True)
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ui.display_menu()
        text = buf.getvalue()
        self.assertIn("Mini Terminal", text)
        self.assertIn("Il2Cpp", text)


if __name__ == "__main__":
    unittest.main()
