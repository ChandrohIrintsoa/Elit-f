import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf_r2 as r2
from elitf_ui import LogManager


class FakeUI:
    console = None

    def __init__(self):
        self.printed = []
        self.raw_printed = []

    def _print(self, *a, **k):
        self.printed.append(" ".join(str(x) for x in a))

    def print_raw(self, text):
        self.raw_printed.append(text)

    def r2_readline(self, prompt=""):
        return None

    def confirm(self, question, default=False):
        return default


def _make_session(tmp):
    so = tmp / "libapp.so"
    so.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    ui = FakeUI()
    sess = r2.R2Session([{"name": "libapp.so", "path": str(so)}],
                        str(tmp / "out"), LogManager(), ui)
    sess.r2_bin = "/usr/bin/true"
    return sess, ui


class OutputLimitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_limit_is_10mb(self):
        with patch.dict(os.environ, {}, clear=False):
            if "R2_OUTPUT_LIMIT" in os.environ:
                del os.environ["R2_OUTPUT_LIMIT"]
            self.assertEqual(r2._r2_output_limit(), 10_000_000)

    def test_env_var_override(self):
        with patch.dict(os.environ, {"R2_OUTPUT_LIMIT": "50000000"}):
            self.assertEqual(r2._r2_output_limit(), 50_000_000)

    def test_env_var_invalid_falls_back(self):
        with patch.dict(os.environ, {"R2_OUTPUT_LIMIT": "not_a_number"}):
            self.assertEqual(r2._r2_output_limit(), 10_000_000)

    def test_env_var_zero_falls_back(self):
        with patch.dict(os.environ, {"R2_OUTPUT_LIMIT": "0"}):
            self.assertEqual(r2._r2_output_limit(), 10_000_000)

    def test_show_output_no_truncation_under_limit(self):
        sess, ui = _make_session(self.root)
        small_output = "A" * 100
        sess._show_output(small_output, ok=True)
        self.assertEqual(ui.raw_printed[-1], small_output)

    def test_show_output_truncates_over_limit_with_hint(self):
        sess, ui = _make_session(self.root)
        with patch("elitf_r2._r2_output_limit", return_value=100):
            big_output = "A" * 500
            sess._show_output(big_output, ok=True)
            text = ui.raw_printed[-1]
            self.assertIn("[sortie tronquee", text)
            self.assertIn("sur 500", text)
            self.assertIn("R2_OUTPUT_LIMIT", text)
            self.assertIn("cmd > fichier.txt", text)

    def test_limit_builtin_shows_current_value(self):
        sess, ui = _make_session(self.root)
        sess.handle_builtin("!limit")
        joined = "\n".join(ui.printed)
        self.assertIn("Limite de sortie", joined)
        self.assertTrue("caractères" in joined or "caracteres" in joined,
                        f"expected 'caractères' or 'caracteres' in: {joined}")

    def test_limit_builtin_sets_new_value(self):
        sess, ui = _make_session(self.root)
        original = r2.R2_OUTPUT_LIMIT
        try:
            sess.handle_builtin("!limit 50000000")
            self.assertEqual(r2.R2_OUTPUT_LIMIT, 50_000_000)
            joined = "\n".join(ui.printed)
            self.assertIn("50000000", joined)
        finally:
            r2.R2_OUTPUT_LIMIT = original

    def test_limit_builtin_rejects_invalid(self):
        sess, ui = _make_session(self.root)
        original = r2.R2_OUTPUT_LIMIT
        try:
            sess.handle_builtin("!limit abc")
            self.assertEqual(r2.R2_OUTPUT_LIMIT, original)
            joined = "\n".join(ui.printed)
            self.assertIn("invalide", joined.lower())
        finally:
            r2.R2_OUTPUT_LIMIT = original

    def test_limit_builtin_rejects_too_small(self):
        sess, ui = _make_session(self.root)
        original = r2.R2_OUTPUT_LIMIT
        try:
            sess.handle_builtin("!limit 100")
            self.assertEqual(r2.R2_OUTPUT_LIMIT, original)
        finally:
            r2.R2_OUTPUT_LIMIT = original

    def test_help_lists_limit_builtin(self):
        sess, ui = _make_session(self.root)
        sess._print_help()
        joined = "\n".join(ui.printed)
        self.assertIn("!limit", joined)


class PrintRawTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_print_raw_bypasses_rich_wrapping(self):
        import io
        import contextlib
        from elitf_ui import ElitfUI
        ui = ElitfUI(force_plain=True)
        long_line = "A" * 500
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ui.print_raw(long_line)
        self.assertIn(long_line, buf.getvalue())
        self.assertEqual(buf.getvalue().count("A"), 500)


if __name__ == "__main__":
    unittest.main()
