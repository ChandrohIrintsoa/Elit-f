import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf_r2 as r2
from elitf_ui import LogManager


class FakeUI:
    console = None

    def __init__(self, lines=()):
        self.lines = list(lines)
        self.printed = []
        self.raw_printed = []
        self._targets_selection = None

    def _print(self, *a, **k):
        self.printed.append(" ".join(str(x) for x in a))

    def print_raw(self, text):
        self.raw_printed.append(text)

    def r2_readline(self, prompt=""):
        if not self.lines:
            return None
        return self.lines.pop(0)

    def confirm(self, question, default=False):
        return default

    def get_target_selection(self):
        if self._targets_selection is not None:
            return self._targets_selection
        return [0]


def _make_targets(root, count=1):
    targets = []
    for i in range(count):
        so = root / f"lib{i}.so"
        so.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
        targets.append({"name": f"lib{i}.so", "path": str(so)})
    return targets


class R2CatalogTests(unittest.TestCase):
    def test_catalog_has_all_expected_categories(self):
        expected = {
            "analyse", "info", "print", "search", "xrefs", "write", "config",
            "seek", "flags", "block", "compare", "crypto", "debug", "graphs",
            "info_extra", "open", "resize", "types", "yank", "zignatures",
            "sdb", "mount", "visual", "system",
        }
        self.assertEqual(set(r2.R2_TERMINAL_CATALOG.keys()), expected)

    def test_each_category_has_required_keys(self):
        for key, cat in r2.R2_TERMINAL_CATALOG.items():
            self.assertIn("title", cat, f"category {key} missing title")
            self.assertIn("commands", cat, f"category {key} missing commands")
            self.assertIsInstance(cat["commands"], list)
            self.assertTrue(cat["commands"], f"category {key} has no commands")

    def test_each_command_has_cmd_and_desc(self):
        for key, cat in r2.R2_TERMINAL_CATALOG.items():
            for entry in cat["commands"]:
                self.assertIn("cmd", entry, f"category {key} entry missing cmd")
                self.assertIn("desc", entry, f"category {key} entry missing desc")

    def test_total_commands_at_least_300(self):
        total = sum(len(c["commands"]) for c in r2.R2_TERMINAL_CATALOG.values())
        self.assertGreaterEqual(total, 300,
            f"expected at least 300 commands, got {total}")

    def test_write_commands_marked_write(self):
        for entry in r2.R2_TERMINAL_CATALOG["write"]["commands"]:
            self.assertTrue(entry.get("write", False),
                f"write cmd {entry['cmd']} not marked write=True")


class R2MiniTerminalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_returns_none_when_no_target_selected(self):
        targets = _make_targets(self.root, 2)
        ui = FakeUI()
        ui._targets_selection = []
        log = LogManager()
        result = r2.r2_mini_terminal(targets, str(self.root / "out"),
                                     log_mgr=log, ui=ui)
        self.assertIsNone(result)

    def test_requires_ui(self):
        targets = _make_targets(self.root, 1)
        with self.assertRaises(ValueError):
            r2.r2_mini_terminal(targets, str(self.root / "out"),
                                log_mgr=None, ui=None)

    def test_terminal_quits_on_q(self):
        targets = _make_targets(self.root, 1)
        ui = FakeUI(lines=["q"])
        with patch.object(r2.R2Session, "run_r2", return_value=(0, "", "")):
            sess = r2.R2Session(targets, str(self.root / "out"),
                                LogManager(), ui)
            sess.r2_bin = "/usr/bin/true"
            sess.terminal()
        self.assertEqual(ui.lines, [])

    def test_terminal_handles_help_builtin(self):
        targets = _make_targets(self.root, 1)
        ui = FakeUI(lines=["!help", "q"])
        with patch.object(r2.R2Session, "run_r2", return_value=(0, "", "")):
            sess = r2.R2Session(targets, str(self.root / "out"),
                                LogManager(), ui)
            sess.r2_bin = "/usr/bin/true"
            sess.terminal()
        joined = "\n".join(ui.printed)
        self.assertIn("Mini terminal", joined)

    def test_terminal_dispatches_unknown_builtin_gracefully(self):
        targets = _make_targets(self.root, 1)
        ui = FakeUI(lines=["!unknown_builtin", "q"])
        with patch.object(r2.R2Session, "run_r2", return_value=(0, "", "")):
            sess = r2.R2Session(targets, str(self.root / "out"),
                                LogManager(), ui)
            sess.r2_bin = "/usr/bin/true"
            sess.terminal()
        joined = "\n".join(ui.printed)
        self.assertIn("builtin inconnu", joined)


class R2SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.targets = _make_targets(self.root, 2)

    def tearDown(self):
        self.tmp.cleanup()

    def test_session_initializes_with_multiple_targets(self):
        ui = FakeUI()
        sess = r2.R2Session(self.targets, str(self.root / "out"),
                            LogManager(), ui)
        self.assertEqual(len(sess.targets), 2)
        self.assertEqual(sess.active, 0)
        self.assertTrue(sess.active_target["name"].startswith("lib0.so"))

    def test_use_switches_active_target_by_index(self):
        ui = FakeUI()
        sess = r2.R2Session(self.targets, str(self.root / "out"),
                            LogManager(), ui)
        self.assertTrue(sess.use("2"))
        self.assertEqual(sess.active, 1)

    def test_use_switches_by_name_substring(self):
        ui = FakeUI()
        sess = r2.R2Session(self.targets, str(self.root / "out"),
                            LogManager(), ui)
        self.assertTrue(sess.use("lib1"))
        self.assertEqual(sess.active, 1)

    def test_use_returns_false_for_unknown(self):
        ui = FakeUI()
        sess = r2.R2Session(self.targets, str(self.root / "out"),
                            LogManager(), ui)
        self.assertFalse(sess.use("nonexistent"))

    def test_handle_builtin_targets_lists_all(self):
        ui = FakeUI()
        sess = r2.R2Session(self.targets, str(self.root / "out"),
                            LogManager(), ui)
        result = sess.handle_builtin("!targets")
        self.assertEqual(result, "handled")
        joined = "\n".join(ui.printed)
        self.assertIn("lib0.so", joined)
        self.assertIn("lib1.so", joined)

    def test_handle_builtin_set_adds_env_cmd(self):
        ui = FakeUI()
        sess = r2.R2Session(self.targets, str(self.root / "out"),
                            LogManager(), ui)
        sess.handle_builtin("!set e asm.bytes=true")
        self.assertIn("e asm.bytes=true", sess.env_cmds)

    def test_handle_builtin_unset_removes_env_cmd(self):
        ui = FakeUI()
        sess = r2.R2Session(self.targets, str(self.root / "out"),
                            LogManager(), ui)
        sess.handle_builtin("!set e asm.bytes=true")
        sess.handle_builtin("!unset e asm.bytes=true")
        self.assertNotIn("e asm.bytes=true", sess.env_cmds)

    def test_handle_builtin_rw_on_creates_backup(self):
        ui = FakeUI()
        sess = r2.R2Session(self.targets, str(self.root / "out"),
                            LogManager(), ui)
        sess.handle_builtin("!rw on")
        self.assertTrue(sess.rw)
        backup = self.targets[0]["path"] + ".elitf.bak"
        self.assertTrue(os.path.exists(backup))

    def test_handle_builtin_quit_returns_quit(self):
        ui = FakeUI()
        sess = r2.R2Session(self.targets, str(self.root / "out"),
                            LogManager(), ui)
        self.assertEqual(sess.handle_builtin("q"), "quit")
        self.assertEqual(sess.handle_builtin("quit"), "quit")
        self.assertEqual(sess.handle_builtin("exit"), "quit")

    def test_compose_r2_command_with_addr(self):
        entry = r2._cat("pdf", "disasm func", [("addr", "Adresse", "")])
        cmd = r2._compose_r2_command(entry, ["sym.main"])
        self.assertEqual(cmd, "pdf @ sym.main")

    def test_compose_r2_command_with_value(self):
        entry = r2._cat("px", "hexdump", [("count", "N", "64")])
        cmd = r2._compose_r2_command(entry, ["128"])
        self.assertEqual(cmd, "px 128")

    def test_compose_r2_command_with_raw_template(self):
        entry = r2._cat("", "filter strings",
                        [("motif", "Motif", "")], raw="izz~{0}")
        cmd = r2._compose_r2_command(entry, ["password"])
        self.assertEqual(cmd, "izz~password")


if __name__ == "__main__":
    unittest.main()
