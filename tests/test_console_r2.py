
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf
import elitf_r2 as r2
from elitf_ui import LogManager


class FakeUI:
    console = None

    def __init__(self, lines=()):
        self.lines = list(lines)
        self.printed = []

    def _print(self, *a, **k):
        self.printed.append(" ".join(str(x) for x in a))

    def r2_readline(self, prompt=""):
        if not self.lines:
            return None
        return self.lines.pop(0)

    def confirm(self, question, default=False):
        return default


def _make_session(root, lines=(), targets=None):
    if targets is None:
        so = root / 'libapp.so'
        so.write_bytes(b'ELF-PAYLOAD')
        targets = [{'name': 'libapp.so', 'path': str(so)}]
    ui = FakeUI(lines)
    return r2.R2Session(targets, str(root / 'out'), LogManager(), ui), ui


class R2SessionRunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_requires_ui_and_targets(self):
        with self.assertRaises(ValueError):
            r2.R2Session([{'name': 'x.so', 'path': '/x'}], '/tmp/out', None, None)

    def test_run_r2_composes_argv(self):
        session, _ = _make_session(self.root)
        session.r2_bin = '/fake/r2'
        fake = subprocess.CompletedProcess([], 0, 'afl output\n', '')
        with patch.object(r2.subprocess, 'run', return_value=fake) as sp:
            rc, out, err = session.run_r2('afl')
        self.assertEqual(rc, 0)
        self.assertIn('afl output', out)
        argv = sp.call_args.args[0]
        self.assertEqual(argv[0], '/fake/r2')
        self.assertNotIn('-w', argv)
        self.assertEqual(argv[-1], session.active_target['path'])
        self.assertEqual(argv[-2], 'afl')
        self.assertGreaterEqual(argv.count('-c'), 4)  # header + afl

    def test_run_r2_write_mode_adds_dash_w_and_backup(self):
        session, _ = _make_session(self.root)
        session.r2_bin = '/fake/r2'
        fake = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(r2.subprocess, 'run', return_value=fake):
            session.handle_builtin('!rw on')
            rc, _, _ = session.run_r2('wx 00bf @ 0x1000')
        self.assertEqual(rc, 0)
        self.assertTrue(session.rw)
        backup = Path(str(self.root / 'libapp.so') + '.elitf.bak')
        self.assertTrue(backup.exists())
        self.assertEqual(backup.read_bytes(), b'ELF-PAYLOAD')

    def test_analysis_replay(self):
        session, _ = _make_session(self.root)
        session.r2_bin = '/fake/r2'
        fake = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(r2.subprocess, 'run', return_value=fake) as sp:
            session.run_r2('aaa')
            self.assertEqual(session.analysis_cmds, ['aaa'])
            session.run_r2('pdf @ 0x1000')
            argv = sp.call_args.args[0]
            cmds = [argv[i + 1] for i, a in enumerate(argv) if a == '-c']
            self.assertIn('aaa', cmds)
            self.assertEqual(cmds[-1], 'pdf @ 0x1000')
            session.anal_replay = False
            session.run_r2('pd 10 @ 0x2000')
            new_argv = sp.call_args.args[0]
            cmds = [new_argv[i + 1] for i, a in enumerate(new_argv) if a == '-c']
            self.assertNotIn('aaa', cmds)

    def test_analysis_query_does_not_overwrite_replay(self):
        session, _ = _make_session(self.root)
        session.r2_bin = '/fake/r2'
        fake = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(r2.subprocess, 'run', return_value=fake):
            session.run_r2('aaa')
            session.run_r2('afl')
            self.assertEqual(session.analysis_cmds, ['aaa'])

    def test_run_r2_without_r2_binary(self):
        session, _ = _make_session(self.root)
        session.r2_bin = None
        rc, out, err = session.run_r2('afl')
        self.assertNotEqual(rc, 0)
        self.assertTrue(err)

    def test_use_switches_active_target(self):
        so1 = self.root / 'libapp.so'
        so2 = self.root / 'libflutter.so'
        so1.write_bytes(b'A')
        so2.write_bytes(b'B')
        session, _ = _make_session(self.root, targets=[
            {'name': 'libapp.so', 'path': str(so1)},
            {'name': 'libflutter.so', 'path': str(so2)}])
        self.assertEqual(session.active, 0)
        self.assertTrue(session.use('2'))
        self.assertEqual(session.active, 1)
        self.assertTrue(session.use('libapp'))
        self.assertEqual(session.active, 0)
        self.assertFalse(session.use('99'))

    def test_r2_readline_does_not_exist_on_ui(self):
        # FakeUI expose r2_readline; ElitfUI doit aussi l'exposer (contrat UI)
        from elitf_ui import ElitfUI
        self.assertTrue(hasattr(ElitfUI, 'r2_readline'))
        self.assertTrue(hasattr(ElitfUI, 'confirm'))


class R2SessionBuiltinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_quit_inputs(self):
        for line in ('q', 'quit', 'exit', '!q'):
            session, _ = _make_session(self.root)
            self.assertEqual(session.handle_builtin(line), 'quit')

    def test_non_builtin_passthrough(self):
        session, _ = _make_session(self.root)
        self.assertIsNone(session.handle_builtin('afl'))
        self.assertIsNone(session.handle_builtin('px 32 @ 0x1000'))

    def test_help_and_targets_are_handled(self):
        session, _ = _make_session(self.root)
        self.assertEqual(session.handle_builtin('!help'), 'handled')
        self.assertEqual(session.handle_builtin('!targets'), 'handled')

    def test_use_builtin(self):
        so2 = self.root / 'libflutter.so'
        so2.write_bytes(b'B')
        session, _ = _make_session(self.root, targets=[
            {'name': 'libapp.so', 'path': str(self.root / 'libapp.so')},
            {'name': 'libflutter.so', 'path': str(so2)}])
        self.assertEqual(session.handle_builtin('!use 2'), 'handled')
        self.assertEqual(session.active, 1)

    def test_anal_toggle(self):
        session, _ = _make_session(self.root)
        self.assertTrue(session.anal_replay)
        self.assertEqual(session.handle_builtin('!anal off'), 'handled')
        self.assertFalse(session.anal_replay)
        session.handle_builtin('!anal on')
        self.assertTrue(session.anal_replay)

    def test_set_unset_session_env(self):
        session, _ = _make_session(self.root)
        self.assertEqual(session.handle_builtin('!set e asm.bytes=true'), 'handled')
        self.assertEqual(session.env_cmds, ['e asm.bytes=true'])
        session.handle_builtin('!set e asm.bytes=true')  # pas de doublon
        self.assertEqual(len(session.env_cmds), 1)
        self.assertEqual(session.handle_builtin('!unset e asm.bytes=true'), 'handled')
        self.assertEqual(session.env_cmds, [])

    def test_rw_toggle_creates_backup(self):
        session, _ = _make_session(self.root)
        self.assertEqual(session.handle_builtin('!rw on'), 'handled')
        self.assertTrue(session.rw)
        self.assertTrue(Path(str(self.root / 'libapp.so') + '.elitf.bak').exists())
        self.assertEqual(session.handle_builtin('!rw off'), 'handled')
        self.assertFalse(session.rw)

    def test_lib_shows_active_path(self):
        session, ui = _make_session(self.root)
        self.assertEqual(session.handle_builtin('!lib'), 'handled')
        self.assertTrue(any(str(self.root / 'libapp.so') in p for p in ui.printed))

    def test_unknown_builtin_is_handled(self):
        session, _ = _make_session(self.root)
        self.assertEqual(session.handle_builtin('!inconnu'), 'handled')

    def test_empty_line_handled(self):
        session, _ = _make_session(self.root)
        self.assertEqual(session.handle_builtin(''), 'handled')


class PptoolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()
        os.environ.pop('ELITF_PPTOOL', None)

    def test_find_pptool_env_override(self):
        tool = self.root / 'pptool'
        tool.write_text('#!/bin/sh\n')
        with patch.dict(os.environ, {'ELITF_PPTOOL': str(tool)}):
            self.assertEqual(r2._find_pptool(), str(tool))

    def test_find_pptool_missing(self):
        with patch.dict(os.environ, {'ELITF_PPTOOL': ''}):
            with patch.object(r2.shutil, 'which', return_value=None):
                self.assertIsNone(r2._find_pptool())

    def test_run_pptool_passthrough_with_placeholders(self):
        session, _ = _make_session(self.root)
        session.pptool_bin = '/fake/pptool'
        fake = subprocess.CompletedProcess([], 0, 'PPTool output\n', '')
        with patch.object(r2.subprocess, 'run', return_value=fake) as sp:
            ok, text = session.run_pptool('-f {so}')
        self.assertTrue(ok)
        self.assertIn('PPTool output', text)
        argv = sp.call_args.args[0]
        self.assertEqual(argv, ['/fake/pptool', '-f', str(self.root / 'libapp.so')])

    def test_run_pptool_missing_reports_clearly(self):
        session, _ = _make_session(self.root)
        session.pptool_bin = None
        ok, text = session.run_pptool('-f x')
        self.assertFalse(ok)
        self.assertIn('pptool', text.lower())

    def test_terminal_routes_pptool_prefix(self):
        session, _ = _make_session(self.root, lines=['pptool -f {so}', 'q'])
        session.r2_bin = '/fake/r2'
        session.pptool_bin = '/fake/pptool'
        fake = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(r2.subprocess, 'run', return_value=fake) as sp:
            session.terminal()
        argvs = [c.args[0] for c in sp.call_args_list]
        self.assertEqual(argvs[-1], ['/fake/pptool', '-f', str(self.root / 'libapp.so')])


class TerminalLoopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_terminal_runs_r2_commands_then_quits(self):
        session, _ = _make_session(
            self.root, lines=['afl', '!use 1', 'px 32 @ 0x1000', 'q'])
        session.r2_bin = '/fake/r2'
        fake = subprocess.CompletedProcess([], 0, 'out\n', '')
        with patch.object(r2.subprocess, 'run', return_value=fake) as sp:
            session.terminal()
        self.assertEqual(sp.call_count, 2)

    def test_terminal_missing_r2_warns_and_returns(self):
        session, ui = _make_session(self.root, lines=['afl', 'q'])
        session.r2_bin = None
        session.terminal()
        self.assertTrue(any('r2' in p.lower() for p in ui.printed))

    def test_terminal_eof_quits(self):
        session, _ = _make_session(self.root, lines=[])
        session.r2_bin = '/fake/r2'
        with patch.object(r2.subprocess, 'run',
                          return_value=subprocess.CompletedProcess([], 0, '', '')) as sp:
            session.terminal()
        self.assertEqual(sp.run.call_count, 0)


class R2CatalogTests(unittest.TestCase):
    def test_catalog_structure_is_complete_and_safe(self):
        self.assertIsInstance(r2.R2_TERMINAL_CATALOG, dict)
        self.assertGreaterEqual(set(r2.R2_TERMINAL_CATALOG),
                                {'analyse', 'info', 'print', 'search',
                                 'xrefs', 'write', 'config'})
        for cat in r2.R2_TERMINAL_CATALOG.values():
            self.assertIn('title', cat)
            self.assertTrue(cat['commands'])
            for entry in cat['commands']:
                self.assertIn('desc', entry)
                cmd = entry.get('cmd', '')
                raw = entry.get('raw', '')
                self.assertTrue(cmd or raw, f'entrée sans commande: {entry}')
                self.assertFalse(cmd.startswith('!'), entry)
                self.assertNotIn(cmd, {'V', 'v', 'q', 'quit', 'exit'}, entry)
                for arg in entry.get('args') or []:
                    self.assertEqual(len(arg), 3, entry)
                    self.assertTrue(all(isinstance(x, str) for x in arg), entry)

    def test_compose_command_addr_and_count(self):
        entry = {'cmd': 'px', 'args': [('count', 'N', '64'), ('addr', 'A', '')]}
        self.assertEqual(r2._compose_r2_command(entry, ['64', '0x1000']),
                         'px 64 @ 0x1000')
        self.assertEqual(r2._compose_r2_command(entry, ['32', '']), 'px 32')

    def test_compose_command_raw_template(self):
        entry = {'raw': 'izz~{0}', 'args': [('motif', 'M', '')]}
        self.assertEqual(r2._compose_r2_command(entry, ['password']),
                         'izz~password')

    def test_write_entries_require_args(self):
        for entry in r2.R2_TERMINAL_CATALOG['write']['commands']:
            self.assertTrue(entry.get('args'), entry)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.out = self.root / 'out'
        (self.root / 'build' / 'sub').mkdir(parents=True)
        (self.root / 'build' / 'sub' / 'f.o').write_bytes(b'x' * 10)
        (self.root / 'bin').mkdir()
        (self.root / 'bin' / 'elitf_x').write_bytes(b'y' * 20)
        (self.root / 'packages').mkdir()
        (self.root / 'packages' / 'lib.a').write_bytes(b'z' * 5)
        (self.root / '__pycache__').mkdir()
        (self.root / '__pycache__' / 'm.cpython-312.pyc').write_bytes(b'p')
        (self.out / 'inputs' / 'abc').mkdir(parents=True)
        (self.out / 'inputs' / 'abc' / 'libapp.so').write_bytes(b'i' * 7)
        (self.out / 'r2_output').mkdir()
        (self.out / 'r2_output' / 'r.txt').write_bytes(b'r')

    def tearDown(self):
        self.temp.cleanup()

    def test_find_cleanup_targets_discovers_all_kinds(self):
        items = elitf.find_cleanup_targets(str(self.root), str(self.out))
        kinds = {i['kind'] for i in items}
        self.assertEqual(kinds, {'build', 'bin', 'packages', 'inputs',
                                 'r2_output', 'pycache'})
        for item in items:
            self.assertTrue(os.path.isdir(item['path']), item)
            self.assertGreater(item['size'], 0, item)

    def test_find_cleanup_targets_skips_missing(self):
        items = elitf.find_cleanup_targets(str(self.root), str(self.root / 'nope'))
        kinds = {i['kind'] for i in items}
        self.assertNotIn('inputs', kinds)
        self.assertNotIn('r2_output', kinds)

    def test_perform_cleanup_deletes_only_selected(self):
        items = elitf.find_cleanup_targets(str(self.root), str(self.out))
        by_kind = {i['kind']: i for i in items}
        picks = [items.index(by_kind['build']), items.index(by_kind['inputs'])]
        deleted, freed = elitf.perform_cleanup(str(self.root), str(self.out),
                                               items, picks)
        self.assertFalse((self.root / 'build').exists())
        self.assertFalse((self.out / 'inputs').exists())
        self.assertTrue((self.root / 'bin').exists())
        self.assertGreater(freed, 0)
        self.assertEqual(len(deleted), 2)

    def test_perform_cleanup_refuses_path_outside(self):
        evil = tempfile.mkdtemp()  # hors project_dir et outdir
        self.addCleanup(subprocess.run, ['rm', '-rf', evil])
        items = [{'kind': 'evil', 'label': 'pirate', 'path': evil, 'size': 1}]
        with self.assertRaises(ValueError):
            elitf.perform_cleanup(str(self.root), str(self.out), items, [0])
        self.assertTrue(os.path.isdir(evil))

    def test_perform_cleanup_never_project_root(self):
        items = [{'kind': 'root', 'label': 'racine', 'path': str(self.root),
                  'size': 0}]
        with self.assertRaises(ValueError):
            elitf.perform_cleanup(str(self.root), str(self.out), items, [0])
        self.assertTrue(self.root.exists())


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bin_dir = self.root / 'bin'
        self.bin_dir.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_install_launcher_writes_executables(self):
        paths = elitf.install_launcher(project_dir=str(self.root),
                                       bin_dir=str(self.bin_dir))
        self.assertEqual(len(paths), 2)
        names = {os.path.basename(p) for p in paths}
        self.assertEqual(names, {'Elit-f', 'elitf'})
        for p in paths:
            self.assertTrue(os.access(p, os.X_OK), p)
            content = Path(p).read_text()
            self.assertIn(str(self.root), content)
            self.assertIn('elitf.py', content)
            self.assertTrue(content.startswith('#!'), p)

    def test_install_launcher_is_idempotent(self):
        elitf.install_launcher(project_dir=str(self.root), bin_dir=str(self.bin_dir))
        target = self.bin_dir / 'Elit-f'
        target.write_text('OLD-CONTENT')
        elitf.install_launcher(project_dir=str(self.root), bin_dir=str(self.bin_dir))
        self.assertIn('elitf.py', target.read_text())

    def test_launcher_installed_detection(self):
        self.assertFalse(elitf.launcher_installed(bin_dir=str(self.bin_dir)))
        elitf.install_launcher(project_dir=str(self.root), bin_dir=str(self.bin_dir))
        self.assertTrue(elitf.launcher_installed(bin_dir=str(self.bin_dir)))


class InfoFlowTests(unittest.TestCase):
    def test_filter_selected_targets_updates_ui(self):
        class FakeTargetUI:
            detected_so = [{'name': 'a.so', 'path': '/a'},
                           {'name': 'b.so', 'path': '/b'},
                           {'name': 'c.so', 'path': '/c'}]
        ui = FakeTargetUI()
        result = elitf.filter_selected_targets(ui, [0, 2])
        self.assertEqual(len(ui.detected_so), 2)
        self.assertEqual([t['name'] for t in result], ['a.so', 'c.so'])

    def test_filter_selected_targets_empty_keeps_all(self):
        class FakeTargetUI:
            detected_so = [{'name': 'a.so', 'path': '/a'}]
        ui = FakeTargetUI()
        elitf.filter_selected_targets(ui, [])
        self.assertEqual(len(ui.detected_so), 1)


if __name__ == '__main__':
    unittest.main()
