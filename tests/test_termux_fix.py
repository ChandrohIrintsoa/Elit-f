
"""Tests Termux : fetch Dart SDK robuste (retries git + fallback archive)
et affichage Live adapté aux petits écrans (pas d'inondation de frames).

Contexte : sur Termux avec un réseau mobile instable, `git sparse-checkout
set` échouait (exit 128) sans aucun message exploitable, et le layout Live
de hauteur fixe (26 lignes) débordait de l'écran → le bandeau se réimprimait
à l'infini. Ces tests verrouillent les deux correctifs.
"""

import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dartvm_fetch_build as dfb
from dartvm_fetch_build import DartLibInfo
from elitf_ui import ElitfUI


def _proc(rc, out='', err=''):
    return subprocess.CompletedProcess(['git'], rc, stdout=out, stderr=err)


class GitRetryTests(unittest.TestCase):
    """_git : capture stderr + tentatives automatiques."""

    def setUp(self):
        self.fake_info = DartLibInfo('3.10.7', 'android', 'arm64')

    def test_git_retry_then_success(self):
        with patch.object(dfb, 'subprocess') as sp, \
             patch.object(dfb.time, 'sleep') as slp:
            sp.run.side_effect = [_proc(128, err='fatal: réseau down'),
                                  _proc(128, err='fatal: encore'),
                                  _proc(0)]
            proc = dfb._git(['sparse-checkout', 'set', 'runtime'],
                            attempts=3, delay=0)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(sp.run.call_count, 3)
        self.assertEqual(slp.call_count, 2)  # pause entre tentatives

    def test_git_error_contains_stderr(self):
        with patch.object(dfb, 'subprocess') as sp, \
             patch.object(dfb.time, 'sleep'):
            sp.run.return_value = _proc(
                128, err='fatal: could not read from remote repository')
            with self.assertRaises(RuntimeError) as ctx:
                dfb._git(['fetch'], attempts=2, delay=0)
        msg = str(ctx.exception)
        self.assertIn('could not read from remote repository', msg)
        self.assertIn('attempt 2/2', msg)

    def test_git_missing_binary_no_retry(self):
        with patch.object(dfb, 'subprocess') as sp:
            sp.run.side_effect = FileNotFoundError('git')
            with self.assertRaises(FileNotFoundError):
                dfb._git(['status'], attempts=5, delay=0)
        self.assertEqual(sp.run.call_count, 1)  # binaire absent : pas de retry

    def test_git_clone_sparse_uses_retries_and_paths(self):
        with patch.object(dfb, '_git') as g:
            dfb._git_clone_sparse(self.fake_info, '/tmp/nope')
        self.assertEqual(g.call_count, 2)
        clone_args = g.call_args_list[0].args[0]
        self.assertIn('clone', clone_args)
        self.assertIn('--sparse', clone_args)
        self.assertIn('--filter=blob:none', clone_args)
        sparse_args = g.call_args_list[1].args[0]
        self.assertEqual(sparse_args[0], 'sparse-checkout')
        for p in dfb.SPARSE_PATHS:
            self.assertIn(p, sparse_args)
        self.assertGreaterEqual(g.call_args_list[1].kwargs.get('attempts', 0), 3)


class TarballFallbackTests(unittest.TestCase):
    """Plan B sans git : archive du tag + extraction sélective."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.info = DartLibInfo('3.10.7', 'android', 'arm64')

    def tearDown(self):
        self.temp.cleanup()

    def _make_sdk_tarball(self, dest):
        base = self.root / 'sdk-3.10.7'
        for rel in ('runtime/vm/version_in.cc', 'runtime/vm/os_android.cc',
                    'tools/utils.py', 'third_party/double-conversion/src/props.cc',
                    'README.md', 'docs/index.md'):
            p = base / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('// fake\n')
        with tarfile.open(dest, 'w:gz') as tf:
            tf.add(base, arcname='sdk-3.10.7')

    def test_tarball_checkout_extracts_only_needed_dirs(self):
        archive = self.root / 'dart-sdk-3.10.7.tar.gz'
        self._make_sdk_tarball(str(archive))
        clonedir = self.root / 'v3.10.7'
        with patch.object(dfb, 'SDK_DIR', str(self.root)), \
             patch.object(dfb, '_download_tarball') as dl:
            dfb._tarball_checkout(self.info, str(clonedir))
            dl.assert_not_called()  # archive déjà en cache
        self.assertTrue((clonedir / 'runtime' / 'vm' / 'version_in.cc').is_file())
        self.assertTrue((clonedir / 'tools' / 'utils.py').is_file())
        self.assertTrue((clonedir / 'third_party' / 'double-conversion'
                         / 'src' / 'props.cc').is_file())
        self.assertFalse((clonedir / 'README.md').exists())
        self.assertFalse((clonedir / 'docs').exists())

    def test_tarball_checkout_rejects_empty_archive(self):
        archive = self.root / 'dart-sdk-3.10.7.tar.gz'
        empty = self.root / 'sdk-empty'
        empty.mkdir()
        (empty / 'README').write_text('x')
        with tarfile.open(str(archive), 'w:gz') as tf:
            tf.add(empty, arcname='sdk-3.10.7')
        clonedir = self.root / 'v3.10.7'
        with patch.object(dfb, 'SDK_DIR', str(self.root)):
            with self.assertRaises(RuntimeError) as ctx:
                dfb._tarball_checkout(self.info, str(clonedir))
        self.assertIn('unreadable or empty', str(ctx.exception))

    def test_download_resumes_and_finalises(self):
        payload = os.urandom(4096)
        src = self.root / 'src.tar.gz'
        src.write_bytes(payload)
        dest = self.root / 'out.tar.gz'
        # `.part` existant : le serveur sans support Range répond 200 →
        # le téléchargement repart de zéro mais aboutit quand même.
        (self.root / 'out.tar.gz.part').write_bytes(b'stale')
        with patch.object(dfb.time, 'sleep'):
            dfb._download_with_urllib('file://' + str(src), str(dest), attempts=2)
        self.assertEqual(dest.read_bytes(), payload)
        self.assertFalse(Path(str(dest) + '.part').exists())

    def test_checkout_dart_falls_back_to_tarball_when_git_dies(self):
        clonedir = self.root / ('v' + self.info.version + self.info.variant_suffix)

        def fake_tarball(info, cdir, log=None, on_progress=None):
            # un fichier top-level serait supprimé par le nettoyage de
            # checkout_dart (comportement voulu) → marqueur dans runtime/
            os.makedirs(os.path.join(cdir, 'runtime'), exist_ok=True)
            (Path(cdir) / 'runtime' / 'flag').write_text('tarball')

        with patch.object(dfb, 'SDK_DIR', str(self.root)), \
             patch.object(dfb, '_git_clone_sparse',
                          side_effect=RuntimeError('git sparse-checkout: exit 128')), \
             patch.object(dfb, '_tarball_checkout', side_effect=fake_tarball) as tb, \
             patch.object(dfb.subprocess, 'run') as sp:
            sp.return_value = _proc(0)
            out = dfb.checkout_dart(self.info)
        self.assertEqual(out, str(clonedir))
        tb.assert_called_once()
        self.assertEqual((clonedir / 'runtime' / 'flag').read_text(), 'tarball')
        # make_version a bien été enchaîné après l'extraction
        self.assertTrue(sp.called)

    def test_checkout_dart_reports_both_failures(self):
        with patch.object(dfb, 'SDK_DIR', str(self.root)), \
             patch.object(dfb, '_git_clone_sparse',
                          side_effect=RuntimeError('git: exit 128')), \
             patch.object(dfb, '_tarball_checkout',
                          side_effect=RuntimeError('Download failed')):
            with self.assertRaises(RuntimeError) as ctx:
                dfb.checkout_dart(self.info)
        msg = str(ctx.exception)
        self.assertIn('git: exit 128', msg)
        self.assertIn('Download failed', msg)
        self.assertIn('ELITF_DART_SDK_GIT', msg)


class CapturedBuildTests(unittest.TestCase):
    """cmake/ninja capturés quand un log est fourni (écran Live protégé)."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.info = DartLibInfo('3.10.7', 'android', 'arm64')

    def tearDown(self):
        self.temp.cleanup()

    def test_cmake_dart_with_log_captures_output(self):
        messages = []
        with patch.object(dfb, 'BUILD_DIR', str(self.root / 'build')), \
             patch.object(dfb, 'CMAKE_TEMPLATE_FILE', str(self.root / 'tpl')), \
             patch.object(dfb, 'CREATE_SRCLIST_FILE', str(self.root / 'srclist')), \
             patch.object(dfb, '_run_ninja_build') as nj, \
             patch.object(dfb.subprocess, 'run') as sp:
            sp.return_value = _proc(0)
            # le template n'existe pas : cmake_dart écrit lui-même
            # CMakeLists.txt ; on évite la copie icu_compat absente
            (self.root / 'tpl').write_text('VERSION_PLACE_HOLDER')
            (self.root / 'target').mkdir()
            with patch.object(dfb.shutil, 'copy2'):
                dfb.cmake_dart(self.info, str(self.root / 'target'),
                               log=messages.append,
                               on_progress=lambda d, t, p: None)
        self.assertTrue(messages)  # jalons émis via le panneau de logs
        for call in sp.call_args_list:
            self.assertTrue(call.kwargs.get('capture_output'),
                            'sans log fourni en UI, la sortie doit être capturée')
        descs = ' | '.join(messages)
        self.assertIn('CMake', descs)
        # ninja n'est plus capturé mais STREAMÉ (progression [N/M] réelle) :
        # il ne doit jamais passer par subprocess.run brut, et reçoit log+progress
        nj.assert_called_once()
        self.assertEqual(nj.call_args.kwargs.get('log'), messages.append)
        self.assertIsNotNone(nj.call_args.kwargs.get('on_progress'))
        for call in sp.call_args_list:
            self.assertFalse(isinstance(call.args[0], list) and
                             'ninja' in call.args[0],
                             'ninja ne doit pas être relancé via subprocess.run')

    def test_cmake_dart_without_log_keeps_direct_output(self):
        with patch.object(dfb, 'BUILD_DIR', str(self.root / 'build')), \
             patch.object(dfb, 'CMAKE_TEMPLATE_FILE', str(self.root / 'tpl')), \
             patch.object(dfb, 'CREATE_SRCLIST_FILE', str(self.root / 'srclist')), \
             patch.object(dfb.subprocess, 'run') as sp:
            sp.return_value = _proc(0)
            (self.root / 'tpl').write_text('x')
            (self.root / 'target').mkdir()
            with patch.object(dfb.shutil, 'copy2'):
                dfb.cmake_dart(self.info, str(self.root / 'target'))
        for call in sp.call_args_list:
            self.assertFalse(call.kwargs.get('capture_output', False))

    def test_run_captured_checked_includes_stderr(self):
        with patch.object(dfb.subprocess, 'run') as sp:
            sp.side_effect = subprocess.CalledProcessError(
                1, ['ninja'], stderr='FAILED: foo.cc clang++ error')
            with self.assertRaises(RuntimeError) as ctx:
                dfb._run_captured_checked(['ninja'], log=lambda m: None,
                                          desc='Compilation')
        self.assertIn('FAILED: foo.cc', str(ctx.exception))

    def test_fetch_and_build_propagates_log(self):
        messages = []
        with patch.object(dfb, 'check_build_tools'), \
             patch.object(dfb, 'checkout_dart') as co, \
             patch.object(dfb, 'cmake_dart') as cm:
            co.return_value = '/tmp/checkout'
            dfb.fetch_and_build(self.info, log=messages.append)
        self.assertEqual(co.call_args.kwargs.get('log'), messages.append)
        self.assertEqual(cm.call_args.kwargs.get('log'), messages.append)

    def test_emit_routes_to_log_when_present(self):
        sink = []
        dfb._emit(sink.append, 'via log')
        self.assertEqual(sink, ['via log'])


class LiveLayoutTests(unittest.TestCase):
    """Le layout Live doit tenir dans l'écran (pas d'inondation Termux)."""

    def test_small_termux_screen(self):
        h_h, p_h, logs_h, desc_w, bar_w = ElitfUI._live_layout_sizes(40, 24)
        self.assertEqual((h_h, p_h), (3, 5))
        self.assertLessEqual(h_h + p_h + logs_h, 24 - 1)
        self.assertGreaterEqual(desc_w, 8)
        self.assertGreaterEqual(bar_w, 6)
        self.assertLessEqual(desc_w + bar_w, 40 - 20)

    def test_desktop_screen_keeps_original_dimensions(self):
        _, _, logs_h, desc_w, bar_w = ElitfUI._live_layout_sizes(120, 40)
        self.assertEqual((logs_h, desc_w, bar_w), (18, 40, 30))

    def test_very_small_screen_stays_bounded(self):
        _, _, logs_h, desc_w, bar_w = ElitfUI._live_layout_sizes(24, 12)
        self.assertGreaterEqual(logs_h, 4)
        self.assertGreaterEqual(desc_w, 8)
        self.assertGreaterEqual(bar_w, 6)

    def test_garbage_size_falls_back_to_safe_bounds(self):
        _, _, logs_h, desc_w, bar_w = ElitfUI._live_layout_sizes(None, None)
        self.assertGreaterEqual(logs_h, 4)
        self.assertGreaterEqual(desc_w, 8)
        self.assertGreaterEqual(bar_w, 6)


class LiveLogTailTests(unittest.TestCase):
    """Le panneau Live doit montrer les messages les plus RÉCENTS."""

    def test_get_rich_text_shows_tail(self):
        from elitf_ui import LogManager
        mgr = LogManager(200)
        for i in range(40):
            mgr.add(f"message {i:02d}", "info")
        text = mgr.get_rich_text().plain
        self.assertIn('message 39', text)   # le plus récent : visible
        self.assertIn('message 24', text)   # les ~16 derniers : visibles
        self.assertNotIn('message 00', text)  # les vieux : écartés


class RunLiveRoutingTests(unittest.TestCase):
    """Hors TTY, _run_live doit déléguer à _run_plain (jamais de Live)."""

    def _make_ui(self):
        ui = ElitfUI.__new__(ElitfUI)
        ui.force_plain = False
        ui.log_mgr = MagicMock()
        ui.log_mgr.step_count = 0
        return ui

    def test_non_terminal_console_uses_plain_mode(self):
        from rich.console import Console
        ui = self._make_ui()
        buf = io.StringIO()
        ui.console = Console(file=buf, force_terminal=False, width=100)
        ui._run_plain = MagicMock(return_value='PLAIN')
        # NOTE : _run_live reste la vraie méthode — c'est justement sa garde
        # is_terminal qui doit déléguer vers _run_plain.
        res = ui.run_with_live_display('Titre', 3, lambda lm: None)
        self.assertEqual(res, 'PLAIN')
        ui._run_plain.assert_called_once()

    def test_terminal_console_keeps_live_mode(self):
        from rich.console import Console
        ui = self._make_ui()
        ui.console = Console(file=io.StringIO(), force_terminal=True,
                             width=100, height=30)
        ui._run_plain = MagicMock(return_value='PLAIN')
        ui._run_live = MagicMock(return_value='LIVE')
        res = ui.run_with_live_display('Titre', 3, lambda lm: None)
        self.assertEqual(res, 'LIVE')
        ui._run_plain.assert_not_called()

    def test_run_live_completes_on_forced_terminal(self):
        from rich.console import Console
        ui = self._make_ui()
        ui.console = Console(file=io.StringIO(), force_terminal=True,
                             width=56, height=24)
        ui.log_mgr.get_rich_text = MagicMock(return_value='')

        def work(log_mgr):
            log_mgr.step_count = 2
            return 'OK'

        res = ui._run_live('Analyse Termux', 2, work)
        self.assertEqual(res, 'OK')


if __name__ == '__main__':
    unittest.main()
