# -*- coding: utf-8 -*-
"""Termux : progression réelle pendant le fetch/build du Dart VM.

Bug observé (captures 22:55) : la barre reste à 0% pendant TOUTE la
compilation ninja (30 min–2 h sur mobile) car la sortie est capturée sans
aucun jalon, et ninja démarre avec -j<ncores> → OOM kill possible sur
mobile, qui ressemble à un blocage infini.

Ces tests imposent :
  1. un runner streaming qui traduit les lignes `[N/M]` de ninja en progrès ;
  2. un parallélisme borné par la mémoire disponible (ELITF_NINJA_JOBS) ;
  3. des jalons pendant le téléchargement de l'archive Dart SDK ;
  4. le câblage on_progress -> barre rich (sous-progression monotone) ;
  5. un avertissement de durée sur Termux avant la première compilation.
"""
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import dartvm_fetch_build as dfb  # noqa: E402
import elitf  # noqa: E402
from elitf_ui import ElitfUI, LogManager  # noqa: E402
from dartvm_fetch_build import DartLibInfo  # noqa: E402


class NinjaStreamingTests(unittest.TestCase):
    def test_parse_ninja_line(self):
        self.assertEqual(dfb._parse_ninja_line(
            '[123/2467] Building CXX object runtime/vm/foo.cc.o'), (123, 2467))
        self.assertEqual(dfb._parse_ninja_line('[  5/  2467] x'), (5, 2467))
        self.assertIsNone(dfb._parse_ninja_line('nothing here'))
        self.assertIsNone(dfb._parse_ninja_line(''))

    def test_run_streaming_reports_progress(self):
        calls = []
        cmd = [sys.executable, '-c',
               "print('[1/3] a', flush=True);"
               "print('[2/3] b', flush=True);"
               "print('[3/3] c', flush=True)"]
        dfb._run_streaming(cmd, on_progress=lambda d, t, p: calls.append((d, t, p)))
        self.assertEqual(calls, [(1, 3, 'compile'), (2, 3, 'compile'), (3, 3, 'compile')])

    def test_run_streaming_emits_milestone_logs(self):
        logs = []
        cmd = [sys.executable, '-c',
               "print('[1/2] a', flush=True);"
               "print('[2/2] b', flush=True)"]
        dfb._run_streaming(cmd, log=logs.append, min_interval=0.0,
                           desc='Compiling Dart VM (ninja)…')
        joined = '\n'.join(logs)
        self.assertIn('[2/2]', joined)
        self.assertIn('100%', joined)
        # le message de phase est bien passé par le logger (jamais brut sur le tty)
        self.assertTrue(any('Compiling Dart VM' in m for m in logs))

    def test_run_streaming_throttles_logs(self):
        logs = []
        lines = ';'.join(f"print('[{i}/200] x', flush=True)" for i in range(1, 201))
        cmd = [sys.executable, '-c', lines]
        dfb._run_streaming(cmd, log=logs.append, min_interval=60.0)
        milestone_logs = [m for m in logs if '[' in m and '/200]' in m]
        # 200 lignes en quelques ms : le bridage temporel doit tout réduire
        self.assertLessEqual(len(milestone_logs), 3)

    def test_run_streaming_failure_raises_with_tail(self):
        cmd = [sys.executable, '-c',
               "import sys;"
               "print('[1/2] ok', flush=True);"
               "print('FAILED: runtime/vm/foo.cc.o', flush=True);"
               "print('error: something bad', flush=True);"
               "sys.exit(2)"]
        with self.assertRaises(RuntimeError) as ctx:
            dfb._run_streaming(cmd, desc='Compiling')
        msg = str(ctx.exception)
        self.assertIn('exit 2', msg)
        self.assertIn('FAILED', msg)
        self.assertIn('something bad', msg)

    def test_run_streaming_without_progress_lines(self):
        calls = []
        cmd = [sys.executable, '-c', "print('hello', flush=True)"]
        dfb._run_streaming(cmd, on_progress=lambda *a: calls.append(a))
        self.assertEqual(calls, [])


class ParallelJobsTests(unittest.TestCase):
    def tearDown(self):
        os.environ.pop('ELITF_NINJA_JOBS', None)

    def test_env_override_wins(self):
        os.environ['ELITF_NINJA_JOBS'] = '3'
        self.assertEqual(dfb.safe_parallel_jobs(mem_bytes=1 << 30, cpu_count=8), 3)

    def test_env_zero_invalid_falls_back(self):
        os.environ['ELITF_NINJA_JOBS'] = 'abc'
        self.assertGreaterEqual(dfb.safe_parallel_jobs(mem_bytes=1 << 30, cpu_count=8), 1)

    def test_small_memory_single_job(self):
        # 3,5 Go dispo -> ~2 Go par unité clang -> 1 seul job
        self.assertEqual(dfb.safe_parallel_jobs(mem_bytes=int(3.5 * (1 << 30)), cpu_count=8), 1)

    def test_large_memory_capped_by_cpu(self):
        self.assertEqual(dfb.safe_parallel_jobs(mem_bytes=64 * (1 << 30), cpu_count=16), 16)

    def test_never_exceeds_cpu(self):
        self.assertEqual(dfb.safe_parallel_jobs(mem_bytes=64 * (1 << 30), cpu_count=2), 2)

    def test_unknown_memory_sane_default(self):
        self.assertGreaterEqual(dfb.safe_parallel_jobs(mem_bytes=None, cpu_count=12), 1)
        self.assertLessEqual(dfb.safe_parallel_jobs(mem_bytes=None, cpu_count=12), 4)


class RunNinjaBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.argv_file = os.path.join(self.tmp, 'argv.txt')
        self.fake_ninja = os.path.join(self.tmp, 'fake_ninja.py')
        with open(self.fake_ninja, 'w') as f:
            f.write(
                "import json, sys\n"
                "open(%r, 'w').write(json.dumps(sys.argv))\n"
                "print('[5/9] Building CXX object x.cc.o', flush=True)\n"
                % self.argv_file
            )
        self._old = dfb.NINJA_CMD
        dfb.NINJA_CMD = sys.executable

    def tearDown(self):
        dfb.NINJA_CMD = self._old

    def test_ninja_command_embeds_memory_bound_jobs(self):
        cmd = dfb._ninja_command()
        self.assertEqual(cmd[0], dfb.NINJA_CMD)
        self.assertIn('-j', cmd)
        self.assertEqual(cmd[cmd.index('-j') + 1],
                         str(dfb.safe_parallel_jobs()))

    def test_streaming_mode_uses_dash_j_and_progress(self):
        import json
        logs = []
        calls = []
        # le faux ninja est invoqué via [sys.executable, fake_ninja]
        with mock.patch.object(dfb, '_ninja_command',
                               return_value=[sys.executable, self.fake_ninja]):
            dfb._run_ninja_build(self.tmp, log=logs.append,
                                 on_progress=lambda d, t, p: calls.append((d, t, p)))
        with open(self.argv_file) as f:
            json.load(f)  # le binaire ninja a bien été exécuté
        self.assertEqual(calls[-1], (5, 9, 'compile'))

    def test_direct_mode_runs_without_log(self):
        with mock.patch.object(dfb, '_ninja_command',
                               return_value=[sys.executable, self.fake_ninja]):
            proc = dfb._run_ninja_build(self.tmp, log=None, on_progress=None)
        self.assertEqual(proc.returncode, 0)


class FetchBuildSignatureTests(unittest.TestCase):
    def setUp(self):
        self.info = DartLibInfo('3.10.7', 'android', 'arm64')

    def test_fetch_and_build_passes_callbacks(self):
        seen = {}
        with mock.patch.object(dfb, 'check_build_tools', lambda: None), \
             mock.patch.object(dfb, 'checkout_dart',
                               lambda info, log=None, on_progress=None:
                               seen.update(log=log, on_progress=on_progress) or 'dir'), \
             mock.patch.object(dfb, 'cmake_dart',
                               lambda info, d, log=None, on_progress=None: None):
            dfb.fetch_and_build(self.info, log='L', on_progress='P')
        self.assertEqual(seen['log'], 'L')
        self.assertEqual(seen['on_progress'], 'P')

    def test_cmake_dart_emits_configure_phase_and_streams_ninja(self):
        logs = []
        calls = []
        ninja_kwargs = {}
        fake_proc = SimpleNamespace(stdout='', stderr='', returncode=0)
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(dfb, '_run_captured_checked',
                                   lambda *a, **k: fake_proc), \
                 mock.patch.object(dfb, '_run_ninja_build',
                                   lambda d, log=None, on_progress=None:
                                   ninja_kwargs.update(on_progress=on_progress, log=log)), \
                 mock.patch.object(dfb, 'CREATE_SRCLIST_FILE', os.path.join(tmp, 'x.py')):
                dfb.cmake_dart(self.info, tmp, log=logs.append,
                               on_progress=lambda d, t, p: calls.append((d, t, p)))
        self.assertIsNotNone(ninja_kwargs['on_progress'])
        self.assertIn(('0', '1', 'configure'), [(str(d), str(t), p) for d, t, p in calls])


class DownloadMilestoneTests(unittest.TestCase):
    def test_download_milestones_logged_and_progress(self):
        MB = 1 << 20
        chunks = [b'x' * MB for _ in range(3)] + [b'']

        class FakeResp:
            status = 200
            headers = {'Content-Length': str(3 * (1 << 20))}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return chunks.pop(0) if chunks else b''

        logs = []
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, 'sdk.tar.gz')
            with mock.patch.object(dfb.urllib.request, 'urlopen',
                                   lambda req, timeout: FakeResp()):
                dfb._download_with_urllib('http://x/y', dest, log=logs.append,
                                          on_progress=lambda d, t, p: calls.append((d, t, p)),
                                          min_interval=0.0)
            self.assertTrue(os.path.isfile(dest))
        joined = '\n'.join(logs)
        self.assertIn('Downloaded', joined)
        self.assertTrue(any(abs(d - 3 * MB) < 2 and p == 'download' for d, t, p in calls),
                        calls)
        # le total Content-Length est bien propagé
        self.assertTrue(any(t == 3 * MB for d, t, p in calls), calls)


class ProgressWiringTests(unittest.TestCase):
    def test_logmanager_sub_progress_roundtrip(self):
        lm = LogManager()
        self.assertEqual(lm.get_sub_progress(), (0.0, ''))
        lm.set_sub_progress(1.5, 'Compilation…')
        self.assertEqual(lm.get_sub_progress(), (1.5, 'Compilation…'))
        lm.set_sub_progress(None)
        self.assertEqual(lm.get_sub_progress(), (0.0, ''))

    def test_logmanager_clear_resets_sub_progress(self):
        lm = LogManager()
        lm.set_sub_progress(2.0, 'x')
        lm.clear()
        self.assertEqual(lm.get_sub_progress(), (0.0, ''))

    def test_combined_completed_monotonic(self):
        f = ElitfUI._combined_completed
        self.assertEqual(f(1, 1.5, 20, last=0.0), 1.5)
        # le step() réel rattrape : jamais de retour en arrière
        self.assertEqual(f(2, 0.0, 20, last=1.5), 2.0)
        # borné par steps
        self.assertEqual(f(50, 0.0, 20, last=0.0), 20)
        self.assertEqual(f(0, 0.0, 20, last=0.0), 0)

    def test_compact_progress_label_keeps_counter(self):
        f = ElitfUI.compact_progress_label
        # tient déjà : intact
        self.assertEqual(f('Compilation Dart VM… [17/40]', 40),
                         'Compilation Dart VM… [17/40]')
        # étroit : le compteur [N/M] doit survivre
        out = f('Compilation Dart VM… [17/40]', 15)
        self.assertLessEqual(len(out), 15)
        self.assertIn('[17/40]', out)
        # très étroit : suffixe parenthèse conservé si possible
        out = f('Téléchargement sources Dart… (12.3 Mo)', 15)
        self.assertLessEqual(len(out), 15)
        self.assertIn('12.3 Mo', out)
        # extrême : au minimum une troncature propre
        out = f('Compilation Dart VM… [17/40]', 8)
        self.assertLessEqual(len(out), 8)
        self.assertTrue(out.endswith('…'))
        self.assertEqual(f('', 10), '')
        self.assertEqual(f('x', 0), '')

    def test_phase_handler_labels_and_fraction(self):
        lm = LogManager()
        handler = elitf._make_dartvm_progress(lm, base=1.0)
        handler(1200, 2400, 'compile')
        frac, label = lm.get_sub_progress()
        self.assertTrue(label.startswith('Compilation'))
        self.assertIn('[1200/2400]', label)
        self.assertGreater(frac, 1.0)
        self.assertLessEqual(frac, 1.0 + 2.9 + 1e-9)
        handler(5 << 20, 0, 'download')
        _, label = lm.get_sub_progress()
        self.assertIn('Téléchargement', label)
        self.assertIn('Mo', label)
        handler(0, 1, 'configure')
        _, label = lm.get_sub_progress()
        self.assertIn('Configuration', label)
        handler(0, 0, 'install')
        _, label = lm.get_sub_progress()
        self.assertIn('Installation', label)

    def _make_input(self, bin_dir=None, pkg_dir=None):
        with tempfile.TemporaryDirectory() as tmp:
            libapp = os.path.join(tmp, 'libapp.so')
            open(libapp, 'w').close()
            info = DartLibInfo('3.10.7', 'android', 'arm64')
            with mock.patch.object(elitf, 'BIN_DIR',
                                   bin_dir or elitf.BIN_DIR), \
                 mock.patch.object(elitf, 'PKG_LIB_DIR',
                                   pkg_dir or elitf.PKG_LIB_DIR):
                return elitf.ElitfInput(libapp, info, os.path.join(tmp, 'out'),
                                        rebuild=False, no_analysis=True)

    def test_build_and_run_wires_on_progress(self):
        bin_dir = tempfile.mkdtemp()
        pkg_dir = tempfile.mkdtemp()
        inp = self._make_input(bin_dir=bin_dir, pkg_dir=pkg_dir)
        lm = LogManager()
        seen = {}

        def fake_fetch(info, log=None, on_progress=None):
            seen['on_progress'] = on_progress
            seen['log'] = log
            if on_progress:
                on_progress(10, 100, 'compile')

        def fake_cmake(i, lmgr=None):
            open(inp.bin_file, 'w').close()

        real_fetch = dfb.fetch_and_build
        real_cmake = elitf.cmake_elitf
        real_run = elitf.subprocess.run
        try:
            dfb.fetch_and_build = fake_fetch
            elitf.cmake_elitf = fake_cmake
            elitf.subprocess.run = lambda *a, **k: SimpleNamespace(
                stdout='', stderr='', returncode=0)
            elitf.build_and_run(inp, lm)
        finally:
            dfb.fetch_and_build = real_fetch
            elitf.cmake_elitf = real_cmake
            elitf.subprocess.run = real_run

        self.assertIsNotNone(seen['on_progress'])
        self.assertIsNotNone(seen['log'])
        frac, label = lm.get_sub_progress()
        # après la fin du fetch, la sous-progression est remise à zéro
        self.assertEqual(frac, 0.0)
        msgs = [m for _, m, _ in lm.logs]
        self.assertTrue(any('built successfully' in m for m in msgs), msgs)

    def test_build_and_run_warns_duration_on_termux(self):
        bin_dir = tempfile.mkdtemp()
        pkg_dir = tempfile.mkdtemp()
        inp = self._make_input(bin_dir=bin_dir, pkg_dir=pkg_dir)
        lm = LogManager()

        def fake_fetch(info, log=None, on_progress=None):
            if on_progress:
                on_progress(10, 100, 'compile')

        def fake_cmake(i, lmgr=None):
            open(inp.bin_file, 'w').close()

        old_env = os.environ.get('TERMUX_VERSION')
        real_fetch = dfb.fetch_and_build
        real_cmake = elitf.cmake_elitf
        real_run = elitf.subprocess.run
        try:
            os.environ['TERMUX_VERSION'] = '0.118'
            dfb.fetch_and_build = fake_fetch
            elitf.cmake_elitf = fake_cmake
            elitf.subprocess.run = lambda *a, **k: SimpleNamespace(
                stdout='', stderr='', returncode=0)
            elitf.build_and_run(inp, lm)
        finally:
            if old_env is None:
                os.environ.pop('TERMUX_VERSION', None)
            else:
                os.environ['TERMUX_VERSION'] = old_env
            dfb.fetch_and_build = real_fetch
            elitf.cmake_elitf = real_cmake
            elitf.subprocess.run = real_run

        warns = [m for _, m, lvl in lm.logs if lvl == 'warn']
        self.assertTrue(any('compilation' in m.lower() for m in warns), warns)


if __name__ == '__main__':
    unittest.main()
