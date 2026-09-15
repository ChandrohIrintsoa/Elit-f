
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf
import elitf_r2 as r2
from dartvm_fetch_build import DartLibInfo
from elitf_ui import LogManager


def _make_input(root, libapp_path=None, outdir=None):
    info = DartLibInfo('3.4.2', 'android', 'arm64', True, 'a' * 32)
    return elitf.ElitfInput(libapp_path or str(root / 'libapp.so'), info,
                            outdir or str(root / 'out'), False, False)


def _fake_dart_headers(root):
    """Crée des headers Dart VM factices et retourne le patcher PKG_INC_DIR."""
    vm = root / 'dartvm3.4.2' / 'vm'
    vm.mkdir(parents=True, exist_ok=True)
    for name in ('class_id.h', 'class_table.h', 'stub_code_list.h',
                 'object_store.h', 'object.h', 'thread.h'):
        (vm / name).write_text(' ')  # contenu vide : aucun macro de compat
    return patch.object(elitf, 'PKG_INC_DIR', str(root))


class SubprocessDecodingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_build_and_run_captures_with_errors_replace(self):
        obj = _make_input(self.root)
        os.makedirs(elitf.BIN_DIR, exist_ok=True)
        with open(obj.bin_file, 'w') as f:
            f.write('#!/bin/sh\n')
        fake = subprocess.CompletedProcess([], 0, 'null-safety: off\n', '')
        with patch.object(elitf, 'subprocess') as sp:
            sp.run.return_value = fake
            elitf.build_and_run(obj, LogManager())
            sp.run.assert_called_once()
            self.assertEqual(sp.run.call_args.kwargs.get('errors'), 'replace')
            self.assertTrue(sp.run.call_args.kwargs.get('text'))

    def test_cmake_elitf_captures_with_errors_replace(self):
        obj = _make_input(self.root)
        fake = subprocess.CompletedProcess([], 0, '', '')
        with _fake_dart_headers(self.root), patch.object(elitf, 'ensure_native_deps'), \
                patch.object(elitf, 'subprocess') as sp:
            sp.run.return_value = fake
            elitf.cmake_elitf(obj, LogManager())
            self.assertEqual(sp.run.call_count, 3)  # configure + ninja + install
            for call in sp.run.call_args_list:
                self.assertEqual(call.kwargs.get('errors'), 'replace',
                                 f"subprocess sans errors='replace': {call}")

    def test_run_command_captures_with_errors_replace(self):
        with patch.object(elitf, 'subprocess') as sp:
            sp.run.return_value = subprocess.CompletedProcess([], 0, '', '')
            elitf.run_command(['git', 'status'])
            self.assertEqual(sp.run.call_args.kwargs.get('errors'), 'replace')

    def test_vs_sln_dbg_cmd_quotes_paths(self):
        obj = _make_input(self.root, libapp_path=str(self.root / 'dir with space' / 'libapp.so'),
                          outdir=str(self.root / 'out space'))
        os.makedirs(obj.outdir, exist_ok=True)
        with _fake_dart_headers(self.root), patch.object(elitf, 'subprocess') as sp, \
                patch.dict(os.environ, {'VSCMD_VER': '17.9'}):
            sp.run.return_value = subprocess.CompletedProcess([], 0, '', '')
            elitf.cmake_vs_sln(obj, LogManager())
        dbg_arg = next(a for a in sp.run.call_args.args[0] if 'DBG_CMD' in a)
        self.assertIn(f'-i "{obj.libapp_path}"', dbg_arg)
        self.assertIn('-o "', dbg_arg)


class R2WriteModeBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / 'libapp.so'
        self.target.write_bytes(b'ELF-PAYLOAD')
        self.targets = [{'name': self.target.name, 'path': str(self.target)}]

    def tearDown(self):
        self.temp.cleanup()

    def _run_write_mode(self):
        class FakeUI:
            console = None
            prompts = iter(['0x1234', '00bf'])

            def _print(self, *a, **k):
                pass

            def _prompt_text(self, prompt, default=''):
                return next(self.prompts)

        with patch.object(r2, '_find_r2', return_value='/fake/r2'), \
                patch.object(r2.subprocess, 'run',
                             return_value=subprocess.CompletedProcess([], 0, '', '')):
            return r2._r2_write_mode(self.targets, str(self.root / 'out'),
                                     LogManager(), FakeUI(), 'wx')

    def test_patch_creates_backup(self):
        self._run_write_mode()
        backup = Path(str(self.target) + '.elitf.bak')
        self.assertTrue(backup.exists())
        self.assertEqual(backup.read_bytes(), b'ELF-PAYLOAD')

    def test_second_patch_reuses_existing_backup(self):
        self._run_write_mode()
        backup = Path(str(self.target) + '.elitf.bak')
        backup.write_bytes(b'ORIGINAL-PRISTINE')
        # Ne doit pas lever : le backup existant est conservé, le patch s'applique
        self._run_write_mode()
        self.assertEqual(backup.read_bytes(), b'ORIGINAL-PRISTINE')
        self.assertEqual(self.target.read_bytes(), b'ELF-PAYLOAD')

    def test_backup_helper_preserves_content(self):
        backup = r2._ensure_backup(str(self.target))
        self.assertEqual(Path(backup).read_bytes(), b'ELF-PAYLOAD')
        Path(backup).write_bytes(b'KEEP-ME')
        self.assertEqual(r2._ensure_backup(str(self.target)), backup)
        self.assertEqual(Path(backup).read_bytes(), b'KEEP-ME')


class PrepareSoTargetsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ui = elitf.ElitfUI(force_plain=True)
        self.ui.console = None

    def tearDown(self):
        self.temp.cleanup()

    def test_single_so_file_accepted(self):
        so = self.root / 'libapp.so'
        so.write_bytes(b'ELF')
        targets = elitf.prepare_so_targets(str(so), str(self.root / 'out'), self.ui)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]['name'], 'libapp.so')
        self.assertEqual(targets[0]['path'], str(so))

    def test_zip_extraction_is_idempotent(self):
        apk = self.root / 'app.apk'
        with zipfile.ZipFile(apk, 'w') as z:
            z.writestr('lib/arm64-v8a/libapp.so', b'ELF-app')
            z.writestr('lib/arm64-v8a/libflutter.so', b'ELF-flutter')
        out = self.root / 'out'
        calls = []
        real_extract = elitf._safe_zip_extract

        def counting(zf, member, out_dir):
            calls.append(member)
            return real_extract(zf, member, out_dir)

        with patch.object(elitf, '_safe_zip_extract', side_effect=counting):
            first = elitf.prepare_so_targets(str(apk), str(out), self.ui)
            self.assertEqual(len(calls), 2)
            calls.clear()
            second = elitf.prepare_so_targets(str(apk), str(out), self.ui)
            self.assertEqual(calls, [], 'le zip a été ré-extrait (non idempotent)')
        self.assertEqual(first, second)
        self.assertEqual(len(first), 2)


if __name__ == '__main__':
    unittest.main()
