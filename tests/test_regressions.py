import concurrent.futures
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf
import elitf_r2 as r2
import extract_dart_info as extract
from dartvm_fetch_build import DartLibInfo


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def pair(self, folder):
        folder.mkdir(parents=True, exist_ok=True)
        for name in elitf.EXPECTED_LIBS:
            (folder / name).write_bytes(b'test')
        return tuple(str(folder / name) for name in elitf.EXPECTED_LIBS)

    def targets(self):
        files = [self.root/'a'/'libsame.so', self.root/'b'/'libsame.so']
        for f in files:
            f.parent.mkdir(exist_ok=True)
            f.write_bytes(b'ELF')
        return [{'name': f.name, 'path': str(f)} for f in files]

    def test_pair_direct(self):
        expected = self.pair(self.root)
        self.assertEqual(elitf.validate_two_libs(str(self.root)), expected)

    def test_pair_recursive(self):
        expected = self.pair(self.root/'nested')
        self.assertEqual(elitf.validate_two_libs(str(self.root)), expected)

    def test_pair_does_not_mix_abis(self):
        (self.root/'a').mkdir()
        (self.root/'b').mkdir()
        (self.root/'a/libapp.so').touch()
        (self.root/'b/libflutter.so').touch()
        with self.assertRaises(ValueError):
            elitf.validate_two_libs(str(self.root))

    def test_pair_ambiguous(self):
        self.pair(self.root/'a')
        self.pair(self.root/'b')
        with self.assertRaises(ValueError):
            elitf.validate_two_libs(str(self.root))

    def test_empty_search(self):
        path = self.root/'empty'
        path.touch()
        self.assertFalse(elitf._search_in_file(path, b'x'))

    def test_zip_traversal(self):
        with zipfile.ZipFile(io.BytesIO(), 'w') as z:
            z.writestr('../escape', 'bad')
            with self.assertRaises(ValueError):
                elitf._safe_zip_extract(z, '../escape', str(self.root))

    def test_apk_prefers_supported_64_bit(self):
        apk = self.root/'app.APK'
        with zipfile.ZipFile(apk, 'w') as z:
            for abi in ('armeabi-v7a', 'x86_64'):
                for name in elitf.EXPECTED_LIBS:
                    z.writestr(f'lib/{abi}/{name}', abi)
        paths = elitf.extract_libs_from_apk(str(apk), str(self.root/'out'))
        self.assertTrue(all('x86_64' in p for p in paths))

    def test_zip_symlink_escape(self):
        inside = self.root/'inside'
        outside = self.root/'outside'
        inside.mkdir()
        outside.mkdir()
        (inside/'link').symlink_to(outside, target_is_directory=True)
        with zipfile.ZipFile(io.BytesIO(), 'w') as z:
            z.writestr('link/escape', 'bad')
            with self.assertRaises(ValueError):
                elitf._safe_zip_extract(z, 'link/escape', str(inside))
        self.assertFalse((outside/'escape').exists())

    def test_cli_apk_generate_integration(self):
        apk = self.root/'input.APK'
        with zipfile.ZipFile(apk, 'w') as z:
            z.writestr('lib/arm64-v8a/libtest.so', b'ELF')
        out = self.root/'out space'
        result = subprocess.run([sys.executable, elitf.__file__, str(apk), str(out),
                                 '--action', 'r2', '--generate-only', '--nu'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(list((out/'inputs').rglob('libtest.so')))
        self.assertTrue(list((out/'r2_output').glob('*.r2')))

    def test_disassembly_script_contains_disassembly(self):
        r2.generate_r2_scripts(self.targets(), str(self.root/'out'))
        for path in (self.root/'out').rglob('*_disasm.r2'):
            self.assertIn('pdr @@f', path.read_text())

    def test_version_validation(self):
        for version in (None, '', '../main', '3.4', '3.4.2;cmd'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                DartLibInfo(version, 'android', 'arm64')

    def test_cache_exact_version(self):
        one = DartLibInfo('3.4.1', 'android', 'arm64')
        two = DartLibInfo('3.4.2', 'android', 'arm64')
        self.assertNotEqual(one.lib_name, two.lib_name)
        self.assertEqual(two.version, '3.4.2')

    def test_cache_variants(self):
        names = {DartLibInfo('3.4.2', 'android', 'arm64', compressed, snap).lib_name
                 for compressed in (True, False) for snap in ('a'*32, 'b'*32)}
        self.assertEqual(len(names), 4)

    def test_old_dart_no_analysis(self):
        info = DartLibInfo('2.14.0', 'android', 'arm64')
        self.assertTrue(elitf.ElitfInput('app', info, 'out', False, False).no_analysis)

    def test_x64_no_arm_analyzer(self):
        info = DartLibInfo('3.4.2', 'android', 'x64')
        with self.assertRaisesRegex(ValueError, 'ARM64'):
            elitf.ElitfInput('app', info, 'out', False, False)

    def test_windows_executable_suffix(self):
        with patch.object(sys, 'platform', 'win32'):
            info = DartLibInfo('3.4.2', 'android', 'arm64')
            obj = elitf.ElitfInput('app', info, 'out', False, False)
        self.assertTrue(obj.bin_file.endswith('.exe'))

    def test_cli_no_prompt(self):
        with patch.object(elitf, 'check_dependencies', return_value=[]), patch.object(elitf, 'run_flutter_analysis') as run, patch('builtins.input', side_effect=AssertionError('prompt')):
            self.assertEqual(elitf.main_cli('input', str(self.root), False, False), 0)
            run.assert_called_once()

    def test_cli_error_status(self):
        with patch.object(elitf, 'check_dependencies', return_value=[]), patch.object(elitf, 'run_flutter_analysis', side_effect=ValueError('bad input')):
            self.assertEqual(elitf.main_cli('input', str(self.root), False, False), 1)

    def test_r2_duplicate_names_and_spaces(self):
        scripts = r2.run_r2_custom(self.targets(), str(self.root/'out space'), 'aa', ['functions'], execute=False)
        self.assertEqual(len(set(scripts)), 2)
        for path in scripts:
            content = Path(path).read_text()
            self.assertIn('aflj > "', content)
            self.assertNotIn('__OUTDIR__', content)
            self.assertNotIn('\x00', content)
        for path in (self.root/'out space').rglob('*.sh'):
            subprocess.run(['bash', '-n', str(path)], check=True)

    def test_r2_all_blocks_no_nuls(self):
        content = r2._build_r2_script('all_anal', list(r2.R2_EXTRACTION_BLOCKS))
        self.assertNotIn('\x00', content)
        self.assertIn('icj >', content)

    def test_r2_unknown_block_rejected(self):
        with self.assertRaises(ValueError):
            r2._build_r2_script('aa', ['missing'])

    def test_r2_worker_limits(self):
        for value, expected in [('1', 1), ('2', 2), ('100', 3)]:
            with patch.dict(os.environ, {'R2_BATCH_JOBS': value}):
                self.assertEqual(r2._r2_max_workers(3), expected)
        for value in ('0', '-1', 'bad'):
            with patch.dict(os.environ, {'R2_TIMEOUT': value}):
                self.assertEqual(r2._timeout(), 600)

    def test_r2_parallel_and_failure_propagation(self):
        barrier = threading.Barrier(2)
        def work(*args):
            barrier.wait(timeout=3)
            return False
        with patch.dict(os.environ, {'R2_BATCH_JOBS': '2'}), patch.object(r2, '_find_r2', return_value='r2'), patch.object(r2, '_run_single_r2', side_effect=work):
            with self.assertRaises(RuntimeError):
                r2.run_r2_custom(self.targets(), str(self.root/'out'), 'aa', ['strings'])

    def test_r2_timeout(self):
        with patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired('r2', 1)):
            self.assertFalse(r2._run_single_r2('r2', 'script', 'file', 1, None, 'target'))

    def test_r2_error_with_zero_exit(self):
        result = subprocess.CompletedProcess([], 0, '', 'ERROR: bad command')
        with patch.object(subprocess, 'run', return_value=result):
            self.assertFalse(r2._run_single_r2('r2', 'script', 'file', 1, None, 'target'))

    def test_batch_real_shell_failure_and_retry(self):
        fake = self.root/'r2'
        fake.write_text('#!/bin/sh\nexit "${FAKE_EXIT:-0}"\n')
        fake.chmod(0o755)
        scripts = r2.generate_r2_scripts(self.targets(), str(self.root/'out space'))
        batch = self.root/'out space/r2_analyze_all.sh'
        env = {**os.environ, 'PATH': str(self.root)+os.pathsep+os.environ['PATH'], 'FAKE_EXIT': '1'}
        failed = subprocess.run(['bash', str(batch)], env=env, capture_output=True)
        self.assertEqual(failed.returncode, 1)
        env['FAKE_EXIT'] = '0'
        good = subprocess.run(['bash', str(batch)], env=env, capture_output=True)
        self.assertEqual(good.returncode, 0, good.stderr)

    def test_sdk_prefix_truncated(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value = response
        response.status_code = 206
        response.iter_content.return_value = [b'PK\x03\x04'+b'\x00'*40]
        with patch.object(extract.requests, 'get', return_value=response):
            self.assertEqual(extract.get_dart_commit('https://example.test/sdk.zip'), (None, None))

    def test_sdk_prefix_metadata(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('dart-sdk/revision', 'a'*40)
            z.writestr('dart-sdk/version', '3.4.2')
        response = unittest.mock.MagicMock()
        response.__enter__.return_value = response
        response.status_code = 206
        response.iter_content.return_value = [buf.getvalue()]
        with patch.object(extract.requests, 'get', return_value=response):
            self.assertEqual(extract.get_dart_commit('https://example.test/sdk.zip'), ('a'*40, '3.4.2'))

    @unittest.skipUnless(shutil.which('gcc') and shutil.which('readelf'), 'requires gcc/readelf')
    def test_real_elf_snapshot_and_readelf(self):
        source = self.root/'sample.c'
        payload = b'\x00'*20 + b'a'*32 + b'product compressed-pointers\x00' + b'\x00'*128
        source.write_text('const unsigned char _kDartVmSnapshotData[] = {'+','.join(str(b) for b in payload)+'};\n')
        binary = self.root/'sample.so'
        subprocess.run(['gcc', '-shared', '-fPIC', str(source), '-o', str(binary)], check=True)
        self.assertEqual(extract.extract_snapshot_hash_flags(str(binary)), ('a'*32, ['product', 'compressed-pointers']))
        r2.display_binary_info([{'name':binary.name, 'path':str(binary)}], str(self.root/'out'))
        self.assertIn('ELF Header', (self.root/'out/binary_info.txt').read_text())

    def test_compat_header_detection(self):
        vm = self.root/'dartvm3.4.2/vm'
        vm.mkdir(parents=True)
        for name in ('class_id.h', 'class_table.h', 'stub_code_list.h', 'object_store.h', 'object.h', 'thread.h'):
            (vm/name).write_text(' ')
        (vm/'thread.h').write_text('old_marking_stack_block')
        with patch.object(elitf, 'PKG_INC_DIR', str(self.root)):
            self.assertIn('-DOLD_MARKING_STACK_BLOCK=1', elitf.find_compat_macro('3.4.2', False))
            (vm/'thread.h').write_text('marking_stack_block')
            self.assertNotIn('-DOLD_MARKING_STACK_BLOCK=1', elitf.find_compat_macro('3.4.2', False))


if __name__ == '__main__':
    unittest.main()
