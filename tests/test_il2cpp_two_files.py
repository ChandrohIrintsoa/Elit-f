
"""Tests du contrat « exactement 2 fichiers » du Il2CppDumper Elit-f (option [3]).

Comme l'original Il2CppDumper-Python (springmusk026) qui exige exactement
2 fichiers en entrée (libil2cpp.so + global-metadata.dat), le Il2CppDumper
adapté au kernel Elit-f impose le même contrat, transposé à Dart AOT :

  ENTRÉE  : exactement 2 fichiers — libapp.so (binaire Dart AOT)
            + libflutter.so (moteur Flutter = métadonnées de version)
  SORTIE  : exactement 2 fichiers — dump.dart + script.json
            (les littéraux de chaînes restent intégrés dans les deux)
"""

import io
import json
import zipfile
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf_dumper as dumper


class ContractConstantsTests(unittest.TestCase):
    def test_contract_constants(self):
        # Entrée : le même pair que le kernel Elit-f (EXPECTED_LIBS)
        self.assertEqual(dumper.IL2CPP_INPUT_FILES,
                         ('libapp.so', 'libflutter.so'))
        # Sortie : exactement 2 fichiers
        self.assertEqual(dumper.DUMP_FILES, ('dump.dart', 'script.json'))
        self.assertEqual(len(dumper.DUMP_FILES), 2)

    def test_two_files_error_message(self):
        msg = dumper.two_files_error_message("detail test")
        self.assertIn('exactement 2 fichiers', msg)
        self.assertIn('libapp.so', msg)
        self.assertIn('libflutter.so', msg)
        self.assertIn('detail test', msg)


class ResolveTwoFilesDirTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _pair(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'libapp.so').write_bytes(b'\x7fELF app')
        (directory / 'libflutter.so').write_bytes(b'\x7fELF flutter')

    def test_pair_at_root(self):
        self._pair(self.root)
        libapp, libflutter = dumper.resolve_two_files(str(self.root))
        self.assertEqual(Path(libapp).name, 'libapp.so')
        self.assertEqual(Path(libflutter).name, 'libflutter.so')
        self.assertTrue(Path(libapp).is_file())
        self.assertTrue(Path(libflutter).is_file())

    def test_pair_nested_in_abi_dir(self):
        self._pair(self.root / 'lib' / 'arm64-v8a')
        (self.root / 'assets').mkdir()
        (self.root / 'assets' / 'data.bin').write_bytes(b'x')
        libapp, libflutter = dumper.resolve_two_files(str(self.root))
        self.assertEqual(Path(libapp).name, 'libapp.so')
        self.assertEqual(Path(libflutter).name, 'libflutter.so')

    def test_extra_so_files_ignored(self):
        # D'autres .so peuvent exister : le contrat utilise exactement le pair
        self._pair(self.root)
        (self.root / 'libsqlite.so').write_bytes(b'\x7fELF other')
        libapp, libflutter = dumper.resolve_two_files(str(self.root))
        self.assertEqual(Path(libapp).name, 'libapp.so')
        self.assertEqual(Path(libflutter).name, 'libflutter.so')

    def test_missing_flutter_raises_contract_error(self):
        (self.root / 'libapp.so').write_bytes(b'\x7fELF app')
        with self.assertRaises(ValueError) as ctx:
            dumper.resolve_two_files(str(self.root))
        self.assertIn('exactement 2 fichiers', str(ctx.exception))
        self.assertIn('libflutter.so', str(ctx.exception))

    def test_empty_dir_raises_contract_error(self):
        with self.assertRaises(ValueError) as ctx:
            dumper.resolve_two_files(str(self.root))
        self.assertIn('exactement 2 fichiers', str(ctx.exception))

    def test_multiple_pairs_raises(self):
        self._pair(self.root / 'lib' / 'arm64-v8a')
        self._pair(self.root / 'lib' / 'x86_64')
        with self.assertRaises(ValueError) as ctx:
            dumper.resolve_two_files(str(self.root))
        self.assertIn('exactement 2 fichiers', str(ctx.exception))

    def test_missing_path_raises(self):
        with self.assertRaises(ValueError) as ctx:
            dumper.resolve_two_files(str(self.root / 'inexistant'))
        self.assertIn('exactement 2 fichiers', str(ctx.exception))


class ResolveTwoFilesApkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _write_apk(self, path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('classes.dex', b'dex')
            zf.writestr('lib/arm64-v8a/libapp.so', b'\x7fELF app')
            zf.writestr('lib/arm64-v8a/libflutter.so', b'\x7fELF flutter')
        path.write_bytes(buf.getvalue())

    def test_apk_extracts_exactly_the_pair(self):
        apk = self.root / 'app.apk'
        self._write_apk(apk)
        extract_dir = self.root / 'inputs'
        libapp, libflutter = dumper.resolve_two_files(
            str(apk), extract_dir=str(extract_dir))
        self.assertEqual(Path(libapp).name, 'libapp.so')
        self.assertEqual(Path(libflutter).name, 'libflutter.so')
        self.assertTrue(Path(libapp).is_file())
        self.assertTrue(Path(libflutter).is_file())

    def test_apk_without_pair_raises(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('classes.dex', b'dex')
        apk = self.root / 'app.apk'
        apk.write_bytes(buf.getvalue())
        with self.assertRaises(ValueError) as ctx:
            dumper.resolve_two_files(str(apk))
        self.assertIn('exactement 2 fichiers', str(ctx.exception))


class ResolveTwoFilesSiblingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_single_libapp_finds_sibling_flutter(self):
        (self.root / 'libapp.so').write_bytes(b'\x7fELF app')
        (self.root / 'libflutter.so').write_bytes(b'\x7fELF flutter')
        libapp, libflutter = dumper.resolve_two_files(
            str(self.root / 'libapp.so'))
        self.assertEqual(Path(libapp).name, 'libapp.so')
        self.assertEqual(Path(libflutter).name, 'libflutter.so')

    def test_single_libflutter_finds_sibling_app(self):
        (self.root / 'libapp.so').write_bytes(b'\x7fELF app')
        (self.root / 'libflutter.so').write_bytes(b'\x7fELF flutter')
        libapp, libflutter = dumper.resolve_two_files(
            str(self.root / 'libflutter.so'))
        self.assertEqual(Path(libapp).name, 'libapp.so')
        self.assertEqual(Path(libflutter).name, 'libflutter.so')

    def test_single_libapp_without_sibling_raises(self):
        (self.root / 'libapp.so').write_bytes(b'\x7fELF app')
        with self.assertRaises(ValueError) as ctx:
            dumper.resolve_two_files(str(self.root / 'libapp.so'))
        self.assertIn('exactement 2 fichiers', str(ctx.exception))
        self.assertIn('libflutter.so', str(ctx.exception))

    def test_single_unrelated_file_raises(self):
        other = self.root / 'libfoo.so'
        other.write_bytes(b'\x7fELF foo')
        with self.assertRaises(ValueError) as ctx:
            dumper.resolve_two_files(str(other))
        self.assertIn('exactement 2 fichiers', str(ctx.exception))


class ResolveTwoFilesContentFallbackTests(unittest.TestCase):
    """Détection par contenu (comme detect_files de l'original, par magic)."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_renamed_files_detected_by_content(self):
        app = self.root / 'binaire_app.so'
        app.write_bytes(b'\x7fELF' + b'_' * 64
                        + b'_kDartIsolateSnapshotInstructions\x00')
        flutter = self.root / 'moteur.so'
        flutter.write_bytes(b'\x7fELF Dart VM version: 3.10.7 (stable)\x00'
                            + b'a' * 40 + b'\x00')
        libapp, libflutter = dumper.resolve_two_files(str(self.root))
        self.assertEqual(Path(libapp), app)
        self.assertEqual(Path(libflutter), flutter)

    def test_content_detection_roles(self):
        app = self.root / 'x.so'
        # Le snapshot ISOLATE n'existe que dans libapp.so (libflutter.so peut
        # porter les symboles du snapshot VM → discriminateur Isolate)
        app.write_bytes(b'zz _kDartIsolateSnapshotData zz')
        flutter = self.root / 'y.so'
        flutter.write_bytes(b'zz Dart_VersionString zz')
        self.assertEqual(dumper.detect_role_by_content(str(app)), 'app')
        self.assertEqual(dumper.detect_role_by_content(str(flutter)),
                         'flutter')
        self.assertIsNone(dumper.detect_role_by_content(
            str(self.root / 'inexistant.so')))


class ExtractDumpMetaTests(unittest.TestCase):
    def test_meta_best_effort_on_fake_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'libapp.so').write_bytes(b'not an elf')
            (root / 'libflutter.so').write_bytes(b'not an elf')
            meta = dumper.extract_dump_meta(str(root / 'libapp.so'),
                                            str(root / 'libflutter.so'))
            self.assertEqual(meta['binary'], 'libapp.so')
            # Pas de crash, pas de réseau : le dump reste utilisable


class EnsureKernelContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.indir = self.root / 'in'
        self.indir.mkdir()
        (self.indir / 'libapp.so').write_bytes(b'\x7fELF app')
        (self.indir / 'libflutter.so').write_bytes(b'\x7fELF flutter')

    def tearDown(self):
        self.temp.cleanup()

    def _write_kernel_outputs(self, outdir):
        outdir = Path(outdir)
        (outdir / 'asm').mkdir(parents=True, exist_ok=True)
        (outdir / 'asm' / 'a.txt').write_text(
            "// lib: app, url: package:app/main.dart\n"
            "\n// class id: 2, size: 0x38\nclass :: {\n"
            "  void main() {\n    // ** addr: 0x390000, size: 0x40\n"
            "    0x390000: ret\n  }\n}\n", encoding='utf-8')
        (outdir / 'pp.txt').write_text(
            "pool heap offset: 0x1000\n[pp+0x8] String: 'hi'\n",
            encoding='utf-8')

    def test_ensure_kernel_outputs_resolves_two_files(self):
        outdir = self.root / 'out'
        with patch.object(dumper, 'run_flutter_analysis') as rfa:
            rfa.side_effect = lambda *a, **k: self._write_kernel_outputs(outdir)
            summary = dumper.ensure_kernel_outputs(
                str(self.indir), str(outdir), False, False, None, None, False)
            rfa.assert_called_once()
        self.assertEqual(summary['input_count'], 2)
        self.assertEqual(
            sorted(Path(p).name for p in summary['input_files']),
            ['libapp.so', 'libflutter.so'])
        # Contrat sortie : exactement 2 fichiers
        dump_dir = Path(summary['dump_dir'])
        self.assertEqual(sorted(p.name for p in dump_dir.iterdir()),
                         ['dump.dart', 'script.json'])

    def test_ensure_kernel_outputs_contract_violation(self):
        empty = self.root / 'empty'
        empty.mkdir()
        with patch.object(dumper, 'run_flutter_analysis') as rfa:
            with self.assertRaises(ValueError) as ctx:
                dumper.ensure_kernel_outputs(
                    str(empty), str(self.root / 'out2'), False, False,
                    None, None, False)
            self.assertIn('exactement 2 fichiers', str(ctx.exception))
            rfa.assert_not_called()


class GenerateAllTwoFilesTests(unittest.TestCase):
    """Le dossier du dump ne doit contenir QUE dump.dart + script.json."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'asm').mkdir(parents=True)
        (self.root / 'asm' / 'a.txt').write_text(
            "// lib: app, url: package:app/main.dart\n"
            "\n// class id: 2, size: 0x38\nclass :: {\n"
            "  void main() {\n    // ** addr: 0x390000, size: 0x40\n"
            "    0x390000: ret\n  }\n}\n", encoding='utf-8')
        (self.root / 'pp.txt').write_text(
            "pool heap offset: 0x1000\n[pp+0x8] String: 'hi'\n",
            encoding='utf-8')

    def tearDown(self):
        self.temp.cleanup()

    def test_exactly_two_files_generated(self):
        summary = dumper.generate_all(str(self.root))
        dump_dir = Path(summary['dump_dir'])
        self.assertEqual(sorted(p.name for p in dump_dir.iterdir()),
                         ['dump.dart', 'script.json'])
        self.assertEqual(
            [Path(f).name for f in summary['files']],
            ['dump.dart', 'script.json'])
        # Les littéraux restent intégrés dans les 2 fichiers
        dart_text = (dump_dir / 'dump.dart').read_text(encoding='utf-8')
        self.assertIn('StringLiteral', dart_text)
        raw = json.loads((dump_dir / 'script.json').read_text(
            encoding='utf-8'))
        self.assertIn('ScriptString', raw)
        self.assertIn('ScriptMethod', raw)

    def test_legacy_files_from_previous_runs_purged(self):
        dump_dir = self.root / 'il2cpp_dump'
        dump_dir.mkdir()
        for legacy in ('stringliteral.json', 'ida_elitf_dumper.py',
                       'ghidra_elitf_dumper.py', 'ida_dart_struct.h'):
            (dump_dir / legacy).write_text('old', encoding='utf-8')
        summary = dumper.generate_all(str(self.root))
        remaining = sorted(p.name for p in Path(summary['dump_dir']).iterdir())
        self.assertEqual(remaining, ['dump.dart', 'script.json'])


if __name__ == '__main__':
    unittest.main()
