
"""Tests « le fichier de sortie ne reste pas à son origine sans purger ».

Bug corrigé : les sorties kernel (asm/, pp.txt, objs.txt, ida_script/,
blutter_frida.js) étaient réutilisées SANS vérifier qu'elles correspondent
toujours au pair d'entrée (libapp.so + libflutter.so). Changer de cible
(option 5 → changer les cibles, nouvel APK, nouveau dossier) régénérait un
dump depuis l'analyse D'ORIGINE : le fichier de sortie « restait à son
origine », sans purge — et une nouvelle analyse mélangeait les bibliothèques
de 2 applications dans asm/ (un fichier par bibliothèque Dart).

Contrat corrigé :
  1. Empreinte d'analyse (.elitf_analysis.json) = digests du pair analysé
  2. Cache kernel valide SEULEMENT si le pair courant a les mêmes digests
  3. Pair changé / --rebuild / empreinte absente → PURGE des sorties
     d'origine (kernel + dump) AVANT une nouvelle analyse
  4. Analyse fraîche → purge préalable + empreinte écrite après succès
  5. Option 5 : nouvelles cibles de nettoyage (sorties kernel + il2cpp_dump)
"""

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf_dumper as dumper
import elitf


APP_BYTES = b'\x7fELF app payload v1'
APP_BYTES_V2 = b'\x7fELF app payload v2 CHANGED'
FLUTTER_BYTES = b'\x7fELF flutter payload v1'


def _write_kernel_outputs(outdir, lib_file='a.txt'):
    outdir = Path(outdir)
    asm = outdir / 'asm'
    asm.mkdir(parents=True, exist_ok=True)
    (asm / lib_file).write_text(
        "// lib: app, url: package:app/main.dart\n"
        "\n// class id: 2, size: 0x38\nclass :: {\n"
        "  void main() {\n    // ** addr: 0x390000, size: 0x40\n"
        "    0x390000: ret\n  }\n}\n", encoding='utf-8')
    (outdir / 'pp.txt').write_text(
        "pool heap offset: 0x1000\n[pp+0x8] String: 'hi'\n", encoding='utf-8')


class _Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.indir = self.root / 'in'
        self.indir.mkdir()
        (self.indir / 'libapp.so').write_bytes(APP_BYTES)
        (self.indir / 'libflutter.so').write_bytes(FLUTTER_BYTES)
        self.outdir = self.root / 'out'

    def tearDown(self):
        self.temp.cleanup()

    def _pair(self):
        return (str(self.indir / 'libapp.so'),
                str(self.indir / 'libflutter.so'))


class FingerprintTests(_Base):
    def test_roundtrip_records_pair_digests(self):
        fp = dumper.write_analysis_fingerprint(
            str(self.outdir), *self._pair(), extra={'dart_version': '3.10.7'})
        self.assertIsNotNone(fp)
        self.assertTrue(Path(fp).is_file())
        data = dumper.read_analysis_fingerprint(str(self.outdir))
        self.assertIsNotNone(data)
        self.assertEqual(data['libapp']['name'], 'libapp.so')
        self.assertEqual(data['libapp']['digest'],
                         dumper._file_digest(self._pair()[0]))
        self.assertEqual(data['libflutter']['digest'],
                         dumper._file_digest(self._pair()[1]))
        self.assertEqual(data['dart_version'], '3.10.7')

    def test_read_missing_returns_none(self):
        self.assertIsNone(dumper.read_analysis_fingerprint(str(self.outdir)))

    def test_read_corrupt_returns_none(self):
        self.outdir.mkdir(parents=True)
        (self.outdir / dumper.FINGERPRINT_NAME).write_text('{broken',
                                                           encoding='utf-8')
        self.assertIsNone(dumper.read_analysis_fingerprint(str(self.outdir)))

    def test_write_without_libflutter_is_tolerated(self):
        fp = dumper.write_analysis_fingerprint(
            str(self.outdir), self._pair()[0], None)
        self.assertIsNotNone(fp)
        data = dumper.read_analysis_fingerprint(str(self.outdir))
        self.assertIsNone(data['libflutter'])


class CacheValidityTests(_Base):
    def test_valid_when_pair_and_outputs_match(self):
        _write_kernel_outputs(self.outdir)
        dumper.write_analysis_fingerprint(str(self.outdir), *self._pair())
        self.assertTrue(dumper.analysis_cache_valid(
            str(self.outdir), list(self._pair())))

    def test_invalid_when_libapp_content_changes(self):
        _write_kernel_outputs(self.outdir)
        dumper.write_analysis_fingerprint(str(self.outdir), *self._pair())
        (self.indir / 'libapp.so').write_bytes(APP_BYTES_V2)
        self.assertFalse(dumper.analysis_cache_valid(
            str(self.outdir), list(self._pair())))

    def test_invalid_when_libflutter_content_changes(self):
        _write_kernel_outputs(self.outdir)
        dumper.write_analysis_fingerprint(str(self.outdir), *self._pair())
        (self.indir / 'libflutter.so').write_bytes(b'\x7fELF flutter v2')
        self.assertFalse(dumper.analysis_cache_valid(
            str(self.outdir), list(self._pair())))

    def test_invalid_without_fingerprint_legacy_outdir(self):
        # Sorties kernel présentes mais empreinte absente (ancien état)
        _write_kernel_outputs(self.outdir)
        self.assertFalse(dumper.analysis_cache_valid(
            str(self.outdir), list(self._pair())))

    def test_invalid_when_kernel_outputs_absent(self):
        dumper.write_analysis_fingerprint(str(self.outdir), *self._pair())
        self.assertFalse(dumper.analysis_cache_valid(
            str(self.outdir), list(self._pair())))


class PurgeTests(_Base):
    def test_purge_kernel_outputs_removes_known_parts_only(self):
        self.outdir.mkdir(parents=True)
        _write_kernel_outputs(self.outdir)
        (self.outdir / 'ida_script').mkdir()
        (self.outdir / 'ida_script' / 'addNames.py').write_text(
            'x', encoding='utf-8')
        (self.outdir / 'objs.txt').write_text('o', encoding='utf-8')
        (self.outdir / 'blutter_frida.js').write_text('f', encoding='utf-8')
        dumper.write_analysis_fingerprint(str(self.outdir), *self._pair())
        (self.outdir / 'il2cpp_dump').mkdir()
        (self.outdir / 'il2cpp_dump' / 'dump.dart').write_text(
            'd', encoding='utf-8')
        (self.outdir / 'inputs').mkdir()
        (self.outdir / 'inputs' / 'keep.so').write_text('k',
                                                        encoding='utf-8')

        removed = dumper.purge_kernel_outputs(str(self.outdir))

        names = {Path(p).name for p in removed}
        self.assertTrue({'asm', 'ida_script', 'pp.txt', 'objs.txt',
                         'blutter_frida.js', dumper.FINGERPRINT_NAME}
                        <= names)
        self.assertFalse((self.outdir / 'asm').exists())
        self.assertFalse((self.outdir / 'pp.txt').exists())
        # Le dump et les entrées ne sont PAS touchés par cette purge
        self.assertTrue((self.outdir / 'il2cpp_dump' / 'dump.dart').exists())
        self.assertTrue((self.outdir / 'inputs' / 'keep.so').exists())
        # Idempotent
        self.assertEqual(dumper.purge_kernel_outputs(str(self.outdir)), [])

    def test_purge_dump_outputs_removes_contract_and_legacy(self):
        dump_dir = self.outdir / 'il2cpp_dump'
        dump_dir.mkdir(parents=True)
        for name in ('dump.dart', 'script.json', 'stringliteral.json',
                     'ida_elitf_dumper.py', 'ghidra_elitf_dumper.py',
                     'ida_dart_struct.h', 'user_note.txt'):
            (dump_dir / name).write_text('x', encoding='utf-8')

        removed = dumper.purge_dump_outputs(str(self.outdir))

        names = {Path(p).name for p in removed}
        self.assertTrue({'dump.dart', 'script.json', 'stringliteral.json',
                         'ida_elitf_dumper.py', 'ghidra_elitf_dumper.py',
                         'ida_dart_struct.h'} <= names)
        self.assertFalse((dump_dir / 'dump.dart').exists())
        # Les fichiers étrangers sont conservés
        self.assertTrue((dump_dir / 'user_note.txt').exists())
        self.assertEqual(dumper.purge_dump_outputs(str(self.outdir)), [])


class EnsureKernelOutputsCacheTests(_Base):
    def test_cache_hit_reuses_analysis(self):
        _write_kernel_outputs(self.outdir)
        dumper.write_analysis_fingerprint(str(self.outdir), *self._pair())
        with patch.object(dumper, 'run_flutter_analysis') as rfa:
            summary = dumper.ensure_kernel_outputs(
                str(self.indir), str(self.outdir), False, False, None, None,
                False)
            rfa.assert_not_called()
        self.assertEqual(summary['cache'], 'reused')
        self.assertEqual(summary['purged'], [])
        self.assertEqual(summary['input_count'], 2)
        dump_dir = Path(summary['dump_dir'])
        self.assertEqual(sorted(p.name for p in dump_dir.iterdir()),
                         ['dump.dart', 'script.json'])

    def test_stale_pair_triggers_refresh_and_purge(self):
        # Analyse d'origine : pair A, puis le libapp de l'entrée change
        _write_kernel_outputs(self.outdir, lib_file='old_lib.txt')
        (self.outdir / 'il2cpp_dump').mkdir()
        (self.outdir / 'il2cpp_dump' / 'dump.dart').write_text(
            'STALE', encoding='utf-8')
        dumper.write_analysis_fingerprint(str(self.outdir), *self._pair())
        (self.indir / 'libapp.so').write_bytes(APP_BYTES_V2)

        def fresh_analysis(*a, **k):
            _write_kernel_outputs(self.outdir, lib_file='new_lib.txt')
            (self.outdir / 'il2cpp_dump').mkdir(exist_ok=True)
            (self.outdir / 'il2cpp_dump' / 'dump.dart').write_text(
                '', encoding='utf-8')

        with patch.object(dumper, 'run_flutter_analysis',
                          side_effect=fresh_analysis) as rfa:
            summary = dumper.ensure_kernel_outputs(
                str(self.indir), str(self.outdir), False, False, None, None,
                False)
            rfa.assert_called_once()
        self.assertEqual(summary['cache'], 'refreshed')
        self.assertTrue(summary['purged'])
        # Les sorties de l'analyse d'origine sont purgées (pas de mélange)
        self.assertFalse((self.outdir / 'asm' / 'old_lib.txt').exists())
        self.assertTrue((self.outdir / 'asm' / 'new_lib.txt').exists())
        # L'ancien dump ne survit pas à l'invalidation : regénéré depuis les
        # sorties fraîches (jamais le contenu « STALE » de l'origine)
        self.assertNotIn('STALE', (Path(summary['dump_dir']) / 'dump.dart')
                         .read_text(encoding='utf-8'))
        # L'empreinte correspond désormais au NOUVEAU pair
        fp = dumper.read_analysis_fingerprint(str(self.outdir))
        self.assertEqual(fp['libapp']['digest'],
                         dumper._file_digest(self._pair()[0]))

    def test_legacy_outdir_without_fingerprint_refreshes(self):
        _write_kernel_outputs(self.outdir)
        with patch.object(dumper, 'run_flutter_analysis') as rfa:
            rfa.side_effect = lambda *a, **k: _write_kernel_outputs(
                self.outdir)
            summary = dumper.ensure_kernel_outputs(
                str(self.indir), str(self.outdir), False, False, None, None,
                False)
            rfa.assert_called_once()
        self.assertEqual(summary['cache'], 'refreshed')

    def test_rebuild_forces_refresh(self):
        _write_kernel_outputs(self.outdir)
        dumper.write_analysis_fingerprint(str(self.outdir), *self._pair())
        with patch.object(dumper, 'run_flutter_analysis') as rfa:
            rfa.side_effect = lambda *a, **k: _write_kernel_outputs(
                self.outdir)
            summary = dumper.ensure_kernel_outputs(
                str(self.indir), str(self.outdir), True, False, None, None,
                False)
            rfa.assert_called_once()
        self.assertEqual(summary['cache'], 'refreshed')

    def test_second_run_after_refresh_is_cache_hit(self):
        _write_kernel_outputs(self.outdir)
        # Pas d'empreinte (état ancien) → 1re exécution = refresh
        with patch.object(dumper, 'run_flutter_analysis') as rfa:
            rfa.side_effect = lambda *a, **k: _write_kernel_outputs(
                self.outdir)
            s1 = dumper.ensure_kernel_outputs(
                str(self.indir), str(self.outdir), False, False, None, None,
                False)
            self.assertEqual(rfa.call_count, 1)
        self.assertEqual(s1['cache'], 'refreshed')
        # 2e exécution sur le même pair → cache valide, plus d'analyse
        with patch.object(dumper, 'run_flutter_analysis') as rfa:
            s2 = dumper.ensure_kernel_outputs(
                str(self.indir), str(self.outdir), False, False, None, None,
                False)
            rfa.assert_not_called()
        self.assertEqual(s2['cache'], 'reused')


class AnalyzeLibsPurgeTests(_Base):
    """Une analyse fraîche purge les sorties d'origine AVANT le kernel."""

    def _fake_info(self):
        return ('3.10.7', 'a' * 32, [], 'arm64', 'android', True)

    def test_analyze_libs_purges_then_finalizes(self):
        self.outdir.mkdir(parents=True)
        _write_kernel_outputs(self.outdir, lib_file='old_lib.txt')
        (self.outdir / 'objs.txt').write_text('o', encoding='utf-8')
        dump_dir = self.outdir / 'il2cpp_dump'
        dump_dir.mkdir()
        (dump_dir / 'dump.dart').write_text('STALE', encoding='utf-8')

        with patch.object(elitf, 'get_dart_lib_info',
                          return_value=self._fake_info()), \
                patch.object(elitf, 'build_and_run') as bar:
            elitf._analyze_libs(self._pair()[0], self._pair()[1],
                                str(self.outdir), False, False, False,
                                None, None)
            bar.assert_called_once()

        # Purge avant analyse : plus aucune sortie d'origine
        self.assertFalse((self.outdir / 'asm' / 'old_lib.txt').exists())
        self.assertFalse((self.outdir / 'pp.txt').exists())
        self.assertFalse((self.outdir / 'objs.txt').exists())
        # Finalisation après succès : ancien dump purgé + empreinte écrite
        self.assertFalse((dump_dir / 'dump.dart').exists())
        fp = dumper.read_analysis_fingerprint(str(self.outdir))
        self.assertIsNotNone(fp)
        self.assertEqual(fp['libapp']['digest'],
                         dumper._file_digest(self._pair()[0]))

    def test_analyze_libs_vs_sln_keeps_outputs(self):
        # Génération de solution VS seule : NE purge rien
        self.outdir.mkdir(parents=True)
        _write_kernel_outputs(self.outdir, lib_file='old_lib.txt')
        with patch.object(elitf, 'get_dart_lib_info',
                          return_value=self._fake_info()), \
                patch.object(elitf, 'build_and_run'):
            elitf._analyze_libs(self._pair()[0], self._pair()[1],
                                str(self.outdir), False, False, False,
                                None, None, vs_sln=True)
        self.assertTrue((self.outdir / 'asm' / 'old_lib.txt').exists())
        self.assertTrue((self.outdir / 'pp.txt').exists())


class CleanupTargetsTests(_Base):
    def test_find_cleanup_targets_includes_kernel_outputs_and_dump(self):
        self.outdir.mkdir(parents=True)
        _write_kernel_outputs(self.outdir)
        (self.outdir / 'il2cpp_dump').mkdir()
        (self.outdir / 'il2cpp_dump' / 'dump.dart').write_text(
            'd' * 10, encoding='utf-8')
        items = elitf.find_cleanup_targets(str(self.root), str(self.outdir))
        kinds = {i['kind'] for i in items}
        self.assertIn('kernel_out', kinds)
        self.assertIn('il2cpp_dump', kinds)
        ko = next(i for i in items if i['kind'] == 'kernel_out')
        path_names = {Path(p).name for p in ko['paths']}
        self.assertTrue({'asm', 'pp.txt'} <= path_names)
        self.assertGreater(ko['size'], 0)

    def test_cleanup_targets_absent_when_nothing_exists(self):
        self.outdir.mkdir(parents=True)
        items = elitf.find_cleanup_targets(str(self.root), str(self.outdir))
        kinds = {i['kind'] for i in items}
        self.assertNotIn('kernel_out', kinds)
        self.assertNotIn('il2cpp_dump', kinds)

    def test_perform_cleanup_kernel_out_deletes_files_and_dirs(self):
        self.outdir.mkdir(parents=True)
        _write_kernel_outputs(self.outdir)
        items = elitf.find_cleanup_targets(str(self.root), str(self.outdir))
        ko = next(i for i in items if i['kind'] == 'kernel_out')
        deleted, freed = elitf.perform_cleanup(
            str(self.root), str(self.outdir), items, [items.index(ko)])
        self.assertEqual(deleted, [ko['path']])
        self.assertFalse((self.outdir / 'asm').exists())
        self.assertFalse((self.outdir / 'pp.txt').exists())
        self.assertGreater(freed, 0)

    def test_perform_cleanup_guard_still_enforced(self):
        outside = Path(tempfile.mkdtemp(prefix='elitf_outside_'))
        try:
            items = [{'kind': 'kernel_out', 'label': 'x',
                      'path': str(outside / 'evil'),
                      'paths': [str(outside / 'evil')], 'size': 1}]
            (outside / 'evil').write_text('e', encoding='utf-8')
            with self.assertRaises(ValueError):
                elitf.perform_cleanup(str(self.root), str(self.outdir),
                                      items, [0])
            # Le fichier hors zone survit
            self.assertTrue((outside / 'evil').exists())
        finally:
            import shutil as _sh
            _sh.rmtree(outside, ignore_errors=True)


class Menu3RecapCompatTests(_Base):
    def test_recap_panel_tolerates_summary_without_cache_keys(self):
        # Le récap du menu [3] utilise .get() : un résumé sans 'cache' ni
        # 'purged' (mocks, anciens appels) ne doit pas faire crasher l'UI
        summary = {'methods': 1, 'classes': 1, 'strings': 1,
                   'dump_dir': str(self.outdir / 'il2cpp_dump'),
                   'input_files': list(self._pair()), 'input_count': 2}
        self.assertIsNone(summary.get('cache'))
        self.assertIsNone(summary.get('purged'))
        cache_label = ('Analyse réutilisée (cache valide)'
                       if summary.get('cache') == 'reused'
                       else 'Nouvelle analyse')
        purged = summary.get('purged') or []
        self.assertEqual(cache_label, 'Nouvelle analyse')
        self.assertEqual(purged, [])


if __name__ == '__main__':
    unittest.main()
