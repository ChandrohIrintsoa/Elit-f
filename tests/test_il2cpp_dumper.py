
"""Tests du dumper style Il2CppDumper adapté au kernel Elit-f (option [3]).

Le kernel Elit-f produit asm/*.txt + pp.txt ; elitf_dumper les convertit en
sorties Il2CppDumper-Python. Contrat « exactement 2 fichiers » :
  ENTRÉE : libapp.so + libflutter.so   SORTIE : dump.dart + script.json
(voir tests/test_il2cpp_two_files.py ; les générateurs stringliteral/IDA/
Ghidra restent disponibles comme API opt-in mais ne font plus partie du
dossier de sortie par défaut)
"""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf_dumper as dumper


# Format EXACT produit par src/DartDumper.cpp (DartLibrary::PrintCommentInfo,
# DartClass::PrintHead/PrintFoot, DartField::Print, DartFunction::PrintHead/Foot)
ASM_CORE = """// lib: dart core, url: dart:core

// class id: 2, size: 0x38
class :: {
  static late String _rootScheme; // offset: 0x8

  void main() {
    // ** addr: 0x390000, size: 0x40
    0x390000: stp x29, x30, [sp, -0x10]!
    0x390004: mov x29, sp
  }
  int get hashCode {
    // ** addr: 0x390100, size: 0x18
    0x390100: ret
  }
  set _scheme(String value) {
    // ** addr: 0x390140, size: 0x20
    0x390140: ret
  }
}

// class id: 10, size: 0x58, field offset: 0x38
abstract class _MyState<T> extends State<T> implements Lifecycle {
    implements Foo, Bar with Mixin
  int counter; // offset: 0x8
  final _MyState field_10;
//   const constructor, transformed mixin,
  void build(BuildContext context) async {
    // ** addr: 0x6f57ec, size: 0x120
    0x6f57ec: mov x0, x1  ; THR::stack_limit
  }
  static void reset() {
    // ** addr: 0x6f7000, size: 0x10
    0x6f7000: ret
  }
}

// class id: 11, size: 0x0
class OnlyForward;
"""

ASM_APP = """// lib: my app, url: package:app/main.dart

// class id: 20, size: 0x60
class :: {
  Future<void> doWork() async {
    // ** addr: 0x700000, size: 0x30
    0x700000: ret
  }
  Future<void> doWork() async {
    // ** addr: 0x700100, size: 0x30
    0x700100: ret
  }
}
"""

PP_TXT = """pool heap offset: 0x1234000
[pp+0x8] String: 'hello world'
[pp+0x10] String: 'it\\'s ok\\nmulti \\\\ end'
[pp+0x18] IMM: 0x2a
[pp+0x20] IMM: double(3.14) from 0x40091eb851eb851f
[pp+0x28] UnlinkedCall: 0x390000 - _MyState$$build
[pp+0x30] NativeFn: [no name] at 0x7f00
[pp+0x38] String: ''
"""


def _write_kernel_outputs(root):
    (root / 'asm').mkdir(parents=True, exist_ok=True)
    (root / 'asm' / 'dart-core.txt').write_text(ASM_CORE, encoding='utf-8')
    (root / 'asm' / 'app-main.txt').write_text(ASM_APP, encoding='utf-8')
    (root / 'pp.txt').write_text(PP_TXT, encoding='utf-8')


class ParseAsmTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        _write_kernel_outputs(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_parses_libraries(self):
        libs = dumper.parse_asm_dir(str(self.root / 'asm'))
        self.assertEqual(len(libs), 2)
        by_url = {l['url']: l for l in libs}
        self.assertIn('dart:core', by_url)
        self.assertIn('package:app/main.dart', by_url)
        self.assertEqual(by_url['dart:core']['name'], 'dart core')

    def test_parses_top_level_class_and_methods(self):
        libs = dumper.parse_asm_dir(str(self.root / 'asm'))
        core = next(l for l in libs if l['url'] == 'dart:core')
        top = next(c for c in core['classes'] if c['name'] == '::')
        self.assertEqual(top['id'], 2)
        self.assertEqual(top['size'], 0x38)
        names = [m['name'] for m in top['methods']]
        self.assertEqual(names, ['main', 'hashCode', '_scheme'])
        main = top['methods'][0]
        self.assertEqual(main['addr'], 0x390000)
        self.assertEqual(main['size'], 0x40)
        self.assertEqual(main['signature'], 'void main()')
        # getter → 'int get hashCode'
        self.assertEqual(top['methods'][1]['signature'], 'int get hashCode')
        # setter → 'set _scheme(String value)'
        self.assertEqual(top['methods'][2]['signature'], 'set _scheme(String value)')

    def test_parses_class_modifiers_fields_and_meta(self):
        libs = dumper.parse_asm_dir(str(self.root / 'asm'))
        core = next(l for l in libs if l['url'] == 'dart:core')
        cls = next(c for c in core['classes'] if c['name'] == '_MyState')
        self.assertEqual(cls['decl_kind'], 'abstract class')
        self.assertEqual(cls['id'], 10)
        self.assertEqual(cls['field_offset'], 0x38)
        self.assertTrue(cls['const_constructor'])
        self.assertTrue(cls['transformed_mixin'])
        self.assertIn('State<T>', cls['extends'])
        offs = [f['offset'] for f in cls['fields']]
        self.assertEqual(offs, [0x8, 0x10])
        self.assertEqual(cls['fields'][0]['decl'], 'int counter;')
        self.assertEqual(cls['fields'][1]['name'], 'field_10')

    def test_parses_bodyless_class(self):
        libs = dumper.parse_asm_dir(str(self.root / 'asm'))
        core = next(l for l in libs if l['url'] == 'dart:core')
        fwd = next(c for c in core['classes'] if c['name'] == 'OnlyForward')
        self.assertEqual(fwd['id'], 11)
        self.assertEqual(fwd['methods'], [])
        self.assertTrue(fwd['bodyless'])

    def test_method_flags(self):
        libs = dumper.parse_asm_dir(str(self.root / 'asm'))
        core = next(l for l in libs if l['url'] == 'dart:core')
        cls = next(c for c in core['classes'] if c['name'] == '_MyState')
        build = cls['methods'][0]
        self.assertEqual(build['addr'], 0x6f57ec)
        self.assertEqual(build['size'], 0x120)
        self.assertTrue(build['async'])
        self.assertFalse(build['static'])
        self.assertTrue(cls['methods'][1]['static'])


class ParsePpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'pp.txt').write_text(PP_TXT, encoding='utf-8')

    def tearDown(self):
        self.temp.cleanup()

    def test_extracts_strings_with_unescape(self):
        pp = dumper.parse_pp(str(self.root / 'pp.txt'))
        self.assertEqual(pp['heap_offset'], 0x1234000)
        self.assertEqual(pp['entries'], 7)
        self.assertEqual(pp['strings'][0]['offset'], 0x8)
        self.assertEqual(pp['strings'][0]['value'], 'hello world')
        self.assertEqual(pp['strings'][1]['value'], "it's ok\nmulti \\ end")
        self.assertEqual(pp['strings'][2]['value'], '')

    def test_ignores_non_string_entries(self):
        pp = dumper.parse_pp(str(self.root / 'pp.txt'))
        values = [s['value'] for s in pp['strings']]
        self.assertNotIn('0x2a', values)


class DumpDartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        _write_kernel_outputs(self.root)
        self.libs = dumper.parse_asm_dir(str(self.root / 'asm'))
        self.pp = dumper.parse_pp(str(self.root / 'pp.txt'))

    def tearDown(self):
        self.temp.cleanup()

    def test_dump_dart_structure(self):
        out = self.root / 'dump.dart'
        dumper.generate_dump_dart(self.libs, str(out),
                                  meta={'binary': 'libapp.so',
                                        'dart_version': '3.10.7'})
        text = out.read_text(encoding='utf-8')
        self.assertIn('Il2CppDumper', text)
        self.assertIn('// Library: dart core', text)
        self.assertIn('// URL: dart:core', text)
        self.assertIn('class :: {', text)
        self.assertIn('abstract class _MyState<T> extends State<T>', text)
        self.assertIn('// RVA: 0x390000 VA: 0x390000 Size: 0x40', text)
        self.assertIn('void main() { }', text)
        self.assertIn('int counter; // offset: 0x8', text)
        self.assertIn('class OnlyForward;', text)

    def test_dump_dart_lists_string_literals(self):
        out = self.root / 'dump.dart'
        dumper.generate_dump_dart(self.libs, str(out),
                                  meta={'binary': 'libapp.so'}, pp=self.pp)
        text = out.read_text(encoding='utf-8')
        self.assertIn('// StringLiteral', text)
        self.assertIn("'hello world'", text)


class ScriptJsonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        _write_kernel_outputs(self.root)
        self.libs = dumper.parse_asm_dir(str(self.root / 'asm'))
        self.pp = dumper.parse_pp(str(self.root / 'pp.txt'))

    def tearDown(self):
        self.temp.cleanup()

    def test_script_json_format(self):
        out = self.root / 'script.json'
        dumper.generate_script_json(self.libs, self.pp, str(out))
        raw = json.loads(out.read_text(encoding='utf-8'))
        self.assertIn('ScriptMethod', raw)
        self.assertIn('ScriptString', raw)
        main = raw['ScriptMethod'][0]
        self.assertEqual(main['Address'], 0x390000)  # décimal dans le JSON
        self.assertEqual(main['Name'], 'main')
        self.assertEqual(main['Signature'], 'void main()')
        build = next(m for m in raw['ScriptMethod']
                     if m['Name'] == '_MyState$$build')
        self.assertEqual(build['Address'], 0x6f57ec)

    def test_method_name_uses_class_prefix(self):
        out = self.root / 'script.json'
        data = dumper.generate_script_json(self.libs, self.pp, str(out))
        names = {m['Name'] for m in data['ScriptMethod']}
        self.assertIn('_MyState$$reset', names)

    def test_duplicate_names_deduplicated_with_address(self):
        out = self.root / 'script.json'
        data = dumper.generate_script_json(self.libs, self.pp, str(out))
        names = [m['Name'] for m in data['ScriptMethod']]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('doWork', names)
        self.assertIn('doWork_0x700100', names)

    def test_script_string_entries(self):
        out = self.root / 'script.json'
        data = dumper.generate_script_json(self.libs, self.pp, str(out))
        vals = {s['Value'] for s in data['ScriptString']}
        self.assertIn('hello world', vals)


class StringLiteralTests(unittest.TestCase):
    def test_stringliteral_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'pp.txt').write_text(PP_TXT, encoding='utf-8')
            pp = dumper.parse_pp(str(root / 'pp.txt'))
            out = root / 'stringliteral.json'
            data = dumper.generate_stringliteral_json(pp, str(out))
            raw = json.loads(out.read_text(encoding='utf-8'))
            self.assertEqual(raw[0], {'index': 0, 'value': 'hello world'})
            self.assertEqual(data[2]['value'], '')
            self.assertEqual([r['index'] for r in raw], [0, 1, 2])


class ToolScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        _write_kernel_outputs(self.root)
        self.libs = dumper.parse_asm_dir(str(self.root / 'asm'))
        self.pp = dumper.parse_pp(str(self.root / 'pp.txt'))

    def tearDown(self):
        self.temp.cleanup()

    def test_ida_script_written(self):
        out = self.root / 'ida_elitf_dumper.py'
        dumper.generate_ida_script(self.libs, str(out))
        text = out.read_text(encoding='utf-8')
        self.assertIn('ScriptMethod', text)
        self.assertIn('get_imagebase', text)
        self.assertIn('add_func', text)
        self.assertIn('set_name', text)
        self.assertIn('ask_file', text)
        compile(text, str(out), 'exec')

    def test_ghidra_script_written(self):
        out = self.root / 'ghidra_elitf_dumper.py'
        dumper.generate_ghidra_script(self.libs, str(out))
        text = out.read_text(encoding='utf-8')
        self.assertIn('ScriptMethod', text)
        self.assertIn('getFunctionAt', text)
        self.assertIn('askFile', text)
        compile(text, str(out), 'exec')


class GenerateAllTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        _write_kernel_outputs(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_generate_all_writes_exactly_two_files(self):
        summary = dumper.generate_all(str(self.root))
        dump_dir = self.root / 'il2cpp_dump'
        # Contrat : EXACTEMENT 2 fichiers (dump.dart + script.json)
        self.assertEqual(sorted(p.name for p in dump_dir.iterdir()),
                         ['dump.dart', 'script.json'])
        self.assertEqual([Path(f).name for f in summary['files']],
                         ['dump.dart', 'script.json'])
        self.assertEqual(summary['libraries'], 2)
        self.assertEqual(summary['methods'], 7)
        self.assertEqual(summary['strings'], 3)
        self.assertEqual(summary['classes'], 4)
        self.assertIn('dump_dir', summary)

    def test_generate_all_purges_legacy_files(self):
        # Fichiers des versions précédentes → purgés : le dossier final
        # contient exactement dump.dart + script.json
        dump_dir = self.root / 'il2cpp_dump'
        dump_dir.mkdir()
        (dump_dir / 'stringliteral.json').write_text('[]', encoding='utf-8')
        (dump_dir / 'ida_elitf_dumper.py').write_text('# old',
                                                      encoding='utf-8')
        (dump_dir / 'ghidra_elitf_dumper.py').write_text('# old',
                                                         encoding='utf-8')
        (self.root / 'ida_dart_struct.h').write_text(
            'typedef struct DartThread;', encoding='utf-8')
        summary = dumper.generate_all(str(self.root))
        self.assertEqual(sorted(p.name for p in Path(summary['dump_dir'])
                                .iterdir()),
                         ['dump.dart', 'script.json'])

    def test_generate_all_missing_outputs_raises(self):
        (self.root / 'pp.txt').unlink()
        with self.assertRaises(FileNotFoundError):
            dumper.generate_all(str(self.root))


class EnsureKernelOutputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_runs_analysis_only_when_missing(self):
        # Contrat 2 fichiers : l'indir doit contenir libapp.so + libflutter.so
        indir = self.root / 'in'
        indir.mkdir()
        (indir / 'libapp.so').write_bytes(b'\x7fELF app')
        (indir / 'libflutter.so').write_bytes(b'\x7fELF flutter')
        with patch.object(dumper, 'run_flutter_analysis') as rfa:
            rfa.side_effect = lambda *a, **k: _write_kernel_outputs(self.root)
            summary = dumper.ensure_kernel_outputs(
                str(indir), str(self.root), False, False, None, None, False)
            rfa.assert_called_once()
            self.assertEqual(summary['input_count'], 2)
        # outputs maintenant présents → pas de nouvelle analyse
        with patch.object(dumper, 'run_flutter_analysis') as rfa:
            dumper.ensure_kernel_outputs(
                str(indir), str(self.root), False, False, None, None, False)
            rfa.assert_not_called()


if __name__ == '__main__':
    unittest.main()
