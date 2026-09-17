import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from io import StringIO

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf_il2cpp as il2cpp


class _LogCapture:
    def __init__(self):
        self.entries = []

    def add(self, msg, level="info"):
        self.entries.append((level, msg))

    def step(self):
        pass


def _build_v27_metadata_with_one_type():
    strings = (b"\x00App\x00NS\x00Foo\x00Bar\x00m1\x00m2\x00arg0\x00"
               b"ValueType\x00")
    string_off = 176
    string_size = len(strings)

    type_defs_off = string_off + string_size
    name_idx = strings.find(b"Foo\x00")
    ns_idx = strings.find(b"NS\x00")
    type_blob = struct.pack("<i", name_idx)
    type_blob += struct.pack("<i", ns_idx)
    type_blob += struct.pack("<i", -1) * 4
    type_blob += struct.pack("<i", -1)
    type_blob += struct.pack("<I", 0x100000)
    type_blob += struct.pack("<i", 0)
    type_blob += struct.pack("<i", 0)
    type_blob += struct.pack("<i", -1) * 6
    type_blob += struct.pack("<H", 2)
    type_blob += struct.pack("<H", 0)
    type_blob += struct.pack("<H", 0)
    type_blob += struct.pack("<H", 0)
    type_blob += struct.pack("<H", 0)
    type_blob += struct.pack("<H", 0)
    type_blob += struct.pack("<H", 0)
    type_blob += struct.pack("<H", 0)
    type_blob += struct.pack("<I", 0)
    type_blob += struct.pack("<I", 0x02000001)
    type_blob += struct.pack("<i", -1)
    type_defs_size = len(type_blob)

    methods_off = type_defs_off + type_defs_size
    m1_idx = strings.find(b"m1\x00")
    m2_idx = strings.find(b"m2\x00")
    def method_blob(name_idx):
        b = struct.pack("<i", name_idx)
        b += struct.pack("<i", 0)
        b += struct.pack("<i", -1)
        b += struct.pack("<i", 0)
        b += struct.pack("<i", -1)
        b += struct.pack("<I", 0)
        b += struct.pack("<i", -1)
        b += struct.pack("<I", 0x06000001 + name_idx)
        b += struct.pack("<H", 0)
        b += struct.pack("<H", 0)
        return b
    methods_blob = method_blob(m1_idx) + method_blob(m2_idx)
    methods_size = len(methods_blob)

    images_off = methods_off + methods_size
    app_idx = strings.find(b"App\x00")
    images_blob = struct.pack("<i", app_idx)
    images_blob += struct.pack("<i", -1)
    images_blob += struct.pack("<i", 0)
    images_blob += struct.pack("<I", 1)
    images_blob += struct.pack("<I", 0)
    images_blob += struct.pack("<I", 0)
    images_blob += struct.pack("<I", 0)
    images_blob += struct.pack("<I", 0x20000001)
    images_blob += struct.pack("<i", -1)
    images_blob += struct.pack("<I", 0)
    images_size = len(images_blob)

    header = bytearray(struct.pack("<Ii", il2cpp.IL2CPP_MAGIC,
                                   il2cpp.IL2CPP_METADATA_VERSION_27))
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", string_off, string_size)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", methods_off, methods_size)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", images_off, images_size)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", type_defs_off, type_defs_size)
    header += struct.pack("<iI", 0, 0)
    header += struct.pack("<iI", 0, 0)

    while len(header) < string_off:
        header += b"\x00"
    return bytes(header) + strings + type_blob + methods_blob + images_blob


class Il2CppMetadataTests(unittest.TestCase):
    def test_rejects_bad_magic(self):
        with self.assertRaises(ValueError) as ctx:
            il2cpp.Il2CppMetadata(b"\x00" * 32)
        self.assertIn("magic", str(ctx.exception).lower())

    def test_rejects_unsupported_version(self):
        data = struct.pack("<Ii", il2cpp.IL2CPP_MAGIC, 99) + b"\x00" * 200
        with self.assertRaises(ValueError) as ctx:
            il2cpp.Il2CppMetadata(data)
        self.assertIn("version", str(ctx.exception).lower())

    def test_parses_v27_with_one_type_two_methods(self):
        md = _build_v27_metadata_with_one_type()
        parser = il2cpp.Il2CppMetadata(md)
        self.assertEqual(parser.version, 27)
        types = list(parser.iter_typedefs())
        methods = list(parser.iter_methods())
        images = list(parser.iter_images())
        self.assertEqual(len(types), 1)
        self.assertEqual(len(methods), 2)
        self.assertEqual(len(images), 1)
        self.assertEqual(types[0]["name"], "Foo")
        self.assertEqual(types[0]["namespace"], "NS")
        self.assertEqual(images[0]["name"], "App")
        self.assertEqual({m["name"] for m in methods}, {"m1", "m2"})

    def test_str_at_handles_negative_offset(self):
        md = _build_v27_metadata_with_one_type()
        parser = il2cpp.Il2CppMetadata(md)
        self.assertEqual(parser.str_at(-1), "")


class Il2CppInspectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="elitf_il2cpp_test_")
        self.root = Path(self.tmp)
        self.md_path = self.root / "global-metadata.dat"
        self.md_path.write_bytes(_build_v27_metadata_with_one_type())
        self.bin_path = self.root / "libil2cpp.so"
        self.bin_path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
        self.outdir = self.root / "out"
        self.outdir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_load_succeeds_with_valid_inputs(self):
        log = _LogCapture()
        insp = il2cpp.Il2CppInspector(str(self.bin_path), str(self.md_path),
                                       str(self.outdir), log_mgr=log)
        insp.load()
        self.assertEqual(insp.metadata.version, 27)
        self.assertEqual(len(insp.types), 1)
        self.assertEqual(len(insp.methods), 2)
        self.assertEqual(len(insp.images), 1)

    def test_dump_cs_contains_class_and_methods(self):
        log = _LogCapture()
        insp = il2cpp.Il2CppInspector(str(self.bin_path), str(self.md_path),
                                       str(self.outdir), log_mgr=log)
        insp.load()
        dump_path = self.outdir / "dump.cs"
        insp.write_dump_cs(str(dump_path))
        text = dump_path.read_text(encoding="utf-8")
        self.assertIn("namespace NS", text)
        self.assertIn("class Foo", text)
        self.assertIn("m1", text)
        self.assertIn("m2", text)
        self.assertIn("TypeDefIndex", text)

    def test_symbol_map_has_one_line_per_method(self):
        log = _LogCapture()
        insp = il2cpp.Il2CppInspector(str(self.bin_path), str(self.md_path),
                                       str(self.outdir), log_mgr=log)
        insp.load()
        sym_path = self.outdir / "symbols.txt"
        insp.write_symbol_map(str(sym_path))
        lines = [l for l in sym_path.read_text().splitlines() if l.strip()]
        self.assertEqual(len(lines), 2)
        for line in lines:
            parts = line.split(maxsplit=1)
            self.assertTrue(parts[0].startswith("0x"))
            self.assertTrue(parts[1].startswith("Il2Cpp_"))

    def test_ida_script_is_valid_python(self):
        log = _LogCapture()
        insp = il2cpp.Il2CppInspector(str(self.bin_path), str(self.md_path),
                                       str(self.outdir), log_mgr=log)
        insp.load()
        ida_path = self.outdir / "ida.py"
        insp.write_ida_script(str(ida_path))
        src = ida_path.read_text(encoding="utf-8")
        self.assertIn("import idaapi", src)
        self.assertIn("import idc", src)
        self.assertIn("_NAMES = [", src)
        compile(src, str(ida_path), "exec")

    def test_ghidra_script_contains_create_label(self):
        log = _LogCapture()
        insp = il2cpp.Il2CppInspector(str(self.bin_path), str(self.md_path),
                                       str(self.outdir), log_mgr=log)
        insp.load()
        gh_path = self.outdir / "ghidra.py"
        insp.write_ghidra_script(str(gh_path))
        src = gh_path.read_text(encoding="utf-8")
        self.assertIn("createLabel", src)
        self.assertIn("@category Il2Cpp", src)
        compile(src, str(gh_path), "exec")

    def test_run_full_creates_all_expected_files(self):
        log = _LogCapture()
        insp = il2cpp.Il2CppInspector(str(self.bin_path), str(self.md_path),
                                       str(self.outdir), log_mgr=log)
        insp.load()
        out = insp.run_full()
        files = set(os.listdir(out))
        expected = {"dump.cs", "il2cpp_symbols.txt", "il2cpp_ida.py",
                    "il2cpp_ghidra.py", "string_literals.txt",
                    "metadata_summary.txt"}
        self.assertTrue(expected.issubset(files),
                        f"missing: {expected - files}")


class FindAndExtractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="elitf_find_test_")
        self.root = Path(self.tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_find_in_dir_returns_pair(self):
        (self.root / "libil2cpp.so").write_bytes(b"ELF")
        (self.root / "global-metadata.dat").write_bytes(b"\xaf\x1b\xb1\xfa")
        r = il2cpp.find_il2cpp_targets(str(self.root))
        self.assertEqual(len(r), 1)
        lib, md = r[0]
        self.assertTrue(lib.endswith("libil2cpp.so"))
        self.assertTrue(md.endswith("global-metadata.dat"))

    def test_find_returns_empty_when_no_targets(self):
        self.assertEqual(il2cpp.find_il2cpp_targets(str(self.root)), [])

    def test_extract_targets_from_apk(self):
        import zipfile
        apk = self.root / "fake.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("lib/arm64-v8a/libil2cpp.so", b"\x7fELF")
            zf.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat",
                        b"\xaf\x1b\xb1\xfa")
        work = self.root / "work"
        work.mkdir()
        lib, md = il2cpp.extract_targets(str(apk), str(work))
        self.assertTrue(Path(lib).exists())
        self.assertTrue(Path(md).exists())

    def test_extract_raises_on_invalid_input(self):
        with self.assertRaises(ValueError):
            il2cpp.extract_targets("/nonexistent/path", str(self.root / "w"))


class RunIl2CppAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="elitf_run_test_")
        self.root = Path(self.tmp)
        (self.root / "libil2cpp.so").write_bytes(
            b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
        (self.root / "global-metadata.dat").write_bytes(
            _build_v27_metadata_with_one_type())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_run_il2cpp_analysis_creates_output_dir(self):
        out = self.root / "out"
        log = _LogCapture()
        result = il2cpp.run_il2cpp_analysis(str(self.root), str(out),
                                            log_mgr=log)
        self.assertTrue(Path(result).exists())
        self.assertTrue((Path(result) / "dump.cs").exists())


if __name__ == "__main__":
    unittest.main()
