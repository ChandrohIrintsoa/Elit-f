import os
import struct
import sys
import tempfile
import unittest
import shutil
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf_il2cpp as il2cpp
import elitf_r2 as r2
from elitf_ui import LogManager


class _LogCapture:
    def __init__(self):
        self.entries = []
    def add(self, msg, level="info"):
        self.entries.append((level, msg))
    def step(self):
        pass


def _build_metadata(version, with_type=True):
    strings = b"\x00App\x00NS\x00Foo\x00m1\x00\x00"
    fmt, names = il2cpp._build_header_struct(version)
    string_off = struct.calcsize(fmt)
    string_size = len(strings)

    td_stride = il2cpp._typedef_stride(float(version))
    meth_stride = il2cpp._method_stride(float(version))
    img_stride = il2cpp._image_stride(float(version))

    type_defs_off = string_off + string_size
    name_idx = strings.find(b"Foo\x00")
    ns_idx = strings.find(b"NS\x00")
    type_blob = struct.pack("<i", name_idx)
    type_blob += struct.pack("<i", ns_idx)
    type_blob += struct.pack("<i", -1) * 4
    type_blob += struct.pack("<i", -1)
    type_blob += struct.pack("<I", 0x100000)
    type_blob += struct.pack("<i", 0) * 8
    type_blob += struct.pack("<H", 1)
    type_blob += struct.pack("<H", 0) * 7
    type_blob += struct.pack("<I", 0)
    type_blob += struct.pack("<I", 0x02000001)
    while len(type_blob) < td_stride:
        type_blob += b"\x00"
    type_blob = type_blob[:td_stride]
    type_defs_size = len(type_blob)

    methods_off = type_defs_off + type_defs_size
    m1_idx = strings.find(b"m1\x00")
    methods_blob = struct.pack("<i", m1_idx)
    methods_blob += struct.pack("<i", 0)
    methods_blob += struct.pack("<i", -1)
    methods_blob += struct.pack("<i", 0)
    methods_blob += struct.pack("<i", -1)
    methods_blob += struct.pack("<I", 0x06000001)
    methods_blob += struct.pack("<H", 0)
    methods_blob += struct.pack("<H", 0)
    methods_blob += struct.pack("<H", 0)
    methods_blob += struct.pack("<H", 1)
    while len(methods_blob) < meth_stride:
        methods_blob += b"\x00"
    methods_blob = methods_blob[:meth_stride]
    methods_size = len(methods_blob)

    images_off = methods_off + methods_size
    app_idx = strings.find(b"App\x00")
    images_blob = struct.pack("<i", app_idx)
    images_blob += struct.pack("<i", -1)
    images_blob += struct.pack("<i", 0)
    images_blob += struct.pack("<I", 1)
    images_blob += struct.pack("<I", 0)
    images_blob += struct.pack("<I", 0)
    images_blob += struct.pack("<I", 0x20000001)
    images_blob += struct.pack("<i", -1)
    images_blob += struct.pack("<I", 0)
    images_blob += struct.pack("<I", 0)
    while len(images_blob) < img_stride:
        images_blob += b"\x00"
    images_blob = images_blob[:img_stride]
    images_size = len(images_blob)

    values = {name: 0 for name in names}
    values["sanity"] = il2cpp.IL2CPP_MAGIC
    values["version"] = version
    values["stringOffset"] = string_off
    values["stringSize"] = string_size
    values["methodsOffset"] = methods_off
    values["methodsSize"] = methods_size
    values["typeDefinitionsOffset"] = type_defs_off
    values["typeDefinitionsSize"] = type_defs_size
    values["imagesOffset"] = images_off
    values["imagesSize"] = images_size
    packed = struct.pack(fmt, *[values[n] for n in names])
    header = bytearray(packed)
    while len(header) < string_off:
        header += b"\x00"
    return bytes(header) + strings + type_blob + methods_blob + images_blob


class VersionCoverageTests(unittest.TestCase):
    def test_supports_v16(self):
        md = _build_metadata(16)
        parser = il2cpp.Il2CppMetadata(md)
        self.assertEqual(parser.version, 16)
        self.assertEqual(len(list(parser.iter_typedefs())), 1)
        self.assertEqual(len(list(parser.iter_methods())), 1)

    def test_supports_v19(self):
        md = _build_metadata(19)
        parser = il2cpp.Il2CppMetadata(md)
        self.assertEqual(parser.version, 19)
        self.assertEqual(len(list(parser.iter_typedefs())), 1)
        self.assertEqual(len(list(parser.iter_methods())), 1)

    def test_supports_v20(self):
        md = _build_metadata(20)
        parser = il2cpp.Il2CppMetadata(md)
        self.assertEqual(parser.version, 20)

    def test_supports_v22(self):
        md = _build_metadata(22)
        parser = il2cpp.Il2CppMetadata(md)
        self.assertEqual(parser.version, 22)

    def test_supports_v23(self):
        md = _build_metadata(23)
        parser = il2cpp.Il2CppMetadata(md)
        self.assertEqual(parser.version, 23)

    def test_supports_v24(self):
        md = _build_metadata(24)
        parser = il2cpp.Il2CppMetadata(md)
        self.assertEqual(parser.version, 24)

    def test_supports_v28(self):
        md = _build_metadata(28)
        parser = il2cpp.Il2CppMetadata(md)
        self.assertEqual(parser.version, 28)

    def test_supports_v31(self):
        md = _build_metadata(31)
        parser = il2cpp.Il2CppMetadata(md)
        self.assertEqual(parser.version, 31)
        self.assertEqual(len(list(parser.iter_typedefs())), 1)
        self.assertEqual(len(list(parser.iter_methods())), 1)

    def test_rejects_unknown_version(self):
        md = struct.pack("<Ii", il2cpp.IL2CPP_MAGIC, 99) + b"\x00" * 200
        with self.assertRaises(ValueError):
            il2cpp.Il2CppMetadata(md)


class StrideAccuracyTests(unittest.TestCase):
    def test_typedef_stride_v22_is_108(self):
        self.assertEqual(il2cpp._typedef_stride(22), 108)

    def test_typedef_stride_v24_1_is_92(self):
        self.assertEqual(il2cpp._typedef_stride(24.1), 92)

    def test_typedef_stride_v27_is_88(self):
        self.assertEqual(il2cpp._typedef_stride(27), 88)

    def test_method_stride_v24_1_is_60(self):
        self.assertEqual(il2cpp._method_stride(24.1), 60)

    def test_method_stride_v27_is_32(self):
        self.assertEqual(il2cpp._method_stride(27), 32)

    def test_method_stride_v31_is_36(self):
        self.assertEqual(il2cpp._method_stride(31), 36)

    def test_image_stride_v18_is_20(self):
        self.assertEqual(il2cpp._image_stride(18), 20)

    def test_image_stride_v24_1_is_40(self):
        self.assertEqual(il2cpp._image_stride(24.1), 40)


class R2FixesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.so = self.root / "libapp.so"
        self.so.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)

    def tearDown(self):
        self.tmp.cleanup()

    def test_C1_run_r2_does_not_use_dash_N(self):
        ui = type("U", (), {"console": None, "_print": lambda *a, **k: None,
                            "print_raw": lambda *a, **k: None,
                            "r2_readline": lambda *a, **k: None,
                            "confirm": lambda *a, **k: False})()
        sess = r2.R2Session([{"name": "libapp.so", "path": str(self.so)}],
                            str(self.root / "out"), LogManager(), ui)
        sess.r2_bin = "/usr/bin/true"
        captured = {}
        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with patch.object(r2.subprocess, "run", side_effect=fake_run):
            sess.run_r2("iI")
        self.assertNotIn("-N", captured["argv"],
            "r2 -N must be dropped — it skips bin plugin loading")

    def test_C1_run_r2_uses_bin_cache_flag(self):
        ui = type("U", (), {"console": None, "_print": lambda *a, **k: None,
                            "print_raw": lambda *a, **k: None,
                            "r2_readline": lambda *a, **k: None,
                            "confirm": lambda *a, **k: False})()
        sess = r2.R2Session([{"name": "libapp.so", "path": str(self.so)}],
                            str(self.root / "out"), LogManager(), ui)
        sess.r2_bin = "/usr/bin/true"
        captured = {}
        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with patch.object(r2.subprocess, "run", side_effect=fake_run):
            sess.run_r2("iI")
        self.assertIn("bin.cache=true", captured["argv"])

    def test_C2_compose_command_with_addr2(self):
        entry = {"cmd": "age", "args": [("addr", "From", ""), ("addr2", "To", "")]}
        cmd = r2._compose_r2_command(entry, ["0x1000", "0x2000"])
        self.assertEqual(cmd, "age 0x2000 @ 0x1000")

    def test_C3_compose_command_escapes_semicolons(self):
        entry = {"cmd": "wa", "args": [("value", "Asm", "mov r0, 0; bx lr"),
                                       ("addr", "Addr", "")]}
        cmd = r2._compose_r2_command(entry, ["mov r0, 0; bx lr", "0x1000"])
        self.assertIn('"mov r0, 0; bx lr"', cmd)
        self.assertIn("@ 0x1000", cmd)

    def test_C4_set_rejects_shell_injection(self):
        ui = type("U", (), {"console": None, "printed": [],
                            "_print": lambda self, *a, **k: None})()
        class FakeUI:
            console = None
            printed = []
            def _print(self, *a, **k):
                self.printed.append(" ".join(str(x) for x in a))
            def r2_readline(self, p=""): return None
            def confirm(self, q, d=False): return d
        ui = FakeUI()
        sess = r2.R2Session([{"name": "libapp.so", "path": str(self.so)}],
                            str(self.root / "out"), LogManager(), ui)
        sess.r2_bin = "/usr/bin/true"
        sess.handle_builtin("!set ! rm -rf /")
        self.assertEqual(sess.env_cmds, [],
            "shell injection via !set must be rejected")
        joined = "\n".join(ui.printed)
        self.assertIn("Refusé", joined)

    def test_C4_set_accepts_valid_e_var_value(self):
        class FakeUI:
            console = None
            printed = []
            def _print(self, *a, **k):
                self.printed.append(" ".join(str(x) for x in a))
            def r2_readline(self, p=""): return None
            def confirm(self, q, d=False): return d
        ui = FakeUI()
        sess = r2.R2Session([{"name": "libapp.so", "path": str(self.so)}],
                            str(self.root / "out"), LogManager(), ui)
        sess.r2_bin = "/usr/bin/true"
        sess.handle_builtin("!set e asm.bytes=true")
        self.assertIn("e asm.bytes=true", sess.env_cmds)

    def test_R3_switch_resets_analysis_cmds(self):
        so2 = self.root / "libflutter.so"
        so2.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
        class FakeUI:
            console = None
            def _print(self, *a, **k): pass
            def r2_readline(self, p=""): return None
            def confirm(self, q, d=False): return d
        ui = FakeUI()
        sess = r2.R2Session([
            {"name": "libapp.so", "path": str(self.so)},
            {"name": "libflutter.so", "path": str(so2)},
        ], str(self.root / "out"), LogManager(), ui)
        sess.analysis_cmds = ["aaa"]
        sess._switch(1)
        self.assertEqual(sess.analysis_cmds, [],
            "switching target must reset analysis_cmds to avoid stale symbols")

    def test_R1_header_lines_has_anal_strings(self):
        self.assertIn("e anal.strings=true", r2.R2_HEADER_LINES)
        self.assertIn("e io.cache=true", r2.R2_HEADER_LINES)

    def test_R4_output_limit_raised_to_1mb(self):
        self.assertGreaterEqual(r2.R2_OUTPUT_LIMIT, 1_000_000)


if __name__ == "__main__":
    unittest.main()
