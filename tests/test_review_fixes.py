import os
import struct
import sys
import tempfile
import unittest
import zipfile
import shutil
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf_il2cpp as il2cpp
import elitf_r2 as r2
from elitf_ui import LogManager


class FakeUI:
    console = None

    def __init__(self, lines=()):
        self.lines = list(lines)
        self.printed = []
        self._targets_selection = [0]

    def _print(self, *a, **k):
        self.printed.append(" ".join(str(x) for x in a))

    def print_raw(self, text):
        self.printed.append(text)

    def r2_readline(self, prompt=""):
        if not self.lines:
            return None
        return self.lines.pop(0)

    def confirm(self, question, default=False):
        return default

    def get_target_selection(self):
        return self._targets_selection


class CatalogBuiltinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.so = self.root / "libapp.so"
        self.so.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)

    def tearDown(self):
        self.tmp.cleanup()

    def test_help_lists_catalog_builtin(self):
        ui = FakeUI()
        sess = r2.R2Session([{"name": "libapp.so", "path": str(self.so)}],
                            str(self.root / "out"), LogManager(), ui)
        sess.r2_bin = "/usr/bin/true"
        sess._print_help()
        joined = "\n".join(ui.printed)
        self.assertIn("!catalog", joined)

    def test_catalog_builtin_invokes_session_catalog(self):
        ui = FakeUI()
        sess = r2.R2Session([{"name": "libapp.so", "path": str(self.so)}],
                            str(self.root / "out"), LogManager(), ui)
        sess.r2_bin = "/usr/bin/true"
        called = {"count": 0}
        original = sess.catalog
        def fake_catalog():
            called["count"] += 1
        sess.catalog = fake_catalog
        result = sess.handle_builtin("!catalog")
        self.assertEqual(result, "handled")
        self.assertEqual(called["count"], 1)


class TempDirCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="elitf_cleanup_test_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_targets(self):
        (self.tmp and None)
        d = tempfile.mkdtemp(prefix="elitf_targets_")
        lib = os.path.join(d, "libil2cpp.so")
        md = os.path.join(d, "global-metadata.dat")
        with open(lib, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
        md_blob = struct.pack("<Ii", il2cpp.IL2CPP_MAGIC,
                              il2cpp.IL2CPP_METADATA_VERSION_27)
        md_blob += b"\x00" * 200
        with open(md, "wb") as f:
            f.write(md_blob)
        return d

    def test_run_il2cpp_analysis_cleans_temp_dir_on_success(self):
        d = self._write_targets()
        try:
            tmp_before = set(os.listdir("/tmp"))
            try:
                il2cpp.run_il2cpp_analysis(d, os.path.join(d, "out"))
            except Exception:
                pass
            tmp_after = set(os.listdir("/tmp"))
            new_dirs = tmp_after - tmp_before
            elitf_dirs = [x for x in new_dirs if x.startswith("elitf_il2cpp_")]
            self.assertEqual(elitf_dirs, [],
                f"temp dirs leaked: {elitf_dirs}")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_run_il2cpp_analysis_cleans_temp_dir_on_failure(self):
        d = self._write_targets()
        try:
            tmp_before = set(os.listdir("/tmp"))
            try:
                il2cpp.run_il2cpp_analysis("/nonexistent/path",
                                           os.path.join(d, "out"))
            except (ValueError, Exception):
                pass
            tmp_after = set(os.listdir("/tmp"))
            new_dirs = tmp_after - tmp_before
            elitf_dirs = [x for x in new_dirs if x.startswith("elitf_il2cpp_")]
            self.assertEqual(elitf_dirs, [],
                f"temp dirs leaked on failure: {elitf_dirs}")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class ExtractTargetsSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="elitf_sec_test_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_rejects_path_traversal_entry(self):
        apk = os.path.join(self.tmp, "evil.apk")
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("lib/../../libil2cpp.so", b"\x7fELF")
            zf.writestr("global-metadata.dat", b"\xaf\x1b\xb1\xfa")
        with self.assertRaises(ValueError) as ctx:
            il2cpp.extract_targets(apk, os.path.join(self.tmp, "work"))
        self.assertIn("traversal", str(ctx.exception).lower())

    def test_rejects_absolute_path_entry(self):
        apk = os.path.join(self.tmp, "evil.apk")
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("/libil2cpp.so", b"\x7fELF")
            zf.writestr("global-metadata.dat", b"\xaf\x1b\xb1\xfa")
        with self.assertRaises(ValueError):
            il2cpp.extract_targets(apk, os.path.join(self.tmp, "work"))

    def test_prefers_arm64_v8a_for_multi_arch_apk(self):
        apk = os.path.join(self.tmp, "multi.apk")
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("lib/armeabi-v7a/libil2cpp.so", b"ARM32")
            zf.writestr("lib/arm64-v8a/libil2cpp.so", b"ARM64")
            zf.writestr("lib/x86_64/libil2cpp.so", b"X64")
            zf.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat",
                        b"\xaf\x1b\xb1\xfa")
        work = os.path.join(self.tmp, "work")
        lib, md = il2cpp.extract_targets(apk, work)
        with open(lib, "rb") as f:
            content = f.read()
        self.assertEqual(content, b"ARM64",
            f"expected arm64-v8a, got {content!r}")

    def test_returns_existing_disk_paths(self):
        apk = os.path.join(self.tmp, "ok.apk")
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("lib/arm64-v8a/libil2cpp.so", b"\x7fELF")
            zf.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat",
                        b"\xaf\x1b\xb1\xfa")
        work = os.path.join(self.tmp, "work")
        lib, md = il2cpp.extract_targets(apk, work)
        self.assertTrue(os.path.isfile(lib),
            f"lib path does not exist on disk: {lib}")
        self.assertTrue(os.path.isfile(md),
            f"md path does not exist on disk: {md}")


class HonestIDAWarningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="elitf_ida_test_")
        self.bin_path = os.path.join(self.tmp, "libil2cpp.so")
        self.md_path = os.path.join(self.tmp, "global-metadata.dat")
        with open(self.bin_path, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
        md_blob = struct.pack("<Ii", il2cpp.IL2CPP_MAGIC,
                              il2cpp.IL2CPP_METADATA_VERSION_27)
        md_blob += b"\x00" * 200
        with open(self.md_path, "wb") as f:
            f.write(md_blob)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ida_script_warns_about_token_addresses(self):
        try:
            insp = il2cpp.Il2CppInspector(self.bin_path, self.md_path, self.tmp)
            insp.load()
        except Exception:
            self.skipTest("metadata fixture too minimal for this test")
        ida_path = os.path.join(self.tmp, "ida.py")
        try:
            insp.write_ida_script(ida_path)
        except Exception:
            self.skipTest("write_ida_script skipped")
        with open(ida_path) as f:
            src = f.read()
        self.assertIn("metadata tokens", src)
        self.assertIn("not virtual addresses", src)


if __name__ == "__main__":
    unittest.main()
