#!/usr/bin/env python3
import os
import re
import struct
import sys
import shutil
import zipfile
import subprocess

IL2CPP_MAGIC = 0xFAB11BAF

IL2CPP_METADATA_VERSIONS = (
    16, 21, 22, 23, 24, 27, 28, 29,
)

IL2CPP_METADATA_VERSION_24 = 24
IL2CPP_METADATA_VERSION_27 = 27
IL2CPP_METADATA_VERSION_29 = 29

_IL2CPP_HEADER_FMT_V24 = "<I" + "i" * 35
_IL2CPP_HEADER_FMT_V27 = "<I" + "i" * 43
_IL2CPP_HEADER_FMT_V29 = "<I" + "i" * 51

_IL2CPP_STRING_OFFSET = b"global-metadata.dat"
_LIBIL2CPP_NAME = "libil2cpp.so"
_GLOBAL_METADATA_NAME = "global-metadata.dat"

_TYPE_KINDS = {
    1: "ValueType", 2: "Class", 3: "Interface",
    4: "GenericClass", 5: "Array", 6: "Enum",
    7: "GenericInstance", 8: "GenericParameter",
    11: "Ptr", 12: "FnPtr", 13: "ByRef",
    14: "MVar", 15: "Type", 16: "ModOpt", 17: "ModReq",
    18: "Sentinel", 19: "Pinned",
}

_TYPE_ATTR_VIS = {
    0x00: "public", 0x01: "famorassem", 0x02: "assembly",
    0x03: "family", 0x04: "famandassem", 0x05: "private",
}

_TYPE_ATTR_LAYOUT = {
    0x00: "auto", 0x08: "sequential", 0x10: "explicit",
}

_TYPE_ATTR_FORMAT = {
    0x00: "ansi", 0x18: "unicode", 0x30: "autochar",
}

_R2_BIN_NAMES = ("r2", "radare2")
_READELF_NAMES = ("readelf", "greadelf", "llvm-readelf")

_SYM_NAME_SAFE = re.compile(r"[^A-Za-z0-9_.$<>]")

def _safe_name(name):
    if not name:
        return "_"
    name = _SYM_NAME_SAFE.sub("_", name)
    if not name:
        return "_"
    if name[0].isdigit():
        name = "_" + name
    return name


def _find_tool(names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _read_cstr(buf, offset):
    if offset < 0 or offset >= len(buf):
        return ""
    end = buf.find(b"\x00", offset)
    if end == -1:
        end = len(buf)
    try:
        return buf[offset:end].decode("utf-8", "replace")
    except Exception:
        return buf[offset:end].decode("latin-1", "replace")


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _i32(buf, off):
    return struct.unpack_from("<i", buf, off)[0]


def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def _ptr(buf, off, bits):
    if bits == 32:
        return _u32(buf, off)
    return _u64(buf, off)


def _align_up(v, a):
    a = a or 1
    return (v + a - 1) // a * a


class Il2CppMetadata:
    def __init__(self, data):
        self.raw = data
        self.version = 0
        self.string_lits = ()
        self.string_off = 0
        self.string_size = 0
        self.events_off = 0
        self.events_size = 0
        self.properties_off = 0
        self.properties_size = 0
        self.methods_off = 0
        self.methods_size = 0
        self.param_default_off = 0
        self.param_default_size = 0
        self.field_default_off = 0
        self.field_default_size = 0
        self.field_and_param_off = 0
        self.field_and_param_size = 0
        self.field_marshals_off = 0
        self.field_marshals_size = 0
        self.params_off = 0
        self.params_size = 0
        self.fields_off = 0
        self.fields_size = 0
        self.generic_insts_off = 0
        self.generic_insts_size = 0
        self.generic_methods_off = 0
        self.generic_methods_size = 0
        self.generic_containers_off = 0
        self.generic_containers_size = 0
        self.images_off = 0
        self.images_size = 0
        self.assemblies_off = 0
        self.assemblies_size = 0
        self.metadata_usage_off = 0
        self.metadata_usage_size = 0
        self.type_defs_off = 0
        self.type_defs_size = 0
        self.interface_offsets_off = 0
        self.interface_offsets_size = 0
        self.nested_off = 0
        self.nested_size = 0
        self.generic_constraints_off = 0
        self.generic_constraints_size = 0
        self.flags_off = 0
        self.flags_size = 0
        self.unresolved_indirect_off = 0
        self.unresolved_indirect_size = 0
        self.extra_field_info_off = 0
        self.extra_field_info_size = 0
        self._parse_header()

    def _parse_header(self):
        if len(self.raw) < 8:
            raise ValueError("global-metadata.dat too small")
        magic = _u32(self.raw, 0)
        version = _i32(self.raw, 4)
        if magic != IL2CPP_MAGIC:
            raise ValueError("Bad Il2Cpp metadata magic: 0x%08x" % magic)
        if version not in IL2CPP_METADATA_VERSIONS:
            raise ValueError("Unsupported Il2Cpp metadata version: %d" % version)
        self.version = version
        if version <= IL2CPP_METADATA_VERSION_24:
            self._parse_header_v24()
        elif version < IL2CPP_METADATA_VERSION_29:
            self._parse_header_v27()
        else:
            self._parse_header_v29()

    def _parse_header_v24(self):
        sz = struct.calcsize(_IL2CPP_HEADER_FMT_V24)
        if len(self.raw) < sz:
            raise ValueError("Truncated Il2Cpp header (v24)")
        f = struct.unpack_from(_IL2CPP_HEADER_FMT_V24, self.raw, 0)
        (_magic, _ver,
         _str_lit_off, _str_lit_size,
         _str_lit_data_off, _str_lit_data_size,
         self.string_off, self.string_size,
         self.events_off, self.events_size,
         self.properties_off, self.properties_size,
         self.methods_off, self.methods_size,
         self.param_default_off, self.param_default_size,
         self.field_default_off, self.field_default_size,
         self.field_and_param_off, self.field_and_param_size,
         self.field_marshals_off, self.field_marshals_size,
         self.params_off, self.params_size,
         self.fields_off, self.fields_size,
         self.generic_insts_off, self.generic_insts_size,
         self.generic_methods_off, self.generic_methods_size,
         self.generic_containers_off, self.generic_containers_size,
         self.images_off, self.images_size,
         self.assemblies_off, self.assemblies_size) = f
        self.metadata_usage_off = 0
        self.metadata_usage_size = 0
        self.type_defs_off = 0
        self.type_defs_size = 0
        self.interface_offsets_off = 0
        self.interface_offsets_size = 0
        self.nested_off = 0
        self.nested_size = 0
        self.generic_constraints_off = 0
        self.generic_constraints_size = 0
        self.flags_off = 0
        self.flags_size = 0
        self.unresolved_indirect_off = 0
        self.unresolved_indirect_size = 0
        self.extra_field_info_off = 0
        self.extra_field_info_size = 0

    def _parse_header_v27(self):
        sz = struct.calcsize(_IL2CPP_HEADER_FMT_V27)
        if len(self.raw) < sz:
            raise ValueError("Truncated Il2Cpp header (v27)")
        f = struct.unpack_from(_IL2CPP_HEADER_FMT_V27, self.raw, 0)
        (_magic, _ver,
         _str_lit_off, _str_lit_size,
         _str_lit_data_off, _str_lit_data_size,
         self.string_off, self.string_size,
         self.events_off, self.events_size,
         self.properties_off, self.properties_size,
         self.methods_off, self.methods_size,
         self.param_default_off, self.param_default_size,
         self.field_default_off, self.field_default_size,
         self.field_and_param_off, self.field_and_param_size,
         self.field_marshals_off, self.field_marshals_size,
         self.params_off, self.params_size,
         self.fields_off, self.fields_size,
         self.generic_insts_off, self.generic_insts_size,
         self.generic_methods_off, self.generic_methods_size,
         self.generic_containers_off, self.generic_containers_size,
         self.images_off, self.images_size,
         self.assemblies_off, self.assemblies_size,
         self.metadata_usage_off, self.metadata_usage_size,
         self.type_defs_off, self.type_defs_size,
         self.interface_offsets_off, self.interface_offsets_size,
         self.nested_off, self.nested_size) = f
        self.generic_constraints_off = 0
        self.generic_constraints_size = 0
        self.flags_off = 0
        self.flags_size = 0
        self.unresolved_indirect_off = 0
        self.unresolved_indirect_size = 0
        self.extra_field_info_off = 0
        self.extra_field_info_size = 0

    def _parse_header_v29(self):
        sz = struct.calcsize(_IL2CPP_HEADER_FMT_V29)
        if len(self.raw) < sz:
            raise ValueError("Truncated Il2Cpp header (v29)")
        f = struct.unpack_from(_IL2CPP_HEADER_FMT_V29, self.raw, 0)
        (_magic, _ver,
         _str_lit_off, _str_lit_size,
         _str_lit_data_off, _str_lit_data_size,
         self.string_off, self.string_size,
         self.events_off, self.events_size,
         self.properties_off, self.properties_size,
         self.methods_off, self.methods_size,
         self.param_default_off, self.param_default_size,
         self.field_default_off, self.field_default_size,
         self.field_and_param_off, self.field_and_param_size,
         self.field_marshals_off, self.field_marshals_size,
         self.params_off, self.params_size,
         self.fields_off, self.fields_size,
         self.generic_insts_off, self.generic_insts_size,
         self.generic_methods_off, self.generic_methods_size,
         self.generic_containers_off, self.generic_containers_size,
         self.images_off, self.images_size,
         self.assemblies_off, self.assemblies_size,
         self.metadata_usage_off, self.metadata_usage_size,
         self.type_defs_off, self.type_defs_size,
         self.interface_offsets_off, self.interface_offsets_size,
         self.nested_off, self.nested_size,
         self.generic_constraints_off, self.generic_constraints_size,
         self.flags_off, self.flags_size,
         self.unresolved_indirect_off, self.unresolved_indirect_size,
         self.extra_field_info_off, self.extra_field_info_size) = f

    def str_at(self, offset):
        if offset < 0:
            return ""
        return _read_cstr(self.raw, self.string_off + offset)

    def count(self, off, size, item):
        if off <= 0 or size <= 0:
            return 0
        return max(0, size // item)

    def count_typedefs(self):
        if self.version <= IL2CPP_METADATA_VERSION_24:
            return 0
        return self.count(self.type_defs_off, self.type_defs_size, 92)

    def count_methods(self):
        return self.count(self.methods_off, self.methods_size, 36)

    def count_images(self):
        return self.count(self.images_off, self.images_size, 40)

    def count_params(self):
        return self.count(self.params_off, self.params_size, 12)

    def count_fields(self):
        return self.count(self.fields_off, self.fields_size, 8)

    def iter_string_literals(self):
        if self.version <= IL2CPP_METADATA_VERSION_24:
            return
        if len(self.raw) < 8:
            return
        try:
            lit_off = _u32(self.raw, 8)
            lit_size = _i32(self.raw, 12)
            data_off = _u32(self.raw, 16)
            data_size = _i32(self.raw, 20)
        except struct.error:
            return
        n = max(0, lit_size // 8)
        for i in range(n):
            base = lit_off + i * 8
            if base + 8 > len(self.raw):
                break
            length = _u32(self.raw, base)
            data_index = _u32(self.raw, base + 4)
            start = data_off + data_index
            end = start + length
            if 0 <= start < len(self.raw) and 0 < end <= len(self.raw):
                yield self.raw[start:end].decode("utf-8", "replace")

    def iter_images(self):
        if self.images_off == 0 or self.images_size == 0:
            return
        n = self.count_images()
        for i in range(n):
            base = self.images_off + i * 40
            if base + 40 > len(self.raw):
                break
            name_idx = _i32(self.raw, base)
            asm_idx = _i32(self.raw, base + 4)
            type_start = _i32(self.raw, base + 8)
            type_count = _u32(self.raw, base + 12)
            exported_start = _u32(self.raw, base + 16)
            exported_count = _u32(self.raw, base + 20)
            entry_point = _u32(self.raw, base + 24)
            token = _u32(self.raw, base + 28)
            custom_attr_start = _i32(self.raw, base + 32)
            custom_attr_count = _u32(self.raw, base + 36)
            yield {
                "name": self.str_at(name_idx),
                "assembly_index": asm_idx,
                "type_start": type_start,
                "type_count": type_count,
                "exported_start": exported_start,
                "exported_count": exported_count,
                "entry_point": entry_point,
                "token": token,
                "custom_attr_start": custom_attr_start,
                "custom_attr_count": custom_attr_count,
            }

    def iter_typedefs(self):
        if self.version <= IL2CPP_METADATA_VERSION_24:
            return
        n = self.count_typedefs()
        for i in range(n):
            base = self.type_defs_off + i * 92
            if base + 92 > len(self.raw):
                break
            name_idx = _i32(self.raw, base)
            namespace_idx = _i32(self.raw, base + 4)
            byval_idx = _i32(self.raw, base + 8)
            declaring_idx = _i32(self.raw, base + 12)
            parent_idx = _i32(self.raw, base + 16)
            element_idx = _i32(self.raw, base + 20)
            generic_container_idx = _i32(self.raw, base + 24)
            flags = _u32(self.raw, base + 28)
            field_start = _i32(self.raw, base + 32)
            method_start = _i32(self.raw, base + 36)
            event_start = _i32(self.raw, base + 40)
            property_start = _i32(self.raw, base + 44)
            nested_start = _i32(self.raw, base + 48)
            interfaces_start = _i32(self.raw, base + 52)
            vtable_start = _i32(self.raw, base + 56)
            interface_offsets_start = _i32(self.raw, base + 60)
            method_count = _u16(self.raw, base + 64)
            property_count = _u16(self.raw, base + 66)
            field_count = _u16(self.raw, base + 68)
            event_count = _u16(self.raw, base + 70)
            nested_count = _u16(self.raw, base + 72)
            vtable_count = _u16(self.raw, base + 74)
            interfaces_count = _u16(self.raw, base + 76)
            interface_offsets_count = _u16(self.raw, base + 78)
            bitfield = _u32(self.raw, base + 80)
            token = _u32(self.raw, base + 84)
            custom_attr_start = _i32(self.raw, base + 88)
            yield {
                "index": i,
                "name": self.str_at(name_idx),
                "namespace": self.str_at(namespace_idx),
                "byval_type_index": byval_idx,
                "declaring_type_index": declaring_idx,
                "parent_type_index": parent_idx,
                "element_type_index": element_idx,
                "generic_container_index": generic_container_idx,
                "flags": flags,
                "field_start": field_start,
                "method_start": method_start,
                "event_start": event_start,
                "property_start": property_start,
                "nested_start": nested_start,
                "interfaces_start": interfaces_start,
                "vtable_start": vtable_start,
                "interface_offsets_start": interface_offsets_start,
                "method_count": method_count,
                "property_count": property_count,
                "field_count": field_count,
                "event_count": event_count,
                "nested_count": nested_count,
                "vtable_count": vtable_count,
                "interfaces_count": interfaces_count,
                "interface_offsets_count": interface_offsets_count,
                "bitfield": bitfield,
                "token": token,
            }

    def iter_methods(self):
        if self.methods_off == 0 or self.methods_size == 0:
            return
        n = self.count_methods()
        for i in range(n):
            base = self.methods_off + i * 36
            if base + 36 > len(self.raw):
                break
            name_idx = _i32(self.raw, base)
            declaring_type = _i32(self.raw, base + 4)
            return_type = _i32(self.raw, base + 8)
            param_start = _i32(self.raw, base + 12)
            custom_attr_start = _i32(self.raw, base + 16)
            custom_attr_count = _u32(self.raw, base + 20)
            generic_container_index = _i32(self.raw, base + 24)
            token = _u32(self.raw, base + 28)
            flags = _u16(self.raw, base + 32)
            iflags = _u16(self.raw, base + 34)
            yield {
                "index": i,
                "name": self.str_at(name_idx),
                "declaring_type": declaring_type,
                "return_type": return_type,
                "param_start": param_start,
                "custom_attr_start": custom_attr_start,
                "custom_attr_count": custom_attr_count,
                "generic_container_index": generic_container_index,
                "token": token,
                "flags": flags,
                "iflags": iflags,
            }

    def iter_params(self):
        if self.params_off == 0 or self.params_size == 0:
            return
        n = self.count_params()
        for i in range(n):
            base = self.params_off + i * 12
            if base + 12 > len(self.raw):
                break
            name_idx = _i32(self.raw, base)
            token = _u32(self.raw, base + 4)
            type_index = _i32(self.raw, base + 8)
            yield {
                "index": i,
                "name": self.str_at(name_idx),
                "token": token,
                "type_index": type_index,
            }

    def iter_fields(self):
        if self.fields_off == 0 or self.fields_size == 0:
            return
        n = self.count_fields()
        for i in range(n):
            base = self.fields_off + i * 8
            if base + 8 > len(self.raw):
                break
            name_idx = _i32(self.raw, base)
            token = _u32(self.raw, base + 4)
            yield {
                "index": i,
                "name": self.str_at(name_idx),
                "token": token,
            }


class Il2CppBinary:
    def __init__(self, path, bits=64):
        self.path = path
        self.bits = bits
        self.data = b""
        self._fp = None

    def load(self):
        with open(self.path, "rb") as f:
            self.data = f.read()
        if self.data[:4] == b"\x7fELF":
            ei_class = self.data[4]
            self.bits = 64 if ei_class == 2 else 32
        elif self.data[:2] == b"MZ":
            pe_off = _u32(self.data, 0x3c) if len(self.data) >= 0x40 else 0
            if pe_off and self.data[pe_off:pe_off + 4] == b"PE\x00\x00":
                machine = _u16(self.data, pe_off + 4)
                self.bits = 64 if machine == 0x8664 else 32
        elif self.data[:4] == b"\xfe\xed\xfa\xce" or self.data[:4] == b"\xce\xfa\xed\xfe":
            self.bits = 32
        elif self.data[:4] == b"\xfe\xed\xfa\xcf" or self.data[:4] == b"\xcf\xfa\xed\xfe":
            self.bits = 64
        return self

    def symbols(self):
        readelf = _find_tool(_READELF_NAMES)
        if not readelf:
            return []
        try:
            r = subprocess.run([readelf, "-s", "-W", self.path],
                               capture_output=True, text=True, timeout=60,
                               stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            return []
        out = []
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 8:
                continue
            try:
                addr = int(parts[1], 16)
            except ValueError:
                continue
            name = parts[-1]
            if name:
                out.append((addr, name))
        return out


class Il2CppInspector:
    def __init__(self, binary_path, metadata_path, outdir, log_mgr=None):
        self.binary_path = binary_path
        self.metadata_path = metadata_path
        self.outdir = os.path.abspath(outdir)
        self.log_mgr = log_mgr
        self.metadata = None
        self.binary = None
        self.types = []
        self.methods = []
        self.params = []
        self.fields = []
        self.images = []

    def _log(self, msg, level="info"):
        if self.log_mgr:
            self.log_mgr.add(msg, level)
            if level in ("info", "success", "warn", "error"):
                self.log_mgr.step()

    def load(self):
        with open(self.metadata_path, "rb") as f:
            md_data = f.read()
        self.metadata = Il2CppMetadata(md_data)
        self.binary = Il2CppBinary(self.binary_path).load()
        self.types = list(self.metadata.iter_typedefs())
        self.methods = list(self.metadata.iter_methods())
        self.params = list(self.metadata.iter_params())
        self.fields = list(self.metadata.iter_fields())
        self.images = list(self.metadata.iter_images())
        self._log("Loaded Il2Cpp metadata v%d (%d types, %d methods, %d images)" %
                  (self.metadata.version, len(self.types), len(self.methods),
                   len(self.images)), "info")
        return self

    def write_dump_cs(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("/* Il2Cpp dump generated by Elit-f (Il2CppInspector module) */\n")
            f.write("/* metadata version: %d */\n\n" % self.metadata.version)
            for image in self.images:
                f.write("// Image: %s (types %d..%d)\n" %
                        (image["name"], image["type_start"],
                         image["type_start"] + image["type_count"]))
            f.write("\n")
            for t in self.types:
                self._write_type(f, t)
        return path

    def _write_type(self, f, t):
        ns = t["namespace"]
        name = t["name"] or "_Unknown"
        flags = t["flags"]
        vis = _TYPE_ATTR_VIS.get(flags & 0x07, "private")
        if t["declaring_type_index"] >= 0:
            vis = "nested " + vis
        kind = "class"
        is_interface = (flags & 0x20) != 0
        is_abstract = (flags & 0x80) != 0
        is_sealed = (flags & 0x100) != 0
        is_enum = (t["element_type_index"] >= 0 and t["parent_type_index"] >= 0
                   and "Enum" in self._type_name(t["parent_type_index"]))
        if is_interface:
            kind = "interface"
        elif is_enum:
            kind = "enum"
        f.write("\n")
        if ns:
            f.write("namespace %s\n{\n" % ns)
        f.write(vis)
        if is_abstract and kind == "class":
            f.write(" abstract")
        if is_sealed and kind == "class":
            f.write(" sealed")
        f.write(" %s %s" % (kind, name))
        if t["generic_container_index"] >= 0:
            f.write("<T>")
        f.write(" // TypeDefIndex: %d\n" % t["index"])
        f.write("{\n")
        for fi in range(t["field_count"]):
            field_idx = t["field_start"] + fi
            if 0 <= field_idx < len(self.fields):
                field = self.fields[field_idx]
                f.write("    public object %s; // 0x%08x\n" %
                        (field["name"] or "field_%d" % field_idx,
                         field["token"]))
        for mi in range(t["method_count"]):
            meth_idx = t["method_start"] + mi
            if 0 <= meth_idx < len(self.methods):
                m = self.methods[meth_idx]
                ret = self._type_name(m["return_type"])
                params = []
                for pi in range(8):
                    pidx = m["param_start"] + pi
                    if 0 <= pidx < len(self.params):
                        p = self.params[pidx]
                        params.append("%s %s" % (self._type_name(p["type_index"]),
                                                  p["name"] or "arg%d" % pi))
                f.write("    %s %s(%s); // 0x%08x\n" %
                        (ret, m["name"] or "method_%d" % meth_idx,
                         ", ".join(params) or "", m["token"]))
        f.write("}\n")
        if ns:
            f.write("} // namespace %s\n" % ns)

    def _type_name(self, type_index):
        if type_index is None or type_index < 0:
            return "void"
        if type_index < len(self.types):
            t = self.types[type_index]
            if t["namespace"]:
                return "%s.%s" % (t["namespace"], t["name"])
            return t["name"] or "_Unknown"
        return "Type_%d" % type_index

    def write_symbol_map(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for t in self.types:
                ns = t["namespace"]
                name = t["name"] or "Type_%d" % t["index"]
                full = "%s.%s" % (ns, name) if ns else name
                safe = _safe_name(full)
                for mi in range(t["method_count"]):
                    meth_idx = t["method_start"] + mi
                    if 0 <= meth_idx < len(self.methods):
                        m = self.methods[meth_idx]
                        mname = m["name"] or "method_%d" % meth_idx
                        sym = "Il2Cpp_%s_%s" % (safe, _safe_name(mname))
                        f.write("0x%08x %s\n" % (m["token"], sym))
        return path

    def write_ida_script(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("import idaapi\n")
            f.write("import idc\n\n")
            f.write("print('Il2CppInspector (Elit-f): applying Il2Cpp names from metadata tokens')\n")
            f.write("print('NOTE: addresses below are metadata tokens (0x06xxxxxx), not virtual addresses.')\n")
            f.write("print('For real vaddr mapping, parse CodeRegistration/methodPointers from libil2cpp.so.')\n\n")
            f.write("_NAMES = [\n")
            for t in self.types:
                ns = t["namespace"]
                name = t["name"] or "Type_%d" % t["index"]
                full = "%s.%s" % (ns, name) if ns else name
                safe = _safe_name(full)
                for mi in range(t["method_count"]):
                    meth_idx = t["method_start"] + mi
                    if 0 <= meth_idx < len(self.methods):
                        m = self.methods[meth_idx]
                        mname = m["name"] or "method_%d" % meth_idx
                        sym = "Il2Cpp_%s_%s" % (safe, _safe_name(mname))
                        f.write("    (0x%08x, '%s'),\n" % (m["token"], sym))
            f.write("]\n\n")
            f.write("for ea, name in _NAMES:\n")
            f.write("    try:\n")
            f.write("        idc.set_name(ea, name, idaapi.SN_NOWARN | idaapi.SN_NOCHECK)\n")
            f.write("    except Exception as e:\n")
            f.write("        print('rename failed @ 0x%x: %s' % (ea, e))\n\n")
            f.write("print('Il2CppInspector: done (%d entries)' % len(_NAMES))\n")
        return path

    def write_ghidra_script(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Ghidra script — Il2Cpp symbol names from Elit-f\n")
            f.write("# @category Il2Cpp\n\n")
            f.write("from ghidra.program.model.symbol import SourceType\n\n")
            f.write("print('Il2CppInspector (Elit-f): applying Il2Cpp names from metadata tokens')\n")
            f.write("print('NOTE: addresses below are metadata tokens (0x06xxxxxx), not virtual addresses.')\n\n")
            f.write("names = [\n")
            for t in self.types:
                ns = t["namespace"]
                name = t["name"] or "Type_%d" % t["index"]
                full = "%s.%s" % (ns, name) if ns else name
                safe = _safe_name(full)
                for mi in range(t["method_count"]):
                    meth_idx = t["method_start"] + mi
                    if 0 <= meth_idx < len(self.methods):
                        m = self.methods[meth_idx]
                        mname = m["name"] or "method_%d" % meth_idx
                        sym = "Il2Cpp_%s_%s" % (safe, _safe_name(mname))
                        f.write("    (0x%08x, \"%s\"),\n" % (m["token"], sym))
            f.write("]\n\n")
            f.write("for ea, name in names:\n")
            f.write("    addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(ea)\n")
            f.write("    currentProgram.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED, True)\n")
        return path

    def write_string_literal_dump(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            n = 0
            for s in self.metadata.iter_string_literals():
                f.write("[%d] %s\n" % (n, s))
                n += 1
            f.write("// total: %d\n" % n)
        return path

    def write_metadata_summary(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("Il2Cpp metadata summary\n")
            f.write("=======================\n")
            f.write("file: %s\n" % self.metadata_path)
            f.write("version: %d\n" % self.metadata.version)
            f.write("images: %d\n" % len(self.images))
            f.write("types: %d\n" % len(self.types))
            f.write("methods: %d\n" % len(self.methods))
            f.write("fields: %d\n" % len(self.fields))
            f.write("params: %d\n" % len(self.params))
            f.write("\nImages:\n")
            for img in self.images:
                f.write("- %s (types %d..%d, token 0x%08x)\n" %
                        (img["name"], img["type_start"],
                         img["type_start"] + img["type_count"], img["token"]))
        return path

    def run_full(self):
        os.makedirs(self.outdir, exist_ok=True)
        out = os.path.join(self.outdir, "il2cpp_output")
        os.makedirs(out, exist_ok=True)
        self._log("Writing dump.cs...", "info")
        self.write_dump_cs(os.path.join(out, "dump.cs"))
        self._log("Writing symbol map...", "info")
        self.write_symbol_map(os.path.join(out, "il2cpp_symbols.txt"))
        self._log("Writing IDA Python script...", "info")
        self.write_ida_script(os.path.join(out, "il2cpp_ida.py"))
        self._log("Writing Ghidra script...", "info")
        self.write_ghidra_script(os.path.join(out, "il2cpp_ghidra.py"))
        self._log("Writing string literals...", "info")
        self.write_string_literal_dump(os.path.join(out, "string_literals.txt"))
        self._log("Writing metadata summary...", "info")
        self.write_metadata_summary(os.path.join(out, "metadata_summary.txt"))
        self._log("Il2Cpp analysis complete -> %s" % out, "success")
        return out


def _find_in_dir(indir, name):
    for root, dirs, files in os.walk(indir):
        if name in files:
            return os.path.join(root, name)
    return None


def find_il2cpp_targets(indir):
    if os.path.isfile(indir) and zipfile.is_zipfile(indir):
        out = []
        with zipfile.ZipFile(indir, "r") as zf:
            for n in zf.namelist():
                if n.endswith(_LIBIL2CPP_NAME) or n.endswith(_GLOBAL_METADATA_NAME):
                    out.append((n, n))
        return out
    if os.path.isdir(indir):
        lib = _find_in_dir(indir, _LIBIL2CPP_NAME)
        md = _find_in_dir(indir, _GLOBAL_METADATA_NAME)
        if lib and md:
            return [(lib, md)]
    return []


_ABI_PREFERENCE = ("arm64-v8a", "armeabi-v7a", "x86", "x86_64")


def _is_safe_zip_entry(name):
    if not name:
        return False
    norm = name.replace("\\", "/")
    if norm.startswith("/"):
        return False
    parts = norm.split("/")
    if any(p in ("..", ".") for p in parts):
        return False
    if len(name) > 1 and name[1] == ":":
        return False
    return True


def extract_targets(archive_or_dir, work_dir):
    os.makedirs(work_dir, exist_ok=True)
    if os.path.isfile(archive_or_dir) and zipfile.is_zipfile(archive_or_dir):
        with zipfile.ZipFile(archive_or_dir, "r") as zf:
            names = [n for n in zf.namelist()
                     if n.endswith(_LIBIL2CPP_NAME) or n.endswith(_GLOBAL_METADATA_NAME)]
            if not names:
                raise ValueError("APK/XAPK ne contient ni libil2cpp.so ni global-metadata.dat")
            for n in names:
                if not _is_safe_zip_entry(n):
                    raise ValueError("Entrée ZIP invalide (path traversal): %s" % n)
            lib_candidates = [n for n in names if n.endswith(_LIBIL2CPP_NAME)]
            md_candidates = [n for n in names if n.endswith(_GLOBAL_METADATA_NAME)]
            lib_path = _select_preferred_abi(lib_candidates)
            md_path = md_candidates[0] if len(md_candidates) == 1 else \
                _select_preferred_abi(md_candidates)
            if not lib_path or not md_path:
                raise ValueError("Cibles Il2Cpp incomplètes dans l'APK")
            zf.extract(lib_path, work_dir)
            zf.extract(md_path, work_dir)
            lib_disk = os.path.join(work_dir, lib_path)
            md_disk = os.path.join(work_dir, md_path)
            if not os.path.isfile(lib_disk) or not os.path.isfile(md_disk):
                raise ValueError("Extraction Il2Cpp échouée: fichiers absents")
            return (lib_disk, md_disk)
    if os.path.isdir(archive_or_dir):
        lib = _find_in_dir(archive_or_dir, _LIBIL2CPP_NAME)
        md = _find_in_dir(archive_or_dir, _GLOBAL_METADATA_NAME)
        if not lib or not md:
            raise ValueError("Répertoire sans libil2cpp.so / global-metadata.dat")
        return (lib, md)
    raise ValueError("Cible Il2Cpp invalide: %s" % archive_or_dir)


def _select_preferred_abi(candidates):
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    for abi in _ABI_PREFERENCE:
        for c in candidates:
            if ("/" + abi + "/") in c.replace("\\", "/"):
                return c
    return sorted(candidates)[0]


def run_il2cpp_analysis(indir, outdir, log_mgr=None, ui=None):
    import tempfile
    import shutil
    work_dir = tempfile.mkdtemp(prefix="elitf_il2cpp_")
    try:
        try:
            lib_path, md_path = extract_targets(indir, work_dir)
        except Exception as exc:
            if log_mgr:
                log_mgr.add("Erreur extraction Il2Cpp: %s" % exc, "error")
            raise
        inspector = Il2CppInspector(lib_path, md_path, outdir, log_mgr=log_mgr)
        inspector.load()
        return inspector.run_full()
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def main_cli(indir, outdir):
    out = run_il2cpp_analysis(indir, outdir)
    print("Il2Cpp output: %s" % out)
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: elitf_il2cpp.py <indir-or-apk> <outdir>")
        sys.exit(1)
    sys.exit(main_cli(sys.argv[1], sys.argv[2]))
