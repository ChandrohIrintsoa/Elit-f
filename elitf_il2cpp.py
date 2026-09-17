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
    16, 17, 18, 19, 20, 21, 22, 23, 24, 27, 28, 29, 31,
)

IL2CPP_METADATA_VERSION_24 = 24
IL2CPP_METADATA_VERSION_27 = 27
IL2CPP_METADATA_VERSION_29 = 29
IL2CPP_METADATA_VERSION_31 = 31

_HEADER_FIELD_ORDER = (
    ("sanity", "I"),
    ("version", "i"),
    ("stringLiteralOffset", "I"),
    ("stringLiteralSize", "i"),
    ("stringLiteralDataOffset", "I"),
    ("stringLiteralDataSize", "i"),
    ("stringOffset", "I"),
    ("stringSize", "i"),
    ("eventsOffset", "I"),
    ("eventsSize", "i"),
    ("propertiesOffset", "I"),
    ("propertiesSize", "i"),
    ("methodsOffset", "I"),
    ("methodsSize", "i"),
    ("parameterDefaultValuesOffset", "I"),
    ("parameterDefaultValuesSize", "i"),
    ("fieldDefaultValuesOffset", "I"),
    ("fieldDefaultValuesSize", "i"),
    ("fieldAndParameterDefaultValueDataOffset", "I"),
    ("fieldAndParameterDefaultValueDataSize", "i"),
    ("fieldMarshaledSizesOffset", "i"),
    ("fieldMarshaledSizesSize", "i"),
    ("parametersOffset", "I"),
    ("parametersSize", "i"),
    ("fieldsOffset", "I"),
    ("fieldsSize", "i"),
    ("genericParametersOffset", "I"),
    ("genericParametersSize", "i"),
    ("genericParameterConstraintsOffset", "I"),
    ("genericParameterConstraintsSize", "i"),
    ("genericContainersOffset", "I"),
    ("genericContainersSize", "i"),
    ("nestedTypesOffset", "I"),
    ("nestedTypesSize", "i"),
    ("interfacesOffset", "I"),
    ("interfacesSize", "i"),
    ("vtableMethodsOffset", "I"),
    ("vtableMethodsSize", "i"),
    ("interfaceOffsetsOffset", "i"),
    ("interfaceOffsetsSize", "i"),
    ("typeDefinitionsOffset", "I"),
    ("typeDefinitionsSize", "i"),
    ("rgctxEntriesOffset", "I", 0, 24.1),
    ("rgctxEntriesCount", "i", 0, 24.1),
    ("imagesOffset", "I"),
    ("imagesSize", "i"),
    ("assembliesOffset", "I"),
    ("assembliesSize", "i"),
    ("metadataUsageListsOffset", "I", 19, 24.5),
    ("metadataUsageListsCount", "i", 19, 24.5),
    ("metadataUsagePairsOffset", "I", 19, 24.5),
    ("metadataUsagePairsCount", "i", 19, 24.5),
    ("fieldRefsOffset", "I", 19, None),
    ("fieldRefsSize", "i", 19, None),
    ("referencedAssembliesOffset", "i", 20, None),
    ("referencedAssembliesSize", "i", 20, None),
    ("attributesInfoOffset", "I", 21, 27.2),
    ("attributesInfoCount", "i", 21, 27.2),
    ("attributeTypesOffset", "I", 21, 27.2),
    ("attributeTypesCount", "i", 21, 27.2),
    ("attributeDataOffset", "I", 29, None),
    ("attributeDataSize", "i", 29, None),
    ("attributeDataRangeOffset", "I", 29, None),
    ("attributeDataRangeSize", "i", 29, None),
    ("unresolvedVirtualCallParameterTypesOffset", "i", 22, None),
    ("unresolvedVirtualCallParameterTypesSize", "i", 22, None),
    ("unresolvedVirtualCallParameterRangesOffset", "i", 22, None),
    ("unresolvedVirtualCallParameterRangesSize", "i", 22, None),
    ("windowsRuntimeTypeNamesOffset", "i", 23, None),
    ("windowsRuntimeTypeNamesSize", "i", 23, None),
    ("windowsRuntimeStringsOffset", "i", 27, None),
    ("windowsRuntimeStringsSize", "i", 27, None),
    ("exportedTypeDefinitionsOffset", "i", 24, None),
    ("exportedTypeDefinitionsSize", "i", 24, None),
)


def _field_present(field, version, sub):
    if len(field) <= 2:
        return True
    mn = field[2] if len(field) > 2 else 0
    mx = field[3] if len(field) > 3 else None
    if mn and version < mn:
        return False
    if mx is not None and version > mx:
        return False
    return True


def _build_header_struct(version):
    fields = [(n, t) for n, t, *rest in _HEADER_FIELD_ORDER if _field_present((n, t, *rest), version, 0)]
    fmt = "<" + "".join(t for _, t in fields)
    return fmt, [n for n, _ in fields]


def _read_header(buf, version):
    fmt, names = _build_header_struct(version)
    sz = struct.calcsize(fmt)
    if len(buf) < sz:
        raise ValueError("Truncated Il2Cpp header (v%d, need %d, got %d)" % (version, sz, len(buf)))
    values = struct.unpack_from(fmt, buf, 0)
    header = dict(zip(names, values))
    header["_size"] = sz
    return header


def _detect_sub_version(buf, version, header):
    if version != 24:
        return float(version)
    if header.get("stringLiteralOffset") == 264:
        return 24.0
    if version == 24 and header.get("typeDefinitionsSize", 0) > 0:
        td_count = header["typeDefinitionsSize"] // 92
        if td_count > 0:
            first_td_off = header["typeDefinitionsOffset"]
            if first_td_off and first_td_off + 92 <= len(buf):
                token = struct.unpack_from("<I", buf, first_td_off + 80)[0]
                if token == 1:
                    return 24.1
                return 24.2
    return 24.1


_TYPE_ATTR_VIS = {
    0x00: "public", 0x01: "famorassem", 0x02: "assembly",
    0x03: "family", 0x04: "famandassem", 0x05: "private",
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


def _typedef_stride(version):
    if version <= 22:
        return 108
    if version <= 24.1:
        return 92
    return 88


def _method_stride(version):
    if version <= 24.1:
        return 60
    if version < 31:
        return 32
    return 36


def _image_stride(version):
    if version <= 18:
        return 20
    if version <= 23:
        return 24
    if version <= 24.0:
        return 32
    return 40


def _param_stride(version):
    if version <= 24.0:
        return 16
    return 12


def _field_stride(version):
    if version <= 18:
        return 12
    if version <= 24.0:
        return 16
    return 12


class Il2CppMetadata:
    def __init__(self, data):
        self.raw = data
        self.version = 0
        self.sub_version = 0.0
        self.header = {}
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
        self.header = _read_header(self.raw, version)
        self.sub_version = _detect_sub_version(self.raw, version, self.header)

    def _offset_size(self, name):
        off = self.header.get(name + "Offset", 0)
        size = self.header.get(name + "Size", 0)
        if isinstance(off, int) and off < 0:
            off = 0
        if isinstance(size, int) and size < 0:
            size = 0
        return off, size

    def str_at(self, offset):
        if offset < 0:
            return ""
        base = self.header.get("stringOffset", 0)
        return _read_cstr(self.raw, base + offset)

    def _count(self, name, item_size):
        off, size = self._offset_size(name)
        if off <= 0 or size <= 0 or item_size <= 0:
            return 0
        return max(0, size // item_size)

    def count_typedefs(self):
        return self._count("typeDefinitions", _typedef_stride(self.sub_version))

    def count_methods(self):
        return self._count("methods", _method_stride(self.sub_version))

    def count_images(self):
        return self._count("images", _image_stride(self.sub_version))

    def count_params(self):
        return self._count("parameters", _param_stride(self.sub_version))

    def count_fields(self):
        return self._count("fields", _field_stride(self.sub_version))

    def iter_string_literals(self):
        off, size = self._offset_size("stringLiteral")
        data_off, data_size = self._offset_size("stringLiteralData")
        if off <= 0 or size <= 0:
            return
        n = max(0, size // 8)
        for i in range(n):
            base = off + i * 8
            if base + 8 > len(self.raw):
                break
            length = _u32(self.raw, base)
            data_index = _i32(self.raw, base + 4)
            start = data_off + data_index
            end = start + length
            if 0 <= start < len(self.raw) and 0 < end <= len(self.raw):
                yield self.raw[start:end].decode("utf-8", "replace")

    def iter_images(self):
        off, size = self._offset_size("images")
        if off <= 0 or size <= 0:
            return
        stride = _image_stride(self.sub_version)
        n = size // stride
        for i in range(n):
            base = off + i * stride
            if base + stride > len(self.raw):
                break
            name_idx = _i32(self.raw, base)
            asm_idx = _i32(self.raw, base + 4)
            type_start = _i32(self.raw, base + 8)
            type_count = _u32(self.raw, base + 12)
            exported_start = _u32(self.raw, base + 16) if self.version >= 24 else 0
            exported_count = _u32(self.raw, base + 20) if self.version >= 24 else 0
            entry_point_idx = _i32(self.raw, base + 24 if self.version >= 24 else 16)
            token_off = base + 28 if self.version >= 24 else 20
            token = _u32(self.raw, token_off) if self.version >= 19 else 0
            yield {
                "name": self.str_at(name_idx),
                "assembly_index": asm_idx,
                "type_start": type_start,
                "type_count": type_count,
                "exported_start": exported_start,
                "exported_count": exported_count,
                "entry_point": entry_point_idx,
                "token": token,
            }

    def iter_typedefs(self):
        off, size = self._offset_size("typeDefinitions")
        if off <= 0 or size <= 0:
            return
        stride = _typedef_stride(self.sub_version)
        n = size // stride
        for i in range(n):
            base = off + i * stride
            if base + stride > len(self.raw):
                break
            name_idx = _i32(self.raw, base)
            ns_idx = _i32(self.raw, base + 4)
            cur = base + 8
            if self.sub_version <= 24:
                cur += 4
            byval_idx = _i32(self.raw, cur); cur += 4
            if self.sub_version <= 24.5:
                byref_idx = _i32(self.raw, cur); cur += 4
            else:
                byref_idx = -1
            declaring_idx = _i32(self.raw, cur); cur += 4
            parent_idx = _i32(self.raw, cur); cur += 4
            element_idx = _i32(self.raw, cur); cur += 4
            if self.sub_version <= 24.1:
                cur += 8
            generic_container_idx = _i32(self.raw, cur); cur += 4
            if self.sub_version <= 22:
                cur += 8
            if 21 <= self.sub_version <= 22:
                cur += 8
            flags = _u32(self.raw, cur); cur += 4
            field_start = _i32(self.raw, cur); cur += 4
            method_start = _i32(self.raw, cur); cur += 4
            event_start = _i32(self.raw, cur); cur += 4
            property_start = _i32(self.raw, cur); cur += 4
            nested_start = _i32(self.raw, cur); cur += 4
            interfaces_start = _i32(self.raw, cur); cur += 4
            vtable_start = _i32(self.raw, cur); cur += 4
            interface_offsets_start = _i32(self.raw, cur); cur += 4
            method_count = _u16(self.raw, cur); cur += 2
            property_count = _u16(self.raw, cur); cur += 2
            field_count = _u16(self.raw, cur); cur += 2
            event_count = _u16(self.raw, cur); cur += 2
            nested_count = _u16(self.raw, cur); cur += 2
            vtable_count = _u16(self.raw, cur); cur += 2
            interfaces_count = _u16(self.raw, cur); cur += 2
            interface_offsets_count = _u16(self.raw, cur); cur += 2
            bitfield = _u32(self.raw, cur); cur += 4
            token = _u32(self.raw, cur) if self.version >= 19 else 0
            yield {
                "index": i,
                "name": self.str_at(name_idx),
                "namespace": self.str_at(ns_idx),
                "byval_type_index": byval_idx,
                "byref_type_index": byref_idx,
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
        off, size = self._offset_size("methods")
        if off <= 0 or size <= 0:
            return
        stride = _method_stride(self.sub_version)
        n = size // stride
        for i in range(n):
            base = off + i * stride
            if base + stride > len(self.raw):
                break
            name_idx = _i32(self.raw, base)
            declaring_type = _i32(self.raw, base + 4)
            return_type = _i32(self.raw, base + 8)
            cur = base + 12
            if self.version >= 31:
                return_param_token = _i32(self.raw, cur); cur += 4
            else:
                return_param_token = 0
            param_start = _i32(self.raw, cur); cur += 4
            if self.sub_version <= 24:
                cur += 4
            generic_container_idx = _i32(self.raw, cur); cur += 4
            if self.sub_version <= 24.1:
                cur += 16
            token = _u32(self.raw, cur); cur += 4
            flags = _u16(self.raw, cur); cur += 2
            iflags = _u16(self.raw, cur); cur += 2
            slot = _u16(self.raw, cur); cur += 2
            param_count = _u16(self.raw, cur); cur += 2
            yield {
                "index": i,
                "name": self.str_at(name_idx),
                "declaring_type": declaring_type,
                "return_type": return_type,
                "return_parameter_token": return_param_token,
                "param_start": param_start,
                "param_count": param_count,
                "generic_container_index": generic_container_idx,
                "token": token,
                "flags": flags,
                "iflags": iflags,
                "slot": slot,
            }

    def iter_params(self):
        off, size = self._offset_size("parameters")
        if off <= 0 or size <= 0:
            return
        stride = _param_stride(self.sub_version)
        n = size // stride
        for i in range(n):
            base = off + i * stride
            if base + stride > len(self.raw):
                break
            name_idx = _i32(self.raw, base)
            token = _u32(self.raw, base + 4)
            if self.sub_version <= 24.0:
                cur = base + 8
                if self.sub_version <= 24:
                    cur += 4
                type_index = _i32(self.raw, cur)
            else:
                type_index = _i32(self.raw, base + 8)
            yield {
                "index": i,
                "name": self.str_at(name_idx),
                "token": token,
                "type_index": type_index,
            }

    def iter_fields(self):
        off, size = self._offset_size("fields")
        if off <= 0 or size <= 0:
            return
        stride = _field_stride(self.sub_version)
        n = size // stride
        for i in range(n):
            base = off + i * stride
            if base + stride > len(self.raw):
                break
            name_idx = _i32(self.raw, base)
            if self.sub_version <= 24.0:
                type_index = _i32(self.raw, base + 4)
                token = _u32(self.raw, base + 8) if self.version >= 19 else 0
                if self.sub_version <= 18:
                    token = 0
            else:
                type_index = _i32(self.raw, base + 4)
                token = _u32(self.raw, base + 8) if self.version >= 19 else 0
            yield {
                "index": i,
                "name": self.str_at(name_idx),
                "type_index": type_index,
                "token": token,
            }


class Il2CppBinary:
    def __init__(self, path, bits=64):
        self.path = path
        self.bits = bits
        self.data = b""

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
        elif self.data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
            self.bits = 32
        elif self.data[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
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
        self._log("Loaded Il2Cpp metadata v%s (sub %s) — %d types, %d methods, %d images" %
                  (self.metadata.version, self.metadata.sub_version,
                   len(self.types), len(self.methods), len(self.images)), "info")
        return self

    def write_dump_cs(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("/* Il2Cpp dump generated by Elit-f (Il2CppInspector module) */\n")
            f.write("/* metadata version: %s (sub %s) */\n\n" %
                    (self.metadata.version, self.metadata.sub_version))
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
                n_params = m.get("param_count", 8) or 8
                n_params = min(n_params, 8)
                for pi in range(n_params):
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
            f.write("version: %s (sub %s)\n" % (self.metadata.version, self.metadata.sub_version))
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
                if n.endswith("libil2cpp.so") or n.endswith("global-metadata.dat"):
                    out.append((n, n))
        return out
    if os.path.isdir(indir):
        lib = _find_in_dir(indir, "libil2cpp.so")
        md = _find_in_dir(indir, "global-metadata.dat")
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
                     if n.endswith("libil2cpp.so") or n.endswith("global-metadata.dat")]
            if not names:
                raise ValueError("APK/XAPK ne contient ni libil2cpp.so ni global-metadata.dat")
            for n in names:
                if not _is_safe_zip_entry(n):
                    raise ValueError("Entrée ZIP invalide (path traversal): %s" % n)
            lib_candidates = [n for n in names if n.endswith("libil2cpp.so")]
            md_candidates = [n for n in names if n.endswith("global-metadata.dat")]
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
        lib = _find_in_dir(archive_or_dir, "libil2cpp.so")
        md = _find_in_dir(archive_or_dir, "global-metadata.dat")
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
