import io
import os
import re
import requests
import sys
import zipfile
import zlib
from struct import unpack

from elftools.elf.elffile import ELFFile

def _va_to_file_offset(elf, va):
    for seg in elf.iter_segments():
        if seg.header.p_type == 'PT_LOAD':
            if seg.header.p_vaddr <= va < seg.header.p_vaddr + seg.header.p_filesz:
                return va - seg.header.p_vaddr + seg.header.p_offset
    return None

def extract_snapshot_hash_flags(libapp_file):
    with open(libapp_file, 'rb') as f:
        elf = ELFFile(f)
        dynsym = elf.get_section_by_name('.dynsym')
        if dynsym is None:
            raise ValueError('No .dynsym section found in ' + libapp_file)
        syms = (dynsym.get_symbol_by_name('_kDartVmSnapshotData') or
                dynsym.get_symbol_by_name('_kDartSnapshotData'))
        if not syms:
            raise ValueError('Symbol _kDartVmSnapshotData/_kDartSnapshotData not found in ' + libapp_file)
        sym = syms[0]
        if 0 < sym['st_size'] < 52:
            raise ValueError(f"Snapshot data symbol too small: {sym['st_size']}")

        offset = _va_to_file_offset(elf, sym['st_value'])
        if offset is None:
            raise ValueError(f'Cannot resolve virtual address 0x{sym["st_value"]:x} to file offset')

        f.seek(offset + 20)
        raw_hash = f.read(32)
        if not re.fullmatch(rb'[0-9a-f]{32}', raw_hash):
            raise ValueError('Invalid or truncated snapshot hash')
        snapshot_hash = raw_hash.decode('ascii')
        data = f.read(256)
        null_pos = data.find(b'\x00')
        if null_pos == -1:
            raise ValueError('Unterminated snapshot flags')
        flags = data[:null_pos].decode('ascii', errors='replace').strip().split(' ')
        flags = [f for f in flags if f]

    return snapshot_hash, flags

def extract_libflutter_info(libflutter_file):
    with open(libflutter_file, 'rb') as f:
        elf = ELFFile(f)
        if elf.header.e_machine == 'EM_AARCH64':
            arch = 'arm64'
        elif elf.header.e_machine == 'EM_X86_64':
            arch = 'x64'
        else:
            raise ValueError(f"Unsupported architecture: {elf.header.e_machine}")

        section = elf.get_section_by_name('.rodata')
        if section is None:
            raise ValueError('No .rodata section found in ' + libflutter_file)
        data = section.data()

        sha_hashes = re.findall(rb'\x00([a-f0-9]{40})(?=\x00)', data)
        engine_ids = [h.decode() for h in sha_hashes]
        engine_ids = list(dict.fromkeys(engine_ids))

        m = re.search(br'\x00([\d\w\.-]+) \((stable|beta|dev)\)', data)
        if m is None:
            dart_version = None
        else:
            dart_version = m.group(1).decode()

    return engine_ids, dart_version, arch

def get_dart_sdk_url_size(engine_ids, os_name='android', arch='arm64'):
    os_map = {'android': 'linux', 'ios': 'darwin', 'macos': 'darwin'}
    arch_map = {'arm64': 'arm64', 'x64': 'x64'}
    os_sdk = os_map.get(os_name, 'linux')
    arch_sdk = arch_map.get(arch, 'arm64')
    for engine_id in engine_ids:
        base = f'https://storage.googleapis.com/flutter_infra_release/flutter/{engine_id}'
        candidates = (
            f'{base}/dart-sdk-{os_sdk}-{arch_sdk}.zip',
            f'{base}/dart-sdk-windows-x64.zip',
        )
        for url in candidates:
            try:
                resp = requests.head(url, timeout=30)
            except requests.RequestException:
                continue
            if resp.status_code == 200:
                content_length = resp.headers.get('Content-Length')
                if content_length:
                    sdk_size = int(content_length)
                else:
                    sdk_size = 0
                return engine_id, url, sdk_size

    return None, None, None

def get_dart_commit(url):
    if url is None:
        return None, None
    try:
        with requests.get(url, headers={"Range": "bytes=0-65535"}, stream=True, timeout=60) as response:
            if response.status_code not in (200, 206):
                return None, None
            chunks = bytearray()
            for chunk in response.iter_content(chunk_size=4096):
                chunks.extend(chunk[:65536-len(chunks)])
                if len(chunks) >= 65536:
                    break
        fp = io.BytesIO(chunks)
        values = {}
        while len(chunks) - fp.tell() >= 30:
            header = unpack('<IHHHHHIIIHH', fp.read(30))
            signature, _, flags, method, _, _, _, size, _, name_len, extra_len = header
            if signature != 0x04034b50 or flags & 9:
                break
            name = fp.read(name_len)
            fp.seek(extra_len, io.SEEK_CUR)
            data = fp.read(size)
            if len(data) != size:
                break
            if name not in (b'dart-sdk/revision', b'dart-sdk/version'):
                continue
            if method == zipfile.ZIP_STORED:
                raw = data
            elif method == zipfile.ZIP_DEFLATED:
                raw = zlib.decompressobj(-zlib.MAX_WBITS).decompress(data, 4096)
            else:
                continue
            values[name] = raw.decode('ascii').strip()
        return values.get(b'dart-sdk/revision'), values.get(b'dart-sdk/version')
    except (requests.RequestException, ValueError, zlib.error, UnicodeError):
        return None, None

def extract_elf_arch(path):
    with open(path, 'rb') as stream:
        machine = ELFFile(stream).header.e_machine
    mapping = {'EM_AARCH64': 'arm64', 'EM_X86_64': 'x64'}
    if machine not in mapping:
        raise ValueError(f'Unsupported ELF architecture: {machine}')
    return mapping[machine]

def extract_dart_info(libapp_file: str, libflutter_file: str, os_name: str = 'android', arch: str = 'arm64'):
    snapshot_hash, flags = extract_snapshot_hash_flags(libapp_file)
    engine_ids, dart_version, detected_arch = extract_libflutter_info(libflutter_file)
    if extract_elf_arch(libapp_file) != detected_arch:
        raise ValueError('libapp and libflutter architectures differ')
    arch = detected_arch

    if dart_version is None:
        engine_id, sdk_url, sdk_size = get_dart_sdk_url_size(engine_ids, os_name, arch)
        commit_id, dart_version = get_dart_commit(sdk_url)

    if dart_version is None:
        raise ValueError('Dart version could not be detected; use --dart-version')
    return dart_version, snapshot_hash, flags, arch, os_name

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: extract_dart_info.py <lib_dir>')
        sys.exit(1)
    libdir = sys.argv[1]
    libapp_file = os.path.join(libdir, 'libapp.so')
    libflutter_file = os.path.join(libdir, 'libflutter.so')

    print(extract_dart_info(libapp_file, libflutter_file))
