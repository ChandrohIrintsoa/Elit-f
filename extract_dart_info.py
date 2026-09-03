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
        syms = dynsym.get_symbol_by_name('_kDartVmSnapshotData')
        if not syms:
            raise ValueError('Symbol _kDartVmSnapshotData not found in ' + libapp_file)
        sym = syms[0]
        if sym['st_size'] <= 128:
            raise ValueError(f"Symbol _kDartVmSnapshotData too small: {sym['st_size']}")

        offset = _va_to_file_offset(elf, sym['st_value'])
        if offset is None:
            raise ValueError(f'Cannot resolve virtual address 0x{sym["st_value"]:x} to file offset')

        f.seek(offset + 20)
        raw_hash = f.read(32)
        try:
            snapshot_hash = raw_hash.decode('ascii')
        except UnicodeDecodeError:
            snapshot_hash = raw_hash.hex()
        data = f.read(256)
        null_pos = data.find(b'\x00')
        if null_pos == -1:
            null_pos = len(data)
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
        if len(engine_ids) != 2:
            raise ValueError(f'Expected 2 engine hashes, found {len(engine_ids)}: {", ".join(engine_ids)}')

        m = re.search(br'\x00([\d\w\.-]+) \((stable|beta|dev)\)', data)
        if m is None:
            dart_version = None
        else:
            dart_version = m.group(1).decode()

    return engine_ids, dart_version, arch

def get_dart_sdk_url_size(engine_ids, os_name='android', arch='arm64'):
    os_map = {'android': 'linux', 'ios': 'mac', 'macos': 'mac'}
    arch_map = {'arm64': 'arm64', 'x64': 'x64'}
    os_sdk = os_map.get(os_name, 'linux')
    arch_sdk = arch_map.get(arch, 'arm64')
    for engine_id in engine_ids:
        url = f'https://storage.googleapis.com/flutter_infra_release/flutter/{engine_id}/dart-sdk-{os_sdk}-{arch_sdk}-release.zip'
        resp = requests.head(url, timeout=30)
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
    commit_id = None
    dart_version = None
    fp = None
    try:
        with requests.get(url, headers={"Range": "bytes=0-4096"}, stream=True, timeout=60) as r:
            if r.status_code in (200, 206):
                chunks = []
                for chunk in r.iter_content(chunk_size=4096):
                    chunks.append(chunk)
                    break
                x = b''.join(chunks)
                fp = io.BytesIO(x)
    except (requests.RequestException, ValueError):
        return None, None

    if fp is not None:
        while fp.tell() < 4096 - 30 and (commit_id is None or dart_version is None):
            raw = fp.read(30)
            if len(raw) < 30:
                break
            _, _, _, compMethod, _, _, _, compressSize, _, filenameLen, extraLen = unpack('<IHHHHHIIIHH', raw)
            filename = fp.read(filenameLen)
            if extraLen > 0:
                fp.seek(extraLen, io.SEEK_CUR)
            data = fp.read(compressSize)

            if compMethod == zipfile.ZIP_STORED:
                raw_data = data
            elif compMethod == zipfile.ZIP_DEFLATED:
                raw_data = zlib.decompress(data, wbits=-zlib.MAX_WBITS)
            else:
                continue

            if filename == b'dart-sdk/revision':
                commit_id = raw_data.decode('utf-8', errors='replace').strip()
            elif filename == b'dart-sdk/version':
                dart_version = raw_data.decode('utf-8', errors='replace').strip()

    return commit_id, dart_version

def extract_dart_info(libapp_file: str, libflutter_file: str, os_name: str = 'android', arch: str = 'arm64'):
    snapshot_hash, flags = extract_snapshot_hash_flags(libapp_file)
    engine_ids, dart_version, detected_arch = extract_libflutter_info(libflutter_file)
    if arch is None or arch == 'arm64':
        arch = detected_arch

    if dart_version is None:
        engine_id, sdk_url, sdk_size = get_dart_sdk_url_size(engine_ids, os_name, arch)
        commit_id, dart_version = get_dart_commit(sdk_url)

    return dart_version, snapshot_hash, flags, arch, os_name

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: extract_dart_info.py <lib_dir>')
        sys.exit(1)
    libdir = sys.argv[1]
    libapp_file = os.path.join(libdir, 'libapp.so')
    libflutter_file = os.path.join(libdir, 'libflutter.so')

    print(extract_dart_info(libapp_file, libflutter_file))
