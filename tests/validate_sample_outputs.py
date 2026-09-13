import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess

from elftools.elf.elffile import ELFFile


def validate(source, output):
    source, output = Path(source), Path(output)
    with (source / 'libapp.so').open('rb') as f:
        elf = ELFFile(f)
        regions = [(p['p_vaddr'], p['p_vaddr'] + p['p_memsz'])
                   for p in elf.iter_segments()
                   if p['p_type'] == 'PT_LOAD' and p['p_flags'] & 1]
    sizes = {}
    for name in ('pp.txt', 'objs.txt', 'blutter_frida.js', 'ida_script/addNames.py', 'ida_script/ida_dart_struct.h'):
        path = output / name
        assert path.is_file() and path.stat().st_size > 0, name
        sizes[name] = path.stat().st_size
    script = (output / 'ida_script/addNames.py').read_text()
    ast.parse(script)
    labels = re.findall(r'idaapi.set_name\((0x[0-9a-f]+|\d+), "([^"]+)"\)', script)
    assert labels, 'no exported labels'
    addresses = [int(a, 0) for a, _ in labels]
    assert len(set(addresses)) == len(addresses), 'duplicate IDA addresses'
    assert len({n for _, n in labels}) == len(labels), 'duplicate IDA labels'
    assert all(any(lo <= address < hi for lo, hi in regions) for address in addresses), 'label outside executable segments'
    assemblies = list((output / 'asm').rglob('*.dart'))
    assert assemblies and all(p.stat().st_size for p in assemblies), 'missing/empty assembly files'
    subprocess.run(['node', '--check', str(output / 'blutter_frida.js')], check=True, capture_output=True)
    return {
        'input_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.glob('*.so')},
        'output_bytes': sizes,
        'assembly_files': len(assemblies),
        'ida_unique_labels': len(labels),
        'ida_alias_comments': script.count('idc.set_cmt('),
        'ida_python_syntax': 'passed',
        'frida_javascript_syntax': 'passed',
        'labels_in_executable_segments': True,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('input')
    parser.add_argument('output')
    args = parser.parse_args()
    print(json.dumps(validate(args.input, args.output), indent=2))
