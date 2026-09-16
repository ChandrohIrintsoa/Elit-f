#!/usr/bin/python3

import os
import sys
import subprocess

def extract_tools_version(version_file):
    vals = {}
    with open(version_file, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            line = line.strip()
            if not line:
                continue
            parts = line.split(' ', 1)
            if len(parts) != 2:
                continue
            k, v = parts[0], parts[1]
            vals[k] = v

    return vals

def get_short_git_hash():
    return subprocess.run(['git', 'rev-parse', '--short=10', 'HEAD'], capture_output=True, check=True).stdout.decode().strip()

def get_git_timestamp():
    return subprocess.run(['git', 'log', '-n', '1', '--pretty=format:%cd'], capture_output=True, check=True).stdout.decode().strip()

if len(sys.argv) < 3:
    print('Usage: dartvm_make_version.py <sdk_dir> <snapshot_hash>', file=sys.stderr)
    sys.exit(1)

SDK_DIR = sys.argv[1]
SNAPSHOT_HASH = sys.argv[2]
os.chdir(SDK_DIR)
SDK_DIR = '.'

tools_version_file = os.path.join(SDK_DIR, 'tools', 'VERSION')
version_info = extract_tools_version(tools_version_file)

version_info['SNAPSHOT_HASH'] = SNAPSHOT_HASH
version_info['GIT_HASH'] = get_short_git_hash()
version_info['COMMIT_TIME'] = get_git_timestamp()

for req_key in ('MAJOR', 'MINOR', 'PATCH'):
    if req_key not in version_info:
        print(f'Missing key "{req_key}" in {tools_version_file}', file=sys.stderr)
        sys.exit(1)
version_info['VERSION_STR'] = f'{version_info["MAJOR"]}.{version_info["MINOR"]}.{version_info["PATCH"]}'

version_in_file = os.path.join(SDK_DIR, 'runtime', 'vm', 'version_in.cc')
version_out_file = os.path.join(SDK_DIR, 'runtime', 'vm', 'version.cc')

with open(version_in_file, 'r') as f:
    code = f.read()

for k, v in version_info.items():
    code = code.replace('{{' + k + '}}', v)

with open(version_out_file, 'w') as f:
    f.write(code)
