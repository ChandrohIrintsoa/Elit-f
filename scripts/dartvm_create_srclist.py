#!/usr/bin/python3
import glob
import os
import re
import sys

def extract_sources(gni_file):
    with open(gni_file, 'r') as f:
        data = f.read()

    objs = {}
    matches = re.findall(r'\s*(\w+?)\s*=\s*\[\s*([\"\w\-\.\/\,\s]+?),?\s*\]\s*', data)
    for name, names in matches:
        srcs = re.findall(r'\"([\w\-\.]+)\",?\s*', names)
        objs[name] = srcs

    return objs

def get_src_files(path):
    name = os.path.split(path)[-1]
    gni_file = os.path.join(path, name+'_sources.gni')
    objs = extract_sources(gni_file)
    key = name+'_sources'
    if key not in objs:
        raise KeyError(f"Variable '{key}' not found in {gni_file}")
    return objs[key]

def get_default_src_files(gni_file):
    objs = extract_sources(gni_file)
    for key in objs.keys():
        if key.endswith('_cc_files'):
            return objs[key]
    return []

def get_src_from_path(path):
    srcs = glob.glob(os.path.join(path, '*.cc'))
    return srcs

BASEDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
os.chdir(BASEDIR)
BASEDIR = '.'

tmpdir = os.path.join(BASEDIR, 'runtime')
if os.path.isdir(tmpdir):
    SDKDIR = BASEDIR
    BASEDIR = tmpdir
else:
    SDKDIR = os.path.join(BASEDIR, '..')

cc_srcs = []
for path in ('vm', 'platform', 'vm/heap', 'vm/ffi', 'vm/regexp'):
    path = os.path.join(BASEDIR, path)
    if not os.path.isdir(path):
        continue
    srcs = get_src_files(path)

    for src in srcs:
        cc_srcs.append(os.path.join(path, src))

extra_files = ( 'vm/version.cc', 'vm/dart_api_impl.cc', 'vm/native_api_impl.cc',
        'vm/compiler/runtime_api.cc', 'vm/compiler/jit/compiler.cc', 'platform/no_tsan.cc')
for name in extra_files:
    src = os.path.join(BASEDIR, name)
    if os.path.isfile(src):
        cc_srcs.append(src)

for lib in ('async', 'concurrent', 'core', 'developer', 'ffi', 'isolate', 'math', 'typed_data', 'vmservice', 'internal'):
    gni_file = os.path.join(BASEDIR, 'lib', lib+'_sources.gni')
    if os.path.isfile(gni_file):
        srcs = get_default_src_files(gni_file)
        cc_srcs.extend([ os.path.join(BASEDIR, 'lib', src) for src in srcs if src.endswith('.cc') ])

double_conversion_dir = BASEDIR+'/third_party/double-conversion/src'
if not os.path.isdir(double_conversion_dir):
    double_conversion_dir = SDKDIR+'/third_party/double-conversion/src'
    if not os.path.isdir(double_conversion_dir):
        print(f'Warning: double-conversion not found in {double_conversion_dir}', file=sys.stderr)
cc_srcs.extend(get_src_from_path(double_conversion_dir))

if os.sep == '\\':
    cc_srcs = [ src.replace(os.sep, '/') for src in cc_srcs ]

with open('sourcelist.cmake', 'w') as f:
    f.write('set(SRCS \n    ')
    f.write('\n    '.join(cc_srcs))
    f.write('\n)\n')

