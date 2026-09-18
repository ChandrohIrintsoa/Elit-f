#!/usr/bin/env python3

import io
import os
import requests
import shutil
import zipfile
from pathlib import Path

ICU_LIB_URL = 'https://github.com/unicode-org/icu/releases/download/release-73-2/icu4c-73_2-Win64-MSVC2019.zip'
CAPSTONE_LIB_URL = 'https://github.com/capstone-engine/capstone/releases/download/4.0.2/capstone-4.0.2-win64.zip'

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
BIN_DIR = os.path.join(SCRIPT_DIR, '..', 'bin')
EXTERNAL_DIR = os.path.join(SCRIPT_DIR, '..', 'external')
ICU_WINDOWS_FILE = os.path.join(EXTERNAL_DIR, 'icu-windows.zip')
ICU_WINDOWS_DIR = os.path.join(EXTERNAL_DIR, 'icu-windows')
CAPSTONE_DIR = os.path.join(EXTERNAL_DIR, 'capstone')


def _download(url, dst):
    r = requests.get(url)
    r.raise_for_status()
    with open(dst, 'wb') as f:
        f.write(r.content)


def _setup_icu():
    print('Downloading ICU from', ICU_LIB_URL)
    _download(ICU_LIB_URL, ICU_WINDOWS_FILE)
    print('Extracting ICU')
    with zipfile.ZipFile(ICU_WINDOWS_FILE) as z:
        z.extractall(ICU_WINDOWS_DIR)
    os.remove(ICU_WINDOWS_FILE)


def _setup_capstone():
    if os.path.exists(CAPSTONE_DIR):
        shutil.rmtree(CAPSTONE_DIR)
    print('Downloading Capstone from', CAPSTONE_LIB_URL)
    buffer = io.BytesIO(requests.get(CAPSTONE_LIB_URL).content)
    print('Extracting Capstone')
    with zipfile.ZipFile(buffer) as z:
        capstone_zip_dir = z.namelist()[0].split('/', 1)[0]
        z.extractall(EXTERNAL_DIR)
    os.rename(os.path.join(EXTERNAL_DIR, capstone_zip_dir), CAPSTONE_DIR)


def main():
    Path(BIN_DIR).mkdir(parents=True, exist_ok=True)
    Path(EXTERNAL_DIR).mkdir(parents=True, exist_ok=True)
    _setup_icu()
    _setup_capstone()
    print('Copying dlls to', BIN_DIR)
    shutil.copy(os.path.join(CAPSTONE_DIR, 'capstone.dll'), BIN_DIR)
    shutil.copy(os.path.join(ICU_WINDOWS_DIR, 'bin64', 'icudt73.dll'), BIN_DIR)
    shutil.copy(os.path.join(ICU_WINDOWS_DIR, 'bin64', 'icuuc73.dll'), BIN_DIR)
    print('Done')


if __name__ == '__main__':
    main()
