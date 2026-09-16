
"""Elit-f Dumper — sorties style Il2CppDumper-Python adaptées au kernel Elit-f.

Remplace l'option [3] « Analyser et générer les scripts IDA » : au lieu de
recompiler le kernel avec IDA_FCN, on exploite les sorties textuelles du
kernel Elit-f (asm/*.txt + pp.txt) et on génère les artefacts équivalents à
Il2CppDumper (github.com/springmusk026/Il2CppDumper-Python).

Contrat « exactement 2 fichiers » (comme l'original Il2CppDumper, qui prend
exactement 2 fichiers : libil2cpp.so + global-metadata.dat) :

  ENTRÉE  : libapp.so (binaire Dart AOT) + libflutter.so (moteur Flutter =
            porteur des métadonnées de version) — resolve_two_files()
  SORTIE  : exactement 2 fichiers —
    - dump.dart    équivalent de dump.cs (pseudocode Dart adressé,
                   littéraux de chaînes inclus)
    - script.json  {ScriptMethod, ScriptString} pour scripts IDA/Ghidra
                   (littéraux inclus également)

Les générateurs stringliteral.json / IDA / Ghidra restent disponibles comme
API opt-in (generate_stringliteral_json, generate_ida_script,
generate_ghidra_script) mais ne font plus partie du dossier de sortie par
défaut ; les fichiers hérités des exécutions précédentes sont purgés.

Format des entrées (produit par src/DartDumper.cpp) :
  asm/<lib>.txt : « // lib: <nom>, url: <url> », « // class id: N, size: 0xX »,
                  en-têtes de classe/champ/fonction, « // ** addr: 0x..., size: 0x... »
  pp.txt        : « [pp+0xOFFSET] String: 'valeur' » etc.
"""

import json
import mmap
import os
import re
import shutil
import tempfile
import zipfile

__all__ = [
    'IL2CPP_INPUT_FILES', 'DUMP_FILES', 'FINGERPRINT_NAME',
    'KERNEL_OUTPUT_DIRS', 'KERNEL_OUTPUT_FILES',
    'parse_asm_dir', 'parse_pp', 'generate_dump_dart', 'generate_script_json',
    'generate_stringliteral_json', 'generate_ida_script',
    'generate_ghidra_script', 'generate_all', 'ensure_kernel_outputs',
    'resolve_two_files', 'detect_role_by_content', 'extract_dump_meta',
    'two_files_error_message',
    'write_analysis_fingerprint', 'read_analysis_fingerprint',
    'analysis_cache_valid', 'purge_kernel_outputs', 'purge_dump_outputs',
]


# ---------------------------------------------------------------------------
# Contrat « exactement 2 fichiers » (entrée / sortie)
# ---------------------------------------------------------------------------

# Entrée : le même pair que le kernel Elit-f (elitf.EXPECTED_LIBS) —
# l'équivalent Dart de libil2cpp.so + global-metadata.dat.
IL2CPP_INPUT_FILES = ('libapp.so', 'libflutter.so')

# Sortie : exactement 2 fichiers générés dans il2cpp_dump/.
DUMP_FILES = ('dump.dart', 'script.json')

# Fichiers des versions précédentes → purgés à chaque génération pour que le
# dossier de sortie ne contienne jamais plus que DUMP_FILES.
_LEGACY_DUMP_FILES = ('stringliteral.json', 'ida_elitf_dumper.py',
                      'ghidra_elitf_dumper.py', 'ida_dart_struct.h')

# Empreinte de l'analyse kernel : digests du pair (libapp.so + libflutter.so)
# au moment de l'analyse. Elle permet de détecter les sorties kernel devenues
# obsolètes (le fichier de sortie ne doit pas « rester à son origine » quand
# la cible change) et de valider le cache entre les exécutions.
FINGERPRINT_NAME = '.elitf_analysis.json'

# Sorties intermédiaires du kernel Elit-f (src/main.cpp) : répertoires +
# fichiers écrits à la racine du outdir. Purgeables sans toucher au dump
# (il2cpp_dump/) ni aux entrées (inputs/) ni aux sorties r2 (r2_output/).
KERNEL_OUTPUT_DIRS = ('asm', 'ida_script')
KERNEL_OUTPUT_FILES = ('pp.txt', 'objs.txt', 'blutter_frida.js',
                       FINGERPRINT_NAME)

_APP_NAME_RE = re.compile(r'^libapp.*\.so$', re.IGNORECASE)
_FLUTTER_NAME_RE = re.compile(r'^libflutter.*\.so$', re.IGNORECASE)
_DART_VERSION_RE = re.compile(rb'\d[\w.+-]+ \((?:stable|beta|dev)\)')


def _file_digest(path):
    """Digest SHA-256 d'un fichier (flux par blocs — adapté aux gros .so)."""
    import hashlib
    hasher = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def _fingerprint_path(outdir):
    return os.path.join(outdir, FINGERPRINT_NAME)


def write_analysis_fingerprint(outdir, libapp_path, libflutter_path=None,
                               extra=None):
    """Enregistre l'empreinte de l'analyse (digests du pair) dans outdir.

    :returns: le chemin de l'empreinte, ou None en cas d'échec (best-effort —
        l'analyse reste valide même si l'empreinte est impossible à écrire).
    """
    try:
        os.makedirs(outdir, exist_ok=True)
        data = {
            'libapp': {'name': os.path.basename(libapp_path),
                       'digest': _file_digest(libapp_path)},
            'libflutter': None,
        }
        if libflutter_path:
            data['libflutter'] = {
                'name': os.path.basename(libflutter_path),
                'digest': _file_digest(libflutter_path)}
        if extra:
            data.update(extra)
        import time
        data['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                            time.gmtime())
        path = _fingerprint_path(outdir)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, sort_keys=True)
        return path
    except (OSError, ValueError):
        return None


def read_analysis_fingerprint(outdir):
    """Lit l'empreinte d'analyse ; None si absente ou illisible."""
    try:
        with open(_fingerprint_path(outdir), encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def analysis_cache_valid(outdir, input_files):
    """True si les sorties kernel correspondent au pair d'entrée courant.

    Valide SEULEMENT si : les sorties kernel existent, une empreinte existe
    et les digests des 2 fichiers du pair correspondent à l'analyse
    enregistrée. Sans empreinte (outdir d'une version précédente), le cache
    est invalidé : une nouvelle analyse purge puis régénère les sorties.
    """
    if not has_kernel_outputs(outdir):
        return False
    fp = read_analysis_fingerprint(outdir)
    if not fp:
        return False
    libapp_path, libflutter_path = input_files[0], input_files[1]
    if not libapp_path or not libflutter_path:
        return False
    fp_app = (fp.get('libapp') or {}).get('digest')
    fp_flutter = (fp.get('libflutter') or {}).get('digest')
    if not fp_app or not fp_flutter:
        return False
    try:
        return (_file_digest(libapp_path) == fp_app
                and _file_digest(libflutter_path) == fp_flutter)
    except OSError:
        return False


def purge_kernel_outputs(outdir):
    """Purge les sorties intermédiaires du kernel dans outdir.

    Supprime asm/, ida_script/, pp.txt, objs.txt, blutter_frida.js et
    l'empreinte d'analyse — uniquement ces noms connus, jamais il2cpp_dump/,
    inputs/ ni r2_output/. :returns: la liste des chemins supprimés.
    """
    removed = []
    for name in KERNEL_OUTPUT_DIRS:
        path = os.path.join(outdir, name)
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
            removed.append(path)
    for name in KERNEL_OUTPUT_FILES:
        path = os.path.join(outdir, name)
        if os.path.isfile(path):
            try:
                os.remove(path)
                removed.append(path)
            except OSError:
                pass
    return removed


def purge_dump_outputs(outdir):
    """Purge le dump précédent (dump.dart + script.json + fichiers hérités).

    L'ancien dump ne doit pas survivre à une invalidation : un dump qui ne
    correspond plus au pair courant est trompeur. :returns: chemins supprimés.
    """
    dump_dir = os.path.join(outdir, 'il2cpp_dump')
    removed = []
    for name in DUMP_FILES + _LEGACY_DUMP_FILES:
        path = os.path.join(dump_dir, name)
        if os.path.isfile(path):
            try:
                os.remove(path)
                removed.append(path)
            except OSError:
                pass
    return removed


def two_files_error_message(detail=''):
    """Message d'erreur contractuel « exactement 2 fichiers » (FR)."""
    base = ("Il2CppDumper : exactement 2 fichiers requis en entrée — "
            "libapp.so (binaire Dart AOT) + libflutter.so (moteur Flutter), "
            "comme l'original Il2CppDumper (libil2cpp.so + "
            "global-metadata.dat).")
    if detail:
        return f"{base} {detail}"
    return base


def detect_role_by_content(path):
    """Détection par contenu (comme detect_files de l'original, par magic).

    :returns: 'app' si le fichier porte les symboles du snapshot ISOLATE Dart
        (_kDartIsolateSnapshot*, uniquement dans libapp.so) ; 'flutter' s'il
        ressemble au moteur Flutter (Dart_VersionString ou version
        « x.y.z (stable|beta|dev) ») ; None sinon (y compris fichier absent).
    """
    try:
        with open(path, 'rb') as f:
            if os.fstat(f.fileno()).st_size == 0:
                return None
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                if mm.find(b'_kDartIsolateSnapshot') != -1:
                    return 'app'
                if mm.find(b'Dart_VersionString') != -1 \
                        or _DART_VERSION_RE.search(mm):
                    return 'flutter'
    except (OSError, ValueError):
        return None
    return None


def _find_partner_file(directory, regex, expected_name):
    """Cherche le fichier jumeau dans directory (nom exact d'abord)."""
    exact = os.path.join(directory, expected_name)
    if os.path.isfile(exact):
        return exact
    matches = [fn for fn in sorted(os.listdir(directory))
               if regex.match(fn)
               and os.path.isfile(os.path.join(directory, fn))]
    if len(matches) == 1:
        return os.path.join(directory, matches[0])
    if len(matches) > 1:
        raise ValueError(two_files_error_message(
            f"Plusieurs candidats pour {expected_name} : "
            + ', '.join(matches)))
    return None


def _resolve_pair_from_single_file(path):
    """Un .so seul → cherche son jumeau dans le même dossier."""
    name = os.path.basename(path)
    directory = os.path.dirname(os.path.abspath(path))
    if _APP_NAME_RE.match(name):
        partner = _find_partner_file(directory, _FLUTTER_NAME_RE,
                                     'libflutter.so')
        if partner:
            return os.path.abspath(path), partner
        raise ValueError(two_files_error_message(
            f"« {name} » trouvé, mais libflutter.so est introuvable à côté"
            f" ({directory}) — réunissez les 2 fichiers dans le même dossier."))
    if _FLUTTER_NAME_RE.match(name):
        partner = _find_partner_file(directory, _APP_NAME_RE, 'libapp.so')
        if partner:
            return partner, os.path.abspath(path)
        raise ValueError(two_files_error_message(
            f"« {name} » trouvé, mais libapp.so est introuvable à côté"
            f" ({directory}) — réunissez les 2 fichiers dans le même dossier."))
    raise ValueError(two_files_error_message(
        f"« {name} » n'est ni libapp.so ni libflutter.so."))


def _resolve_pair_from_apk(apk_file, extract_dir):
    """APK/zip → extraction du pair (même contrat que extract_libs_from_apk)."""
    from elitf import extract_libs_from_apk  # import tardif (cycle évité)
    target_dir = extract_dir or tempfile.mkdtemp(prefix='elitf_il2cpp_')
    os.makedirs(target_dir, exist_ok=True)
    try:
        libapp_path, libflutter_path = extract_libs_from_apk(
            apk_file, target_dir)
    except ValueError as e:
        raise ValueError(two_files_error_message(
            f"APK « {os.path.basename(apk_file)} » : {e}"))
    return libapp_path, libflutter_path


def _find_pair_by_name(indir):
    """Paire par noms souples libapp*.so / libflutter*.so (co-localisée
    d'abord), ou None. Lève si plusieurs paires concurrentes."""
    apps, flutters = {}, {}
    for root, dirs, files in os.walk(indir):
        dirs.sort()
        for fn in files:
            full = os.path.abspath(os.path.join(root, fn))
            if _APP_NAME_RE.match(fn):
                apps.setdefault(root, full)
            elif _FLUTTER_NAME_RE.match(fn):
                flutters.setdefault(root, full)
    common = [d for d in apps if d in flutters]
    direct = [d for d in common
              if os.path.abspath(d) == os.path.abspath(indir)]
    if direct:
        return apps[direct[0]], flutters[direct[0]]
    if len(common) == 1:
        return apps[common[0]], flutters[common[0]]
    if len(common) > 1:
        raise ValueError(two_files_error_message(
            'Plusieurs paires trouvées : '
            + ', '.join(sorted(common))))
    if len(apps) == 1 and len(flutters) == 1:
        return next(iter(apps.values())), next(iter(flutters.values()))
    return None


def _find_pair_by_content(indir):
    """Paire par contenu (fichiers renommés) : exactement 1 candidat/rôle."""
    apps, flutters = [], []
    for root, dirs, files in os.walk(indir):
        dirs.sort()
        for fn in sorted(files):
            full = os.path.abspath(os.path.join(root, fn))
            role = detect_role_by_content(full)
            if role == 'app':
                apps.append(full)
            elif role == 'flutter':
                flutters.append(full)
    if len(apps) == 1 and len(flutters) == 1:
        return apps[0], flutters[0]
    return None


def _count_named_candidates(indir):
    n_app = n_flutter = 0
    for root, _dirs, files in os.walk(indir):
        for fn in files:
            if _APP_NAME_RE.match(fn):
                n_app += 1
            elif _FLUTTER_NAME_RE.match(fn):
                n_flutter += 1
    return n_app, n_flutter


def resolve_two_files(indir, extract_dir=None):
    """Contrat Il2CppDumper Elit-f : EXACTEMENT 2 fichiers en entrée.

    Comme l'original Il2CppDumper (libil2cpp.so + global-metadata.dat) et le
    kernel Elit-f (EXPECTED_LIBS) : libapp.so (binaire Dart AOT) +
    libflutter.so (moteur Flutter, porteur des métadonnées de version).

    :param indir: APK/zip, répertoire contenant le pair (p.ex.
        lib/arm64-v8a/), ou chemin d'un des 2 fichiers (jumeau cherché à côté)
    :param extract_dir: dossier d'extraction pour un APK (défaut : tempdir)
    :returns: (libapp_path, libflutter_path)
    :raises ValueError: si le contrat « exactement 2 fichiers » n'est pas
        satisfait (message contractuel FR)
    """
    indir = os.path.expanduser(str(indir))
    if os.path.isfile(indir):
        if zipfile.is_zipfile(indir):
            return _resolve_pair_from_apk(indir, extract_dir)
        return _resolve_pair_from_single_file(indir)
    if os.path.isdir(indir):
        # 1) convention kernel Elit-f (validate_two_libs : co-localisés,
        #    libapp.so/libflutter.so ou App/Flutter)
        try:
            from elitf import validate_two_libs  # import tardif (cycle évité)
            pair = validate_two_libs(indir)
            return pair[0], pair[1]
        except ImportError:
            pass
        except ValueError as e:
            if 'Multiple' in str(e):
                raise ValueError(two_files_error_message(str(e)))
        # 2) noms souples libapp*.so / libflutter*.so
        pair = _find_pair_by_name(indir)
        if pair:
            return pair
        # 3) contenu (fichiers renommés) — comme detect_files de l'original
        pair = _find_pair_by_content(indir)
        if pair:
            return pair
        # 4) refus contractuel avec diagnostic
        n_app, n_flutter = _count_named_candidates(indir)
        raise ValueError(two_files_error_message(
            f"Dans « {indir} » : {n_app} fichier(s) libapp*, "
            f"{n_flutter} fichier(s) libflutter*. Placez les 2 fichiers "
            "dans le même dossier (p.ex. extraction lib/arm64-v8a/ de l'APK)."))
    raise ValueError(two_files_error_message(f"Chemin introuvable : {indir}"))


def extract_dump_meta(libapp_path, libflutter_path):
    """Métadonnées d'en-tête du dump, issues des 2 fichiers du contrat.

    Best-effort et SANS réseau (extract_snapshot_hash_flags sur libapp.so,
    extract_libflutter_info sur libflutter.so) : n'échoue jamais — en cas de
    fichier non standard, l'en-tête se limite au nom du binaire.
    """
    meta = {'binary': os.path.basename(libapp_path)}
    try:
        from extract_dart_info import (extract_snapshot_hash_flags,
                                       extract_libflutter_info)
        snapshot_hash, _flags = extract_snapshot_hash_flags(libapp_path)
        meta['snapshot'] = snapshot_hash
        _engine_ids, dart_version, _arch = extract_libflutter_info(
            libflutter_path)
        if dart_version:
            meta['dart_version'] = dart_version
    except Exception:
        pass
    return meta


# ---------------------------------------------------------------------------
# Parsing des sorties kernel
# ---------------------------------------------------------------------------

_LIB_RE = re.compile(r'^// lib: (.*?), url: (.*)$')
_CLS_META_RE = re.compile(
    r'^// class id: (\d+), size: (0x[0-9a-fA-F]+)'
    r'(?:, field offset: (0x[0-9a-fA-F]+))?')
_METHOD_ADDR_RE = re.compile(
    r'^\s*// \*\* addr: (0x[0-9a-fA-F]+), size: (0x[0-9a-fA-F]+)')
_FIELD_OFFSET_RE = re.compile(r'^(.*); // offset: (0x[0-9a-fA-F]+)$')
_FIELD_AUTO_RE = re.compile(r'^(.*?\S)\s+field_([0-9a-fA-F]+);$')
_CLASS_HEAD_RE = re.compile(
    r'^(class |abstract class |enum |maybe_class )(\S.*?)(?:\s*\{)?$')
_PP_HEAD_RE = re.compile(r'^pool heap offset: (0x[0-9a-fA-F]+)')
_PP_STRING_RE = re.compile(r"^\[pp\+(0x[0-9a-fA-F]+)\] String: (.*)$")
_PP_ANY_RE = re.compile(r'^\[pp\+(0x[0-9a-fA-F]+)\]')
_METHOD_MODIFIERS = {'const', 'abstract', 'static', 'factory', 'set', 'get',
                     '[closure]', '[ffi]'}


def _strip_type_vector(name):
    depth = 0
    open_idx = -1
    for i, ch in enumerate(name):
        if ch == '<':
            if depth == 0:
                open_idx = i
            depth += 1
        elif ch == '>':
            depth -= 1
            if depth == 0:
                return name[:open_idx] if open_idx >= 0 else name
    return name


def _parse_class_head(text):
    """`abstract class Foo<T> extends Bar implements X` → dict partiel."""
    m = _CLASS_HEAD_RE.match(text)
    if not m:
        return None
    kind, rest = m.group(1).strip(), m.group(2).strip()
    bodyless = rest.endswith(';')
    if bodyless:
        rest = rest[:-1].rstrip()
    extends = None
    name_part = rest
    ext = re.search(r'\s+extends\s+(.*)$', rest)
    if ext:
        extends = ext.group(1).strip()
        name_part = rest[:ext.start()].strip()
    name = _strip_type_vector(name_part)
    return {'decl_kind': kind, 'name': name, 'extends': extends,
            'bodyless': bodyless}


def _parse_method_head(text):
    """En-tête fonction (sans indent, sans ' {') → (nom, signature, flags)."""
    text = text.rstrip()
    if text.endswith('{'):
        text = text[:-1].rstrip()
    signature = text
    modifiers = []
    tokens = text.split(' ')
    i = 0
    while i < len(tokens) and tokens[i] in _METHOD_MODIFIERS:
        modifiers.append(tokens[i])
        i += 1
    rest = ' '.join(tokens[i:])
    async_flag = rest.endswith(' async')
    if async_flag:
        rest = rest[:-len(' async')].rstrip()
    if '(' in rest:
        before = rest[:rest.index('(')].rstrip()
        name = before.split(' ')[-1] if ' ' in before else before
    else:
        name = rest.split(' ')[-1] if rest else ''
    return {
        'name': name,
        'signature': signature,
        'modifiers': modifiers,
        'async': async_flag,
        'static': 'static' in modifiers,
    }


def parse_asm_dir(asm_dir):
    """Parse les fichiers asm/*.txt du kernel Elit-f → liste de bibliothèques."""
    libs = []
    lib = None
    cls = None
    pending_meta = None
    pending_method = None
    for path in sorted(os.listdir(asm_dir)):
        if not path.endswith('.txt'):
            continue
        full = os.path.join(asm_dir, path)
        with open(full, 'r', encoding='utf-8', errors='replace') as f:
            for raw in f:
                line = raw.rstrip('\n')
                m = _LIB_RE.match(line)
                if m:
                    lib = {'name': m.group(1), 'url': m.group(2),
                           'classes': [], 'source': path}
                    libs.append(lib)
                    cls = None
                    pending_method = None
                    continue
                if lib is None:
                    continue
                if line == '}' and cls is not None:
                    cls = None
                    continue
                if line == '  }' and pending_method is not None:
                    cls['methods'].append(pending_method)
                    pending_method = None
                    continue
                m = _CLS_META_RE.match(line)
                if m:
                    pending_meta = {
                        'id': int(m.group(1)),
                        'size': int(m.group(2), 16),
                        'field_offset': (int(m.group(3), 16)
                                         if m.group(3) else None),
                    }
                    continue
                if (line.startswith('//   ') or line.startswith('  ')) \
                        and ('const constructor' in line
                             or 'transformed mixin' in line):
                    if cls:
                        if 'const constructor' in line:
                            cls['const_constructor'] = True
                        if 'transformed mixin' in line:
                            cls['transformed_mixin'] = True
                    continue
                # ligne "implements … {" de continuation d'en-tête de classe
                if (cls is not None and pending_method is None
                        and line.startswith('    ')
                        and line.rstrip().endswith(' {')):
                    cls['implements_line'] = line.strip()[:-1].rstrip()
                    continue
                if line.startswith('class ') or \
                        line.startswith(('abstract class ', 'enum ',
                                         'maybe_class ')):
                    head = _parse_class_head(line)
                    if head is None:
                        continue
                    bodyless = head.get('bodyless', False)
                    meta = pending_meta or {'id': None, 'size': None,
                                            'field_offset': None}
                    pending_meta = None
                    cls = {
                        'name': head['name'],
                        'decl_kind': head['decl_kind'],
                        'extends': head['extends'],
                        'decl': line.rstrip()[:-1].rstrip()
                        if not bodyless else line.rstrip(),
                        'id': meta['id'],
                        'size': meta['size'],
                        'field_offset': meta['field_offset'],
                        'const_constructor': False,
                        'transformed_mixin': False,
                        'bodyless': bodyless,
                        'fields': [],
                        'methods': [],
                        'implements_line': None,
                    }
                    lib['classes'].append(cls)
                    continue
                if cls is None or cls.get('bodyless'):
                    continue
                m = _METHOD_ADDR_RE.match(line)
                if m and pending_method is not None:
                    pending_method['addr'] = int(m.group(1), 16)
                    pending_method['size'] = int(m.group(2), 16)
                    continue
                stripped = line.strip()
                if stripped.startswith('//') or not stripped:
                    continue
                if line.startswith('  ') and not line.startswith('   ') \
                        and line.rstrip().endswith(' {'):
                    pending_method = _parse_method_head(line.strip()[:-1])
                    pending_method.setdefault('addr', None)
                    pending_method.setdefault('size', None)
                    continue
                m = _FIELD_OFFSET_RE.match(stripped)
                if m:
                    cls['fields'].append({
                        'decl': m.group(1).strip() + ';',
                        'offset': int(m.group(2), 16),
                        'name': _field_name(m.group(1).strip()),
                    })
                    continue
                m = _FIELD_AUTO_RE.match(stripped)
                if m and ' ' in m.group(1):
                    cls['fields'].append({
                        'decl': m.group(1).strip() + ' field_' + m.group(2) + ';',
                        'offset': int(m.group(2), 16),
                        'name': 'field_' + m.group(2),
                    })
    # ordre stable : dart:* avant package:* (indépendant des noms de fichiers)
    libs.sort(key=lambda l: l['url'])
    return libs


def _field_name(decl):
    decl = decl.rstrip(';').strip()
    if decl.startswith(('static ', 'late ', 'final ', 'const ')):
        for kw in ('static ', 'late ', 'final ', 'const '):
            decl = decl.replace(kw, '', 1) if decl.startswith(kw) else decl
    return decl.split(' ')[-1] if ' ' in decl else decl


def _unescape_dart(text):
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '\\' and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == 'n':
                out.append('\n')
            elif nxt == 't':
                out.append('\t')
            elif nxt == 'r':
                out.append('\r')
            elif nxt == 'x' and i + 3 < len(text):
                try:
                    out.append(chr(int(text[i + 2:i + 4], 16)))
                    i += 4
                    continue
                except ValueError:
                    out.append(nxt)
            else:
                out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def parse_pp(pp_path):
    """Parse pp.txt (object pool) → littéraux de chaînes + stats."""
    strings = []
    entries = 0
    heap_offset = None
    with open(pp_path, 'r', encoding='utf-8', errors='replace') as f:
        for raw in f:
            line = raw.rstrip('\n')
            m = _PP_HEAD_RE.match(line)
            if m:
                heap_offset = int(m.group(1), 16)
                continue
            if _PP_ANY_RE.match(line):
                entries += 1
            m = _PP_STRING_RE.match(line)
            if m:
                value = m.group(2).strip()
                if len(value) >= 2 and value.startswith("'") \
                        and value.endswith("'"):
                    value = _unescape_dart(value[1:-1])
                strings.append({'offset': int(m.group(1), 16), 'value': value})
    return {'heap_offset': heap_offset, 'entries': entries, 'strings': strings}


# ---------------------------------------------------------------------------
# Génération des sorties Il2CppDumper
# ---------------------------------------------------------------------------

_HEADER_FMT = (
    "// Dumped by Elit-f Dumper — style Il2CppDumper-Python, adapté Dart AOT\n"
    "// Binaire : {binary}\n"
    "{meta}"
    "// Source : kernel Elit-f (asm/, pp.txt) — adresses = RVA depuis la base\n")


def _meta_lines(meta):
    if not meta:
        return ''
    lines = []
    if meta.get('dart_version'):
        lines.append(f"// Dart : {meta['dart_version']}")
    if meta.get('snapshot'):
        lines.append(f"// Snapshot : {meta['snapshot']}")
    if lines:
        return '\n'.join(lines) + '\n'
    return ''


def generate_dump_dart(libs, out_path, meta=None, pp=None):
    """Génère dump.dart — équivalent Dart du dump.cs d'Il2CppDumper."""
    with open(out_path, 'w', encoding='utf-8') as of:
        of.write(_HEADER_FMT.format(binary=(meta or {}).get('binary', 'libapp.so'),
                                    meta=_meta_lines(meta)))
        of.write('\n')
        for lib in libs:
            of.write(f"// Library: {lib['name']}\n")
            of.write(f"// URL: {lib['url']}\n\n")
            for cls in lib['classes']:
                if cls.get('bodyless'):
                    of.write(f"{cls['decl']} // class id: {cls['id']}\n\n")
                    continue
                of.write(f"{cls['decl']} {{")
                of.write(f" // class id: {cls['id']}, size: "
                         f"{_hex(cls['size'])}\n")
                if cls.get('implements_line'):
                    of.write(f"    {cls['implements_line']}\n")
                if cls['fields']:
                    of.write('  // Fields\n')
                    for field in cls['fields']:
                        of.write(f"  {field['decl']} // offset: "
                                 f"{_hex(field['offset'])}\n")
                    of.write('\n')
                if cls['methods']:
                    of.write('  // Methods\n\n')
                    for m in cls['methods']:
                        addr = m.get('addr') or 0
                        size = m.get('size') or 0
                        of.write(f"  // RVA: {_hex(addr)} VA: {_hex(addr)}"
                                 f" Size: {_hex(size)}\n")
                        of.write(f"  {m['signature']} {{ }}\n\n")
                of.write('}\n\n')
        if pp:
            of.write('// StringLiterals (object pool Dart)\n')
            for i, s in enumerate(pp['strings']):
                of.write(f"// StringLiteral[{i}] pp+{_hex(s['offset'])}: "
                         f"'{s['value']}'\n")


def _hex(v):
    return f"0x{v:x}"


def _ida_safe_name(name):
    cleaned = re.sub(r'[^A-Za-z0-9_$.:@]', '_', name)
    return cleaned or 'sub'


def _script_method_name(cls_name, method, used):
    if cls_name in ('::', ''):
        base = _ida_safe_name(method['name'])
    else:
        base = _ida_safe_name(f"{cls_name}$${method['name']}")
    addr = method.get('addr')
    if base in used and addr is not None:
        base = f"{base}_0x{addr:x}"
    while base in used:
        base += '_'
    used.add(base)
    return base


def generate_script_json(libs, pp, out_path):
    """Génère script.json (format Il2CppDumper : ScriptMethod/ScriptString)."""
    methods = []
    used = set()
    for lib in libs:
        for cls in lib['classes']:
            for m in cls['methods']:
                if m.get('addr') is None:
                    continue
                methods.append({
                    'Address': m['addr'],
                    'Name': _script_method_name(cls['name'], m, used),
                    'Signature': m['signature'],
                })
    script_strings = [{'Address': s['offset'], 'Value': s['value']}
                      for s in pp['strings']]
    data = {'ScriptMethod': methods, 'ScriptString': script_strings}
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write('\n')
    return data


def generate_stringliteral_json(pp, out_path):
    """Génère stringliteral.json ([{"index": i, "value": "..."}])."""
    data = [{'index': i, 'value': s['value']}
            for i, s in enumerate(pp['strings'])]
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write('\n')
    return data


_IDA_TEMPLATE = '''# -*- coding: utf-8 -*-
# Script IDA généré par Elit-f Dumper (adaptation Il2CppDumper pour Dart AOT).
# Usage : IDA > File > Script file... > choisir ce script,
#         puis sélectionner le fichier script.json généré à côté.
# Les adresses de script.json sont des RVA : appliquées sur l'image IDA.
import json

import ida_funcs
import ida_name
import idaapi
import idc


def apply_script(data, base):
    applied = 0
    for m in data.get("ScriptMethod", []):
        ea = base + int(m["Address"])
        if ida_funcs.get_func(ea) is None:
            ida_funcs.add_func(ea)
        name = m.get("Name") or ""
        if name and ida_name.set_name(ea, name, ida_name.SN_CHECK):
            applied += 1
        sig = m.get("Signature") or ""
        if sig:
            idc.set_cmt(ea, sig, 0)
    for s in data.get("ScriptString", []):
        ea = base + int(s["Address"])
        value = (s.get("Value") or "").replace("\\n", " ")
        if value:
            idc.set_cmt(ea, "Dart string: " + value[:200], 0)
    return applied


def main():
    path = idaapi.ask_file(True, "script.json", "Elit-f: choisir script.json")
    if not path:
        return
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    base = idaapi.get_imagebase()
    n = apply_script(data, base)
    print("Elit-f Dumper: %d symboles appliques (base=%#x)" % (n, base))


main()
'''


def generate_ida_script(libs, out_path):
    """Génère le script IDA interactif (noms + fonctions + commentaires)."""
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(_IDA_TEMPLATE)


_GHIDRA_TEMPLATE = '''# -*- coding: utf-8 -*-
# Script Ghidra (Jython) généré par Elit-f Dumper (adaptation Il2CppDumper Dart).
# Usage : Script Manager > Run > choisir ce script, puis sélectionner script.json.
import io
import json

import ghidra.program.model.symbol as symbol
from ghidra.app.cmd.function import CreateFunctionCmd

fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
base = currentProgram.getImageBase().getOffset()

path = askFile("Elit-f: choisir script.json", "Ouvrir")
if path is not None:
    data = json.loads(io.open(path.getAbsolutePath(), encoding="utf-8").read())
    applied = 0
    for m in data.get("ScriptMethod", []):
        addr = af.getAddress(base + int(m["Address"]))
        if fm.getFunctionAt(addr) is None:
            CreateFunctionCmd(addr).applyTo(currentProgram, monitor)
        fn = fm.getFunctionAt(addr)
        name = m.get("Name") or ""
        if fn is not None and name:
            fn.setName(name, symbol.SourceType.USER_DEFINED)
            sig = m.get("Signature") or ""
            if sig:
                fn.setComment(sig)
            applied += 1
    print("Elit-f Dumper: %d symboles appliques" % applied)
'''


def generate_ghidra_script(libs, out_path):
    """Génère le script Ghidra/Jython équivalent."""
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(_GHIDRA_TEMPLATE)


def generate_all(outdir, dump_dir=None, meta=None):
    """Pipeline complet : sorties kernel → artefacts Il2CppDumper.

    Contrat « exactement 2 fichiers » : génère dump.dart + script.json dans
    dump_dir (défaut outdir/il2cpp_dump) et purge les fichiers hérités des
    versions précédentes (stringliteral.json, scripts IDA/Ghidra, struct
    header) — les littéraux restant intégrés dans les 2 fichiers.

    :param outdir: répertoire de sortie de l'analyse kernel (contient asm/, pp.txt)
    :param dump_dir: sous-répertoire des artefacts (défaut outdir/il2cpp_dump)
    :return: résumé {libraries, classes, methods, strings, dump_dir, files,
             dump_files}
    """
    asm_dir = os.path.join(outdir, 'asm')
    pp_path = os.path.join(outdir, 'pp.txt')
    if not has_kernel_outputs(outdir):
        raise FileNotFoundError(
            f"Aucune sortie kernel dans {asm_dir} — lancez d'abord l'analyse "
            "Flutter/Dart AOT (option 1).")
    if not os.path.isfile(pp_path):
        raise FileNotFoundError(f"pp.txt introuvable dans {outdir}")
    dump_dir = dump_dir or os.path.join(outdir, 'il2cpp_dump')
    os.makedirs(dump_dir, exist_ok=True)

    libs = parse_asm_dir(asm_dir)
    pp = parse_pp(pp_path)

    # Contrat : EXACTEMENT 2 fichiers générés (dump.dart + script.json).
    files = []
    dump_dart = os.path.join(dump_dir, 'dump.dart')
    generate_dump_dart(libs, dump_dart, meta=meta, pp=pp)
    files.append(dump_dart)

    script_json = os.path.join(dump_dir, 'script.json')
    generate_script_json(libs, pp, script_json)
    files.append(script_json)

    # Purge des fichiers excédentaires des exécutions précédentes : le
    # dossier de sortie ne contient que dump.dart + script.json.
    for legacy in _LEGACY_DUMP_FILES:
        legacy_path = os.path.join(dump_dir, legacy)
        if os.path.isfile(legacy_path):
            os.remove(legacy_path)

    classes = sum(len(l['classes']) for l in libs)
    methods = sum(len(c['methods']) for l in libs for c in l['classes'])
    return {
        'libraries': len(libs),
        'classes': classes,
        'methods': methods,
        'strings': len(pp['strings']),
        'dump_dir': dump_dir,
        'files': files,
        'dump_files': list(DUMP_FILES),
    }


def has_kernel_outputs(outdir):
    """True si les sorties texte du kernel Elit-f (asm/ + pp.txt) existent."""
    asm_dir = os.path.join(outdir, 'asm')
    return (os.path.isfile(os.path.join(outdir, 'pp.txt'))
            and os.path.isdir(asm_dir)
            and any(n.endswith('.txt') for n in os.listdir(asm_dir)))


def run_flutter_analysis(*args, **kwargs):
    """Injecté tardivement (évite l'import cyclique avec elitf)."""
    from elitf import run_flutter_analysis as _impl
    return _impl(*args, **kwargs)


def ensure_kernel_outputs(indir, outdir, rebuild, no_analysis, ui, log_mgr,
                          vs_sln=False, meta=None, input_files=None):
    """Vérifie les sorties kernel ; lance l'analyse Elit-f si absentes.

    Contrat « exactement 2 fichiers » : résout et valide le pair d'entrée
    (libapp.so + libflutter.so) AVANT toute analyse — ValueError contractuelle
    si l'entrée ne satisfait pas le contrat (comme l'original Il2CppDumper
    qui exige ses 2 fichiers).

    Fraîcheur des sorties : les sorties kernel ne sont réutilisées que si
    l'empreinte d'analyse correspond AUSSI au pair courant. Sinon (cible
    changée, --rebuild, empreinte absente), les sorties de l'analyse
    d'origine sont purgées (kernel + ancien dump) avant la nouvelle analyse —
    le fichier de sortie ne « reste » plus à son analyse d'origine.

    :param input_files: pair déjà résolu (libapp, libflutter) ; résolu depuis
        indir sinon
    :return: résumé generate_all() + input_files/input_count (contrat)
             + cache ('reused'|'refreshed') + purged (chemins purgés)
    """
    if input_files is None:
        input_files = resolve_two_files(indir)
    libapp_file, libflutter_file = input_files
    if meta is None:
        meta = extract_dump_meta(libapp_file, libflutter_file)
    if log_mgr:
        log_mgr.add(
            f"Contrat 2 fichiers : {os.path.basename(libapp_file)} + "
            f"{os.path.basename(libflutter_file)} → dump.dart + script.json",
            "info")
    cache_ok = (not rebuild) and analysis_cache_valid(outdir, input_files)
    if cache_ok:
        cache_status, purged = 'reused', []
        if log_mgr:
            log_mgr.add(
                "Analyse kernel réutilisée (cache valide pour ce pair "
                "2 fichiers)", "info")
    else:
        # Sorties de l'analyse d'origine obsolètes (pair changé, --rebuild
        # ou empreinte absente) : purge AVANT la nouvelle analyse, pour
        # qu'aucun fichier de sortie ne survive à son origine.
        purged = (purge_kernel_outputs(outdir)
                  + purge_dump_outputs(outdir))
        cache_status = 'refreshed'
        if log_mgr:
            detail = (f"{len(purged)} élément(s) de l'analyse d'origine "
                      f"purgé(s)") if purged else "sorties kernel absentes"
            log_mgr.add(
                f"Sorties kernel obsolètes ({detail}) — nouvelle analyse "
                "Flutter/Dart AOT", "info")
        run_flutter_analysis(indir, outdir, rebuild, no_analysis, False, ui,
                             log_mgr, vs_sln)
        # Empreinte écrite ici aussi (redondant avec _analyze_libs si
        # l'analyse réelle a tourné ; indispensable si elle est mockée).
        write_analysis_fingerprint(
            outdir, libapp_file, libflutter_file,
            extra={'dart_version': meta.get('dart_version'),
                   'snapshot': meta.get('snapshot')})
    summary = generate_all(outdir, meta=meta)
    summary['cache'] = cache_status
    summary['purged'] = purged
    summary['input_files'] = [os.path.abspath(p) for p in input_files]
    summary['input_count'] = len(input_files)
    if log_mgr:
        cache_txt = ('cache valide' if cache_status == 'reused'
                     else f"{len(purged)} élément(s) d'origine purgé(s)")
        log_mgr.add(
            f"Dump Il2CppDumper : {summary['methods']} méthodes, "
            f"{summary['classes']} classes, {summary['strings']} chaînes → "
            f"{summary['dump_dir']} (2 fichiers : dump.dart + script.json ; "
            f"{cache_txt})",
            "success")
    return summary
