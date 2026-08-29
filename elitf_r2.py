#!/usr/bin/env python3
"""
elitf_r2.py — Génération et exécution de scripts radare2 / lecture d'infos binaires.

Contient :
  * Templates de scripts r2 (R2_SCRIPT_TEMPLATE, R2_DISASM_TEMPLATE, R2_BATCH_TEMPLATE)
  * Templates par mode d'analyse (R2_TEMPLATES par niveau : minimal, quick, standard, full, ...)
  * `generate_r2_scripts(so_list, outdir, log_mgr=None)` : génère les .r2 et le batch .sh
  * `run_r2_scripts(so_list, outdir, log_mgr=None)`      : génère + exécute r2 si présent
  * `r2_unified_analysis(so_list, outdir, log_mgr=None, ui=None)` : fonction unifiée
    avec sélection de cibles + sous-menu de tous les modes d'analyse r2.
  * `display_binary_info(so_list, outdir, log_mgr=None)` : readelf-like, écrit dans un fichier

Ces fonctions acceptent un `LogManager` optionnel (issu de `elitf_ui`) pour reporter
la progression sans dépendre directement de Rich.
"""
import os
import shutil
import subprocess

# =========================================================================
#  R2 Analysis command blocks (reusable pieces)
# =========================================================================

# Header commun à tous les scripts r2
R2_HEADER = r"""e scr.color=0
e scr.utf8=0
e anal.strings=true
e bin.cache=true
"""

# Niveaux d'analyse radare2 (du plus léger au plus complet)
R2_ANALYSIS_LEVELS = {
    # 'a' seul : analyse minimale — détecte quelques fonctions de base
    "a": {
        "label": "a  — Analyse minimale",
        "desc": "Analyse la plus légère (a uniquement)",
        "commands": "a\nafl\n",
    },
    # 'aa' : analyse de base — références, strings, fonctions principales
    "aa": {
        "label": "aa — Analyse de base",
        "desc": "Analyse standard (aa : refs, strings, fonctions)",
        "commands": "aa\nafl\n",
    },
    # 'aaa' : analyse avancée — appels, classes, récupération de types
    "aaa": {
        "label": "aaa — Analyse avancée",
        "desc": "Analyse automatique poussée (aaa)",
        "commands": "aaa\nafl\n",
    },
    # Toutes les commandes d'analyse disponibles
    "all_anal": {
        "label": "Toutes les commandes d'analyse",
        "desc": "aa + aaa + aac + aar + afr + aae + aaft + aao + aav + aas + aat + aap + aau + ad",
        "commands": """ab
aa
aaa
aac
aar
afr
aae
aaft
aao
aav
aas
aat
aap
aau
ad@e:anal.depth=8
afl
""",
    },
}

# Blocs d'extraction d'informations (réutilisables selon le mode)
R2_EXTRACTION_BLOCKS = {
    "functions": {
        "label": "Fonctions uniquement",
        "desc": "Liste des fonctions (afl, aflq, afij)",
        "commands": r"""e log.dest=FILE
afl > __OUTDIR__/__NAME__functions.txt
aflq > __OUTDIR__/__NAME__func_list.txt
aflq~? > __OUTDIR__/__NAME__func_count.txt
afl~sym\. > __OUTDIR__/__NAME__sym_functions.txt
afl~sub\. > __OUTDIR__/__NAME__sub_functions.txt
afl* > __OUTDIR__/__NAME__functions_json.txt
afij > __OUTDIR__/__NAME__functions_info.json
e log.dest=stderr
""",
    },
    "strings": {
        "label": "Strings uniquement",
        "desc": "Extraction de strings (iz, izz, izq, izzq)",
        "commands": """e log.dest=FILE
izz > __OUTDIR__/__NAME__strings.txt
iz > __OUTDIR__/__NAME__data_strings.txt
izq > __OUTDIR__/__NAME__data_strings_raw.txt
izzq > __OUTDIR__/__NAME__all_strings_raw.txt
e log.dest=stderr
""",
    },
    "imports_exports": {
        "label": "Imports / Exports",
        "desc": "Imports, exports, symboles, rélocations",
        "commands": """e log.dest=FILE
ii > __OUTDIR__/__NAME__imports.txt
iiq > __OUTDIR__/__NAME__imports_raw.txt
iE > __OUTDIR__/__NAME__exports.txt
iEq > __OUTDIR__/__NAME__exports_raw.txt
is > __OUTDIR__/__NAME__symbols.txt
isq > __OUTDIR__/__NAME__symbols_raw.txt
isq~FUNC > __OUTDIR__/__NAME__func_symbols.txt
ir > __OUTDIR__/__NAME__relocations.txt
e log.dest=stderr
""",
    },
    "xrefs": {
        "label": "Cross-références",
        "desc": "Xrefs vers imports, depuis fonctions, compteurs",
        "commands": """e log.dest=FILE
axt sym.imp.* > __OUTDIR__/__NAME__xrefs_to_imports.txt
axt * > __OUTDIR__/__NAME__xrefs_all.txt
axf * > __OUTDIR__/__NAME__xrefs_from.txt
axt @ `aflq~?` > __OUTDIR__/__NAME__xrefs_count.txt
e log.dest=stderr
""",
    },
    "binary_info": {
        "label": "Info binaire (headers, sections, arch)",
        "desc": "Headers, sections, entrypoints, mémoire, architecture",
        "commands": """e log.dest=FILE
iS > __OUTDIR__/__NAME__sections.txt
iI > __OUTDIR__/__NAME__binary_info.txt
ie > __OUTDIR__/__NAME__entrypoints.txt
Ih > __OUTDIR__/__NAME__headers.txt
im > __OUTDIR__/__NAME__memory_map.txt
iA > __OUTDIR__/__NAME__arch_info.txt
il > __OUTDIR__/__NAME__libraries.txt
f > __OUTDIR__/__NAME__flags.txt
e log.dest=stderr
""",
    },
    "classes": {
        "label": "Classes (C++ / Obj-C)",
        "desc": "Classes, méthodes, hiérarchies",
        "commands": """e log.dest=FILE
ic > __OUTDIR__/__NAME__classes.txt
icq > __OUTDIR__/__NAME__classes_raw.txt
ic* > __OUTDIR__/__NAME__classes_json.txt
e log.dest=stderr
""",
    },
    "security": {
        "label": "Sécurité (crypto, tokens, secrets)",
        "desc": "AES, RSA, SHA, MD5, HMAC, clés, mots de passe, tokens, JWT, certificats",
        "commands": """e log.dest=FILE
/w AES > __OUTDIR__/__NAME__crypto_aes.txt
/w RSA > __OUTDIR__/__NAME__crypto_rsa.txt
/w SHA > __OUTDIR__/__NAME__crypto_sha.txt
/w MD5 > __OUTDIR__/__NAME__crypto_md5.txt
/w HMAC > __OUTDIR__/__NAME__crypto_hmac.txt
/w key= > __OUTDIR__/__NAME__key_assignments.txt
/w password > __OUTDIR__/__NAME__passwords.txt
/w secret > __OUTDIR__/__NAME__secrets.txt
/w token > __OUTDIR__/__NAME__tokens.txt
/w api_key > __OUTDIR__/__NAME__api_keys.txt
/w private_key > __OUTDIR__/__NAME__private_keys.txt
/w public_key > __OUTDIR__/__NAME__public_keys.txt
/w BEGIN CERTIFICATE > __OUTDIR__/__NAME__certificates.txt
/w BASE64 > __OUTDIR__/__NAME__base64.txt
/w encryption > __OUTDIR__/__NAME__encryption.txt
/w decrypt > __OUTDIR__/__NAME__decryption.txt
/w encrypt > __OUTDIR__/__NAME__encrypt_refs.txt
e log.dest=stderr
""",
    },
    "network": {
        "label": "Réseau (URLs, endpoints, auth)",
        "desc": "HTTP(S), WebSocket, Firebase, APIs, cookies, bearer, JWT, autorisations",
        "commands": """e log.dest=FILE
/w \x00http > __OUTDIR__/__NAME__urls.txt
/w \x00file:// > __OUTDIR__/__NAME__file_urls.txt
/w https:// > __OUTDIR__/__NAME__https_urls.txt
/w http:// > __OUTDIR__/__NAME__http_urls.txt
/w ws:// > __OUTDIR__/__NAME__ws_urls.txt
/w wss:// > __OUTDIR__/__NAME__wss_urls.txt
/w firebase > __OUTDIR__/__NAME__firebase.txt
/w googleapis > __OUTDIR__/__NAME__google_apis.txt
/w Authorization > __OUTDIR__/__NAME__auth_headers.txt
/w Bearer > __OUTDIR__/__NAME__bearer_tokens.txt
/w jwt > __OUTDIR__/__NAME__jwt.txt
/w Cookie > __OUTDIR__/__NAME__cookies.txt
/w Set-Cookie > __OUTDIR__/__NAME__set_cookies.txt
e log.dest=stderr
""",
    },
    "android": {
        "label": "Android (JNI, paths, dex)",
        "desc": "JNI_OnLoad, Java_, registerNatives, paths Android, dex, SharedPreferences",
        "commands": """e log.dest=FILE
/w JNI_OnLoad > __OUTDIR__/__NAME__jni.txt
/w Java_ > __OUTDIR__/__NAME__jni_methods.txt
/w registerNatives > __OUTDIR__/__NAME__register_natives.txt
/w /proc/ > __OUTDIR__/__NAME__proc_paths.txt
/w /data/ > __OUTDIR__/__NAME__data_paths.txt
/w /sdcard/ > __OUTDIR__/__NAME__sdcard_paths.txt
/w /system/ > __OUTDIR__/__NAME__system_paths.txt
/w .so > __OUTDIR__/__NAME__so_refs.txt
/w lib/ > __OUTDIR__/__NAME__lib_paths.txt
/w dex > __OUTDIR__/__NAME__dex_refs.txt
/w classes.dex > __OUTDIR__/__NAME__dex_files.txt
/w \x00/content/ > __OUTDIR__/__NAME__content_uris.txt
/w SharedPreferences > __OUTDIR__/__NAME__shared_prefs.txt
e log.dest=stderr
""",
    },
    "databases": {
        "label": "Bases de données",
        "desc": "SQLite, .db, .sqlite, protobuf",
        "commands": """e log.dest=FILE
/w SQLite > __OUTDIR__/__NAME__sqlite.txt
/w .db > __OUTDIR__/__NAME__db_refs.txt
/w .sqlite > __OUTDIR__/__NAME__sqlite_refs.txt
/w protobuf > __OUTDIR__/__NAME__protobuf.txt
e log.dest=stderr
""",
    },
    "hooks": {
        "label": "Hooks (x86 inline hooks)",
        "desc": "Détection de hooks x86 (pattern ff4889e7)",
        "commands": """e log.dest=FILE
/x ff4889e7 > __OUTDIR__/__NAME__x86_hooks.txt
e log.dest=stderr
""",
    },
}

# Extraction complète (tout R2_EXTRACTION_BLOCKS)
_ALL_EXTRACTION = "\n".join(
    block["commands"] for block in R2_EXTRACTION_BLOCKS.values()
)

# Modes d'analyse préconfigurés (combinaison analyse + extraction)
R2_PRESETS = {
    "full": {
        "label": "Analyse complète (aaa + toute extraction)",
        "desc": "Toutes les commandes d'analyse + extraction de toutes les informations",
        "analysis_key": "all_anal",
        "extraction_keys": list(R2_EXTRACTION_BLOCKS.keys()),
        "use_write": False,
    },
    "standard": {
        "label": "Analyse standard (aaa + extraction courante)",
        "desc": "aaa + fonctions, strings, imports/exports, xrefs, info binaire",
        "analysis_key": "aaa",
        "extraction_keys": ["functions", "strings", "imports_exports", "xrefs", "binary_info"],
        "use_write": False,
    },
    "quick": {
        "label": "Analyse rapide (aa + extraction basique)",
        "desc": "aa + fonctions, strings, info binaire",
        "analysis_key": "aa",
        "extraction_keys": ["functions", "strings", "binary_info"],
        "use_write": False,
    },
    "minimal": {
        "label": "Analyse minimale (a + fonctions)",
        "desc": "a uniquement + liste des fonctions",
        "analysis_key": "a",
        "extraction_keys": ["functions"],
        "use_write": False,
    },
    "security_audit": {
        "label": "Audit sécurité complet",
        "desc": "aaa + fonctions, strings, sécurité, réseau, Android",
        "analysis_key": "aaa",
        "extraction_keys": ["functions", "strings", "security", "network", "android"],
        "use_write": False,
    },
}

# Radare2 comprehensive analysis + extraction script (legacy — gardé pour rétrocompatibilité).
# Identique au preset "full".
R2_SCRIPT_TEMPLATE = r"""e scr.color=0
e scr.utf8=0
e anal.strings=true
e bin.cache=true
e asm.bytes=false
e asm.lines=false
e asm.offset=true
e log.dest=FILE

ab

aa

aaa

aac

aar

afr

aae

aaft

aao

aav

aas

aat

aap

aau

ad@e:anal.depth=8

afl

e log.dest=stderr

afl > __OUTDIR__/__NAME__functions.txt
izz > __OUTDIR__/__NAME__strings.txt
iS > __OUTDIR__/__NAME__sections.txt
ii > __OUTDIR__/__NAME__imports.txt
iE > __OUTDIR__/__NAME__exports.txt
is > __OUTDIR__/__NAME__symbols.txt
ir > __OUTDIR__/__NAME__relocations.txt
ic > __OUTDIR__/__NAME__classes.txt
iI > __OUTDIR__/__NAME__binary_info.txt
ie > __OUTDIR__/__NAME__entrypoints.txt
Ih > __OUTDIR__/__NAME__headers.txt
im > __OUTDIR__/__NAME__memory_map.txt
iA > __OUTDIR__/__NAME__arch_info.txt
il > __OUTDIR__/__NAME__libraries.txt
iz > __OUTDIR__/__NAME__data_strings.txt
izq > __OUTDIR__/__NAME__data_strings_raw.txt
izzq > __OUTDIR__/__NAME__all_strings_raw.txt
iEq > __OUTDIR__/__NAME__exports_raw.txt
iiq > __OUTDIR__/__NAME__imports_raw.txt
isq > __OUTDIR__/__NAME__symbols_raw.txt
f > __OUTDIR__/__NAME__flags.txt
aflq > __OUTDIR__/__NAME__func_list.txt
aflq~? > __OUTDIR__/__NAME__func_count.txt
afl~sym\. > __OUTDIR__/__NAME__sym_functions.txt
afl~sub\. > __OUTDIR__/__NAME__sub_functions.txt
isq~FUNC > __OUTDIR__/__NAME__func_symbols.txt
axt sym.imp.* > __OUTDIR__/__NAME__xrefs_to_imports.txt
axt * > __OUTDIR__/__NAME__xrefs_all.txt
axf * > __OUTDIR__/__NAME__xrefs_from.txt
axt @ `aflq~?` > __OUTDIR__/__NAME__xrefs_count.txt
afl* > __OUTDIR__/__NAME__functions_json.txt
afij > __OUTDIR__/__NAME__functions_info.json
icq > __OUTDIR__/__NAME__classes_raw.txt
ic* > __OUTDIR__/__NAME__classes_json.txt

/w \x00http > __OUTDIR__/__NAME__urls.txt
/w \x00file:// > __OUTDIR__/__NAME__file_urls.txt
/w \x00/content/ > __OUTDIR__/__NAME__content_uris.txt
/w JNI_OnLoad > __OUTDIR__/__NAME__jni.txt
/w Java_ > __OUTDIR__/__NAME__jni_methods.txt
/w registerNatives > __OUTDIR__/__NAME__register_natives.txt
/w /proc/ > __OUTDIR__/__NAME__proc_paths.txt
/w /data/ > __OUTDIR__/__NAME__data_paths.txt
/w /sdcard/ > __OUTDIR__/__NAME__sdcard_paths.txt
/w /system/ > __OUTDIR__/__NAME__system_paths.txt
/w AES > __OUTDIR__/__NAME__crypto_aes.txt
/w RSA > __OUTDIR__/__NAME__crypto_rsa.txt
/w SHA > __OUTDIR__/__NAME__crypto_sha.txt
/w MD5 > __OUTDIR__/__NAME__crypto_md5.txt
/w HMAC > __OUTDIR__/__NAME__crypto_hmac.txt
/w key= > __OUTDIR__/__NAME__key_assignments.txt
/w password > __OUTDIR__/__NAME__passwords.txt
/w secret > __OUTDIR__/__NAME__secrets.txt
/w token > __OUTDIR__/__NAME__tokens.txt
/w api_key > __OUTDIR__/__NAME__api_keys.txt
/w .so > __OUTDIR__/__NAME__so_refs.txt
/w lib/ > __OUTDIR__/__NAME__lib_paths.txt
/w dex > __OUTDIR__/__NAME__dex_refs.txt
/w classes.dex > __OUTDIR__/__NAME__dex_files.txt
/x ff4889e7 > __OUTDIR__/__NAME__x86_hooks.txt
/w SQLite > __OUTDIR__/__NAME__sqlite.txt
/w .db > __OUTDIR__/__NAME__db_refs.txt
/w .sqlite > __OUTDIR__/__NAME__sqlite_refs.txt
/w SharedPreferences > __OUTDIR__/__NAME__shared_prefs.txt
/w encryption > __OUTDIR__/__NAME__encryption.txt
/w decrypt > __OUTDIR__/__NAME__decryption.txt
/w encrypt > __OUTDIR__/__NAME__encrypt_refs.txt
/w BASE64 > __OUTDIR__/__NAME__base64.txt
/w protobuf > __OUTDIR__/__NAME__protobuf.txt
/w https:// > __OUTDIR__/__NAME__https_urls.txt
/w http:// > __OUTDIR__/__NAME__http_urls.txt
/w ws:// > __OUTDIR__/__NAME__ws_urls.txt
/w wss:// > __OUTDIR__/__NAME__wss_urls.txt
/w firebase > __OUTDIR__/__NAME__firebase.txt
/w googleapis > __OUTDIR__/__NAME__google_apis.txt
/w Authorization > __OUTDIR__/__NAME__auth_headers.txt
/w Bearer > __OUTDIR__/__NAME__bearer_tokens.txt
/w jwt > __OUTDIR__/__NAME__jwt.txt
/w private_key > __OUTDIR__/__NAME__private_keys.txt
/w public_key > __OUTDIR__/__NAME__public_keys.txt
/w BEGIN CERTIFICATE > __OUTDIR__/__NAME__certificates.txt
/w Cookie > __OUTDIR__/__NAME__cookies.txt
/w Set-Cookie > __OUTDIR__/__NAME__set_cookies.txt
q
"""

# Minimal r2 script: run analysis + write the list of function addresses
R2_DISASM_TEMPLATE = r"""e scr.color=0
e scr.utf8=0
e asm.bytes=true
e asm.lines=true
e asm.offset=true
e asm.cmt.right=true
e asm.cmt.fold=true
e anal.strings=true
e bin.cache=true
aaa
e log.dest=FILE
__FUNCS_BLOCK__
e log.dest=stderr
q
"""

R2_BATCH_TEMPLATE = r"""#!/data/data/com.termux/files/usr/bin/bash
set -e

OUTDIR="__OUTDIR__"
mkdir -p "$OUTDIR"

__SCRIPTS_BLOCK__

echo "[OK] Radare2 analysis complete: $OUTDIR/"
"""

# Radare2 timeout per .so (overridable via env). libflutter.so can take several minutes.
_R2_TIMEOUT_ENV = os.getenv("R2_TIMEOUT", "600")


def _find_r2():
    """Return the path to the radare2 binary, looking for both `r2` and `radare2`."""
    for candidate in ("r2", "radare2"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _find_readelf():
    """Return the path to a readelf-like binary, or None if not available."""
    for candidate in ("readelf", "greadelf", "llvm-readelf"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _build_r2_script(analysis_key, extraction_keys, use_write=False,
                     asm_bytes=False, asm_lines=False):
    """Construire un script r2 dynamique à partir des blocs d'analyse et d'extraction.

    Args:
        analysis_key: clé dans R2_ANALYSIS_LEVELS ("a", "aa", "aaa", "all_anal")
        extraction_keys: liste de clés dans R2_EXTRACTION_BLOCKS
        use_write: si True, active le mode écriture (r2 -w)
        asm_bytes: si True, affiche les octets dans le désassemblage
        asm_lines: si True, affiche les lignes graphiques

    Returns:
        Le contenu du script r2 (str)
    """
    parts = [R2_HEADER]

    # Configuration asm
    if asm_bytes:
        parts.append("e asm.bytes=true\n")
    else:
        parts.append("e asm.bytes=false\n")
    if asm_lines:
        parts.append("e asm.lines=true\n")
    else:
        parts.append("e asm.lines=false\n")
    parts.append("e asm.offset=true\n")

    # Bloc d'analyse
    if analysis_key and analysis_key in R2_ANALYSIS_LEVELS:
        parts.append("\n")
        parts.append(R2_ANALYSIS_LEVELS[analysis_key]["commands"])

    # Blocs d'extraction
    if extraction_keys:
        for ek in extraction_keys:
            if ek in R2_EXTRACTION_BLOCKS:
                parts.append("\n")
                parts.append(R2_EXTRACTION_BLOCKS[ek]["commands"])

    parts.append("q\n")
    return "".join(parts)


def _build_write_script(patch_mode, patch_data, extraction_keys=None):
    """Construire un script r2 en mode écriture (-w).

    Args:
        patch_mode: "wa" (write assembly), "wx" (write hex), "w" (write string)
        patch_data: données à écrire (assemble, hex, ou string selon le mode)
        extraction_keys: blocs d'extraction optionnels après le patch

    Returns:
        Le contenu du script r2 (str)
    """
    parts = [R2_HEADER]
    parts.append("e asm.bytes=true\n")
    parts.append("e asm.lines=true\n")
    parts.append("e asm.offset=true\n")
    parts.append("e asm.cmt.right=true\n")

    # Le patch sera inséré après la sélection de l'adresse par l'utilisateur
    # On utilise un marqueur que la fonction appelante remplacera
    parts.append("\n__PATCH_BLOCK__\n")

    if extraction_keys:
        for ek in extraction_keys:
            if ek in R2_EXTRACTION_BLOCKS:
                parts.append("\n")
                parts.append(R2_EXTRACTION_BLOCKS[ek]["commands"])

    parts.append("q\n")
    return "".join(parts)


def generate_r2_scripts(so_list, outdir, log_mgr=None):
    """Generate per-.so r2 scripts and a global batch launcher.

    Returns the list of generated `.r2` script paths.
    """
    r2_out = os.path.join(outdir, "r2_output")
    os.makedirs(r2_out, exist_ok=True)
    generated = []
    batch_lines = []
    for so in so_list:
        name = so["name"].removesuffix(".so") + "_"
        script_content = R2_SCRIPT_TEMPLATE.replace("__OUTDIR__", r2_out).replace("__NAME__", name)
        script_path = os.path.join(r2_out, f"r2_{so['name']}.r2")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)
        generated.append(script_path)
        if log_mgr:
            log_mgr.add(f"Generated r2 script: r2_{so['name']}.r2", "success")
            log_mgr.step()

        abs_so = so["path"]
        batch_lines.append(f'r2 -q -i "{script_path}" "{abs_so}"')

        disasm_funcs = f'aflq > "{os.path.join(r2_out, name + "func_list.txt")}"\n'
        disasm_content = (R2_DISASM_TEMPLATE
                          .replace("__OUTDIR__", r2_out)
                          .replace("__NAME__", name)
                          .replace("__FUNCS_BLOCK__", disasm_funcs))
        disasm_path = os.path.join(r2_out, f"r2_{so['name']}_disasm.r2")
        with open(disasm_path, "w", encoding="utf-8") as f:
            f.write(disasm_content)
        if log_mgr:
            log_mgr.add(f"Generated r2 disasm script: r2_{so['name']}_disasm.r2", "success")
            log_mgr.step()

    batch_content = (R2_BATCH_TEMPLATE
                     .replace("__OUTDIR__", r2_out)
                     .replace("__SCRIPTS_BLOCK__", "\n".join(batch_lines)))
    batch_path = os.path.join(outdir, "r2_analyze_all.sh")
    with open(batch_path, "w", encoding="utf-8") as f:
        f.write(batch_content)
    os.chmod(batch_path, 0o755)
    if log_mgr:
        log_mgr.add(f"Generated batch script: r2_analyze_all.sh ({len(generated)} .so)", "success")
    return generated


def _run_single_r2(r2_bin, script_path, so_path, timeout, log_mgr, so_name):
    """Exécuter r2 sur un seul .so avec un script donné.

    Returns:
        True si succès, False sinon.
    """
    try:
        result = subprocess.run(
            [r2_bin, "-q", "-i", script_path, so_path],
            capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            if log_mgr:
                log_mgr.add(f"r2 ok: {so_name}", "success")
            return True
        else:
            if log_mgr:
                err_text = result.stderr.strip()
                if len(err_text) > 200:
                    err_text = err_text[:200] + '...'
                log_mgr.add(f"r2 error on {so_name}: {err_text}", "error")
            return False
    except subprocess.TimeoutExpired:
        if log_mgr:
            log_mgr.add(f"r2 timeout on {so_name} (>{timeout}s)", "warn")
        return False
    except (OSError, subprocess.SubprocessError) as e:
        if log_mgr:
            log_mgr.add(f"r2 failed on {so_name}: {e}", "error")
        return False


def run_r2_scripts(so_list, outdir, log_mgr=None):
    """Generate r2 scripts and execute them if radare2 is available.

    Returns the list of generated script paths.
    """
    r2_out = os.path.join(outdir, "r2_output")
    os.makedirs(r2_out, exist_ok=True)
    r2_bin = _find_r2()
    if not r2_bin:
        if log_mgr:
            log_mgr.add("r2 not found (tried: r2, radare2). Generating scripts only.", "warn")
        return generate_r2_scripts(so_list, outdir, log_mgr)

    generated = []
    succeeded = 0
    try:
        timeout = int(_R2_TIMEOUT_ENV)
    except ValueError:
        timeout = 600

    for so in so_list:
        name = so["name"].removesuffix(".so") + "_"
        script_content = (R2_SCRIPT_TEMPLATE
                          .replace("__OUTDIR__", r2_out)
                          .replace("__NAME__", name))
        script_path = os.path.join(r2_out, f"r2_{so['name']}.r2")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)
        generated.append(script_path)
        if log_mgr:
            log_mgr.add(f"Analyzing {so['name']} with r2...", "info")
        if _run_single_r2(r2_bin, script_path, so["path"], timeout, log_mgr, so["name"]):
            succeeded += 1
        if log_mgr:
            log_mgr.step()
    if log_mgr:
        log_mgr.add(f"r2 analysis finished: {succeeded}/{len(generated)} succeeded", "success")
    return generated


def run_r2_custom(so_list, outdir, analysis_key, extraction_keys, log_mgr=None,
                   use_write=False, execute=True):
    """Générer et optionnellement exécuter des scripts r2 avec des paramètres personnalisés.

    Args:
        so_list: liste de dicts {"path", "name", "size"}
        outdir: répertoire de sortie
        analysis_key: clé dans R2_ANALYSIS_LEVELS ou None
        extraction_keys: liste de clés dans R2_EXTRACTION_BLOCKS
        log_mgr: LogManager optionnel
        use_write: si True, utilise r2 -w (mode écriture)
        execute: si True, exécute r2 ; sinon génère les scripts uniquement

    Returns:
        Liste des chemins de scripts générés.
    """
    r2_out = os.path.join(outdir, "r2_output")
    os.makedirs(r2_out, exist_ok=True)
    r2_bin = _find_r2() if execute else None
    if execute and not r2_bin:
        if log_mgr:
            log_mgr.add("r2 not found. Generating scripts only.", "warn")
        execute = False

    try:
        timeout = int(_R2_TIMEOUT_ENV)
    except ValueError:
        timeout = 600

    # Construction du nom de mode pour les fichiers
    mode_parts = []
    if analysis_key:
        mode_parts.append(analysis_key)
    if extraction_keys:
        mode_parts.append("_".join(extraction_keys[:3]))
        if len(extraction_keys) > 3:
            mode_parts.append(f"+{len(extraction_keys) - 3}more")
    mode_tag = "_".join(mode_parts) if mode_parts else "custom"
    if use_write:
        mode_tag = "write_" + mode_tag

    generated = []
    succeeded = 0
    batch_lines = []

    for so in so_list:
        name = so["name"].removesuffix(".so") + "_"
        script_content = _build_r2_script(
            analysis_key, extraction_keys, use_write=use_write
        )
        script_content = script_content.replace("__OUTDIR__", r2_out).replace("__NAME__", name)
        script_path = os.path.join(r2_out, f"r2_{so['name']}_{mode_tag}.r2")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)
        generated.append(script_path)
        if log_mgr:
            log_mgr.add(f"Generated: r2_{so['name']}_{mode_tag}.r2", "success")

        # Exécution
        if execute:
            r2_args = ["-q", "-i", script_path, so["path"]]
            if use_write:
                r2_args.insert(0, "-w")
            if log_mgr:
                log_mgr.add(f"Analyzing {so['name']} ({mode_tag})...", "info")
            try:
                result = subprocess.run(
                    [r2_bin] + r2_args,
                    capture_output=True, text=True, timeout=timeout,
                    stdin=subprocess.DEVNULL,
                )
                if result.returncode == 0:
                    succeeded += 1
                    if log_mgr:
                        log_mgr.add(f"r2 ok: {so['name']}", "success")
                else:
                    if log_mgr:
                        err_text = result.stderr.strip()
                        if len(err_text) > 200:
                            err_text = err_text[:200] + '...'
                        log_mgr.add(f"r2 error on {so['name']}: {err_text}", "error")
            except subprocess.TimeoutExpired:
                if log_mgr:
                    log_mgr.add(f"r2 timeout on {so['name']} (>{timeout}s)", "warn")
            except (OSError, subprocess.SubprocessError) as e:
                if log_mgr:
                    log_mgr.add(f"r2 failed on {so['name']}: {e}", "error")
        if log_mgr:
            log_mgr.step()

    # Générer le batch script
    if generated:
        for i, so in enumerate(so_list):
            mode_tag_i = mode_tag
            sp = generated[i]
            abs_so = so["path"]
            cmd = f'r2 -q -i "{sp}" "{abs_so}"'
            if use_write:
                cmd = cmd.replace('r2 -q', 'r2 -w -q', 1)
            batch_lines.append(cmd)
        batch_content = (R2_BATCH_TEMPLATE
                         .replace("__OUTDIR__", r2_out)
                         .replace("__SCRIPTS_BLOCK__", "\n".join(batch_lines)))
        batch_path = os.path.join(r2_out, f"r2_{mode_tag}_batch.sh")
        with open(batch_path, "w", encoding="utf-8") as f:
            f.write(batch_content)
        os.chmod(batch_path, 0o755)
        if log_mgr:
            log_mgr.add(f"Batch script: r2_{mode_tag}_batch.sh", "success")

    if log_mgr and execute:
        log_mgr.add(f"r2 {mode_tag}: {succeeded}/{len(generated)} succeeded", "success")
    return generated


def r2_unified_analysis(so_list, outdir, log_mgr=None, ui=None):
    """Fonction unifiée d'analyse r2 : sélection de cibles + sous-menu interactif.

    Cette fonction combine les anciennes options [2] et [3] en une seule entrée
    avec un sous-menu complet offrant tous les niveaux d'analyse radare2.

    Le sous-menu propose :
      - Presets d'analyse (complet, standard, rapide, minimal, audit sécurité)
      - Choix du niveau d'analyse (a, aa, aaa, toutes les commandes)
      - Choix des blocs d'extraction individuels (fonctions, strings, xrefs, etc.)
      - Mode écriture r2 -w (wa, wx, w)
      - Génération de scripts sans exécution

    Args:
        so_list: liste complète des .so détectés (dicts {"path", "name", "size"})
        outdir: répertoire de sortie
        log_mgr: LogManager optionnel
        ui: instance ElitfUI optionnelle (pour l'affichage riche)

    Returns:
        La liste des scripts générés, ou None si l'utilisateur annule.
    """
    # --- Étape 1 : Sélection des cibles ---
    selected = None
    if ui is not None:
        selected = ui.get_target_selection()
        if not selected:
            return None
        targets = [so_list[i] for i in selected]
    else:
        # Mode non-interactif : utiliser toutes les .so
        targets = so_list

    if not targets:
        if log_mgr:
            log_mgr.add("Aucune cible sélectionnée.", "warn")
        return None

    if log_mgr:
        log_mgr.add(f"Cibles sélectionnées: {len(targets)} fichier(s) .so", "info")

    # --- Étape 2 : Sous-menu r2 ---
    if ui is not None:
        choice = ui.get_r2_choice()
    else:
        # Sans UI, utiliser le preset complet par défaut
        choice = "full"

    if choice is None or choice == "back":
        return None

    # --- Étape 3 : Exécuter le mode choisi ---
    if log_mgr:
        log_mgr.add(f"Mode r2: {choice}", "info")

    # --- Presets ---
    if choice in R2_PRESETS:
        preset = R2_PRESETS[choice]
        return run_r2_custom(
            targets, outdir,
            analysis_key=preset["analysis_key"],
            extraction_keys=preset["extraction_keys"],
            log_mgr=log_mgr,
            use_write=preset.get("use_write", False),
            execute=True,
        )

    # --- Niveaux d'analyse purs (sans extraction) ---
    if choice in R2_ANALYSIS_LEVELS:
        return run_r2_custom(
            targets, outdir,
            analysis_key=choice,
            extraction_keys=["functions"],  # Toujours extraire les fonctions
            log_mgr=log_mgr,
            execute=True,
        )

    # --- Blocs d'extraction individuels ---
    if choice in R2_EXTRACTION_BLOCKS:
        return run_r2_custom(
            targets, outdir,
            analysis_key="aaa",  # Analyse aaa par défaut pour l'extraction
            extraction_keys=[choice],
            log_mgr=log_mgr,
            execute=True,
        )

    # --- Mode écriture r2 -w ---
    if choice == "write_wa":
        return _r2_write_mode(targets, outdir, log_mgr, ui, "wa")
    elif choice == "write_wx":
        return _r2_write_mode(targets, outdir, log_mgr, ui, "wx")
    elif choice == "write_w":
        return _r2_write_mode(targets, outdir, log_mgr, ui, "w")

    # --- Génération seule (sans exécution) ---
    if choice == "generate_only":
        if ui is not None:
            gen_choice = ui.get_r2_generate_choice()
            if gen_choice is None:
                return None
        else:
            gen_choice = "full"

        if gen_choice in R2_PRESETS:
            preset = R2_PRESETS[gen_choice]
            return run_r2_custom(
                targets, outdir,
                analysis_key=preset["analysis_key"],
                extraction_keys=preset["extraction_keys"],
                log_mgr=log_mgr,
                use_write=preset.get("use_write", False),
                execute=False,
            )
        else:
            return generate_r2_scripts(targets, outdir, log_mgr)

    # --- Custom : choix libre de l'analyse + extraction ---
    if choice == "custom":
        return _r2_custom_mode(targets, outdir, log_mgr, ui)

    # Fallback
    if log_mgr:
        log_mgr.add(f"Mode inconnu: {choice}", "warn")
    return None


def _r2_write_mode(targets, outdir, log_mgr, ui, write_cmd):
    """Mode écriture r2 : permettre à l'utilisateur de patcher un binaire.

    Args:
        write_cmd: "wa" (assemble), "wx" (hex), "w" (string)
    """
    r2_bin = _find_r2()
    if not r2_bin:
        if log_mgr:
            log_mgr.add("r2 not found. Cannot use write mode.", "error")
        return None

    cmd_labels = {
        "wa": "Écriture assembleur (wa) — écrire des instructions asm à une adresse",
        "wx": "Écriture hexadécimale (wx) — écrire des octets en hex à une adresse",
        "w": "Écriture string (w) — écrire une chaîne à une adresse",
    }

    if log_mgr:
        log_mgr.add(f"Mode écriture: {cmd_labels.get(write_cmd, write_cmd)}", "info")

    results = []
    for so in targets:
        if ui is not None:
            ui._print(f"\n  [bold bright_cyan]Patching: {so['name']}[/]" if ui.console
                      else f"\n  Patching: {so['name']}")

            # Demander l'adresse
            addr = ui._prompt_text(
                "  Adresse (hex, ex: 0x12345 ou sym.imp.printf)",
                default=""
            )
            if not addr:
                continue

            # Demander les données à écrire
            if write_cmd == "wa":
                data = ui._prompt_text(
                    '  Instructions assembleur (ex: "mov r0, 0; bx lr")',
                    default=""
                )
            elif write_cmd == "wx":
                data = ui._prompt_text(
                    "  Octets en hex (ex: 00bf00bf)",
                    default=""
                )
            else:
                data = ui._prompt_text(
                    "  Chaîne à écrire",
                    default=""
                )
            if not data:
                continue

            # Construire et exécuter la commande r2
            r2_cmd = f'{write_cmd} {data} @ {addr}'
            r2_script = f"e scr.color=0\ne scr.utf8=0\n{s}\nq\n"

            r2_out = os.path.join(outdir, "r2_output")
            os.makedirs(r2_out, exist_ok=True)
            name = so["name"].removesuffix(".so") + "_"
            script_path = os.path.join(r2_out, f"r2_{so['name']}_patch_{write_cmd}.r2")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(r2_script)
            results.append(script_path)

            if log_mgr:
                log_mgr.add(f"Patch script: {so['name']} ({write_cmd} @ {addr})", "info")

            try:
                timeout = int(_R2_TIMEOUT_ENV)
            except ValueError:
                timeout = 600

            try:
                result = subprocess.run(
                    [r2_bin, "-w", "-q", "-i", script_path, so["path"]],
                    capture_output=True, text=True, timeout=timeout,
                    stdin=subprocess.DEVNULL,
                )
                if result.returncode == 0:
                    if log_mgr:
                        log_mgr.add(f"Patch appliqué: {so['name']}", "success")
                else:
                    if log_mgr:
                        err = result.stderr.strip()
                        if len(err) > 200:
                            err = err[:200] + '...'
                        log_mgr.add(f"Patch erreur sur {so['name']}: {err}", "error")
            except Exception as e:
                if log_mgr:
                    log_mgr.add(f"Patch échoué sur {so['name']}: {e}", "error")
            if log_mgr:
                log_mgr.step()

    if log_mgr:
        log_mgr.add(f"Mode écriture terminé: {len(results)} script(s)", "success")
    return results


def _r2_custom_mode(targets, outdir, log_mgr, ui):
    """Mode personnalisé : l'utilisateur choisit l'analyse + les blocs d'extraction.

    Returns:
        Liste des scripts générés.
    """
    if ui is not None:
        # Sous-menu de sélection de l'analyse
        ui.display_r2_analysis_picker()
        analysis_choice = ui.get_r2_analysis_choice()
        if analysis_choice is None:
            return None

        # Sous-menu de sélection des blocs d'extraction
        ui.display_r2_extraction_picker()
        extraction_choices = ui.get_r2_extraction_choices()
        if not extraction_choices:
            return None

        # Demander si exécution ou génération seule
        do_execute = ui.get_r2_execute_choice()
    else:
        # Mode non-interactif : tout par défaut
        analysis_choice = "aaa"
        extraction_choices = list(R2_EXTRACTION_BLOCKS.keys())
        do_execute = True

    return run_r2_custom(
        targets, outdir,
        analysis_key=analysis_choice,
        extraction_keys=extraction_choices,
        log_mgr=log_mgr,
        execute=do_execute,
    )


def display_binary_info(so_list, outdir, log_mgr=None):
    """Run readelf-like on each .so and write the result to `outdir/binary_info.txt`.

    The full output is also reported line-by-line at "info" level when a log_mgr
    is provided, so the TUI's live panel reflects real content.
    """
    readelf = _find_readelf()
    if readelf is None:
        if log_mgr:
            log_mgr.add("readelf not found (tried: readelf, greadelf, llvm-readelf). "
                        "Cannot read binary info.", "warn")
        return

    info_path = os.path.join(outdir, "binary_info.txt")
    os.makedirs(outdir, exist_ok=True)
    with open(info_path, "w", encoding="utf-8") as out_f:
        for so in so_list:
            if log_mgr:
                log_mgr.add(f"Reading info: {so['name']}", "info")
            out_f.write(f"\n=== {so['name']} ===\n")
            try:
                result = subprocess.run(
                    [readelf, "-h", "-S", "-l", so["path"]],
                    capture_output=True, text=True, timeout=30,
                    stdin=subprocess.DEVNULL,
                )
                if result.returncode == 0:
                    out_f.write(result.stdout)
                    if log_mgr:
                        for line in result.stdout.strip().split("\n"):
                            log_mgr.add(f"[{so['name']}] {line.strip()}", "info")
                else:
                    err = result.stderr.strip()
                    out_f.write(f"(readelf error: {err})\n")
                    if log_mgr:
                        log_mgr.add(f"readelf error on {so['name']}: {err}", "warn")
            except subprocess.TimeoutExpired:
                out_f.write("(readelf timed out)\n")
                if log_mgr:
                    log_mgr.add(f"readelf timeout on {so['name']}", "warn")
            except (OSError, subprocess.SubprocessError) as e:
                out_f.write(f"(readelf error: {e})\n")
                if log_mgr:
                    log_mgr.add(f"Cannot read binary info on {so['name']}: {e}", "warn")
            finally:
                if log_mgr:
                    log_mgr.step()
    if log_mgr:
        log_mgr.add(f"Binary info written to {info_path}", "success")
