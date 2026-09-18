#!/usr/bin/env python3
import concurrent.futures
import os
import re
import shlex
import hashlib
import shutil
import subprocess

R2_HEADER = r"""e scr.color=0
e scr.utf8=0
e anal.strings=true
e bin.cache=true
"""

R2_ANALYSIS_LEVELS = {

    "a": {
        "label": "a  — Analyse minimale",
        "desc": "Analyse minimale des fonctions (aa)",
        "commands": "aa\nafl\n",
    },

    "aa": {
        "label": "aa — Analyse de base",
        "desc": "Analyse standard (aa : refs, strings, fonctions)",
        "commands": "aa\nafl\n",
    },

    "aaa": {
        "label": "aaa — Analyse avancée",
        "desc": "Analyse automatique poussée (aaa)",
        "commands": "aaa\nafl\n",
    },

    "all_anal": {
        "label": "Toutes les commandes d'analyse",
        "desc": "aa + aaa + aac + aar + afr + aae + aaft + aao + aav + aas + aat + aap + aau + ad",
        "commands": """aa
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

R2_EXTRACTION_BLOCKS = {
    "functions": {
        "label": "Fonctions uniquement",
        "desc": "Liste des fonctions (afl, aflq, afij)",
        "commands": r"""afl > __OUTDIR__/__NAME__functions.txt
aflq > __OUTDIR__/__NAME__func_list.txt
aflq~? > __OUTDIR__/__NAME__func_count.txt
afl~sym\. > __OUTDIR__/__NAME__sym_functions.txt
afl~sub\. > __OUTDIR__/__NAME__sub_functions.txt
aflj > __OUTDIR__/__NAME__functions_json.txt
aflj > __OUTDIR__/__NAME__functions_info.json
""",
    },
    "strings": {
        "label": "Strings uniquement",
        "desc": "Extraction de strings (iz, izz, izq, izzq)",
        "commands": """izz > __OUTDIR__/__NAME__strings.txt
iz > __OUTDIR__/__NAME__data_strings.txt
izq > __OUTDIR__/__NAME__data_strings_raw.txt
izzq > __OUTDIR__/__NAME__all_strings_raw.txt
""",
    },
    "imports_exports": {
        "label": "Imports / Exports",
        "desc": "Imports, exports, symboles, rélocations",
        "commands": """ii > __OUTDIR__/__NAME__imports.txt
iiq > __OUTDIR__/__NAME__imports_raw.txt
iE > __OUTDIR__/__NAME__exports.txt
iEq > __OUTDIR__/__NAME__exports_raw.txt
is > __OUTDIR__/__NAME__symbols.txt
isq > __OUTDIR__/__NAME__symbols_raw.txt
is~FUNC > __OUTDIR__/__NAME__func_symbols.txt
ir > __OUTDIR__/__NAME__relocations.txt
""",
    },
    "xrefs": {
        "label": "Cross-références",
        "desc": "Xrefs vers imports, depuis fonctions, compteurs",
        "commands": """axt @@ sym.imp.* > __OUTDIR__/__NAME__xrefs_to_imports.txt
axl > __OUTDIR__/__NAME__xrefs_all.txt
axf @@f > __OUTDIR__/__NAME__xrefs_from.txt
axlc > __OUTDIR__/__NAME__xrefs_count.txt
""",
    },
    "binary_info": {
        "label": "Info binaire (headers, sections, arch)",
        "desc": "Headers, sections, entrypoints, mémoire, architecture",
        "commands": """iS > __OUTDIR__/__NAME__sections.txt
iI > __OUTDIR__/__NAME__binary_info.txt
ie > __OUTDIR__/__NAME__entrypoints.txt
iH > __OUTDIR__/__NAME__headers.txt
im > __OUTDIR__/__NAME__memory_map.txt
ia > __OUTDIR__/__NAME__arch_info.txt
il > __OUTDIR__/__NAME__libraries.txt
f > __OUTDIR__/__NAME__flags.txt
""",
    },
    "classes": {
        "label": "Classes (C++ / Obj-C)",
        "desc": "Classes, méthodes, hiérarchies",
        "commands": """ic > __OUTDIR__/__NAME__classes.txt
icq > __OUTDIR__/__NAME__classes_raw.txt
icj > __OUTDIR__/__NAME__classes_json.txt
""",
    },
    "security": {
        "label": "Sécurité (crypto, tokens, secrets)",
        "desc": "AES, RSA, SHA, MD5, HMAC, clés, mots de passe, tokens, JWT, certificats",
        "commands": """/w AES > __OUTDIR__/__NAME__crypto_aes.txt
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
""",
    },
    "network": {
        "label": "Réseau (URLs, endpoints, auth)",
        "desc": "HTTP(S), WebSocket, Firebase, APIs, cookies, bearer, JWT, autorisations",
        "commands": """/w http > __OUTDIR__/__NAME__urls.txt
/w file:// > __OUTDIR__/__NAME__file_urls.txt
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
""",
    },
    "android": {
        "label": "Android (JNI, paths, dex)",
        "desc": "JNI_OnLoad, Java_, registerNatives, paths Android, dex, SharedPreferences",
        "commands": """/w JNI_OnLoad > __OUTDIR__/__NAME__jni.txt
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
/w /content/ > __OUTDIR__/__NAME__content_uris.txt
/w SharedPreferences > __OUTDIR__/__NAME__shared_prefs.txt
""",
    },
    "databases": {
        "label": "Bases de données",
        "desc": "SQLite, .db, .sqlite, protobuf",
        "commands": """/w SQLite > __OUTDIR__/__NAME__sqlite.txt
/w .db > __OUTDIR__/__NAME__db_refs.txt
/w .sqlite > __OUTDIR__/__NAME__sqlite_refs.txt
/w protobuf > __OUTDIR__/__NAME__protobuf.txt
""",
    },
    "hooks": {
        "label": "Hooks (x86 inline hooks)",
        "desc": "Détection de hooks x86 (pattern ff4889e7)",
        "commands": """/x ff4889e7 > __OUTDIR__/__NAME__x86_hooks.txt
""",
    },
}

_ALL_EXTRACTION = "\n".join(
    block["commands"] for block in R2_EXTRACTION_BLOCKS.values()
)

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
        "desc": "aa + liste des fonctions",
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

_R2_BATCH_JOBS_ENV = os.getenv("R2_BATCH_JOBS", "")

R2_DISASM_TEMPLATE = r"""e scr.color=0
e scr.utf8=0
e asm.bytes=true
e asm.lines=true
e asm.cmt.right=true
e asm.cmt.fold=true
e anal.strings=true
e bin.cache=true
aaa
__FUNCS_BLOCK__
q
"""

R2_BATCH_TEMPLATE = r"""#!/usr/bin/env bash

OUTDIR=__OUTDIR__
mkdir -p "$OUTDIR" || exit 1
cd "$OUTDIR" || exit 1
FAILURES=$(mktemp "$OUTDIR/.r2_failures.XXXXXX")
trap 'rm -f "$FAILURES"' EXIT

DEFAULTJOBS=4
case "${TERMUX_VERSION:-}:${PREFIX:-}" in ?*:*|*:*/com.termux/*) DEFAULTJOBS=1 ;; esac
MAXJOBS="${R2_BATCH_JOBS:-$DEFAULTJOBS}"
case "$MAXJOBS" in ''|*[!0-9]*) MAXJOBS=2 ;; esac
[ "$MAXJOBS" -lt 1 ] && MAXJOBS=1

run_one() {
    local errfile status
    errfile=$(mktemp "$OUTDIR/.r2_stderr.XXXXXX") || {
        echo "FAILED: cannot create stderr log" >> "$FAILURES"
        return
    }
    status=0
    "$@" 2> "$errfile" || status=$?
    cat "$errfile" >&2
    if [ "$status" -ne 0 ] || grep -Eiq '^(ERROR|ERR|Invalid command)[: ]' "$errfile"; then
        echo "FAILED: $*" >> "$FAILURES"
    fi
    rm -f "$errfile"
}

JOBCOUNT=0
__SCRIPTS_BLOCK__

wait
if [ -s "$FAILURES" ]; then
    echo "[ERR] Radare2 analysis had failures: $OUTDIR/"
    cat "$FAILURES" >&2
    exit 1
fi
echo "[OK] Radare2 analysis complete: $OUTDIR/"
"""

def _batch_line(cmd, target):
    return f'run_one {cmd} {shlex.quote(target)} &\nJOBCOUNT=$((JOBCOUNT+1))\n[ $((JOBCOUNT % MAXJOBS)) -eq 0 ] && wait\n'

def _targets(so_list):
    result = []
    seen = set()
    for so in so_list:
        path = os.path.realpath(so['path'])
        if path in seen:
            continue
        seen.add(path)
        name = re.sub(r'[^A-Za-z0-9_.-]', '_', os.path.basename(path))
        digest = hashlib.sha256(path.encode()).hexdigest()[:12]
        result.append({**so, 'path': path, 'name': name + '_' + digest})
    return result

def _render_script(template, outdir, name):
    def replace(match):
        filename = name + match.group(1)
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', filename):
            raise ValueError('Invalid Radare2 output filename')
        return filename
    return re.sub(r'__OUTDIR__/__NAME__([^\s]+)', replace, template)

def _timeout():
    try:
        value = int(os.getenv('R2_TIMEOUT', '600'))
    except ValueError:
        value = 600
    return value if value > 0 else 600

def _r2_max_workers(count):
    try:
        workers = int(os.getenv('R2_BATCH_JOBS', ''))
    except ValueError:
        workers = 0
    if workers <= 0:
        workers = 1 if os.getenv('TERMUX_VERSION') or 'com.termux' in os.getenv('PREFIX', '') else min(4, os.cpu_count() or 1)
    return max(1, min(count, workers))

_R2_TIMEOUT_ENV = os.getenv("R2_TIMEOUT", "600")

def _find_r2():
    for candidate in ("r2", "radare2"):
        path = shutil.which(candidate)
        if path:
            return path
    return None

def _find_readelf():
    for candidate in ("readelf", "greadelf", "llvm-readelf"):
        path = shutil.which(candidate)
        if path:
            return path
    return None

def _build_r2_script(analysis_key, extraction_keys, use_write=False,
                     asm_bytes=False, asm_lines=False):
    if analysis_key is not None and analysis_key not in R2_ANALYSIS_LEVELS:
        raise ValueError(f'Unknown analysis level: {analysis_key}')
    if any(key not in R2_EXTRACTION_BLOCKS for key in (extraction_keys or [])):
        raise ValueError('Unknown extraction block')
    parts = [R2_HEADER]

    if asm_bytes:
        parts.append("e asm.bytes=true\n")
    else:
        parts.append("e asm.bytes=false\n")
    if asm_lines:
        parts.append("e asm.lines=true\n")
    else:
        parts.append("e asm.lines=false\n")

    if analysis_key and analysis_key in R2_ANALYSIS_LEVELS:
        parts.append("\n")
        parts.append(R2_ANALYSIS_LEVELS[analysis_key]["commands"])

    if extraction_keys:
        for ek in extraction_keys:
            if ek in R2_EXTRACTION_BLOCKS:
                parts.append("\n")
                parts.append(R2_EXTRACTION_BLOCKS[ek]["commands"])

    parts.append("q\n")
    return "".join(parts)

def _build_write_script(patch_mode, patch_data, extraction_keys=None):
    parts = [R2_HEADER]
    parts.append("e asm.bytes=true\n")
    parts.append("e asm.lines=true\n")
    parts.append("e asm.cmt.right=true\n")

    parts.append("\n__PATCH_BLOCK__\n")

    if extraction_keys:
        for ek in extraction_keys:
            if ek in R2_EXTRACTION_BLOCKS:
                parts.append("\n")
                parts.append(R2_EXTRACTION_BLOCKS[ek]["commands"])

    parts.append("q\n")
    return "".join(parts)

def generate_r2_scripts(so_list, outdir, log_mgr=None):
    so_list = _targets(so_list)
    outdir = os.path.abspath(outdir)
    r2_out = os.path.join(outdir, "r2_output")
    os.makedirs(r2_out, exist_ok=True)
    generated = []
    batch_lines = []
    for so in so_list:
        name = so["name"].removesuffix(".so") + "_"
        script_content = _render_script(_build_r2_script("all_anal", list(R2_EXTRACTION_BLOCKS)), r2_out, name)
        script_path = os.path.join(r2_out, f"r2_{so['name']}.r2")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)
        generated.append(script_path)
        if log_mgr:
            log_mgr.add(f"Generated r2 script: r2_{so['name']}.r2", "success")
            log_mgr.step()

        abs_so = so["path"]
        batch_lines.append(_batch_line('r2 -q -i ' + shlex.quote(script_path), abs_so))

        disasm_funcs = _render_script('pdr @@f > __OUTDIR__/__NAME__disassembly.txt\n', r2_out, name)
        disasm_content = (R2_DISASM_TEMPLATE
                          .replace("__OUTDIR__", r2_out)
                          .replace("__NAME__", name)
                          .replace("__FUNCS_BLOCK__", disasm_funcs))
        disasm_path = os.path.join(r2_out, f"r2_{so['name']}_disasm.r2")
        with open(disasm_path, "w", encoding="utf-8") as f:
            f.write(disasm_content)
        batch_lines.append(_batch_line('r2 -q -i ' + shlex.quote(disasm_path), abs_so))
        if log_mgr:
            log_mgr.add(f"Generated r2 disasm script: r2_{so['name']}_disasm.r2", "success")
            log_mgr.step()

    batch_content = (R2_BATCH_TEMPLATE
                     .replace("__OUTDIR__", shlex.quote(r2_out))
                     .replace("__SCRIPTS_BLOCK__", "\n".join(batch_lines)))
    batch_path = os.path.join(outdir, "r2_analyze_all.sh")
    with open(batch_path, "w", encoding="utf-8") as f:
        f.write(batch_content)
    os.chmod(batch_path, 0o755)
    if log_mgr:
        log_mgr.add(f"Generated batch script: r2_analyze_all.sh ({len(generated)} .so)", "success")
    return generated

def _ensure_backup(so_path: str) -> str:

    backup = so_path + '.elitf.bak'
    if os.path.exists(backup):
        return backup
    with open(so_path, 'rb') as source, open(backup, 'xb') as saved:
        shutil.copyfileobj(source, saved)
    return backup

def _run_single_r2(r2_bin, script_path, so_path, timeout, log_mgr, so_name, use_write=False):
    try:
        cmd = [r2_bin]
        if use_write:
            cmd.append("-w")
        cmd += ["-q", "-i", script_path, so_path]
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, errors='replace', timeout=timeout,
            stdin=subprocess.DEVNULL,
            cwd=os.path.dirname(os.path.abspath(script_path)),
        )
        if result.returncode == 0 and not re.search(r'(?im)^(?:ERROR|ERR|Invalid command)[: ]', result.stderr):
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
    so_list = _targets(so_list)
    outdir = os.path.abspath(outdir)
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
        timeout = _timeout()
    except ValueError:
        timeout = 600

    jobs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=_r2_max_workers(len(so_list))) as pool:
        for so in so_list:
            name = so["name"].removesuffix(".so") + "_"
            script_content = _render_script(_build_r2_script("all_anal", list(R2_EXTRACTION_BLOCKS)), r2_out, name)
            script_path = os.path.join(r2_out, f"r2_{so['name']}.r2")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(script_content)
            generated.append(script_path)
            if log_mgr:
                log_mgr.add(f"Analyzing {so['name']} with r2...", "info")
                log_mgr.step()
            jobs.append(pool.submit(_run_single_r2, r2_bin, script_path, so["path"],
                                    timeout, log_mgr, so["name"]))
        for fut in concurrent.futures.as_completed(jobs):
            if fut.result():
                succeeded += 1
    if succeeded != len(generated):
        raise RuntimeError(f"Radare2 failed for {len(generated)-succeeded} target(s)")
    if log_mgr:
        log_mgr.add(f"r2 analysis finished: {succeeded}/{len(generated)} succeeded", "success")
    return generated

def run_r2_custom(so_list, outdir, analysis_key, extraction_keys, log_mgr=None,
                   use_write=False, execute=True):
    so_list = _targets(so_list)
    outdir = os.path.abspath(outdir)
    r2_out = os.path.join(outdir, "r2_output")
    os.makedirs(r2_out, exist_ok=True)
    r2_bin = _find_r2() if execute else None
    if execute and not r2_bin:
        if log_mgr:
            log_mgr.add("r2 not found. Generating scripts only.", "warn")
        execute = False

    try:
        timeout = _timeout()
    except ValueError:
        timeout = 600

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
    jobs = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=_r2_max_workers(len(so_list))) as pool:
        for so in so_list:
            name = so["name"].removesuffix(".so") + "_"
            script_content = _build_r2_script(
                analysis_key, extraction_keys, use_write=use_write
            )
            script_content = _render_script(script_content, r2_out, name)
            script_path = os.path.join(r2_out, f"r2_{so['name']}_{mode_tag}.r2")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(script_content)
            generated.append(script_path)
            if log_mgr:
                log_mgr.add(f"Generated: r2_{so['name']}_{mode_tag}.r2", "success")

            if execute:
                if log_mgr:
                    log_mgr.add(f"Analyzing {so['name']} ({mode_tag})...", "info")
                jobs.append(pool.submit(_run_single_r2, r2_bin, script_path, so["path"],
                                        timeout, log_mgr, so["name"], use_write))

            cmd = 'r2 -q -i ' + shlex.quote(script_path)
            if use_write:
                cmd = 'r2 -w -q -i ' + shlex.quote(script_path)
            batch_lines.append(_batch_line(cmd, so["path"]))
            if log_mgr:
                log_mgr.step()

        for fut in concurrent.futures.as_completed(jobs):
            if fut.result():
                succeeded += 1

    if generated:
        batch_content = (R2_BATCH_TEMPLATE
                         .replace("__OUTDIR__", shlex.quote(r2_out))
                         .replace("__SCRIPTS_BLOCK__", "\n".join(batch_lines)))
        batch_path = os.path.join(r2_out, f"r2_{mode_tag}_batch.sh")
        with open(batch_path, "w", encoding="utf-8") as f:
            f.write(batch_content)
        os.chmod(batch_path, 0o755)
        if log_mgr:
            log_mgr.add(f"Batch script: r2_{mode_tag}_batch.sh", "success")

    if execute and succeeded != len(generated):
        raise RuntimeError(f"Radare2 failed for {len(generated)-succeeded} target(s)")
    if log_mgr and execute:
        log_mgr.add(f"r2 {mode_tag}: {succeeded}/{len(generated)} succeeded", "success")
    return generated

def r2_exec_interactive(so_list, outdir, log_mgr=None, ui=None):
    if ui is None:
        raise ValueError("r2_exec_interactive requires a ui (interactive console)")
    r2_bin = _find_r2()
    if not r2_bin:
        msg = ("r2 introuvable — installez radare2 "
               "(Termux: pkg install radare2, Debian: apt install radare2)")
        if ui.console:
            from rich.panel import Panel as _Panel
            from rich.style import Style as _Style
            ui.console.print(_Panel(msg, title="[bold red]r2 absent[/]",
                                    border_style=_Style(color="red")))
        else:
            print(msg)
        return None
    selected = ui.get_target_selection()
    if not selected:
        if log_mgr:
            log_mgr.add("Aucune cible sélectionnée pour r2 interactif.", "warn")
        return None
    targets = [so_list[i] for i in selected]
    if not targets:
        return None
    target = targets[0]
    if len(targets) > 1:
        ui._print("[dim]r2 interactif ne supporte qu'une cible à la fois — "
                  "utilisation de la première: %s[/]" % target["name"]
                  if ui.console else
                  "r2 interactif ne supporte qu'une cible à la fois — "
                  "utilisation de la premiere: %s" % target["name"])
    if log_mgr:
        log_mgr.add(f"r2 interactif — cible: {target['name']} ({target['path']})", "info")
        log_mgr.step()
    argv = [r2_bin, "-e", "scr.color=2", "-e", "bin.cache=true",
            "-e", "anal.strings=true", "-e", "io.cache=true"]
    if ui.console:
        argv += ["-e", "scr.utf8=true"]
    argv.append(target["path"])
    header = ("=== r2 interactif — cible: %s ===\n"
              "Toutes les commandes r2 natives sont disponibles (a/i/p/s/f/c/C/d/g/t/y/z/k/m/o/r/e/v/?/!)\n"
              "quit ou q pour revenir à Elit-f\n" % target["name"])
    if ui.console:
        from rich.panel import Panel as _Panel
        from rich.style import Style as _Style
        ui.console.print(_Panel(header, title="[bold bright_green]r2 interactif[/]",
                                border_style=_Style(color="bright_green")))
    else:
        print(header)
    import subprocess
    import sys as _sys
    try:
        proc = subprocess.Popen(
            argv,
            stdin=_sys.stdin,
            stdout=_sys.stdout,
            stderr=_sys.stderr,
            close_fds=True,
        )
        proc.wait()
    except OSError as exc:
        ui._print(f"[bold red]Erreur lancement r2: {exc}[/]" if ui.console
                  else f"Erreur lancement r2: {exc}")
        return None
    except KeyboardInterrupt:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    if ui.console:
        ui.console.print("[dim]Retour à Elit-f.[/]")
    else:
        print("\nRetour à Elit-f.")
    return None


r2_mini_terminal = r2_exec_interactive


def display_binary_info(so_list, outdir, log_mgr=None):
    readelf = _find_readelf()
    if readelf is None:
        if log_mgr:
            log_mgr.add("readelf not found (tried: readelf, greadelf, llvm-readelf). "
                        "Cannot read binary info.", "warn")
        raise RuntimeError('readelf not found')

    os.makedirs(outdir, exist_ok=True)
    failures = []

    def _read_one(so):
        if log_mgr:
            log_mgr.add(f"Reading info: {so['name']}", "info")
        try:
            result = subprocess.run(
                [readelf, "-h", "-S", "-l", so["path"]],
                capture_output=True, text=True, timeout=30,
                stdin=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                if log_mgr:
                    for line in result.stdout.strip().split("\n"):
                        log_mgr.add(f"[{so['name']}] {line.strip()}", "info")
                return f"\n=== {so['name']} ===\n" + result.stdout
            err = result.stderr.strip()
            failures.append(so["path"])
            if log_mgr:
                log_mgr.add(f"readelf error on {so['name']}: {err}", "warn")
            return f"\n=== {so['name']} ===\n(readelf error: {err})\n"
        except subprocess.TimeoutExpired:
            failures.append(so["path"])
            if log_mgr:
                log_mgr.add(f"readelf timeout on {so['name']}", "warn")
            return f"\n=== {so['name']} ===\n(readelf timed out)\n"
        except (OSError, subprocess.SubprocessError) as e:
            failures.append(so["path"])
            if log_mgr:
                log_mgr.add(f"Cannot read binary info on {so['name']}: {e}", "warn")
            return f"\n=== {so['name']} ===\n(readelf error: {e})\n"
        finally:
            if log_mgr:
                log_mgr.step()

    with concurrent.futures.ThreadPoolExecutor(max_workers=_r2_max_workers(len(so_list))) as pool:
        sections = list(pool.map(_read_one, so_list))

    info_path = os.path.join(outdir, "binary_info.txt")
    with open(info_path, "w", encoding="utf-8") as out_f:
        out_f.write("".join(sections))
    if failures:
        raise RuntimeError(f"readelf failed for {len(failures)} target(s); see {info_path}")
    if log_mgr:
        log_mgr.add(f"Binary info written to {info_path}", "success")




R2_ANALYSIS_COMMANDS = {
    "a", "aa", "aaa", "aaaa", "af", "aar", "aac", "aae", "aas", "aat",
    "aap", "aau", "aao", "aav", "aaft", "afr", "ad",
}

R2_HEADER_LINES = ["e scr.color=0", "e scr.utf8=0", "e bin.cache=true",
                   "e anal.strings=true", "e io.cache=true"]

def _r2_output_limit():
    try:
        v = int(os.getenv("R2_OUTPUT_LIMIT", "0"))
        if v > 0:
            return v
    except ValueError:
        pass
    return 10_000_000

R2_OUTPUT_LIMIT = _r2_output_limit()

_R2_WRITE_PREFIXES = ("wa ", "wx ", "w ", "wo ", "r ", "r+", "r-", "rm ", "waF ", "wao ", "wv ")
_R2_SHELL_METACHARS = (';', '@', '|', '>', '~', '"', '`', "'", '\\')
_R2_SET_VALIDATOR = re.compile(r'^e\s+[A-Za-z0-9_.]+\s*=\s*\S+$')

PPTOOL_HINT = (
    "pptool introuvable. PPTool est un outil Python de la communauté "
    "Termux/Flutter qui localise les adresses de chargement des objets Dart "
    "dans libapp.so. Installez-le puis relancez, ou pointez la variable "
    "d'environnement ELITF_PPTOOL vers le binaire/le script pptool."
)


def _find_pptool():

    env_path = os.getenv('ELITF_PPTOOL', '')
    if env_path and os.path.isfile(env_path):
        return env_path
    for candidate in ('pptool', 'pptool.py'):
        found = shutil.which(candidate)
        if found:
            return found
    project_dir = os.path.dirname(os.path.abspath(__file__))
    for rel in ('bin/pptool', 'bin/pptool.py', 'pptool.py', 'pptool/pptool.py'):
        candidate = os.path.join(project_dir, rel)
        if os.path.isfile(candidate):
            return candidate
    return None


def _cat(cmd, desc, args=None, raw=None, write=False):
    entry = {"cmd": cmd, "desc": desc}
    if args:
        entry["args"] = args
    if raw is not None:
        entry["raw"] = raw
    if write:
        entry["write"] = True
    return entry


R2_TERMINAL_CATALOG = {
    "analyse": {
        "title": "Analyse (a)",
        "commands": [
            _cat("a", "Analyse minimale"),
            _cat("aa", "Analyse de base (références, strings, fonctions)"),
            _cat("aaa", "Analyse avancée (recommandée avant pdf/axt)"),
            _cat("aaaa", "Analyse expérimentale — très longue"),
            _cat("af", "Analyser la fonction à l'adresse",
                 [("addr", "Adresse (ex: 0x1000, sym.imp.printf)", "")]),
            _cat("afl", "Lister les fonctions analysées"),
            _cat("aflj", "Lister les fonctions en JSON"),
            _cat("afta", "Récupérer les types de toutes les fonctions"),
            _cat("ab", "Infos de bloc de base à l'adresse",
                 [("addr", "Adresse", "")]),
            _cat("afi", "Infos sur la fonction à l'adresse",
                 [("addr", "Adresse", "")]),
            _cat("agf", "Graphe ASCII de la fonction à l'adresse",
                 [("addr", "Adresse", "")]),
        ],
    },
    "info": {
        "title": "Informations binaires (i)",
        "commands": [
            _cat("iI", "Infos du binaire (arch, bits, compilateur, OS)"),
            _cat("iS", "Sections (adresses, tailles, permissions)"),
            _cat("iSS", "Segments en détail"),
            _cat("iH", "En-têtes ELF en détail"),
            _cat("ie", "Point d'entrée"),
            _cat("ii", "Imports"),
            _cat("iE", "Exports"),
            _cat("is", "Symboles"),
            _cat("ir", "Réallocations"),
            _cat("iz", "Strings de la section données"),
            _cat("izz", "Strings de tout le binaire"),
            _cat("ic", "Classes (C++ / Obj-C)"),
            _cat("icj", "Classes en JSON"),
            _cat("im", "Carte mémoire (main/stack/heap)"),
            _cat("il", "Bibliothèques liées"),
            _cat("iM", "Adresse de main"),
            _cat("ia", "Infos sur l'architecture"),
            _cat("ib", "Bords/limites du binaire"),
        ],
    },
    "print": {
        "title": "Impression / Visualisation (p)",
        "commands": [
            _cat("pd", "Désassembler N instructions à l'adresse",
                 [("count", "Nombre d'instructions (défaut 20)", "20"),
                  ("addr", "Adresse", "")]),
            _cat("pdf", "Désassembler la fonction à l'adresse (aaa conseillé)",
                 [("addr", "Adresse ou symbole", "")]),
            _cat("pdr", "Désassemblage récursif à l'adresse",
                 [("addr", "Adresse", "")]),
            _cat("px", "Hexdump de N octets à l'adresse",
                 [("count", "Nombre d'octets (défaut 64)", "64"),
                  ("addr", "Adresse", "")]),
            _cat("pxr", "Hexdump avec annotations (pointeurs, strings)",
                 [("count", "Nombre d'octets", "64"), ("addr", "Adresse", "")]),
            _cat("pxw", "Hexdump en mots 32 bits",
                 [("count", "Nombre d'octets", "64"), ("addr", "Adresse", "")]),
            _cat("pxa", "Hexdump annoté (désassemblage des valeurs)",
                 [("addr", "Adresse", "")]),
            _cat("ps", "String à l'adresse", [("addr", "Adresse", "")]),
            _cat("psz", "String terminée par \\0 à l'adresse",
                 [("addr", "Adresse", "")]),
            _cat("p8", "Octets bruts (hex) à l'adresse",
                 [("count", "Nombre d'octets", "64"), ("addr", "Adresse", "")]),
        ],
    },
    "search": {
        "title": "Recherche (/)",
        "commands": [
            _cat("/", "Rechercher une chaîne de caractères",
                 [("value", "Texte à chercher", "")]),
            _cat("/w", "Rechercher une chaîne UTF-16 (wide)",
                 [("value", "Texte à chercher", "")]),
            _cat("/x", "Rechercher des octets en hexadécimal",
                 [("value", "Octets hex (ex: ff4889e7)", "")]),
            _cat("/c", "Rechercher un code / une instruction asm",
                 [("value", "Instruction (ex: bl sym.imp.printf)", "")]),
            _cat("/r", "Rechercher des gadgets ROP"),
            _cat("/C", "Rechercher des matériaux crypto connus (AES/RSA/SHA)"),
            _cat("", "Filtrer les strings par motif",
                 [("motif", "Motif (ex: password, token, api)", "")],
                 raw="izz~{0}"),
        ],
    },
    "xrefs": {
        "title": "Cross-références (ax)",
        "commands": [
            _cat("axt", "Xrefs VERS l'adresse (qui l'appelle)",
                 [("addr", "Adresse ou symbole", "")]),
            _cat("axf", "Xrefs DEPUIS l'adresse (ce qu'elle appelle)",
                 [("addr", "Adresse ou symbole", "")]),
            _cat("axl", "Lister toutes les xrefs connues"),
            _cat("", "Xrefs vers tous les imports",
                 raw="axt @@ sym.imp.*"),
        ],
    },
    "write": {
        "title": "Écriture / Patching (r2 -w)",
        "commands": [
            _cat("wa", "Écrire des instructions assembleur à une adresse",
                 [("value", "Instructions asm (ex: mov r0, 0; bx lr)", ""),
                  ("addr", "Adresse", "")], write=True),
            _cat("wx", "Écrire des octets en hexadécimal à une adresse",
                 [("value", "Octets hex (ex: 00bf00bf)", ""),
                  ("addr", "Adresse", "")], write=True),
            _cat("w", "Écrire une chaîne de caractères à une adresse",
                 [("value", "Chaîne à écrire", ""),
                  ("addr", "Adresse", "")], write=True),
        ],
    },
    "config": {
        "title": "Configuration session (e)",
        "commands": [
            _cat("e asm.bytes", "Afficher les octets en désassemblage (true/false)",
                 [("value", "valeur (true/false)", "true")]),
            _cat("e asm.lines", "Afficher les lignes de flux (true/false)",
                 [("value", "valeur (true/false)", "true")]),
            _cat("e asm.offset", "Afficher les adresses (true/false)",
                 [("value", "valeur (true/false)", "true")]),
            _cat("e asm.arch", "Changer l'architecture (x86, arm, arm64, mips)",
                 [("value", "arch", "arm")]),
            _cat("e asm.bits", "Bits (16/32/64)",
                 [("value", "bits", "64")]),
            _cat("e anal.depth", "Profondeur maximale de l'analyse",
                 [("value", "profondeur (nombre)", "4")]),
            _cat("e scr.color", "Couleurs r2 (0 = désactivé)",
                 [("value", "valeur (0/1/2/3)", "0")]),
            _cat("e scr.utf8", "UTF-8 en sortie (true/false)",
                 [("value", "valeur", "true")]),
            _cat("e bin.cache", "Cache binaire (true/false)",
                 [("value", "valeur", "true")]),
            _cat("e io.cache", "Cache IO pour écriture",
                 [("value", "valeur", "true")]),
            _cat("e emu.str", "Émulation de strings",
                 [("value", "valeur", "true")]),
            _cat("e", "Lister toute la configuration"),
            _cat("ed", "Éditer la config dans $EDITOR"),
        ],
    },
    "seek": {
        "title": "Déplacement / Seek (s)",
        "commands": [
            _cat("s", "Aller à l'adresse",
                 [("addr", "Adresse ou symbole", "")]),
            _cat("s-", "Reculer dans l'historique"),
            _cat("s+", "Avancer dans l'historique"),
            _cat("s.", "Seek au point d'entrée (entry0)"),
            _cat("s+", "Avancer de N octets",
                 [("value", "Nombre d'octets", "16")]),
            _cat("s-", "Reculer de N octets",
                 [("value", "Nombre d'octets", "16")]),
            _cat("sa", "Seek absolu + alignement",
                 [("addr", "Adresse", "")]),
            _cat("sb", "Seek au bloc de base",
                 [("addr", "Adresse", "")]),
            _cat("sf", "Seek au début de la fonction",
                 [("addr", "Adresse ou symbole de fonction", "")]),
            _cat("sr", "Rewind (debut du fichier)"),
            _cat("sg", "Seek au symbole",
                 [("value", "Nom de symbole", "")]),
            _cat("sl", "Seek par numéro de ligne",
                 [("value", "Ligne", "1")]),
            _cat("sn", "Seek au symbole suivant"),
            _cat("sp", "Seek au symbole précédent"),
            _cat("so", "Seek à l'offset N dans la fonction",
                 [("value", "Offset", "0")]),
            _cat("sv", "Seek au Viewer"),
        ],
    },
    "flags": {
        "title": "Flags / Marqueurs (f)",
        "commands": [
            _cat("f", "Lister tous les flags"),
            _cat("fj", "Flags en JSON"),
            _cat("fs", "Lister les espaces de flags"),
            _cat("fs", "Changer d'espace de flags",
                 [("value", "Nom d'espace", "functions")]),
            _cat("f+", "Ajouter un flag",
                 [("addr", "Adresse", ""), ("value", "Nom du flag", "mon_flag")]),
            _cat("f-", "Supprimer un flag",
                 [("value", "Nom du flag", "")]),
            _cat("fr", "Renommer un flag",
                 [("value", "Ancien nom", ""), ("value", "Nouveau nom", "")]),
            _cat("fc", "Couleur d'un flag",
                 [("value", "Nom du flag", ""), ("value", "Couleur", "red")]),
            _cat("ff", "Lister les flags de fonction"),
            _cat("fb", "Lister les flags par bloc"),
            _cat("fz", "Ajouter un flag avec string"),
            _cat("fl", "Lister flags avec tailles"),
        ],
    },
    "block": {
        "title": "Bloc / Taille (b)",
        "commands": [
            _cat("b", "Taille du bloc courant",
                 [("value", "Taille en octets", "256")]),
            _cat("bf", "Taille du bloc depuis un flag",
                 [("value", "Nom du flag", "")]),
            _cat("b+", "Augmenter la taille du bloc",
                 [("value", "Octets", "16")]),
            _cat("b-", "Diminuer la taille du bloc",
                 [("value", "Octets", "16")]),
            _cat("bc", "Compter les octets non nuls"),
            _cat("bm", "Masque de bloc"),
        ],
    },
    "compare": {
        "title": "Comparer (c)",
        "commands": [
            _cat("c", "Comparer N octets à l'adresse",
                 [("count", "Octets", "32"), ("addr", "Adresse 1", ""),
                  ("addr2", "Adresse 2", "")]),
            _cat("cc", "Comparaison cyclique (CRC)"),
            _cat("ca", "Addition hexadécimale",
                 [("value", "Hex", "0x10")]),
            _cat("cx", "Comparer avec une chaîne hex",
                 [("value", "Hex", "deadbeef")]),
            _cat("cX", "Comparer en hex avec offsets"),
            _cat("cd", "Comparer données (binaire)"),
            _cat("cw", "Comparer mots"),
            _cat("cu", "Comparer unités (1/2/4/8 octets)"),
            _cat("cj", "Comparer en JSON"),
        ],
    },
    "crypto": {
        "title": "Crypto / Entropie (C)",
        "commands": [
            _cat("Ca", "Assembler (ROR/ROL/ADD/SUB/XOR)"),
            _cat("Cc", "Chiffrement César",
                 [("value", "Décalage", "3")]),
            _cat("CA", "AES"),
            _cat("Cd", "Désassembler avec crypto"),
            _cat("Cx", "XOR avec clé",
                 [("value", "Clé hex", "ff")]),
            _cat("Cb", "Brute-force XOR"),
            _cat("Cf", "Trouver des clés crypto"),
            _cat("Cp", "Plain-text crypto"),
            _cat("Co", "OpenSSL crypto"),
            _cat("Ch", "Hash (MD5/SHA1/SHA256)"),
            _cat("Ce", "Entropie de Shannon"),
        ],
    },
    "debug": {
        "title": "Debug / Exécution (d)",
        "commands": [
            _cat("db", "Ajouter un point d'arrêt",
                 [("addr", "Adresse", "")]),
            _cat("db-", "Supprimer un point d'arrêt",
                 [("addr", "Adresse", "")]),
            _cat("dbi", "Lister les breakpoints"),
            _cat("dc", "Continuer l'exécution"),
            _cat("dcu", "Continuer jusqu'à l'adresse",
                 [("addr", "Adresse", "")]),
            _cat("ds", "Step into"),
            _cat("dso", "Step over"),
            _cat("dsf", "Step fin"),
            _cat("dsb", "Step back"),
            _cat("dr", "Afficher les registres"),
            _cat("drr", "Afficher les références de registres"),
            _cat("dr=", "Registres en mode visuel"),
            _cat("dr8", "Registres en hexdump"),
            _cat("drc", "Changer la valeur d'un registre",
                 [("value", "Registre", "rax"), ("value", "Valeur", "0")]),
            _cat("dm", "Carte mémoire du process"),
            _cat("dm=", "Carte mémoire visuelle"),
            _cat("dmm", "Carte mémoire des modules"),
            _cat("dma", "Allouer de la mémoire",
                 [("value", "Taille", "0x1000")]),
            _cat("dmas", "Allouer et écrire une string",
                 [("value", "String", "test")]),
            _cat("dmad", "Allouer et dupliquer des données"),
            _cat("dmh", "Heap info"),
            _cat("do", "Ouvrir un process"),
            _cat("doc", "Recharger core"),
            _cat("dp", "Lister les processus"),
            _cat("dpl", "Lister threads"),
            _cat("dpc", "Process courant"),
            _cat("dpid", "PID courant"),
            _cat("dpt", "Lister les threads"),
            _cat("dptn", "Nouveau thread"),
            _cat("dptk", "Tuer un thread",
                 [("value", "TID", "")]),
            _cat("dg", "Générer un core dump"),
            _cat("dml", "Lister les bibliothèques chargées"),
            _cat("dmlv", "Vérifier les bibliothèques"),
        ],
    },
    "graphs": {
        "title": "Graphes / CFG (g)",
        "commands": [
            _cat("agf", "Graphe ASCII de la fonction à l'adresse",
                 [("addr", "Adresse", "")]),
            _cat("agfl", "Graphe ASCII linéaire",
                 [("addr", "Adresse", "")]),
            _cat("agd", "Graphe DOT de la fonction",
                 [("addr", "Adresse", "")]),
            _cat("agg", "Graphe graphique"),
            _cat("agj", "Graphe JSON"),
            _cat("ag-",
                 "Supprimer un nœud du graphe",
                 [("addr", "Adresse", "")]),
            _cat("agn",
                 "Ajouter un nœud",
                 [("addr", "Adresse", ""), ("value", "Titre", "")]),
            _cat("age",
                 "Ajouter une arête",
                 [("addr", "From", ""), ("addr2", "To", "")]),
            _cat("agc", "Graphe des appels (callgraph)"),
            _cat("agC", "Graphe global des appels"),
            _cat("agr", "Graphe récursif"),
            _cat("agR", "Graphe récursif global"),
            _cat("agx", "Graphe cross-références",
                 [("addr", "Adresse", "")]),
            _cat("agt", "Graphe des threads"),
            _cat("agv", "Graphe visuel"),
        ],
    },
    "info_extra": {
        "title": "Informations avancées (i+)",
        "commands": [
            _cat("iA", "Analyses disponibles"),
            _cat("ia", "Infos sur l'architecture"),
            _cat("iC", "Attributs/signatures"),
            _cat("iD", "Dépendances"),
            _cat("id", "Debug info (DWARF)"),
            _cat("idp", "Liste des fichiers source DWARF"),
            _cat("idpi", "Info sur un fichier source",
                 [("value", "Index", "0")]),
            _cat("idpd", "Lister les fonctions DWARF"),
            _cat("ie", "Points d'entrée"),
            _cat("iE", "Exports"),
            _cat("iEj", "Exports JSON"),
            _cat("ih", "Hashes du binaire"),
            _cat("iHH", "Headers complets"),
            _cat("ik", "KeyValue (sdb)"),
            _cat("iK", "Bin exports (Java/Kotlin)"),
            _cat("il", "Bibliothèques liées"),
            _cat("iL", "Lister les plugins binaires"),
            _cat("io", "Infos IO"),
            _cat("iO", "Open info"),
            _cat("ip", "PDB info"),
            _cat("iP", "PDB paths"),
            _cat("ir", "Réallocations"),
            _cat("iR", "Relro info"),
            _cat("is", "Symboles"),
            _cat("isj", "Symboles JSON"),
            _cat("iS", "Sections"),
            _cat("iSj", "Sections JSON"),
            _cat("iSS", "Segments"),
            _cat("iSSj", "Segments JSON"),
            _cat("iT", "Trap info"),
            _cat("it", "Hashes textuels"),
            _cat("iV", "Version info"),
            _cat("iX", "Cross-bin info"),
            _cat("iz", "Strings de la section données"),
            _cat("izj", "Strings JSON"),
            _cat("izz", "Strings de tout le binaire"),
            _cat("izzj", "Strings globales JSON"),
            _cat("iZ", "Strings size+length"),
        ],
    },
    "open": {
        "title": "Fichiers / Open (o)",
        "commands": [
            _cat("o", "Lister les fichiers ouverts"),
            _cat("oj", "Fichiers ouverts JSON"),
            _cat("oa", "Open avec arch",
                 [("value", "Path", ""), ("value", "Arch", "arm"),
                  ("value", "Bits", "64")]),
            _cat("ob", "Open binaire"),
            _cat("oc", "Close core"),
            _cat("of", "Open fichier"),
            _cat("oi", "Info d'un fd",
                 [("value", "fd", "3")]),
            _cat("om", "Carte mémoire des fichiers"),
            _cat("on", "Open sans analyse"),
            _cat("oo", "Reopen"),
            _cat("ood", "Reopen en debug"),
            _cat("oo+", "Reopen en écriture"),
            _cat("op", "Open pipe"),
            _cat("o-", "Fermer un fd",
                 [("value", "fd", "3")]),
            _cat("ox", "Échanger deux fds"),
        ],
    },
    "resize": {
        "title": "Redimensionner (r)",
        "commands": [
            _cat("r", "Redimensionner à N octets",
                 [("value", "Taille", "0x1000")]),
            _cat("r+", "Augmenter de N octets",
                 [("value", "Octets", "0x100")]),
            _cat("r-", "Diminuer de N octets",
                 [("value", "Octets", "0x100")]),
            _cat("rm", "Supprimer un fichier",
                 [("value", "Path", "")]),
            _cat("rh", "Taille du fichier"),
            _cat("ro", "Rotate N octets",
                 [("value", "Octets", "1")]),
            _cat("rw", "Bytes aléatoires"),
            _cat("rc", "Recompiler"),
            _cat("rp", "Noms de fonctions heuristiques"),
            _cat("rs", "Stuffer"),
        ],
    },
    "types": {
        "title": "Types / C (t)",
        "commands": [
            _cat("t", "Lister les types"),
            _cat("tj", "Types JSON"),
            _cat("tc", "Lister les types complexes"),
            _cat("te", "Lister les enums"),
            _cat("ts", "Lister les structures"),
            _cat("tu", "Lister les unions"),
            _cat("ta", "Analyser un type",
                 [("value", "Nom de type", "")]),
            _cat("td", "Définir un type C",
                 [("value", "Définition", "struct Foo { int x; };")]),
            _cat("tf", "Lister les typedefs"),
            _cat("tn", "Lister les typedefs nacked"),
            _cat("tp", "Définir un type sur un offset",
                 [("value", "Type", ""), ("addr", "Adresse", "")]),
            _cat("tpx", "Prévisualiser un type"),
            _cat("tr", "Supprimer un type",
                 [("value", "Nom", "")]),
            _cat("tt", "Lister les typedefs"),
            _cat("tv", "Variables"),
            _cat("tx", "Lister les types xrefs"),
            _cat("t*", "Types en r2 commands"),
        ],
    },
    "yank": {
        "title": "Yank / Copier (y)",
        "commands": [
            _cat("y", "Copier N octets",
                 [("count", "Octets", "64"), ("addr", "Adresse", "")]),
            _cat("yj", "Copier en JSON"),
            _cat("yy", "Coller à l'adresse",
                 [("addr", "Adresse", "")]),
            _cat("yz", "Copier une string"),
            _cat("yp", "Imprimer le yank buffer"),
            _cat("yx", "Imprimer en hex"),
            _cat("ys", "Imprimer en string"),
            _cat("yw", "Écrire un fichier binaire"),
            _cat("yf", "Copier depuis un fichier",
                 [("value", "Path", ""), ("value", "Offset", "0"),
                  ("value", "Taille", "0")]),
            _cat("yt", "Copier à une adresse",
                 [("count", "Octets", "64"), ("addr", "From", ""),
                  ("addr2", "To", "")]),
            _cat("ytf", "Copier vers un fichier"),
            _cat("ya", "Yank et ajouter"),
            _cat("yP", "Yank permanent (clipboard)"),
        ],
    },
    "zignatures": {
        "title": "Signatures (z)",
        "commands": [
            _cat("z", "Lister les zignatures"),
            _cat("zj", "Zignatures JSON"),
            _cat("z-", "Supprimer une zignature",
                 [("value", "Nom", "")]),
            _cat("za", "Ajouter une zignature",
                 [("value", "Nom", ""), ("value", "Type", "f")]),
            _cat("zg", "Générer des zignatures"),
            _cat("zF", "Filtrer zignatures par type"),
            _cat("zf", "Zignature de la fonction courante"),
            _cat("zo", "Ouvrir un fichier zignatures",
                 [("value", "Path", "")]),
            _cat("zs", "Sauver dans un fichier zignatures",
                 [("value", "Path", "")]),
            _cat("z/ ", "Chercher des zignatures"),
            _cat("z*", "Zignatures en r2 commands"),
        ],
    },
    "sdb": {
        "title": "Base de données (k)",
        "commands": [
            _cat("k", "Lister/Masquer sdb"),
            _cat("kj", "sdb JSON"),
            _cat("kd", "Dump sdb"),
            _cat("ks", "Compter"),
            _cat("ko", "Ouvrir sdb",
                 [("value", "Path", "")]),
            _cat("ka", "Ajouter clé/valeur",
                 [("value", "Clé", ""), ("value", "Valeur", "")]),
            _cat("kg", "Obtenir une clé",
                 [("value", "Clé", "")]),
            _cat("kr", "Supprimer une clé",
                 [("value", "Clé", "")]),
            _cat("kl", "Lister"),
            _cat("kv", "Vérifier une clé"),
            _cat("kf", "Existe (bool)"),
        ],
    },
    "mount": {
        "title": "Montage / Mount (m)",
        "commands": [
            _cat("m", "Lister les mounts"),
            _cat("ml", "Lister"),
            _cat("mi", "Infos mount"),
            _cat("mo", "Ouvrir un mount"),
            _cat("mc", "Fermer un mount"),
            _cat("mf", "Filtrer"),
            _cat("mm", "Mapper à une adresse",
                 [("addr", "Adresse", ""), ("value", "Path", "")]),
            _cat("me", "Évaluer"),
            _cat("mv", "Vérifier"),
            _cat("md", "Supprimer"),
        ],
    },
    "visual": {
        "title": "Mode visuel / Affichage (e scr+)",
        "commands": [
            _cat("e scr.color", "Couleur r2 (0/1/2/3)",
                 [("value", "valeur", "0")]),
            _cat("e scr.utf8", "UTF-8 en sortie",
                 [("value", "valeur", "true")]),
            _cat("e scr.interactive", "Mode interactif (false en batch)",
                 [("value", "valeur", "false")]),
            _cat("e asm.bytes", "Afficher les octets",
                 [("value", "valeur", "true")]),
            _cat("e asm.lines", "Afficher les lignes de flux",
                 [("value", "valeur", "true")]),
            _cat("e asm.comments", "Commentaires en désassemblage",
                 [("value", "valeur", "true")]),
            _cat("e asm.cmt.right", "Commentaires à droite",
                 [("value", "valeur", "true")]),
        ],
    },
    "system": {
        "title": "Système / Divers (?/.)",
        "commands": [
            _cat("?", "Aide générale r2"),
            _cat("??", "Aide détaillée"),
            _cat("?v", "Évaluer une expression arithmétique",
                 [("value", "Expression (ex: 0x1000+0x20)", "")]),
            _cat("?vi", "Évaluer en entier"),
            _cat("?vx", "Évaluer en hex"),
            _cat("?vd", "Calculer distance entre deux adresses",
                 [("addr", "From", ""), ("addr2", "To", "")]),
            _cat("?P", "Imprimer le prompt"),
            _cat(". ", "Interpréter la sortie d'une commande shell",
                 [("value", "Commande shell", "ls")]),
            _cat(".! ", "Exécuter shell et interpréter",
                 [("value", "Commande shell", "uname -a")]),
            _cat("*", "Lister les commentaires"),
            _cat("% ", "Foreach (loop)"),
            _cat("@ ", "Temp seek @ addr"),
            _cat("| ", "Pipe vers shell"),
            _cat("> ", "Rediriger vers fichier"),
            _cat(">> ", "Append vers fichier"),
            _cat("H", "Voir l'historique"),
        ],
    },
}


def _escape_r2_value(v):
    if any(c in v for c in _R2_SHELL_METACHARS):
        escaped = v.replace('\\', '\\\\').replace('"', '\\"')
        return '"' + escaped + '"'
    return v


def _compose_r2_command(entry, values):
    raw = entry.get('raw')
    if raw is not None:
        out = raw
        for i, v in enumerate(values):
            out = out.replace('{' + str(i) + '}', v or '')
        return out
    parts = [entry['cmd']]
    addr_tail = []
    extra_tail = []
    args = entry.get('args') or []
    for (key, _prompt, _default), v in zip(args, values):
        v = (v or '').strip()
        if not v:
            continue
        if key == 'addr':
            addr_tail.append('@ ' + v)
        elif key == 'addr2':
            extra_tail.append(v)
        elif key == 'value':
            parts.append(_escape_r2_value(v))
        else:
            parts.append(v)
    return ' '.join(parts + extra_tail + addr_tail)


class R2Session:


    def __init__(self, so_list, outdir, log_mgr=None, ui=None):
        if ui is None:
            raise ValueError('R2Session requires a ui (interactive console)')
        self.targets = _targets(so_list)
        if not self.targets:
            raise ValueError('No .so targets for r2 console')
        self.outdir = os.path.abspath(outdir)
        self.log_mgr = log_mgr
        self.ui = ui
        self.r2_bin = _find_r2()
        self.pptool_bin = _find_pptool()
        self.active = 0
        self.env_cmds = []
        self.analysis_cmds = []
        self.anal_replay = True
        self.rw = False

    # -- cibles -------------------------------------------------------------

    @property
    def active_target(self):
        return self.targets[self.active]

    def _switch(self, idx):
        if idx != self.active:
            self.analysis_cmds = []
        self.active = idx
        if self.rw:
            self._backup_active()

    def use(self, ref):
        ref = (ref or '').strip()
        if ref.isdigit():
            idx = int(ref) - 1
            if 0 <= idx < len(self.targets):
                self._switch(idx)
                return True
            return False
        for i, t in enumerate(self.targets):
            if ref.lower() in t['name'].lower():
                self._switch(i)
                return True
        return False

    # -- exécution ----------------------------------------------------------

    def _backup_active(self):
        backup = _ensure_backup(self.active_target['path'])
        if self.log_mgr:
            self.log_mgr.add(f"Backup r2 -w: {backup}", "debug")

    def _script_parts(self, cmd):
        tokens = cmd.split()
        first = tokens[0] if tokens else ''
        parts = list(R2_HEADER_LINES) + list(self.env_cmds)
        if (self.anal_replay and self.analysis_cmds
                and first not in R2_ANALYSIS_COMMANDS):
            parts.extend(self.analysis_cmds)
        parts.append(cmd)
        return parts

    def run_r2(self, cmd):
        if not self.r2_bin:
            return 127, '', ('r2 introuvable — installez radare2 '
                             '(Termux: pkg install radare2)')
        try:
            timeout = _timeout()
        except ValueError:
            timeout = 600
        if self.rw:
            self._backup_active()
        argv = [self.r2_bin] + (['-w'] if self.rw else []) + ['-q', '-e', 'bin.cache=true']
        for part in self._script_parts(cmd):
            argv += ['-c', part]
        argv.append(self.active_target['path'])
        r2_out_dir = os.path.join(self.outdir, 'r2_output')
        os.makedirs(r2_out_dir, exist_ok=True)
        try:
            result = subprocess.run(
                argv, capture_output=True, text=True, errors='replace',
                timeout=timeout, stdin=subprocess.DEVNULL, cwd=r2_out_dir)
        except subprocess.TimeoutExpired:
            return 124, '', f'timeout r2 (>{timeout}s) — ajustez R2_TIMEOUT'
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, '', str(exc)
        tokens = cmd.split()
        first = tokens[0] if tokens else ''
        if result.returncode == 0 and first in R2_ANALYSIS_COMMANDS \
                and cmd not in self.analysis_cmds:
            self.analysis_cmds.append(cmd)
        return result.returncode, result.stdout or '', result.stderr or ''

    def _expand_placeholders(self, arg):
        t = self.active_target
        return (arg.replace('{so}', t['path'])
                   .replace('{libapp}', t['path'])
                   .replace('{name}', t['name'])
                   .replace('{outdir}', self.outdir))

    def run_pptool(self, argstr):
        if not self.pptool_bin:
            return False, PPTOOL_HINT
        try:
            args = shlex.split(argstr or '')
        except ValueError:
            return False, 'Arguments pptool invalides (guillemets non fermés ?)'
        args = [self._expand_placeholders(a) for a in args]
        try:
            timeout = _timeout()
        except ValueError:
            timeout = 600
        try:
            result = subprocess.run(
                [self.pptool_bin] + args, capture_output=True, text=True,
                errors='replace', timeout=timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return False, f'timeout pptool (>{timeout}s)'
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
        text = (result.stdout or '')
        if result.stderr and result.stderr.strip():
            text += ('\n' if text else '') + result.stderr
        return result.returncode == 0, text.strip()

    # -- affichage ----------------------------------------------------------

    def _emit(self, text):

        if hasattr(self.ui, 'print_raw'):
            self.ui.print_raw(text)
        else:
            self.ui._print(text)

    def _show_output(self, text, ok=True):
        text = (text or '').rstrip()
        limit = _r2_output_limit()
        if len(text) > limit:
            text = (text[:limit] +
                    f"\n... [sortie tronquee a {limit} caracteres sur {len(text)}]"
                    f"\n    Astuce: augmentez la limite avec R2_OUTPUT_LIMIT=50000000"
                    f" ou redirigez: cmd > fichier.txt")
        if text:
            self._emit(text)
        if not ok:
            self.ui._print("[bold red]X echec de la commande[/]" if self.ui.console
                           else "X echec de la commande")

    def _print_help(self):
        p = self.ui._print
        p("[bold bright_cyan]Mini terminal r2 — commandes[/]"
          if self.ui.console else "Mini terminal r2 — commandes")
        p("  <cmd r2>          Exécuter une commande r2 sur la cible active")
        p("                    ex: afl, px 64 @ 0x1000, pdf @ sym.main, izz~password")
        p("  pptool <args>     Exécuter pptool — placeholders: {so} {libapp} {name} {outdir}")
        p("  !targets          Lister les cibles de la session")
        p("  !use <n|nom>      Changer de cible active")
        p("  !anal on|off      Replay automatique de la dernière analyse (aaa) avant chaque commande")
        p("  !rw on|off        Mode écriture r2 -w (backup .elitf.bak automatique)")
        p("  !set / !unset     Config session appliquée à chaque commande — ex: !set e asm.bytes=true")
        p("  !lib              Chemin de la cible active")
        p("  !catalog          Parcourir le catalogue des commandes r2 (24 catégories, ~310 cmds)")
        p("  !limit [N]        Afficher ou définir la limite de sortie (défaut 10MB)")
        p("  !pptool           État pptool / exécuter avec !pptool <args>")
        p("  q | quit | exit   Quitter le terminal")
        p("Astuce: chaque commande part d'une session r2 fraîche — lancez l'analyse (aaa) ou"
          " activez !anal avant pdf/axt. Redirection possible: afl > fonctions.txt")

    # -- builtins -----------------------------------------------------------

    def handle_builtin(self, line):
        """Traite une ligne builtin (!…/q/quit/exit/'').

        Retourne 'quit', 'handled', ou None si la ligne n'est pas un builtin.
        """
        line = line.strip()
        if line in ('q', 'quit', 'exit', '!q'):
            return 'quit'
        if not line:
            return 'handled'
        if not line.startswith('!'):
            return None
        parts = line[1:].split(None, 1)
        name = parts[0].lower()
        rest = parts[1].strip() if len(parts) > 1 else ''
        if name == 'help':
            self._print_help()
        elif name == 'targets':
            for i, t in enumerate(self.targets, 1):
                mark = '*' if i - 1 == self.active else ' '
                self.ui._print(f" {mark} [{i}] {t['name']}  —  {t['path']}")
        elif name == 'use':
            if not self.use(rest):
                self.ui._print(f"[!] Cible inconnue: {rest!r} (!targets pour la liste)")
        elif name == 'lib':
            self.ui._print(self.active_target['path'])
        elif name == 'anal':
            if rest.lower() in ('on', 'off'):
                self.anal_replay = rest.lower() == 'on'
            last = self.analysis_cmds or 'aucune'
            self.ui._print(f"Replay de l'analyse: {'ON' if self.anal_replay else 'OFF'}"
                           f" (dernière: {last})")
        elif name == 'set':
            if not rest:
                self.ui._print("Usage: !set e var=valeur  (ex: !set e asm.bytes=true)")
            elif not _R2_SET_VALIDATOR.match(rest):
                self.ui._print(f"[!] Refusé — !set attend 'e var=valeur', reçu: {rest!r}")
                self.ui._print("    Les caractères ; ! | > ~ \" ` ' \\ sont interdits.")
            elif rest not in self.env_cmds:
                self.env_cmds.append(rest)
                self.ui._print(f"Config session: {self.env_cmds}"
                               "  (!set e var=valeur)")
            else:
                self.ui._print(f"Déjà présent dans la config: {rest}")
        elif name == 'unset':
            if rest in self.env_cmds:
                self.env_cmds.remove(rest)
            self.ui._print(f"Config session: {self.env_cmds or 'vide'}")
        elif name == 'rw':
            if rest.lower() == 'on':
                self.rw = True
                self._backup_active()
            elif rest.lower() == 'off':
                self.rw = False
            state = 'ON (backup .elitf.bak actif)' if self.rw else 'OFF'
            self.ui._print(f"Mode écriture r2 -w: {state}")
        elif name == 'pptool':
            if not rest:
                if self.pptool_bin:
                    self.ui._print(f"pptool disponible: {self.pptool_bin}")
                    self.ui._print("Placeholders: {so} {libapp} {name} {outdir}"
                                   " — ex: pptool -f {so}")
                else:
                    self.ui._print(PPTOOL_HINT)
            else:
                ok, text = self.run_pptool(rest)
                self._show_output(text, ok)
        elif name == 'catalog':
            self.catalog()
        elif name == 'limit':
            global R2_OUTPUT_LIMIT
            if not rest:
                self.ui._print(f"Limite de sortie: {R2_OUTPUT_LIMIT} caractères"
                               f" ({R2_OUTPUT_LIMIT // 1_000_000} MB)")
                self.ui._print("Pour changer: !limit 50000000  (50 MB)"
                               " ou export R2_OUTPUT_LIMIT=50000000")
            else:
                try:
                    new_limit = int(rest)
                    if new_limit < 1000:
                        raise ValueError("too small")
                    R2_OUTPUT_LIMIT = new_limit
                    self.ui._print(f"Limite de sortie: {R2_OUTPUT_LIMIT} caractères")
                except ValueError:
                    self.ui._print(f"[!] Valeur invalide: {rest!r} — attendu un nombre >= 1000")
        else:
            self.ui._print(f"builtin inconnu: !{name} — !help pour l'aide")
        return 'handled'



    def terminal(self):

        ui = self.ui
        if not self.r2_bin:
            ui._print("[bold red]r2 introuvable — le mini terminal nécessite radare2"
                      " (Termux: pkg install radare2)[/]" if ui.console
                      else "r2 introuvable — le mini terminal nécessite radare2"
                           " (Termux: pkg install radare2)")
            return None
        pptool_state = 'disponible' if self.pptool_bin else 'non installé (!pptool)'
        ui._print(f"[bold bright_cyan]Terminal r2[/] — cible: [bold]"
                  f"{self.active_target['name']}[/] — pptool: {pptool_state}"
                  if ui.console
                  else f"Terminal r2 — cible: {self.active_target['name']}"
                       f" — pptool: {pptool_state}")
        ui._print("[dim]!help pour l'aide — q pour quitter[/]" if ui.console
                  else "!help pour l'aide — q pour quitter")
        while True:
            try:
                line = ui.r2_readline(f"r2({self.active_target['name']})> ")
            except (KeyboardInterrupt, EOFError):
                break
            if line is None:
                break
            line = line.strip()
            if not line:
                continue
            action = self.handle_builtin(line)
            if action == 'quit':
                break
            if action == 'handled':
                continue
            if line == 'pptool' or line.startswith('pptool '):
                ok, text = self.run_pptool(line[len('pptool'):].strip())
                self._show_output(text, ok)
                continue
            if any(line.startswith(p) for p in _R2_WRITE_PREFIXES):
                if not self._ensure_write_mode():
                    continue
            first_token = line.split()[0] if line.split() else ''
            if (first_token in ('pdf', 'pdr', 'axt', 'axf', 'agf', 'agfl',
                                'afi', 'ab') and self.anal_replay
                    and not self.analysis_cmds):
                ui._print("[dim]Astuce: lancez 'aaa' d'abord — "
                          "pdf/axt/agf nécessitent l'analyse[/]" if ui.console
                          else "Astuce: lancez 'aaa' d'abord — "
                               "pdf/axt/agf nécessitent l'analyse")
            rc, out, err = self.run_r2(line)
            self._show_output(out, rc == 0)
            if rc != 0 and err.strip():
                self._emit('[stderr] ' + err.strip())
        return None

    def _ensure_write_mode(self):
        if self.rw:
            return True
        if not self.ui.confirm(
                "Le patching nécessite r2 -w. Activer le mode écriture"
                " (backup .elitf.bak automatique) ?", default=False):
            return False
        self.rw = True
        self._backup_active()
        return True

    def catalog(self):

        ui = self.ui
        if not self.r2_bin:
            ui._print("[bold red]r2 introuvable — le catalogue nécessite radare2"
                      " (Termux: pkg install radare2)[/]" if ui.console
                      else "r2 introuvable — le catalogue nécessite radare2"
                           " (Termux: pkg install radare2)")
            return None
        while True:
            cat_key = ui.get_r2_catalog_category()
            if cat_key in (None, 'back'):
                return None
            while True:
                entry = ui.get_r2_catalog_command(cat_key)
                if entry in (None, 'back'):
                    break
                values = ui.prompt_r2_command_args(entry)
                if values is None:
                    continue
                if entry.get('write') and not self._ensure_write_mode():
                    continue
                cmd = _compose_r2_command(entry, values)
                ui._print(f"[bold bright_cyan]r2>[/] {cmd}" if ui.console
                          else f"r2> {cmd}")
                rc, out, err = self.run_r2(cmd)
                self._show_output(out, rc == 0)
                if rc != 0 and err.strip():
                    self._emit('[stderr] ' + err.strip())
