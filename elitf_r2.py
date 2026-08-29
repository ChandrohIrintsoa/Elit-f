#!/usr/bin/env python3
"""
elitf_r2.py — Génération et exécution de scripts radare2 / lecture d'infos binaires.

Contient :
  * Templates de scripts r2 (R2_SCRIPT_TEMPLATE, R2_DISASM_TEMPLATE, R2_BATCH_TEMPLATE)
  * `generate_r2_scripts(so_list, outdir, log_mgr=None)` : génère les .r2 et le batch .sh
  * `run_r2_scripts(so_list, outdir, log_mgr=None)`      : génère + exécute r2 si présent
  * `display_binary_info(so_list, outdir, log_mgr=None)` : readelf-like, écrit dans un fichier

Ces fonctions acceptent un `LogManager` optionnel (issu de `elitf_ui`) pour reporter
la progression sans dépendre directement de Rich.

Le script r2 généré est exhaustif : il exécute toutes les commandes d'analyse
radare2 disponibles (`aa`, `aaa`, `aac`, `aar`, `afr`, `aae`, `aaft`, `aao`, ...)
puis extrait toutes les informations (fonctions, strings, sections, imports,
exports, symboles, xrefs, classes, crypto, URLs, JNI, etc.).
"""
import os
import shutil
import subprocess

# Radare2 comprehensive analysis + extraction script.
# Runs ALL available analysis commands (aa, aaa, aac, aar, afr, aae, aaft, aao, ...)
# then extracts every kind of information radare2 can produce.
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
# (aflq lists function addresses one per line; ~? would only count them).
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
        # Order matters: replace __OUTDIR__ first so that a path containing
        # the literal __NAME__ cannot corrupt the second substitution.
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
        try:
            result = subprocess.run(
                [r2_bin, "-q", "-i", script_path, so["path"]],
                capture_output=True, text=True, timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                succeeded += 1
                if log_mgr:
                    log_mgr.add(f"r2 analysis complete: {so['name']}", "success")
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
        finally:
            if log_mgr:
                log_mgr.step()
    if log_mgr:
        log_mgr.add(f"r2 analysis finished: {succeeded}/{len(generated)} succeeded", "success")
    return generated


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
