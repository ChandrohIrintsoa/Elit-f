#!/usr/bin/env python3
"""Vérification E2E « le fichier de sortie ne reste pas à son origine ».

Scénarios réels couverts (avec noyau simulé aux limits du contrat) :
  A. Outdir ancien (analyse d'origine, sans empreinte) + cible changée
     → purge des sorties d'origine, nouvelle analyse, dump régénéré.
  B. Changement de cible entre 2 dumps (app A → app B) → AUCUN mélange :
     les bibliothèques de A ne survivent pas dans asm/ ni dans le dump.
  C. Re-run sur la même cible → cache valide, pas de nouvelle analyse,
     toujours exactement 2 fichiers.
  D. Option 5 : nouvelles cibles de nettoyage (kernel_out + il2cpp_dump),
     suppression réelle, garde-fou hors zone refusé.
  E. Empreinte : écriture/lecture, invalidation si le contenu change.
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import elitf
import elitf_dumper as dumper


ASM_TPL = ("// lib: {lib}, url: package:{lib}/main.dart\n"
           "\n// class id: 2, size: 0x38\nclass :: {{\n"
           "  void main() {{\n    // ** addr: 0x390000, size: 0x40\n"
           "    0x390000: ret\n  }}\n}}\n")
PP = "pool heap offset: 0x1000\n[pp+0x8] String: 'hi'\n"


def kernel_sim(outdir, libs):
    """Simule le kernel : un fichier asm/ PAR bibliothèque Dart + pp.txt."""
    asm = Path(outdir) / 'asm'
    asm.mkdir(parents=True, exist_ok=True)
    for lib in libs:
        (asm / f'{lib}.txt').write_text(ASM_TPL.format(lib=lib),
                                        encoding='utf-8')
    (Path(outdir) / 'pp.txt').write_text(PP, encoding='utf-8')


def pair_in(directory, app_bytes, flutter_bytes=b'\x7fELF flutter'):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'libapp.so').write_bytes(app_bytes)
    (directory / 'libflutter.so').write_bytes(flutter_bytes)
    return str(directory / 'libapp.so'), str(directory / 'libflutter.so')


def dump_libs(dump_dir):
    text = (Path(dump_dir) / 'dump.dart').read_text(encoding='utf-8')
    return {lib for lib in ('appa', 'appb', 'appc')
            if f'package:{lib}' in text}


def scenario_a_stale_origin(root):
    print('  A. Outdir ancien (sans empreinte) + nouvelle analyse …')
    indir = root / 'a_in'
    outdir = root / 'a_out'
    pair_in(indir, b'\x7fELF app A')
    kernel_sim(outdir, ['appa'])                      # analyse « d'origine »
    legacy = outdir / 'il2cpp_dump'
    legacy.mkdir(parents=True)
    (legacy / 'dump.dart').write_text('STALE', encoding='utf-8')
    (legacy / 'stringliteral.json').write_text('old', encoding='utf-8')
    with patch.object(dumper, 'run_flutter_analysis',
                      side_effect=lambda *a, **k:
                          kernel_sim(outdir, ['appa'])) as rfa:
        s = dumper.ensure_kernel_outputs(str(indir), str(outdir), False,
                                         False, None, None, False)
    assert rfa.called, "l'analyse devait être relancée (pas d'empreinte)"
    assert s['cache'] == 'refreshed', s['cache']
    assert s['purged'], 'la purge des sorties dorigine doit être signalée'
    assert (Path(s['dump_dir']) / 'dump.dart').exists()
    assert 'STALE' not in (Path(s['dump_dir']) / 'dump.dart').read_text(
        encoding='utf-8')
    assert sorted(p.name for p in Path(s['dump_dir']).iterdir()) == \
        ['dump.dart', 'script.json']
    print('    OK : analyse relancée, origine purgée, 2 fichiers régénérés')


def scenario_b_target_change(root):
    print('  B. Changement de cible app A → app B (aucun mélange) …')
    indir = root / 'b_in'
    outdir = root / 'b_out'
    pair_in(indir, b'\x7fELF app A')
    with patch.object(dumper, 'run_flutter_analysis',
                      side_effect=lambda *a, **k:
                          kernel_sim(outdir, ['appa'])):
        s1 = dumper.ensure_kernel_outputs(str(indir), str(outdir), False,
                                          False, None, None, False)
    assert dump_libs(s1['dump_dir']) == {'appa'}
    # La cible change : même chemin, contenu libapp différent (app B)
    pair_in(indir, b'\x7fELF app B v2 with more bytes')
    with patch.object(dumper, 'run_flutter_analysis',
                      side_effect=lambda *a, **k:
                          kernel_sim(outdir, ['appb', 'appc'])) as rfa:
        s2 = dumper.ensure_kernel_outputs(str(indir), str(outdir), False,
                                          False, None, None, False)
    assert rfa.called, 'cible changée : la nouvelle analyse est requise'
    assert s2['cache'] == 'refreshed'
    libs = dump_libs(s2['dump_dir'])
    assert libs == {'appb', 'appc'}, f'mélange détecté : {libs}'
    asm_files = {p.name for p in (Path(outdir) / 'asm').iterdir()}
    assert asm_files == {'appb.txt', 'appc.txt'}, asm_files
    print('    OK : appa purgé de asm/ et du dump — zéro mélange A/B')


def scenario_c_cache_reuse(root):
    print('  C. Re-run même cible → cache réutilisé …')
    indir = root / 'b_in'
    outdir = root / 'b_out'
    with patch.object(dumper, 'run_flutter_analysis') as rfa:
        s = dumper.ensure_kernel_outputs(str(indir), str(outdir), False,
                                         False, None, None, False)
        assert not rfa.called, 'cache valide : pas de nouvelle analyse'
    assert s['cache'] == 'reused'
    assert sorted(p.name for p in Path(s['dump_dir']).iterdir()) == \
        ['dump.dart', 'script.json']
    print('    OK : cache valide pour ce pair, toujours 2 fichiers')


def scenario_d_cleanup(root):
    print('  D. Option 5 : cibles de nettoyage kernel_out + il2cpp_dump …')
    outdir = root / 'b_out'
    items = elitf.find_cleanup_targets(str(root), str(outdir))
    kinds = {i['kind'] for i in items}
    assert 'kernel_out' in kinds, kinds
    assert 'il2cpp_dump' in kinds, kinds
    ko = next(i for i in items if i['kind'] == 'kernel_out')
    assert 'asm' in {Path(p).name for p in ko['paths']}
    idx = items.index(ko)
    deleted, freed = elitf.perform_cleanup(str(root), str(outdir), items,
                                           [idx])
    assert deleted and freed > 0
    assert not (Path(outdir) / 'asm').exists()
    assert not (Path(outdir) / 'pp.txt').exists()
    # Garde-fou : chemin hors zone refusé (hors projet ET hors outdir)
    import tempfile as _tf
    outside = Path(_tf.mkdtemp(prefix='elitf_outside_'))
    (outside / 'x.txt').write_text('x', encoding='utf-8')
    try:
        bad = [{'kind': 'kernel_out', 'label': 'x',
                'path': str(outside / 'x.txt'),
                'paths': [str(outside / 'x.txt')], 'size': 1}]
        try:
            elitf.perform_cleanup(str(root), str(outdir), bad, [0])
            raise SystemExit('garde-fou NON déclenché')
        except ValueError:
            pass
    finally:
        import shutil as _sh
        _sh.rmtree(outside, ignore_errors=True)
    print('    OK : purge manuelle possible, garde-fou intact')


def scenario_e_fingerprint(root):
    print('  E. Empreinte : invalidation dès que le contenu change …')
    outdir = root / 'e_out'
    indir = root / 'e_in'
    app, flutter = pair_in(indir, b'\x7fELF fp v1')
    kernel_sim(outdir, ['appa'])
    assert dumper.write_analysis_fingerprint(str(outdir), app, flutter)
    fp = dumper.read_analysis_fingerprint(str(outdir))
    digest = (fp or {}).get('libapp', {}).get('digest', '')
    assert len(digest) == 64 and all(c in '0123456789abcdef' for c in digest), \
        digest
    assert dumper.analysis_cache_valid(str(outdir), [app, flutter])
    (Path(indir) / 'libapp.so').write_bytes(b'\x7fELF fp v2 CHANGED')
    assert not dumper.analysis_cache_valid(str(outdir), [app, flutter])
    # Purge idempotente : 1re passe supprime, 2de passe ne trouve plus rien
    first = dumper.purge_kernel_outputs(str(outdir))
    assert first, 'la 1re purge doit retirer asm/ et pp.txt'
    assert dumper.purge_kernel_outputs(str(outdir)) == []
    print('    OK : empreinte fiable, purge idempotente')


def main():
    import shutil
    import tempfile
    root = Path(tempfile.mkdtemp(prefix='elitf_purge_e2e_'))
    try:
        print('Vérification E2E purge des fichiers de sortie :')
        scenario_a_stale_origin(root)
        scenario_b_target_change(root)
        scenario_c_cache_reuse(root)
        scenario_d_cleanup(root)
        scenario_e_fingerprint(root)
        print('E2E purge : TOUT OK')
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    main()
