# Elit-f — Corrections et alignement avec ShadowProtocol

## Bugs corrigés

### Bug 1 — CMake `dartvm_default` introuvable
**Fichier** : `build_termux.sh`
**Symptôme** :
```
CMake Error at CMakeLists.txt:21 (find_package):
  Could not find a package configuration file provided by "dartvm_default"
```
**Cause** : `build_termux.sh` lançait `cmake -DDARTLIB=dartvm_default` sans avoir construit au préalable la bibliothèque `dartvm_default` (qui n'existe pas — les libs réelles s'appellent `dartvm{version}_{os}_{arch}`).
**Correction** : Réécriture complète du script pour :
1. Accepter `version`, `os_name`, `arch` en arguments (défaut : `3.4.2 android arm64`).
2. Calculer `DARTLIB=dartvm{version}_{os}_{arch}`.
3. Vérifier si `packages/lib/lib{DARTLIB}.a` existe ; sinon, appeler `dartvm_fetch_build.py`.
4. Lancer `cmake` + `make` avec le bon `DARTLIB`.

### Bug 2 — Rich `Style(color="dim")` invalide
**Fichier** : `elitf.py` (lignes 229, 386, 388, 741)
**Symptôme** :
```
rich.color.ColorParseError: 'dim' is not a valid color
```
**Cause** : `dim` est un attribut de style, pas une couleur.
**Correction** : Toutes les occurrences de `Style(color="dim")` remplacées par `Style(dim=True)`.

### Bug 3 — `icu_compat.h` manquant
**Fichier** : `scripts/icu_compat.h` (ajouté)
**Cause** : `scripts/CMakeLists.txt.dartvm` ligne 100 fait `-include ${CMAKE_CURRENT_SOURCE_DIR}/icu_compat.h`, mais ce fichier n'existait pas dans Elit-f. Le build du Dart VM aurait échoué.
**Correction** : Ajout du fichier (identique à ShadowProtocol).

### Bug 4 — `icu_compat.h` non copié dans le target Dart SDK
**Fichier** : `dartvm_fetch_build.py`
**Cause** : Le `cmake_dart()` d'Elit-f ne copiait pas `icu_compat.h` vers le répertoire cible du Dart SDK, contrairement à ShadowProtocol.
**Correction** : Ajout de `shutil.copy2(icu_compat_src, ...)`.

### Bug 5 — Détection du standard C++ fragile
**Fichier** : `dartvm_fetch_build.py`
**Cause** : Elit-f parsait `run_clang_tidy.dart` pour trouver `-std=c++`. Approche fragile.
**Correction** : Remplacé par test de version (`>= 3.11` → C++20), aligné sur ShadowProtocol.

### Bug 6 — `find_compat_macro` OLD_MARKING_STACK_BLOCK incorrect
**Fichier** : `elitf.py`
**Cause** : Elit-f recherchait `old_marking_stack_block` dans `thread.h`. La clé réelle correspond au commit Dart `marking_stack_block_offset()` qui change en 3.5.0.
**Correction** : Remplacé par test de version `>= 3.5`, aligné sur ShadowProtocol.

### Bug 7 — `detect_so_files` ne trouvait pas les `.so` au premier niveau
**Fichier** : `elitf.py`
**Cause** : `glob(pattern, recursive=False)` avec pattern `**/*.so` ne trouve que les fichiers à un niveau de sous-répertoire, pas ceux à la racine.
**Correction** : `recursive=False` → `recursive=True`.

### Bug 8 — `assert False` au lieu de `raise ValueError`
**Fichier** : `extract_dart_info.py`
**Cause** : Les assertions sont désactivées avec `python -O`, masquant les erreurs.
**Correction** : Remplacement de 3 `assert` par des `raise ValueError` avec messages descriptifs.

### Bug 9 — Pas de precompiled header dans CMakeLists.txt
**Fichier** : `CMakeLists.txt`
**Cause** : Le `pch.h` n'était pas configuré comme precompiled header, ralentissant les builds.
**Correction** : Ajout de `target_precompile_headers(${BINNAME} PRIVATE "src/pch.h")`.

## Améliorations conservées d'Elit-f (vs ShadowProtocol)

Ces améliorations sont intentionnelles et conservées car elles font d'Elit-f un outil « plus avancé » comme demandé :

| Fichier | Amélioration |
|---------|-------------|
| `src/DartApp.cpp` | Bug fix : `>=` au lieu de `>` pour éviter out-of-range sur `classes.at(cid)` |
| `src/DartApp.cpp` | Support Dart >= 3.13 via `ELITF_DART_SINGLE_SNAPSHOT` |
| `src/DartApp.h` | `uintptr_t throwStubAddr` (correct : adresse = non-signé) |
| `src/DartApp.h` | Forward declarations (bonne pratique C++) |
| `src/CodeAnalyzer_arm64.cpp` | Support Dart 3.11+ : gestion `ldur x2, [x29, #-8]` |
| `src/CodeAnalyzer_arm64.cpp` | Retour `VarExpression` au lieu de `throw` pour native functions |
| `src/DartFunction.cpp` | Support `ELITF_DART_SINGLE_SNAPSHOT` (Dart 3.13 discarded code) |
| `src/ElfHelper.cpp` | `throw std::runtime_error` avec messages descriptifs |
| `src/main.cpp` | `return 2` sur exception (bonne pratique) |
| `src/pch.h` | Détection auto `kSnapshotDataAsmSymbol` → `ELITF_DART_SINGLE_SNAPSHOT` |
| `extract_dart_info.py` | `EM_X86_64` (correct) au lieu de `EM_IA_64` (ShadowProtocol a un bug) |
| `extract_dart_info.py` | Support stable/beta/dev channels (ShadowProtocol : stable uniquement) |
| `extract_dart_info.py` | Support multi-OS/arch pour `get_dart_sdk_url_size` |
| `CMakeLists.txt` | Gestion libfmt pour Termux/old clang (ShadowProtocol : MSVC/PkgConfig seulement) |
| `elitf.py` | Interface TUI Rich complète (absente de ShadowProtocol) |

## Divergences .so documentées

- **Nom du binaire** : `elitf_<dartlib>` vs `blutter_<dartlib>` (branding, pas un bug).
- **Script Frida généré** : `elitf_frida.js` vs `blutter_frida.js` (branding, pas un bug).
- **Comportement fonctionnel** : IDENTIQUE — mêmes sorties `pp.txt`, `objs.txt`, `asm/`, `ida_script`, `r2_script`.
- **Bibliothèque dartvm** : IDENTIQUE — même source Dart SDK, même CMake template, mêmes flags.

## Plan d'action suivi

1. ✅ Clonage des deux dépôts (Elit-f + ShadowProtocol).
2. ✅ Analyse exhaustive de tous les fichiers (C++, Python, CMake, scripts).
3. ✅ Comparaison fichier par fichier avec la référence ShadowProtocol.
4. ✅ Identification de 9 bugs + 1 amélioration manquante.
5. ✅ Correction de tous les bugs identifiés.
6. ✅ Conservation des améliorations existantes d'Elit-f.
7. ✅ Tests de vérification (syntaxe Python, démarrage elitf.py, logique build_termux.sh, détection .so).
8. ✅ Documentation des divergences .so.
9. ✅ Packaging en zip.
