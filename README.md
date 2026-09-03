# Elit-f

Outil de rétro-ingénierie d'applications Flutter par compilation du runtime Dart AOT.

L'outil analyse `libapp.so` (snapshot Dart AOT d'une application Android), détecte automatiquement la version du Dart VM depuis `libflutter.so`, compile le runtime Dart correspondant puis décompile le snapshot : assemblies commentées, Object Pool, objets, script Frida prêt à l'emploi et script de labels IDA.

- Versions de Dart supportées : **3.0 → 3.18** (détection dynamique par scan des en-têtes du SDK, macros de compatibilité automatiques)
- Architectures APK : `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`
- Modes : interface interactive (Rich), CLI classique, mode `--plain` recommandé sur Termux
- Génération : assemblies `asm/`, dump Object Pool `pp.txt`, dump objets imbriqués `objs.txt`, script Frida `blutter_frida.js` (Closure/Map/Set inclus), script IDA `ida_script/`

## Termux

```bash
pkg update && pkg upgrade -y
pkg install -y git cmake ninja clang python capstone icu pkg-config
pip install rich pyelftools requests
```

Cloner le dépôt puis lancer le build initial :

```bash
chmod +x build_termux.sh
./build_termux.sh <dart_version>            # build ciblé d'un dartvm déjà construit
Elit-f ~/cibles/MonApp.apk ~/cibles/out --cli   # pipeline complet automatique
```

Le binaire est installé dans `bin/`, un lanceur `Elit-f` est déposé dans `$PREFIX/bin` (environnements Termux uniquement).

> Permission stockage : `termux-setup-storage` si `/sdcard` n'est pas accessible.

## Debian / Ubuntu (g++ >= 13)

Le code C++ utilise la bibliothèque de formatage C++20 (`std::format`) : un compilateur récent est requis (`g++ >= 13` ou `clang >= 16`).

```bash
apt install python3-pyelftools python3-requests git cmake ninja-build \
    build-essential pkg-config libicu-dev libcapstone-dev
python3 elitf.py <indir> <outdir>
```

## Windows

- Installer git et Python 3
- Installer Visual Studio avec « Desktop development with C++ » et « C++ CMake tools »
- Installer les bibliothèques requises (capstone, icu4c) :

```
python scripts\init_env_win.py
```

- Démarrer « x64 Native Tools Command Prompt » puis lancer `python elitf.py <indir> <outdir>`

## Docker

```bash
docker build -t elitf .
docker/run.sh /path/to/app.apk /path/to/output
docker/run.sh <indir> <outdir> [extra args...]
```

`docker/run.sh` accepte les mêmes arguments que `elitf.py` :

- `indir` : APK ou dossier contenant `libapp.so` et `libflutter.so`
- `outdir` : répertoire de sortie de l'analyse
- `extra args` : options supplémentaires (ex. `--no-analysis`, `--ida-fcn`)

```bash
docker/run.sh /path/to/lib/arm64-v8a /path/to/output --no-analysis --ida-fcn
```

## macOS Ventura / Sonoma (clang 16)

```bash
brew install llvm@16 cmake ninja pkg-config icu4c capstone
pip3 install pyelftools requests rich
```

`elitf.py` sélectionne automatiquement `llvm@16` (via `brew --prefix`) sur macOS antérieur à 15.

## Nix

```bash
nix-shell
python3 elitf.py <indir> <outdir>
```

## Usage

### Fichier APK

```shell
python3 elitf.py path/to/app.apk out_dir
```

### Fichiers `.so`

1. Dossier extrait d'un APK (recherche récursive de `libapp.so` + `libflutter.so`, avec repli sur les fichiers `App`/`Flutter` sans extension) :

```shell
python3 elitf.py path/to/app/lib/arm64-v8a out_dir
```

2. `libapp.so` seul avec une version Dart connue :

```shell
python3 elitf.py --dart-version 3.4.2_android_arm64 libapp.so out_dir
```

Si l'exécutable correspondant à la version Dart n'existe pas encore, le code source du Dart VM est récupéré et compilé automatiquement.

### Options

| Option | Description |
|--------|-------------|
| `indir` | APK ou dossier contenant exactement `libapp.so` + `libflutter.so` |
| `outdir` | Répertoire de sortie |
| `--rebuild` | Force la recompilation de l'exécutable Elit-f |
| `--no-analysis` | Construit sans analyse de code (Dart < 2.15 l'impose) |
| `--ida-fcn` | Génère le script de fonctions IDA (sans les commentaires de structs/pool) |
| `--dart-version` | Mode sans libflutter : `<version>_<os>_<arch>` (ex. `3.4.2_android_arm64`) |
| `--cli` | Force le mode CLI (pas de menu interactif) |
| `--plain` | Désactive les animations Rich (recommandé sur Termux) |
| `--vs-sln` | Génère une solution Visual Studio dans `<outdir>` (console développeur VS requise) |
| `--nu` | Désactive la vérification de mise à jour |

Le suffixe du binaire produit reflète la configuration : `elitf_dartvm<ver>_<os>_<arch>[_no-compressed-ptrs][_no-analysis][_ida-fcn]`.

## Mise à jour

```bash
git pull
python3 elitf.py path/to/app/lib/arm64-v8a out_dir --rebuild
```

Par défaut, `elitf.py` vérifie silencieusement les mises à jour du dépôt (si le dossier est un clone git propre) ; utilisez `--nu` pour désactiver ce comportement.

## Fichiers de sortie

- **asm/** : assemblies de libapp avec symboles
- **blutter_frida.js** : script Frida pour l'application cible (Closure, Map, Set supportés)
- **objs.txt** : dump complet (imbriqué) des objets de l'Object Pool
- **pp.txt** : tous les objets Dart de l'Object Pool
- **ida_script/** : `addNames.py` (labels/fonctions IDA) et `ida_dart_struct.h` (structs Thread/Object Pool)

## Répertoires

- **bin** : exécutables Elit-f par version de Dart au format `elitf_dartvm<ver>_<os>_<arch>`
- **build** : projets de build (supprimable après le build)
- **dartsdk** : checkout du runtime Dart (supprimable après le build)
- **packages** : bibliothèques statiques du Dart Runtime
- **scripts** : scripts Python de récupération/build du Dart VM
- **src** : code source C++, à compiler contre la bibliothèque Dart VM

## Génération d'une solution Visual Studio (développement)

```shell
python elitf.py path\to\lib\arm64-v8a build\vs --vs-sln
```

La solution est générée dans `<outdir>` avec la commande de debug préconfigurée (`-i <libapp> -o <outdir>/out`) et les DLL requises copiées dans `Debug\`.
