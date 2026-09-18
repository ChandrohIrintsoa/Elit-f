# Elit-f

Outil de réversing d'applications Flutter/Dart (AOT) pour Android ARM64. Extrait le pool d'objets, le code assembleur, les scripts IDA et un script Frida depuis `libapp.so` + `libflutter.so`.

## 1. Installation

```sh
git clone https://github.com/ChandrohIrintsoa/Elit-f.git
python -m pip install -r requirements.txt
```

Pré-requis système : `git`, `cmake`, `ninja`, un compilateur C++20 (`clang`/`gcc`), `pkg-config`, `libcapstone-dev`.

Termux :
```sh
pkg install git cmake ninja clang python pkg-config capstone
```

Debian/Ubuntu :
```sh
sudo apt install git cmake ninja-build clang python3-pip libcapstone-dev
```

macOS :
```sh
brew install git cmake ninja llvm
```

## 2. Lanceur Termux (optionnel)

Après installation, tapez `Elit-f` dans le terminal :

```sh
bash install_termux.sh
# ou :
python elitf.py --install-launcher
```

## 3. Utilisation

APK :
```sh
python elitf.py application.apk sortie --cli --nu
```

Répertoire de libs :
```sh
python elitf.py chemin/lib/arm64-v8a sortie --cli --plain --nu
```

`libapp.so` seul (avec `--dart-version`) :
```sh
python elitf.py libapp.so sortie --dart-version 3.4.2_android_arm64 --nu
```

Action `r2` (Radare2) :
```sh
python elitf.py application.apk sortie --action r2 --r2-preset standard --nu
python elitf.py application.apk sortie --action r2 --generate-only --nu
```

Info binaire :
```sh
python elitf.py chemin/libs sortie --action info --nu
python elitf.py libsample.so sortie --action info --nu
```

Aide :
```sh
python elitf.py --help
```

## 4. Sorties

AOT : `asm/`, `pp.txt`, `objs.txt`, `ida_script/`, `blutter_frida.js`.

## 5. Parallélisme

```sh
R2_BATCH_JOBS=2 R2_TIMEOUT=600 python elitf.py chemin/libs sortie --action r2 --nu
```

## 7. Vérification

```sh
python -m compileall -q .
```
