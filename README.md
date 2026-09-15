
## Installation Python
```sh
git clone https://github.com/ChandrohIrintsoa/Elit-f.git
```
Python 3.9 ou supérieur ; dépendances :

```sh
python -m pip install -r requirements.txt
```

## Lancement direct sur Termux (`Elit-f`)

Pour lancer tape `Elit-f` dans Termux :

```sh
bash install_termux.sh
# ou, équivalent :
python elitf.py --install-launcher
```

## Termux / Android — récupération du Dart SDK et affichage

```sh
export ELITF_DART_SDK_GIT=https://miroir.example.net/dart-sdk.git
export ELITF_DART_SDK_TARBALL='https://miroir.example.net/dart-sdk/{version}.tar.gz'
```

## Utilisation

```sh
python elitf.py application.apk sortie --cli --nu
```
```sh
python elitf.py chemin/lib/arm64-v8a sortie --cli --plain --nu
```
```sh
python elitf.py libapp.so sortie --dart-version 3.4.2_android_arm64 --nu
```
```sh
python elitf.py application.apk sortie --action r2 --r2-preset standard --nu
```
```sh
python elitf.py application.apk sortie --action r2 --generate-only --nu
```
```sh
python elitf.py chemin/libs sortie --action info --nu
```
```sh
python elitf.py libsample.so sortie --action info --nu
```
```sh
python elitf.py --help
```


## Sorties

AOT : `asm/`, `pp.txt`, `objs.txt`, `ida_script/`, `blutter_frida.js`.


## Parallélisme

```sh
R2_BATCH_JOBS=2 R2_TIMEOUT=600 python elitf.py chemin/libs sortie --action r2 --nu
```

Les cibles indépendantes sont parallélisées. Analyse puis extraction dans une même session restent ordonnées. Ne pas lancer plusieurs builds simultanés de la même variante dans le même dossier.

## Tests

```sh
python -m unittest discover -s tests -v
python -m compileall -q .
```
