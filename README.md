# Elit-f — version de travail consolidée

## Installation Python

Python 3.9 ou supérieur ; dépendances :

```sh
python -m pip install -r requirements.txt
```

## Utilisation

```sh
python elitf.py application.apk sortie --cli --nu
python elitf.py chemin/lib/arm64-v8a sortie --cli --plain --nu
python elitf.py libapp.so sortie --dart-version 3.4.2_android_arm64 --nu
python elitf.py application.apk sortie --action r2 --r2-preset standard --nu
python elitf.py application.apk sortie --action r2 --generate-only --nu
python elitf.py chemin/libs sortie --action info --nu
python elitf.py --help
```


## Sorties

AOT : `asm/`, `pp.txt`, `objs.txt`, `ida_script/`, `blutter_frida.js`.

## Parallélisme

```sh
R2_BATCH_JOBS=2 R2_TIMEOUT=600 python elitf.py chemin/libs sortie --action r2 --nu
```

## Tests

```sh
python -m unittest discover -s tests -v
python -m compileall -q .
```
