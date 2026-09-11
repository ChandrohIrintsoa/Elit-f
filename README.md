# Elit-f — version de travail consolidée

Lire `SYNTHESE.md` avant utilisation : 30 tests locaux passent, mais la compilation/exécution AOT multi-version et les moteurs externes n'ont pas été validés dans cet environnement. Ce paquet n'est pas une version certifiée sans erreurs.

## Installation Python

Python 3.9 ou supérieur ; dépendances :

```sh
python -m pip install -r requirements.txt
```

Le moteur AOT fourni cible Android ARM64 ELF. Il nécessite Git, CMake, Ninja, un compilateur et une bibliothèque standard supportant C++20 (`std::format`), ICU et Capstone. Les fichiers Docker, Nix, Windows et Termux sont conservés ; leur exécution native reste à vérifier.

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

Sans `--cli`, l'interface Rich reste disponible. Radare2 est optionnel pour générer des scripts, obligatoire pour les exécuter. `readelf`, `greadelf` ou `llvm-readelf` est nécessaire pour les informations binaires.

Les options historiques `--rebuild`, `--no-analysis`, `--ida-fcn`, `--dart-version`, `--plain`, `--vs-sln` et `--nu` sont conservées. La génération VS nécessite une console développeur Visual Studio. `--nu` désactive la recherche de mises à jour ; sans cette option, une mise à jour est seulement signalée, jamais appliquée automatiquement.

Le cache est exact par version/configuration/snapshot. Les anciens binaires ne sont pas réutilisés entre versions présumées compatibles. La première exécution peut donc reconstruire le runtime.

Les noms App/Flutter alternatifs ne signifient pas que Mach-O/iOS est pris en charge. Pour les autres architectures ELF, utiliser `--action r2`. Le C++ AOT x64 et le chargeur iOS ne sont pas fonctionnels dans les sources reçues et sont refusés explicitement.

## Sorties

AOT : `asm/`, `pp.txt`, `objs.txt`, `ida_script/`, `blutter_frida.js`.

Radare2 : `r2_output/`, scripts et batch ; noms suffixés d'une empreinte du chemin pour éviter les collisions. Les bibliothèques extraites d'un APK sont conservées dans `inputs/` pour permettre la relance des scripts générés.

Informations binaires : `binary_info.txt`.

Les modes de patch restent dans le menu r2. Ils modifient la cible sélectionnée après création d'une sauvegarde `.elitf.bak`. Si cette sauvegarde existe, la nouvelle écriture échoue sans l'écraser.

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

Le test ELF natif nécessite GCC et readelf. Les appels réseau et le moteur r2 sont simulés dans les tests concernés ; voir la distinction complète dans `SYNTHESE.md`.

Le dossier `audit/` contient inventaire par archive, comparaison des fonctions, patch par rapport à `Elit-f-main (1)` et résultats des tests.
