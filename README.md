
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

Sur Termux, le téléchargement des sources du Dart SDK est adapté aux réseaux
mobiles instables :

- **git sparse-checkout avec tentatives automatiques** : les commandes git
  échouées sont relancées jusqu'à 4 fois ; les blobs déjà téléchargés sont
  conservés par git, chaque tentative reprend là où la précédente s'est arrêtée.
- **Repli sans git** : si git échoue définitivement, Elit-f télécharge
  directement l'archive du tag (~37 Mo, un seul flux HTTP, reprise
  automatique) et n'en extrait que `runtime/`, `tools/` et
  `third_party/double-conversion`. L'archive est mise en cache dans
  `dartsdk/` : un nouvel essai ne la retélécharge pas.
- **Erreurs lisibles** : la sortie stderr de git/cmake/ninja est capturée ;
  en cas d'échec, la vraie cause s'affiche dans le panneau d'erreur.
- **Affichage adapté aux petits écrans** : l'interface d'exécution se
  redimensionne selon la taille réelle du terminal (plus de bandeau répété à
  l'infini pendant l'initialisation) ; cmake/ninja tournent en sortie capturée
  pour ne pas casser le rafraîchissement de l'écran.
- **Progression réelle pendant la compilation** : la sortie de ninja est
  diffusée en continu — les lignes `[N/M]` alimentent la barre de progression
  (elle ne reste plus bloquée à 0% pendant la compilation du Dart VM) et des
  jalons « Compiling Dart VM: [123/2467] (5%) » apparaissent dans le panneau
  d'opérations. Le téléchargement de l'archive affiche aussi des jalons
  « Downloaded 12.3 MB… » sur les liens lents.
- **Compilation adaptée à la mémoire de l'appareil** : ninja démarre avec
  `-j` borné par la RAM disponible (~2 Go par unité de compilation clang),
  ce qui évite que l'OOM-killer du téléphone ne tue le compilateur en
  plein build (ça ressemblait à un blocage infini à 0%). Surcharge manuelle :

```sh
export ELITF_NINJA_JOBS=4   # forcer le parallélisme (défaut : auto selon RAM)
```

Miroirs (réseau opérateur bloquant GitHub) :

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

Option [3] du menu — Dump Il2CppDumper (**contrat « exactement 2 fichiers »**,
comme l'original Il2CppDumper qui prend exactement 2 fichiers :
`libil2cpp.so` + `global-metadata.dat`) :

**Entrée — exactement 2 fichiers** : `libapp.so` (binaire Dart AOT,
équivalent de `libil2cpp.so`) + `libflutter.so` (moteur Flutter, porteur des
métadonnées de version, équivalent de `global-metadata.dat`). Les 2 fichiers
peuvent être fournis via l'APK (extraction automatique de
`lib/arm64-v8a/`), via un dossier contenant le pair, ou via le chemin de l'un
des 2 fichiers (le jumeau est recherché à côté). Sans le pair complet,
l'option [3] refuse avec un message explicite ; les rôles sont détectés par
nom (`libapp*.so` / `libflutter*.so`) puis par contenu à la manière de
`detect_files` de l'original (symboles `_kDartIsolateSnapshot*` pour le
binaire, `Dart_VersionString`/version `(stable)` pour le moteur).

**Sortie — exactement 2 fichiers** : `il2cpp_dump/` ne contient que
`dump.dart` + `script.json` (générés depuis les sorties du kernel Elit-f ;
l'analyse est lancée automatiquement si `asm/`/`pp.txt` sont absents) ; les
fichiers hérités des versions précédentes (`stringliteral.json`, scripts
IDA/Ghidra, struct header) sont purgés, sans perte d'information :

| Fichier | Contenu |
|---|---|
| `dump.dart` | pseudocode Dart adressé par bibliothèque/classe/champ/méthode (`// RVA: 0x… VA: 0x… Size: 0x…`) + littéraux de chaînes (`// StringLiteral`) + en-tête Dart/snapshot issus des 2 fichiers d'entrée |
| `script.json` | `ScriptMethod` (adresses + noms `Classe$$méthode` + signatures) et `ScriptString` (littéraux adressés) pour les outils externes |

Les générateurs `generate_stringliteral_json`, `generate_ida_script` et
`generate_ghidra_script` restent disponibles en API opt-in
(`python -c "import elitf_dumper; …"`) pour produire `stringliteral.json` et
les scripts IDA/Ghidra à la demande — ils ne font plus partie du dossier de
sortie par défaut.

**Fraîcheur des sorties (le fichier de sortie ne reste pas à son origine)** :
les sorties kernel (`asm/`, `pp.txt`) ne sont réutilisées par l'option [3] que
si l'empreinte d'analyse `<outdir>/.elitf_analysis.json` correspond au pair
d'entrée ACTUEL (digests SHA-256 de `libapp.so` + `libflutter.so`). Si la
cible change (nouvel APK, nouveau dossier, option 5 → changer les cibles),
avec `--rebuild`, ou si l'empreinte est absente (outdir d'une version
précédente) : les sorties de l'analyse d'origine sont **purgées** (`asm/`,
`pp.txt`, `objs.txt`, `ida_script/`, `blutter_frida.js`, ancien dump) avant la
nouvelle analyse — aucun mélange de bibliothèques entre 2 applications
(le kernel écrit un fichier `asm/` PAR bibliothèque Dart, les fichiers de
l'application précédente restaient sinon mélangés aux nouveaux). Toute
analyse fraîche (option 1 incluse) purge aussi les sorties précédentes avant
de lancer le kernel, puis enregistre l'empreinte après succès. Le récapitulatif
de l'option [3] affiche l'état : « Analyse réutilisée (cache valide pour ce
pair) » ou « Nouvelle analyse — N élément(s) de l'analyse d'origine purgé(s) ».

**Option 5 — nouvelles cibles de nettoyage** : la liste de nettoyage couvre
désormais aussi « Sorties kernel de l'analyse » (`asm/`, `pp.txt`, `objs.txt`,
`ida_script/`, `blutter_frida.js`, empreinte) et « Dump Il2CppDumper »
(`il2cpp_dump/`) — purge manuelle possible à tout moment (garde-fous
inchangés : suppression limitée au projet et au dossier de sortie).

## Console r2 — session persistante

Le mini terminal r2 (option [2] > Terminal) maintient désormais **un seul
processus r2** (protocole r2pipe interne, `r2 -q0`) : le seek (`s`), les
flags et le résultat de l'analyse (`aaa`) sont conservés entre les commandes.

```
r2(libapp.so)> s 0x6f57ec
r2(libapp.so)> pd 200        ← désassemble bien à 0x6f57ec (plus de retour à entry0)
```

Avantages : enchaînement `s` → `pd`/`pdf`/`px` correct, analyse `aaa`
exécutée une seule fois (au lieu d'être rejouée à chaque commande), réponse
instantanée. La config `!set e var=valeur` est appliquée en direct dans la
session ; `!rw on|off` relance la session avec `-w` (backup `.elitf.bak`
automatique, idempotent) ; `!use <n|nom>` ouvre une session propre pour la
nouvelle cible. Si le mode persistant échoue (r2 trop ancien, binaire
incompatible), Elit-f replie automatiquement sur l'ancien mode par commande.
La session r2 est fermée proprement à la sortie du terminal (`q`).


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
