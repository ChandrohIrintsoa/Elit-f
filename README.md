
## Installation Python
```sh
git clone https://github.com/ChandrohIrintsoa/Elit-f.git
```
Python 3.9 ou supérieur ; dépendances :

```sh
python -m pip install -r requirements.txt
```

## Lancement direct sur Termux (`Elit-f`)

Pour lancer l'outil en tapant simplement `Elit-f` dans Termux :

```sh
bash install_termux.sh
# ou, équivalent :
python elitf.py --install-launcher
```

Le script crée `$PREFIX/bin/Elit-f` et `$PREFIX/bin/elitf` (idempotent).
Ouvrez ensuite un nouveau shell Termux si la commande est introuvable.
Au premier lancement interactif sur Termux, l'installation du lanceur est
également proposée automatiquement (refus mémorisé via `.elitf_no_launcher`).

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

## Corrections et améliorations (session d'audit)

Méthodologie : skills superpowers (systematic-debugging, test-driven-development,
verification-before-completion) + connaissances Dart/Flutter des skills agent-plugins
(découverte SDK AOT, gestion des sous-processus, codes de sortie).

### Corrigé

1. **Décodage des sorties subprocess (critique)** — `elitf.py` : les 5 appels
   `subprocess.run(text=True)` (cmake configure, ninja, cmake install, exécution du
   moteur d'analyse, commandes git) passent désormais `errors='replace'`. Les
   symboles Dart/objets extraits d'applications obfusquées peuvent contenir des
   octets non-UTF8 ; auparavant, une `UnicodeDecodeError` survenait APRÈS une
   analyse pourtant réussie, faisant croire à un échec total. Aligné sur le
   comportement déjà correct de `elitf_r2.py`.
2. **Patch r2 répété** — `elitf_r2.py` : le backup `.elitf.bak` est créé une seule
   fois (nouvel helper `_ensure_backup`) ; un second patch sur le même `.so`
   échouait auparavant avec `FileExistsError`. Le backup existant est conservé :
   il représente toujours la version pristine, jamais une version déjà patchée.
3. **Fichier .so seul accepté par `--action r2/info`** — `elitf.py`
   `prepare_so_targets` : un chemin de fichier régulier (ex. `libapp.so`) est
   traité comme cible unique au lieu de lever « No shared libraries found ».
4. **Idempotence de l'extraction zip (perf)** — `prepare_so_targets` ne
   ré-extrait plus les `lib/*.so` si le dossier `inputs/<digest>` contient déjà
   des `.so` ; les relances sur le même APK sont instantanées.
5. **Arguments débogueur Visual Studio** — `cmake_vs_sln` quote désormais les
   chemins dans `DBG_CMD` (`-i "..." -o "..."`) : les chemins avec espaces
   fonctionnent.
6. **Mode interactif** — expansion `~` (`os.path.expanduser`) des chemins saisis.
7. **Nettoyage pyflakes** — import `re` inutilisé (`elitf.py`), f-strings sans
   placeholder (`elitf_ui.py`), consolidation d'un double parse de version.

### Ajouté

- `tests/test_ameliorations.py` : 9 tests de régression couvrant les points
  1 à 5 ci-dessus (cycle TDD : échouaient avant correctif, passent après).
- Suite complète : 48 tests (39 préexistants + 9 nouveaux), 0 échec.
- `tests/test_console_r2.py` : 40 tests TDD supplémentaires pour la console
  r2 (mini terminal, catalogue, pptool), l'option 5 (cibles + nettoyage) et le
  lanceur — total : 88 tests, 2 sauts conditionnels, 0 échec.

## Console r2 — mini terminal + catalogue (option 2)

Après la sélection des cibles individuelles, le menu r2 est devenu une
**Console r2** qui reste ouverte pendant toute la session :

| Choix | Description |
|-------|-------------|
| `[1] Mini terminal r2` | Prompt `r2(libapp.so_…)>` : tapez **toutes** les commandes r2 librement (`afl`, `px 64 @ 0x1000`, `pdf @ sym.main`, `izz~password`…) ; la sortie s'affiche en direct. |
| `[2] Catalogue des commandes r2` | Sous-menus par catégories — analyse, infos binaires, impression/hexdump, recherche, xrefs, écriture, configuration, divers (~50 commandes avec description et saisie guidée des arguments). |
| `[3]` Presets d'analyse | full / standard / quick / minimal / audit sécurité. |
| `[4]` Analyse personnalisée | Niveau d'analyse + blocs d'extraction. |
| `[5]` Patching | Mode écriture `wa` / `wx` / `w` (backup `.elitf.bak` automatique). |
| `[6]` Générer sans exécuter | Crée les scripts `.r2` + batch `.sh`. |

**Mini terminal** — commandes intégrées :

- `!help` aide, `!targets` lister les cibles, `!use <n|nom>` changer de cible active
- `!anal on|off` rejouer automatiquement la dernière analyse (`aaa`) avant chaque commande — utile car chaque commande s'exécute dans une session r2 fraîche (`r2 -q -N -c …`)
- `!rw on|off` mode écriture `r2 -w` (backup `.elitf.bak` créé automatiquement)
- `!set` / `!unset` (`e var=valeur`) configuration de session réinjectée à chaque commande
- `!lib` chemin de la cible active, `q`/`quit`/`exit` pour quitter
- redirection native r2 : `afl > fonctions.txt`

**pptool (r2 + pptool ensemble)** — dans le même terminal, les commandes
`pptool …` sont routées vers l'outil **PPTool** (localisateur d'adresses des
objets Dart dans `libapp.so`, outil de la communauté Termux/Flutter) s'il est
installé. Placeholders pratiques : `pptool -f {so}` (`{so}` = cible active,
aussi `{libapp}`, `{name}`, `{outdir}`). `!pptool` affiche son état. PPTool est
recherché dans `PATH`, le dossier du projet, ou via `ELITF_PPTOOL=/chemin/pptool`.

## Option 5 — infos binaires, cibles et nettoyage

L'option `[5] Information binaire détaillée` ouvre désormais un sous-menu :

| Choix | Description |
|-------|-------------|
| `[1]` Afficher les infos | `readelf -h -S -l` sur chaque `.so` → `binary_info.txt` (comportement historique). |
| `[2]` Changer les cibles | Saisir un nouveau répertoire/APK (expansion `~`), re-sélection des `.so` ; le nouveau chemin est propagé aux autres options du menu. |
| `[3]` Supprimer les dossiers compilés et les caches | Détection avec tailles : `build/` (cmake/ninja), `bin/` (binaires compilés), `packages/` (cache SDK Dart VM), `out/inputs` (cache d'extraction APK/zip), `out/r2_output` (sorties r2), `__pycache__`. Sélection par numéros ou `all`, confirmation `o/n`, puis suppression avec garde-fous (jamais hors du projet/de la sortie, jamais les racines elles-mêmes). |

