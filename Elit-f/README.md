## Installation et lancement d'Elit-f sur Termux

### 1. Préparer Termux
```bash
pkg update && pkg upgrade -y
pkg install -y git cmake ninja clang python capstone libfmt pkg-config
pip install rich pyelftools requests
```

### 2. Cloner le dépôt
```bash
git clone https://github.com/ChandrohIrintsoa/Elit-f.git
cd Elit-f
```

### 3. Build initial + installation
```bash
chmod +x build_termux.sh
# Build par défaut (Dart 3.4.2, android, arm64) :
./build_termux.sh
# Ou avec une version de Dart spécifique :
./build_termux.sh 3.4.2 android arm64
```

Le script :
1. Télécharge et compile la bibliothèque `dartvm` correspondant à la version demandée (si elle n'est pas déjà présente dans `packages/lib/`).
2. Configure et compile le binaire `elitf_<dartlib>` contre cette bibliothèque.
3. Installe un lanceur `Elit-f` dans `$PREFIX/bin/`.

> Le premier build est long (téléchargement du SDK Dart + compilation). Les builds suivants réutilisent la bibliothèque déjà compilée.

### 4. Préparer la cible
Récupère l'APK Flutter à analyser (ou un dossier avec `libapp.so` + `libflutter.so` extraits, dans
`lib/arm64-v8a/` de l'APK). Place-le quelque part accessible, ex :
```bash
mkdir -p ~/cibles
cp /sdcard/Download/X.apk ~/cibles/
```
> Termux permission stockage : `termux-setup-storage` si `/sdcard` n'est pas accessible.

### 5. Lancer l'outil
Depuis n'importe où par
```bash
Elit-f ~/cibles/MonApp.apk ~/cibles/out --cli
```
ou en mode interactif (menu) :
```bash
Elit-f
```

> L'outil détecte automatiquement la version de Dart à partir du `libflutter.so` et rebuild le binaire `elitf` correspondant si nécessaire.
