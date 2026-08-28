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
# Build :
./build_termux.sh

```

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
ou en mode menu :
```bash
Elit-f
```
.
