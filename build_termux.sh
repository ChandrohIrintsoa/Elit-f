#!/data/data/com.termux/files/usr/bin/bash
set -e

NDK_TOOLCHAIN=$PREFIX/bin
export PATH=$NDK_TOOLCHAIN:$PATH
export CC=$NDK_TOOLCHAIN/aarch64-linux-android-clang
export CXX=$NDK_TOOLCHAIN/aarch64-linux-android-clang++
export AR=$NDK_TOOLCHAIN/aarch64-linux-android-ar
export RANLIB=$NDK_TOOLCHAIN/aarch64-linux-android-ranlib
export STRIP=$NDK_TOOLCHAIN/aarch64-linux-android-strip
export PKG_CONFIG=$PREFIX/bin/pkg-config
export CMAKE=$PREFIX/bin/cmake

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"



DART_VERSION=${1:-}
OS_NAME=${2:-android}
ARCH=${3:-arm64}

if [ -z "$DART_VERSION" ]; then
        echo "Usage: $0 <dart_version> [os] [arch]"
        echo ""
        echo "Le dart_version DOIT correspondre à la version du Dart SDK détectée"
        echo "depuis le libflutter.so de l'application à analyser."
        echo ""
        echo "Pour détecter automatiquement la version, lancez simplement :"
        echo "  Elit-f <repertoire_ou_apk> <repertoire_sortie> --cli"
        echo "  (Elit-f détectera la version, construira le dartvm si besoin,"
        echo "   puis construira le binaire C++ et l'exécutera)"
        echo ""
        echo "Versions de dartvm déjà construites dans packages/lib :"
        if [ -d "${SCRIPT_DIR}/packages/lib" ]; then
                ls -1 "${SCRIPT_DIR}/packages/lib/"*.a 2>/dev/null | sed 's|.*/lib||;s|\.a$||' | sed 's/^/  /'
        else
                echo "  (aucune — lancez Elit-f sur une application pour en construire une)"
        fi
        exit 1
fi

DARTLIB="dartvm${DART_VERSION}_${OS_NAME}_${ARCH}"

# Vérifier que le dartvm existe
PKG_LIB_DIR="${SCRIPT_DIR}/packages/lib"
LIBFILE="${PKG_LIB_DIR}/lib${DARTLIB}.a"
if [ ! -f "${LIBFILE}" ]; then
        echo "❌ La bibliothèque dartvm '${DARTLIB}' n'existe pas."
        echo "   Pour la construire, lancez :"
        echo "   python3 dartvm_fetch_build.py ${DART_VERSION} ${OS_NAME} ${ARCH}"
        echo "   (ou laissez Elit-f le faire automatiquement en analysant une app)"
        echo ""
        echo "   Versions déjà construites :"
        ls -1 "${PKG_LIB_DIR}/"*.a 2>/dev/null | sed 's|.*/lib||;s|\.a$||' | sed 's/^/     /' || echo "     (aucune)"
        exit 1
fi

echo "[*] dartvm library: ${LIBFILE}"

if [ ! -d "build" ]; then
        mkdir build
fi

# 1) Calculer les macros compat pour cette version de Dart
echo "[*] Computing compat macros for Dart ${DART_VERSION}"
MACROS=$(python3 -c "
import sys
sys.path.insert(0, '${SCRIPT_DIR}')
import elitf
macros = elitf.find_compat_macro('${DART_VERSION}', False)
print(' '.join(macros))
")
echo "    Macros: ${MACROS}"

# 2) Configurer et compiler Elit-f
cd "${SCRIPT_DIR}/build"
cmake .. -DDARTLIB=$DARTLIB -DCMAKE_BUILD_TYPE=Release ${MACROS}
make -j$(nproc)

if [ -f "bin/elitf_${DARTLIB}" ]; then
        $STRIP bin/elitf_${DARTLIB}
        cp bin/elitf_${DARTLIB} bin/elitf_${DARTLIB}.stripped
        rm bin/elitf_${DARTLIB}
fi

echo "Build complete: bin/elitf_${DARTLIB}.stripped"

# 3) Installer le lanceur (uniquement si PREFIX est défini — typiquement Termux)
if [ -n "$PREFIX" ] && [ -d "$PREFIX/bin" ]; then
        ELITF_LAUNCHER="$PREFIX/bin/Elit-f"
        printf '#!/data/data/com.termux/files/usr/bin/bash\ncd "%s"\nexec python3 elitf.py "$@"\n' "$SCRIPT_DIR" > "$ELITF_LAUNCHER"
        chmod 755 "$ELITF_LAUNCHER"
        echo "Launcher installed: $ELITF_LAUNCHER"
else
        echo "Skipped launcher install (PREFIX not set or $PREFIX/bin missing — non-Termux env)."
fi
