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

# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   ./build_termux.sh                                # build dartvm + elitf (default version 3.4.2)
#   ./build_termux.sh <dart_version>                 # e.g. ./build_termux.sh 3.4.2
#   ./build_termux.sh <dart_version> <os> <arch>     # e.g. ./build_termux.sh 3.4.2 android arm64
# ─────────────────────────────────────────────────────────────────────────────
DART_VERSION=${1:-3.4.2}
OS_NAME=${2:-android}
ARCH=${3:-arm64}

DARTLIB="dartvm${DART_VERSION}_${OS_NAME}_${ARCH}"

if [ ! -d "build" ]; then
        mkdir build
fi

# 1) Fetch & build dartvm static library if not already present
PKG_LIB_DIR="${SCRIPT_DIR}/packages/lib"
LIBFILE="${PKG_LIB_DIR}/lib${DARTLIB}.a"
if [ ! -f "${LIBFILE}" ]; then
        echo "[*] Building dartvm library: ${DARTLIB}"
        python3 "${SCRIPT_DIR}/dartvm_fetch_build.py" "${DART_VERSION}" "${OS_NAME}" "${ARCH}"
else
        echo "[*] dartvm library already built: ${LIBFILE}"
fi

# 2) Configure & build Elit-f against the dartvm library
cd "${SCRIPT_DIR}/build"
cmake .. -DDARTLIB=$DARTLIB -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

if [ -f "bin/elitf_${DARTLIB}" ]; then
        $STRIP bin/elitf_${DARTLIB}
        cp bin/elitf_${DARTLIB} bin/elitf_${DARTLIB}.stripped
        rm bin/elitf_${DARTLIB}
fi

echo "Build complete: bin/elitf_${DARTLIB}.stripped"

# 3) Install launcher
ELITF_LAUNCHER="$PREFIX/bin/Elit-f"
printf '#!/data/data/com.termux/files/usr/bin/bash\ncd "%s"\nexec python3 elitf.py "$@"\n' "$SCRIPT_DIR" > "$ELITF_LAUNCHER"
chmod 755 "$ELITF_LAUNCHER"
echo "Launcher installed: $ELITF_LAUNCHER"
