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

if [ ! -d "build" ]; then
        mkdir build
fi
cd build


DARTLIB=${1:-dartvm_default}

cmake .. -DDARTLIB=$DARTLIB -DCMAKE_BUILD_TYPE=Release "$@"
make -j$(nproc)

if [ -f "bin/elitf_${DARTLIB}" ]; then
        $STRIP bin/elitf_${DARTLIB}
        cp bin/elitf_${DARTLIB} bin/elitf_${DARTLIB}.stripped
        rm bin/elitf_${DARTLIB}
fi

echo "Build complete: bin/elitf_${DARTLIB}.stripped"

ELITF_LAUNCHER="$PREFIX/bin/Elit-f"
printf '#!/data/data/com.termux/files/usr/bin/bash\ncd "%s"\nexec python3 elitf.py "$@"\n' "$SCRIPT_DIR" > "$ELITF_LAUNCHER"
chmod 755 "$ELITF_LAUNCHER"
echo "Launcher installed: $ELITF_LAUNCHER"
