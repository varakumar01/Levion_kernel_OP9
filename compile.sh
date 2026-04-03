#!/usr/bin/env bash
# =============================================================================
#  compile.sh — Kernel build script (arm64 / LLVM clang-r547379 + GCC cross)
#  Usage: ./compile.sh [--device=<device>]
#  Example: ./compile.sh --device=lahaina
# =============================================================================

set -e

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()     { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()    { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
banner() {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $*${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}\n"
}

# ─── Argument parsing ─────────────────────────────────────────────────────────
DEVICE=""

for arg in "$@"; do
    case "${arg}" in
        --device=*)   DEVICE="${arg#*=}"   ;;
        *) warn "Unknown argument: ${arg}" ;;
    esac
done

DEVICE="${DEVICE:-lahaina}"

log "Device   : ${DEVICE}"
log "Compiler : LLVM/clang (clang-r547379)"

# ─── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="${SCRIPT_DIR}"
OUT_DIR="${KERNEL_DIR}/out"
TOOLCHAIN_DIR="${KERNEL_DIR}/toolchains"

# Clang
CLANG_TAG="clang-r547379"
CLANG_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86"
CLANG_DIR="${TOOLCHAIN_DIR}/linux-x86/${CLANG_TAG}"

# GCC cross-compilers (used as CROSS_COMPILE linker stubs alongside LLVM)
GCC64_DIR="${TOOLCHAIN_DIR}/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin"
GCC32_DIR="${TOOLCHAIN_DIR}/gcc/linux-x86/arm/arm-linux-androideabi-4.9/bin"

# Defconfig — extend this case block to add more devices
case "${DEVICE}" in
    lahaina) DEFCONFIG="vendor/lahaina-qgki_defconfig" ;;
    *)       DEFCONFIG="vendor/${DEVICE}-qgki_defconfig" ;;
esac

JOBS="$(nproc)"

# ─── Step 1: Update Ubuntu & install dependencies ─────────────────────────────
banner "Step 1 — Update Ubuntu & install dependencies"

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install -y \
    git curl wget python3 python3-pip bc bison flex \
    libssl-dev libelf-dev make build-essential \
    binutils binutils-aarch64-linux-gnu binutils-arm-linux-gnueabi \
    gcc-aarch64-linux-gnu gcc-arm-linux-gnueabi \
    libncurses-dev libncurses5-dev libncursesw5-dev \
    zip unzip rsync ccache cpio kmod \
    lz4 zstd libzstd-dev pahole dwarves \
    libdw-dev pkg-config device-tree-compiler u-boot-tools

ok "Dependencies installed."

# ─── Step 2: Pull LLVM toolchain (clang-r547379) ──────────────────────────────
banner "Step 2 — Pull LLVM toolchain (${CLANG_TAG})"

mkdir -p "${TOOLCHAIN_DIR}/linux-x86"

if [ -d "${CLANG_DIR}" ] && [ -f "${CLANG_DIR}/bin/clang" ]; then
    ok "Clang already present — skipping download."
else
    log "Cloning ${CLANG_TAG} (shallow)..."
    git clone --depth=1 \
        --branch "${CLANG_TAG}" \
        "${CLANG_URL}" \
        "${CLANG_DIR}" || {

        warn "Branch clone failed. Trying sparse-checkout fallback..."
        mkdir -p "${CLANG_DIR}"
        cd "${CLANG_DIR}"
        git init
        git remote add origin "${CLANG_URL}"
        git config core.sparseCheckout true
        echo "${CLANG_TAG}/" >> .git/info/sparse-checkout
        git fetch --depth=1 origin refs/heads/main
        git checkout FETCH_HEAD
        cd "${KERNEL_DIR}"
    }
fi

[ -f "${CLANG_DIR}/bin/clang" ] || die "clang binary missing — check toolchain download."
ok "Clang ready: $("${CLANG_DIR}/bin/clang" --version | head -1)"

# ─── Step 3: Export PATH & environment ────────────────────────────────────────
banner "Step 3 — Export environment"

export PATH="${CLANG_DIR}/bin:${GCC64_DIR}:${GCC32_DIR}:${PATH}"
export ARCH=arm64
export SUBARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
export CROSS_COMPILE_ARM32=arm-linux-gnueabi-

# Enable ccache if available
if command -v ccache &>/dev/null; then
    ccache --max-size=5G
    export USE_CCACHE=1
    export CCACHE_EXEC="$(command -v ccache)"
    log "ccache enabled."
fi

# Build flags — LLVM as compiler, GCC as cross-linker
MAKE_FLAGS=(
    O="${OUT_DIR}"
    ARCH=arm64
    LLVM=1
    CC=clang
    LD=ld.lld
    AR=llvm-ar
    NM=llvm-nm
    OBJCOPY=llvm-objcopy
    OBJDUMP=llvm-objdump
    READELF=llvm-readelf
    OBJSIZE=llvm-size
    STRIP=llvm-strip
    CROSS_COMPILE=aarch64-linux-gnu-
    CROSS_COMPILE_ARM32=arm-linux-gnueabi-
)

log "Active clang : $(clang --version | head -1)"
ok "Environment ready."

# ─── Step 4: Sanity checks ────────────────────────────────────────────────────
banner "Step 4 — Sanity checks"

cd "${KERNEL_DIR}"
[ -f "Makefile" ] || die "Makefile not found — run this from the kernel root."
mkdir -p "${OUT_DIR}"
ok "Kernel dir : ${KERNEL_DIR}"
ok "Out dir    : ${OUT_DIR}"

# ─── Step 5: Clean ────────────────────────────────────────────────────────────
banner "Step 5 — Clean (clean + mrproper)"

make "${MAKE_FLAGS[@]}" clean
make "${MAKE_FLAGS[@]}" mrproper
ok "Tree cleaned."

# ─── Step 6: Git status ───────────────────────────────────────────────────────
banner "Step 6 — Git status"
git status

# ─── Step 7: Defconfig ────────────────────────────────────────────────────────
banner "Step 7 — Apply defconfig (${DEFCONFIG})"

make "${MAKE_FLAGS[@]}" "${DEFCONFIG}"
ok "Defconfig applied."

# ─── Step 8: Build ────────────────────────────────────────────────────────────
banner "Step 8 — Build kernel (-j${JOBS})"

START_TIME=$(date +%s)
make -j"${JOBS}" "${MAKE_FLAGS[@]}"
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ok "Build finished in $(( ELAPSED / 60 ))m $(( ELAPSED % 60 ))s."

# ─── Step 9: Verify images ────────────────────────────────────────────────────
banner "Step 9 — Verify images"

IMAGE="${OUT_DIR}/arch/arm64/boot/Image"
IMAGE_GZ="${OUT_DIR}/arch/arm64/boot/Image.gz"
DTBO="${OUT_DIR}/arch/arm64/boot/dtbo.img"

for f in "${IMAGE}" "${IMAGE_GZ}" "${DTBO}"; do
    [ -f "${f}" ] && ok "Found : ${f}" || warn "Not found : ${f}"
done

# ─── Done ─────────────────────────────────────────────────────────────────────
banner "All done!"
echo -e "${GREEN}  Image    : ${IMAGE}${NC}"
echo -e "${GREEN}  Image.gz : ${IMAGE_GZ}${NC}"
echo -e "${GREEN}  dtbo.img : ${DTBO}${NC}"
echo -e "${GREEN}  Time     : $(( ELAPSED / 60 ))m $(( ELAPSED % 60 ))s${NC}"
echo ""
