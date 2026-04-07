#!/usr/bin/env bash
# compile.sh — Full Levion Kernel build pipeline for OnePlus 9 (lemonade / SM8350)
# Steps: deps → clang → kernel tree → compile → vendor_dlkm → AK3 → zip → release
#
# Usage: bash compile.sh
# Intended for GitHub Actions (runs with +x chmod)

set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Global Configuration
# ══════════════════════════════════════════════════════════════════════════════

WORK_DIR="${HOME}/op9"
TOOLCHAIN_DIR="${WORK_DIR}/kernel-repo/llvm-toolchain/linux-x86"
CLANG_VERSION="clang-r547379"
CLANG_PATH="${TOOLCHAIN_DIR}/${CLANG_VERSION}/bin"

KDIR="${WORK_DIR}/code/Levion_kernel_OP9"
KERNEL_REPO="https://github.com/varakumar01/Levion_kernel_OP9.git"

AK3_DIR="${WORK_DIR}/AnyKernel3"
AK3_REPO="https://github.com/varakumar01/AnyKernel3.git"
AK3_BRANCH="op9"

STOCK_IMG="${WORK_DIR}/code/vendor_dlkm.img"
BUILD_MODULES_DIR="${KDIR}/out/modules"
TEMP_DIR="${WORK_DIR}/code/temp"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RUN_DIR="${TEMP_DIR}/vendor_dlkm_files_${TIMESTAMP}"

OUT_ZIP="${WORK_DIR}/levion_kernel.zip"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERR]${NC}   $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}══ $* ══${NC}"; }

# ══════════════════════════════════════════════════════════════════════════════
# Step 1: Install Dependencies
# ══════════════════════════════════════════════════════════════════════════════
step "Step 1: Installing Build Dependencies"

if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    DISTRO="${ID:-unknown}"
else
    DISTRO="unknown"
fi

info "Detected distro: $DISTRO"

case "$DISTRO" in
    ubuntu|debian|linuxmint)
        info "Running apt install..."
        sudo apt-get update -qq
        sudo apt-get install -y \
            bc \
            bison \
            build-essential \
            cpio \
            curl \
            flex \
            git \
            kmod \
            libelf-dev \
            libncurses-dev \
            libssl-dev \
            lld \
            llvm \
            make \
            pahole \
            python3 \
            rsync \
            tar \
            wget \
            zip \
            zlib1g-dev \
            erofs-utils \
            gcc-aarch64-linux-gnu \
            gcc-arm-linux-gnueabi
        ;;
    fedora|rhel|centos)
        info "Running dnf install..."
        sudo dnf install -y \
            bc \
            bison \
            elfutils-libelf-devel \
            flex \
            gcc \
            git \
            lld \
            llvm \
            make \
            ncurses-devel \
            openssl-devel \
            pahole \
            python3 \
            rsync \
            wget \
            zip \
            zlib-devel \
            erofs-utils \
            gcc-aarch64-linux-gnu \
            gcc-arm-linux-gnueabi
        ;;
    arch|manjaro)
        info "Running pacman install..."
        sudo pacman -Sy --noconfirm \
            base-devel \
            bc \
            bison \
            flex \
            git \
            libelf \
            lld \
            llvm \
            make \
            ncurses \
            openssl \
            pahole \
            python \
            rsync \
            wget \
            zip \
            zlib \
            erofs-utils \
            aarch64-linux-gnu-gcc \
            arm-linux-gnueabi-gcc
        ;;
    *)
        warn "Unsupported distro '$DISTRO' — skipping auto-install."
        warn "Please manually install: bc bison flex make libelf libssl llvm lld pahole python3 erofs-utils gcc-aarch64-linux-gnu gcc-arm-linux-gnueabi"
        ;;
esac

success "Dependencies installed."

# ══════════════════════════════════════════════════════════════════════════════
# Step 2: Pull Clang Toolchain (clang-r547379 from AOSP prebuilts)
# ══════════════════════════════════════════════════════════════════════════════
step "Step 2: Pulling Clang Toolchain ($CLANG_VERSION)"

CLANG_REPO_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86"
CLANG_DEST="${TOOLCHAIN_DIR}"

info "Destination : $CLANG_DEST"
info "Source      : $CLANG_REPO_URL"

mkdir -p "$CLANG_DEST"

if [[ -d "$CLANG_DEST/.git" ]]; then
    info "Repo already exists — fetching latest..."
    cd "$CLANG_DEST"
    git fetch --depth=1 origin
else
    info "Initialising partial clone (no blobs yet)..."
    git clone \
        --filter=blob:none \
        --no-checkout \
        --depth=1 \
        --single-branch \
        "$CLANG_REPO_URL" \
        "$CLANG_DEST"
    cd "$CLANG_DEST"
fi

info "Configuring sparse-checkout for $CLANG_VERSION/ only..."
git sparse-checkout init --cone
git sparse-checkout set "$CLANG_VERSION"

info "Downloading toolchain blobs..."
git checkout

success "Toolchain pulled → $CLANG_DEST/$CLANG_VERSION"

export PATH="${CLANG_PATH}:$PATH"
info "Clang version: $(clang --version | head -1)"

# ══════════════════════════════════════════════════════════════════════════════
# Step 3: Pull Android Kernel Tree
# ══════════════════════════════════════════════════════════════════════════════
step "Step 3: Pulling Kernel Source Tree"

mkdir -p "$(dirname "$KDIR")"

if [[ -d "$KDIR/.git" ]]; then
    info "Kernel repo already exists — pulling latest..."
    cd "$KDIR"
    git pull --rebase
else
    info "Cloning kernel repo..."
    git clone --depth=1 "$KERNEL_REPO" "$KDIR"
fi

cd "$KDIR"
success "Kernel source ready at $KDIR"

# ══════════════════════════════════════════════════════════════════════════════
# Step 4: Compile the Kernel
# ══════════════════════════════════════════════════════════════════════════════
step "Step 4: Compiling Kernel"

# Common make flags
MAKE_FLAGS=(
    O=out
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

cd "$KDIR"

info "Running clean..."
make "${MAKE_FLAGS[@]}" clean

info "Running mrproper..."
make "${MAKE_FLAGS[@]}" mrproper

info "Git status:"
git status

info "Loading defconfig: vendor/lahaina-qgki_defconfig"
make "${MAKE_FLAGS[@]}" vendor/lahaina-qgki_defconfig

info "Building kernel with $(nproc) threads..."
make -j"$(nproc)" "${MAKE_FLAGS[@]}"

# Verify Image exists
KERNEL_IMAGE="${KDIR}/out/arch/arm64/boot/Image"
[[ -f "$KERNEL_IMAGE" ]] || die "Kernel Image not found at $KERNEL_IMAGE — build may have failed."

success "Kernel compiled → $KERNEL_IMAGE"

# Install modules into out/modules
info "Installing kernel modules..."
make "${MAKE_FLAGS[@]}" INSTALL_MOD_PATH=out/modules modules_install

success "Modules installed → $BUILD_MODULES_DIR"

# ══════════════════════════════════════════════════════════════════════════════
# Step 5: Generate vendor_dlkm.img
# ══════════════════════════════════════════════════════════════════════════════
step "Step 5: Generating vendor_dlkm Image"

# ── Validate stock image ──────────────────────────────────────────────────────
[[ -f "$STOCK_IMG" ]] || die "Stock vendor_dlkm.img not found at $STOCK_IMG"

mkdir -p "$RUN_DIR"
info "Output directory: $RUN_DIR"

# ── Extract stock image ───────────────────────────────────────────────────────
EXTRACT_DIR="${RUN_DIR}/extracted"
mkdir -p "$EXTRACT_DIR"

info "Extracting stock vendor_dlkm.img..."
fsck.erofs --extract="$EXTRACT_DIR" --overwrite "$STOCK_IMG" 2>&1
success "Extracted stock image"

MODULES_DIR="${EXTRACT_DIR}/lib/modules"

STOCK_KO_COUNT=$(find "$MODULES_DIR" -name "*.ko" | wc -l)
info "Stock module count: $STOCK_KO_COUNT"

# ── Derive exclude/blocklist sets from stock ──────────────────────────────────
declare -A STOCK_LOAD_SET
while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    STOCK_LOAD_SET["$entry"]=1
done < "${MODULES_DIR}/modules.load"

declare -A BLOCKLIST_SET
if [[ -f "${MODULES_DIR}/modules.blocklist" ]]; then
    while read -r _ mod; do
        [[ -n "$mod" ]] && BLOCKLIST_SET["$mod"]=1
    done < <(grep '^blocklist ' "${MODULES_DIR}/modules.blocklist" || true)
fi

declare -A EXCLUDE_SET
for ko in "${MODULES_DIR}"/*.ko; do
    mod_name=$(basename "$ko" .ko)
    if [[ -z "${STOCK_LOAD_SET[${mod_name}]+x}" ]] && [[ -z "${BLOCKLIST_SET[${mod_name}]+x}" ]]; then
        EXCLUDE_SET["$mod_name"]=1
    fi
done

info "Derived ${#EXCLUDE_SET[@]} excluded modules: ${!EXCLUDE_SET[*]}"

# ── Validate build output ─────────────────────────────────────────────────────
[[ -d "$BUILD_MODULES_DIR" ]] || die "No modules_install output at $BUILD_MODULES_DIR"

BUILD_KO_COUNT=$(find "$BUILD_MODULES_DIR" -type f -name "*.ko" | wc -l)
[[ "$BUILD_KO_COUNT" -gt 0 ]] || die "No .ko files found in $BUILD_MODULES_DIR"
info "Found $BUILD_KO_COUNT built modules"

# ── Replace stock modules with built ones ────────────────────────────────────
info "Removing stock .ko files..."
rm -f "${MODULES_DIR}"/*.ko

info "Copying built modules..."
find "$BUILD_MODULES_DIR" -type f -name "*.ko" | while read -r ko; do
    cp -p "$ko" "${MODULES_DIR}/"
done

NEW_KO_COUNT=$(find "$MODULES_DIR" -name "*.ko" | wc -l)
success "Replaced with $NEW_KO_COUNT built modules"

# ── Rename wlan.ko → qca_cld3_wlan.ko ────────────────────────────────────────
if [[ -f "${MODULES_DIR}/wlan.ko" ]]; then
    mv "${MODULES_DIR}/wlan.ko" "${MODULES_DIR}/qca_cld3_wlan.ko"
    success "Renamed wlan.ko → qca_cld3_wlan.ko"
fi

# ── Strip debug symbols ───────────────────────────────────────────────────────
if command -v llvm-objcopy &>/dev/null; then
    info "Stripping debug symbols..."
    for ko in "${MODULES_DIR}"/*.ko; do
        llvm-objcopy --strip-debug "$ko"
    done
    success "Stripped debug symbols"
else
    warn "llvm-objcopy not in PATH — skipping strip"
fi

# ── Run depmod ────────────────────────────────────────────────────────────────
info "Running depmod..."

DEPMOD_STAGING="${RUN_DIR}/depmod_staging"
DEPMOD_VER="0.0"
DEPMOD_MOD_DIR="${DEPMOD_STAGING}/lib/modules/${DEPMOD_VER}"
mkdir -p "$DEPMOD_MOD_DIR"

cp -p "${MODULES_DIR}"/*.ko "${DEPMOD_MOD_DIR}"/

touch "${DEPMOD_MOD_DIR}/modules.order"
touch "${DEPMOD_MOD_DIR}/modules.builtin"
touch "${DEPMOD_MOD_DIR}/modules.builtin.modinfo"

depmod -a -b "$DEPMOD_STAGING" "$DEPMOD_VER"

for f in modules.alias modules.dep modules.softdep; do
    [[ -f "${DEPMOD_MOD_DIR}/${f}" ]] && cp -p "${DEPMOD_MOD_DIR}/${f}" "${MODULES_DIR}/"
done

success "depmod complete"

# ── Fix paths in modules.dep ──────────────────────────────────────────────────
info "Fixing module paths in modules.dep..."
sed -i 's|[^ :]*lib/modules/[^/]*/||g' "${MODULES_DIR}/modules.dep"
sed -i 's|\([a-zA-Z0-9_.-]*\.ko\)|/vendor_dlkm/lib/modules/\1|g' "${MODULES_DIR}/modules.dep"
success "Paths fixed"

# ── Generate modules.load ─────────────────────────────────────────────────────
info "Generating modules.load..."
: > "${MODULES_DIR}/modules.load"
for ko in "${MODULES_DIR}"/*.ko; do
    mod_name=$(basename "$ko" .ko)
    if [[ -z "${EXCLUDE_SET[${mod_name}]+x}" ]] && [[ -z "${BLOCKLIST_SET[${mod_name}]+x}" ]]; then
        echo "$mod_name" >> "${MODULES_DIR}/modules.load"
    fi
done

LOAD_COUNT=$(wc -l < "${MODULES_DIR}/modules.load")
success "modules.load: $LOAD_COUNT entries (${#EXCLUDE_SET[@]} excluded, ${#BLOCKLIST_SET[@]} blocklisted)"
success "modules.blocklist: preserved from stock"

# ── Create vendor_dlkm.tar.xz ─────────────────────────────────────────────────
OUT_TAR="${RUN_DIR}/vendor_dlkm_${TIMESTAMP}.tar.xz"
info "Creating tarball..."
tar -cpf - -C "$EXTRACT_DIR" lib/ | xz -9e -T0 > "$OUT_TAR"
TAR_SIZE=$(du -sh "$OUT_TAR" | cut -f1)
success "Created $OUT_TAR ($TAR_SIZE)"

# ── Build vendor_dlkm.img (EROFS) ─────────────────────────────────────────────
OUT_IMG="${RUN_DIR}/vendor_dlkm_${TIMESTAMP}.img"
info "Building EROFS vendor_dlkm image..."

FILE_CONTEXTS="${RUN_DIR}/file_contexts"
cat <<'EOF' > "$FILE_CONTEXTS"
/ u:object_r:vendor_file:s0
/vendor_dlkm(/.*)? u:object_r:vendor_file:s0
/vendor_dlkm/etc(/.*)? u:object_r:vendor_configs_file:s0
EOF

mkfs.erofs \
    --mount-point=/vendor_dlkm \
    --all-root \
    --file-contexts="$FILE_CONTEXTS" \
    -zlz4 \
    -b4096 \
    -T1230768000 \
    "$OUT_IMG" \
    "$EXTRACT_DIR"

ORIG_SIZE=$(stat --format="%s" "$STOCK_IMG")
NEW_SIZE=$(stat --format="%s" "$OUT_IMG")

if [[ "$NEW_SIZE" -le "$ORIG_SIZE" ]]; then
    info "Padding image to match partition size ($ORIG_SIZE bytes)..."
    truncate -s "$ORIG_SIZE" "$OUT_IMG"
else
    warn "New image ($NEW_SIZE) > original partition ($ORIG_SIZE)!"
    warn "Image may not fit! Consider removing unused modules."
fi

IMG_SIZE=$(du -sh "$OUT_IMG" | cut -f1)
success "Created $OUT_IMG ($IMG_SIZE)"

info "Verifying EROFS image..."
fsck.erofs "$OUT_IMG" 2>&1 && success "Image passed fsck" || warn "Image failed fsck!"

# ══════════════════════════════════════════════════════════════════════════════
# Step 6: Clone AnyKernel3
# ══════════════════════════════════════════════════════════════════════════════
step "Step 6: Cloning AnyKernel3"

if [[ -d "$AK3_DIR/.git" ]]; then
    info "AK3 repo already exists — pulling latest..."
    cd "$AK3_DIR"
    git checkout "$AK3_BRANCH"
    git pull --rebase
else
    info "Cloning AnyKernel3 (branch: $AK3_BRANCH)..."
    git clone --depth=1 --branch "$AK3_BRANCH" "$AK3_REPO" "$AK3_DIR"
fi

success "AnyKernel3 ready at $AK3_DIR"

# ══════════════════════════════════════════════════════════════════════════════
# Step 7: Update vendor_ramdisk Modules in AK3
# ══════════════════════════════════════════════════════════════════════════════
step "Step 7: Updating vendor_ramdisk Modules in AK3"

# Locate vendor_ramdisk modules directory in AK3
AK3_RAMDISK_MOD_DIR=""
for candidate in \
    "${AK3_DIR}/vendor_ramdisk/lib/modules" \
    "${AK3_DIR}/ramdisk/lib/modules" \
    "${AK3_DIR}/vendor_ramdisk/modules" \
    "${AK3_DIR}/modules"; do
    if [[ -d "$candidate" ]]; then
        AK3_RAMDISK_MOD_DIR="$candidate"
        break
    fi
done

if [[ -z "$AK3_RAMDISK_MOD_DIR" ]]; then
    warn "Could not auto-detect vendor_ramdisk modules directory in AK3."
    warn "Searched: vendor_ramdisk/lib/modules, ramdisk/lib/modules, vendor_ramdisk/modules, modules"
    warn "Skipping vendor_ramdisk module replacement — check AK3 layout manually."
else
    info "AK3 ramdisk modules dir: $AK3_RAMDISK_MOD_DIR"

    # Build list of .ko filenames currently in AK3 ramdisk
    declare -A AK3_KO_NAMES
    while IFS= read -r ko_path; do
        ko_file=$(basename "$ko_path")
        AK3_KO_NAMES["$ko_file"]=1
    done < <(find "$AK3_RAMDISK_MOD_DIR" -name "*.ko")

    info "Found ${#AK3_KO_NAMES[@]} .ko entries in AK3 vendor_ramdisk"

    # Source directory: extracted/lib/modules from the dlkm run
    DLKM_MODULES_SRC="${EXTRACT_DIR}/lib/modules"

    REPLACED=0
    NOT_FOUND=0

    for ko_name in "${!AK3_KO_NAMES[@]}"; do
        src="${DLKM_MODULES_SRC}/${ko_name}"
        dst="${AK3_RAMDISK_MOD_DIR}/${ko_name}"
        if [[ -f "$src" ]]; then
            cp -p "$src" "$dst"
            (( REPLACED++ )) || true
        else
            warn "  Not found in dlkm output: $ko_name — keeping original"
            (( NOT_FOUND++ )) || true
        fi
    done

    success "Replaced $REPLACED vendor_ramdisk modules ($NOT_FOUND not found in dlkm output)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Step 8: Copy Image and vendor_dlkm.img into AK3
# ══════════════════════════════════════════════════════════════════════════════
step "Step 8: Copying Image and vendor_dlkm.img into AK3"

# Copy kernel Image
info "Copying Image → $AK3_DIR/Image"
cp -p "$KERNEL_IMAGE" "${AK3_DIR}/Image"
success "Image copied"

# Copy vendor_dlkm.img
info "Copying vendor_dlkm.img → $AK3_DIR/vendor_dlkm.img"
cp -p "$OUT_IMG" "${AK3_DIR}/vendor_dlkm.img"
success "vendor_dlkm.img copied"

# ══════════════════════════════════════════════════════════════════════════════
# Step 9: Create AnyKernel3 Zip
# ══════════════════════════════════════════════════════════════════════════════
step "Step 9: Zipping AnyKernel3"

cd "$AK3_DIR"

[[ -f "$OUT_ZIP" ]] && rm -f "$OUT_ZIP"

info "Creating levion_kernel.zip..."
zip -r9 "$OUT_ZIP" . -x ".git/*" ".github/*"

ZIP_SIZE=$(du -sh "$OUT_ZIP" | cut -f1)
success "Created $OUT_ZIP ($ZIP_SIZE)"

# ══════════════════════════════════════════════════════════════════════════════
# Step 10: Release Summary
# ══════════════════════════════════════════════════════════════════════════════
step "Step 10: Build Complete — Release Summary"

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║          Levion Kernel Build Summary                 ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Kernel Image:${NC}        $KERNEL_IMAGE"
echo -e "  ${BOLD}vendor_dlkm.img:${NC}     $OUT_IMG ($IMG_SIZE)"
echo -e "  ${BOLD}vendor_dlkm.tar.xz:${NC} $OUT_TAR ($TAR_SIZE)"
echo -e "  ${BOLD}AK3 Zip:${NC}             $OUT_ZIP ($ZIP_SIZE)"
echo -e "  ${BOLD}Modules in image:${NC}    $NEW_KO_COUNT .ko files"
echo -e "  ${BOLD}Loaded modules:${NC}      $LOAD_COUNT entries in modules.load"
echo -e "  ${BOLD}DLKM run dir:${NC}        $RUN_DIR"
echo ""
echo -e "${GREEN}Flash ${BOLD}levion_kernel.zip${NC}${GREEN} via TWRP / KernelFlasher.${NC}"
echo ""
