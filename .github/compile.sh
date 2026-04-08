#!/usr/bin/env bash
# compile.sh — Full Levion Kernel build pipeline for OnePlus 9 (lemonade / SM8350)
# Steps: deps → clang → compile → vendor_dlkm → AK3 zip → summary
#
# Usage: bash compile.sh
# Intended for GitHub Actions (runs with +x chmod)

set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Global Configuration
# ══════════════════════════════════════════════════════════════════════════════

WORK_DIR="${HOME}"
TOOLCHAIN_DIR="${WORK_DIR}/linux-x86"
CLANG_VERSION="clang-r547379"
CLANG_PATH="${TOOLCHAIN_DIR}/${CLANG_VERSION}/bin"

KDIR="${GITHUB_WORKSPACE}"
AK3_DIR="${WORK_DIR}/AnyKernel3"

STOCK_IMG="${AK3_DIR}/vendor_dlkm.img"
BUILD_MODULES_DIR="${KDIR}/out/modules"
OUT_DIR="${WORK_DIR}/out"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RUN_DIR="${OUT_DIR}/vendor_dlkm_files_${TIMESTAMP}"

OUT_ZIP="${OUT_DIR}/levion_kernel.zip"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERR]${NC}   $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}══ $* ══${NC}"; }
pass()    { echo -e "${GREEN}[PASS]${NC}  $*"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

# ══════════════════════════════════════════════════════════════════════════════
# Pre-flight Checks
# ══════════════════════════════════════════════════════════════════════════════
step "Pre-flight: Validating required paths"

info "Checking KDIR (kernel source): ${KDIR}"
if [[ -z "${KDIR:-}" ]]; then
    fail "KDIR is not set — GITHUB_WORKSPACE is empty. Ensure the kernel is checked out before running this script."
fi
if [[ ! -d "${KDIR}" ]]; then
    fail "Kernel source directory not found: ${KDIR}"
fi
pass "Kernel source directory present: ${KDIR}"

info "Checking AnyKernel3 directory: ${AK3_DIR}"
if [[ ! -d "${AK3_DIR}" ]]; then
    fail "AnyKernel3 directory not found: ${AK3_DIR}  — ensure AnyKernel3 is checked out in build.yml before calling this script."
fi
pass "AnyKernel3 directory present: ${AK3_DIR}"

info "Checking stock vendor_dlkm.img: ${STOCK_IMG}"
if [[ ! -f "${STOCK_IMG}" ]]; then
    fail "Stock vendor_dlkm.img not found: ${STOCK_IMG}  — place vendor_dlkm.img inside the AnyKernel3 repo before running."
fi
pass "Stock vendor_dlkm.img present: ${STOCK_IMG}"

success "All pre-flight checks passed."

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

info "Detected distro: ${DISTRO}"

case "${DISTRO}" in
    ubuntu|debian|linuxmint)
        info "Running apt install..."
        sudo apt-get update -qq || fail "apt-get update failed"
        sudo apt-get install -y bc bison build-essential cpio curl flex git kmod libelf-dev libncurses-dev libssl-dev lld llvm make pahole python3 rsync tar wget zip zlib1g-dev erofs-utils \
            || fail "apt-get install failed"
        ;;
    fedora|rhel|centos)
        info "Running dnf install..."
        sudo dnf install -y bc bison elfutils-libelf-devel flex gcc git lld llvm make ncurses-devel openssl-devel pahole python3 rsync wget zip zlib-devel erofs-utils \
            || fail "dnf install failed"
        ;;
    arch|manjaro)
        info "Running pacman install..."
        sudo pacman -Sy --noconfirm base-devel bc bison flex git libelf lld llvm make ncurses openssl pahole python rsync wget zip zlib erofs-utils \
            || fail "pacman install failed"
        ;;
    *)
        warn "Unsupported distro '${DISTRO}' — skipping auto-install."
        warn "Please manually install: bc bison flex make libelf libssl llvm lld pahole python3 erofs-utils gcc-aarch64-linux-gnu gcc-arm-linux-gnueabi"
        ;;
esac

success "Step 1 complete: Dependencies installed."

# ══════════════════════════════════════════════════════════════════════════════
# Step 2: Pull Clang Toolchain (clang-r547379 from AOSP prebuilts)
# ══════════════════════════════════════════════════════════════════════════════
step "Step 2: Pulling Clang Toolchain (${CLANG_VERSION})"

CLANG_REPO_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86"

info "Destination : ${TOOLCHAIN_DIR}"
info "Source      : ${CLANG_REPO_URL}"

mkdir -p "${TOOLCHAIN_DIR}" \
    || fail "Failed to create toolchain directory: ${TOOLCHAIN_DIR}"

if [[ -d "${TOOLCHAIN_DIR}/.git" ]]; then
    info "Repo already exists — fetching latest..."
    cd "${TOOLCHAIN_DIR}"
    git fetch --depth=1 origin \
        || fail "git fetch failed in ${TOOLCHAIN_DIR}"
else
    info "Initialising partial clone (no blobs yet)..."
    git clone \
        --filter=blob:none \
        --no-checkout \
        --depth=1 \
        --single-branch \
        "${CLANG_REPO_URL}" \
        "${TOOLCHAIN_DIR}" \
        || fail "git clone failed for ${CLANG_REPO_URL}"
    cd "${TOOLCHAIN_DIR}"
fi

info "Configuring sparse-checkout for ${CLANG_VERSION}/ only..."
git sparse-checkout init --cone \
    || fail "git sparse-checkout init failed"
git sparse-checkout set "${CLANG_VERSION}" \
    || fail "git sparse-checkout set failed for ${CLANG_VERSION}"

info "Downloading toolchain blobs..."
git checkout \
    || fail "git checkout failed while downloading toolchain blobs"

[[ -d "${TOOLCHAIN_DIR}/${CLANG_VERSION}" ]] \
    || fail "Toolchain directory missing after checkout: ${TOOLCHAIN_DIR}/${CLANG_VERSION}"

export PATH="${CLANG_PATH}:${PATH}"

if ! command -v clang &>/dev/null; then
    fail "clang not found in PATH after toolchain setup. Expected at: ${CLANG_PATH}"
fi

pass "Clang version: $(clang --version | head -1)"
success "Step 2 complete: Toolchain pulled → ${TOOLCHAIN_DIR}/${CLANG_VERSION}"

# ══════════════════════════════════════════════════════════════════════════════
# Step 3: Compile the Kernel
# ══════════════════════════════════════════════════════════════════════════════
step "Step 3: Compiling Kernel"

info "Entering kernel source: ${KDIR}"
cd "${KDIR}"

info "Updating git submodules..."
git submodule update --init --recursive \
    || fail "git submodule update failed"
success "Submodules initialised"

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

# Helper: run a command but don't abort on non-zero (for clean/mrproper)
safe_run() {
    "$@" || warn "Command returned non-zero (continuing): $*"
}

info "Running clean (non-fatal)..."
safe_run make "${MAKE_FLAGS[@]}" clean
info "Running mrproper (non-fatal)..."
safe_run make "${MAKE_FLAGS[@]}" mrproper

info "Git status:"
git -C "${KDIR}" status

info "Loading defconfig: vendor/lahaina-qgki_defconfig"
make "${MAKE_FLAGS[@]}" vendor/lahaina-qgki_defconfig \
    || fail "defconfig step failed"
pass "defconfig loaded"

info "Building kernel with $(nproc) threads..."
make -j"$(nproc)" "${MAKE_FLAGS[@]}" \
    || fail "Kernel compilation failed"

KERNEL_IMAGE="${KDIR}/out/arch/arm64/boot/Image"
if [[ ! -f "${KERNEL_IMAGE}" ]]; then
    fail "Kernel Image not found at ${KERNEL_IMAGE} — build failed."
fi
pass "Kernel Image present: ${KERNEL_IMAGE}"

BUILD_MODULES_DIR="${KDIR}/out/modules"
info "Installing kernel modules into ${BUILD_MODULES_DIR}..."
make "${MAKE_FLAGS[@]}" INSTALL_MOD_PATH=modules modules_install \
    || fail "modules_install failed"

success "Step 3 complete: Kernel compiled and modules installed."

# ══════════════════════════════════════════════════════════════════════════════
# Step 4: Generate vendor_dlkm.img
# ══════════════════════════════════════════════════════════════════════════════
step "Step 4: Generating vendor_dlkm Image"

mkdir -p "${RUN_DIR}" \
    || fail "Failed to create run directory: ${RUN_DIR}"
info "Run output directory: ${RUN_DIR}"

# ── Extract stock image ───────────────────────────────────────────────────────
EXTRACT_DIR="${RUN_DIR}/extracted"
mkdir -p "${EXTRACT_DIR}" \
    || fail "Failed to create extract directory: ${EXTRACT_DIR}"

info "Extracting stock vendor_dlkm.img → ${EXTRACT_DIR}..."
fsck.erofs --extract="${EXTRACT_DIR}" --overwrite "${STOCK_IMG}" 2>&1 \
    || fail "fsck.erofs extraction failed for ${STOCK_IMG}"
pass "Stock image extracted"

MODULES_DIR="${EXTRACT_DIR}/lib/modules"
if [[ ! -d "${MODULES_DIR}" ]]; then
    fail "modules directory not found in extracted image: ${MODULES_DIR}"
fi

STOCK_KO_COUNT=$(find "${MODULES_DIR}" -name "*.ko" | wc -l)
info "Stock module count: ${STOCK_KO_COUNT}"

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

BUILD_KO_COUNT=$(find "${BUILD_MODULES_DIR}" -type f -name "*.ko" | wc -l)
if [[ "${BUILD_KO_COUNT}" -eq 0 ]]; then
    fail "No .ko files found in ${BUILD_MODULES_DIR}"
fi
pass "Found ${BUILD_KO_COUNT} built modules in ${BUILD_MODULES_DIR}"

# ── Replace stock modules with built ones ────────────────────────────────────
info "Removing stock .ko files from ${MODULES_DIR}..."
rm -f "${MODULES_DIR}"/*.ko

info "Copying built modules into ${MODULES_DIR}..."
find "${BUILD_MODULES_DIR}" -type f -name "*.ko" | while read -r ko; do
    cp -p "$ko" "${MODULES_DIR}/"
done

NEW_KO_COUNT=$(find "${MODULES_DIR}" -name "*.ko" | wc -l)
if [[ "${NEW_KO_COUNT}" -eq 0 ]]; then
    fail "No modules were copied into ${MODULES_DIR}"
fi
pass "Replaced with ${NEW_KO_COUNT} built modules"

# ── Rename wlan.ko → qca_cld3_wlan.ko ────────────────────────────────────────
if [[ -f "${MODULES_DIR}/wlan.ko" ]]; then
    mv "${MODULES_DIR}/wlan.ko" "${MODULES_DIR}/qca_cld3_wlan.ko" \
        || fail "Failed to rename wlan.ko → qca_cld3_wlan.ko"
    pass "Renamed wlan.ko → qca_cld3_wlan.ko"
else
    warn "wlan.ko not found — skipping rename"
fi

# ── Strip debug symbols ───────────────────────────────────────────────────────
if command -v llvm-objcopy &>/dev/null; then
    info "Stripping debug symbols from ${MODULES_DIR}/*.ko..."
    for ko in "${MODULES_DIR}"/*.ko; do
        llvm-objcopy --strip-debug "$ko" \
            || warn "Strip failed for $ko — continuing"
    done
    pass "Debug symbols stripped"
else
    warn "llvm-objcopy not in PATH — skipping strip"
fi

# ── Run depmod ────────────────────────────────────────────────────────────────
info "Running depmod..."

DEPMOD_STAGING="${RUN_DIR}/depmod_staging"
DEPMOD_VER="0.0"
DEPMOD_MOD_DIR="${DEPMOD_STAGING}/lib/modules/${DEPMOD_VER}"
mkdir -p "${DEPMOD_MOD_DIR}" \
    || fail "Failed to create depmod staging dir: ${DEPMOD_MOD_DIR}"

cp -p "${MODULES_DIR}"/*.ko "${DEPMOD_MOD_DIR}/" \
    || fail "Failed to copy .ko files to depmod staging"

touch "${DEPMOD_MOD_DIR}/modules.order"
touch "${DEPMOD_MOD_DIR}/modules.builtin"
touch "${DEPMOD_MOD_DIR}/modules.builtin.modinfo"

depmod -a -b "${DEPMOD_STAGING}" "${DEPMOD_VER}" \
    || fail "depmod failed"

for f in modules.alias modules.dep modules.softdep; do
    if [[ -f "${DEPMOD_MOD_DIR}/${f}" ]]; then
        cp -p "${DEPMOD_MOD_DIR}/${f}" "${MODULES_DIR}/" \
            || fail "Failed to copy ${f} to ${MODULES_DIR}"
    else
        warn "depmod did not generate ${f}"
    fi
done

pass "depmod complete"

# ── Fix paths in modules.dep ──────────────────────────────────────────────────
info "Fixing module paths in modules.dep..."
sed -i 's|[^ :]*lib/modules/[^/]*/||g' "${MODULES_DIR}/modules.dep"
sed -i 's|\([a-zA-Z0-9_.-]*\.ko\)|/vendor_dlkm/lib/modules/\1|g' "${MODULES_DIR}/modules.dep"
pass "Module paths fixed in modules.dep"

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
pass "modules.load: ${LOAD_COUNT} entries (${#EXCLUDE_SET[@]} excluded, ${#BLOCKLIST_SET[@]} blocklisted)"
info "modules.blocklist: preserved from stock"

# ── Create vendor_dlkm.tar.xz ─────────────────────────────────────────────────
OUT_TAR="${RUN_DIR}/vendor_dlkm_${TIMESTAMP}.tar.xz"
info "Creating tarball → ${OUT_TAR}..."
tar -cpf - -C "${EXTRACT_DIR}" lib/ | xz -9e -T0 > "${OUT_TAR}" \
    || fail "Failed to create tarball: ${OUT_TAR}"
TAR_SIZE=$(du -sh "${OUT_TAR}" | cut -f1)
pass "Tarball created: ${OUT_TAR} (${TAR_SIZE})"

# ── Build vendor_dlkm.img (EROFS) ─────────────────────────────────────────────
OUT_IMG="${RUN_DIR}/vendor_dlkm_${TIMESTAMP}.img"
info "Building EROFS vendor_dlkm image → ${OUT_IMG}..."

FILE_CONTEXTS="${RUN_DIR}/file_contexts"
cat <<'EOF' > "${FILE_CONTEXTS}"
/ u:object_r:vendor_file:s0
/vendor_dlkm(/.*)? u:object_r:vendor_file:s0
/vendor_dlkm/etc(/.*)? u:object_r:vendor_configs_file:s0
EOF

mkfs.erofs \
    --mount-point=/vendor_dlkm \
    --all-root \
    --file-contexts="${FILE_CONTEXTS}" \
    -zlz4 \
    -b4096 \
    -T1230768000 \
    "${OUT_IMG}" \
    "${EXTRACT_DIR}" \
    || fail "mkfs.erofs failed — could not build vendor_dlkm.img"

if [[ ! -f "${OUT_IMG}" ]]; then
    fail "vendor_dlkm.img was not created at ${OUT_IMG}"
fi

ORIG_SIZE=$(stat --format="%s" "${STOCK_IMG}")
NEW_SIZE=$(stat --format="%s" "${OUT_IMG}")

if [[ "${NEW_SIZE}" -le "${ORIG_SIZE}" ]]; then
    info "Padding image to match partition size (${ORIG_SIZE} bytes)..."
    truncate -s "${ORIG_SIZE}" "${OUT_IMG}" \
        || fail "truncate failed while padding ${OUT_IMG}"
    pass "Image padded to ${ORIG_SIZE} bytes"
else
    warn "New image (${NEW_SIZE}) > original partition (${ORIG_SIZE})!"
    warn "Image may not fit — consider removing unused modules."
fi

IMG_SIZE=$(du -sh "${OUT_IMG}" | cut -f1)
pass "vendor_dlkm.img created: ${OUT_IMG} (${IMG_SIZE})"

info "Verifying EROFS image with fsck.erofs..."
if fsck.erofs "${OUT_IMG}" 2>&1; then
    pass "vendor_dlkm.img passed fsck verification"
else
    warn "vendor_dlkm.img failed fsck — image may still be usable but inspect it"
fi

success "Step 4 complete: vendor_dlkm.img built."

# ══════════════════════════════════════════════════════════════════════════════
# Step 5: Update vendor_ramdisk Modules in AK3
# ══════════════════════════════════════════════════════════════════════════════
step "Step 5: Updating vendor_ramdisk Modules in AK3"

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

if [[ -z "${AK3_RAMDISK_MOD_DIR}" ]]; then
    warn "Could not auto-detect vendor_ramdisk modules directory in AK3."
    warn "Searched: vendor_ramdisk/lib/modules, ramdisk/lib/modules, vendor_ramdisk/modules, modules"
    warn "Skipping vendor_ramdisk module replacement — verify AK3 layout manually."
else
    info "AK3 ramdisk modules dir: ${AK3_RAMDISK_MOD_DIR}"

    declare -A AK3_KO_NAMES
    while IFS= read -r ko_path; do
        ko_file=$(basename "$ko_path")
        AK3_KO_NAMES["$ko_file"]=1
    done < <(find "${AK3_RAMDISK_MOD_DIR}" -name "*.ko")

    info "Found ${#AK3_KO_NAMES[@]} .ko entries in AK3 vendor_ramdisk"

    DLKM_MODULES_SRC="${EXTRACT_DIR}/lib/modules"
    REPLACED=0
    NOT_FOUND=0

    for ko_name in "${!AK3_KO_NAMES[@]}"; do
        src="${DLKM_MODULES_SRC}/${ko_name}"
        dst="${AK3_RAMDISK_MOD_DIR}/${ko_name}"
        if [[ -f "${src}" ]]; then
            cp -p "${src}" "${dst}" \
                || warn "Failed to copy ${ko_name} to AK3 ramdisk"
            (( REPLACED++ )) || true
        else
            warn "  Not found in dlkm output: ${ko_name} — keeping original"
            (( NOT_FOUND++ )) || true
        fi
    done

    pass "Replaced ${REPLACED} vendor_ramdisk modules (${NOT_FOUND} not found in dlkm output)"
fi

success "Step 5 complete: vendor_ramdisk modules updated."

# ══════════════════════════════════════════════════════════════════════════════
# Step 6: Copy Image and vendor_dlkm.img into AK3
# ══════════════════════════════════════════════════════════════════════════════
step "Step 6: Copying Image and vendor_dlkm.img into AK3"

info "Copying Image → ${AK3_DIR}/Image"
cp -p "${KERNEL_IMAGE}" "${AK3_DIR}/Image" \
    || fail "Failed to copy Kernel Image to ${AK3_DIR}/Image"
pass "Kernel Image copied to AK3"

info "Copying vendor_dlkm.img → ${AK3_DIR}/vendor_dlkm.img"
cp -p "${OUT_IMG}" "${AK3_DIR}/vendor_dlkm.img" \
    || fail "Failed to copy vendor_dlkm.img to ${AK3_DIR}/vendor_dlkm.img"
pass "vendor_dlkm.img copied to AK3"

success "Step 6 complete: Artifacts placed in AK3 directory."

# ══════════════════════════════════════════════════════════════════════════════
# Step 7: Create AnyKernel3 Zip
# ══════════════════════════════════════════════════════════════════════════════
step "Step 7: Zipping AnyKernel3"

mkdir -p "${OUT_DIR}" \
    || fail "Failed to create output directory: ${OUT_DIR}"

[[ -f "${OUT_ZIP}" ]] && rm -f "${OUT_ZIP}"

info "Creating levion_kernel.zip from ${AK3_DIR}..."
cd "${AK3_DIR}"
zip -r9 "${OUT_ZIP}" . -x ".git/*" ".github/*" \
    || fail "zip failed while creating ${OUT_ZIP}"

if [[ ! -f "${OUT_ZIP}" ]]; then
    fail "Expected zip not found after packaging: ${OUT_ZIP}"
fi

ZIP_SIZE=$(du -sh "${OUT_ZIP}" | cut -f1)
pass "AnyKernel3 zip created: ${OUT_ZIP} (${ZIP_SIZE})"
success "Step 7 complete: Flash zip ready."

# ══════════════════════════════════════════════════════════════════════════════
# Step 8: Build Complete — Release Summary
# ══════════════════════════════════════════════════════════════════════════════
step "Step 8: Build Complete — Release Summary"

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║          Levion Kernel Build Summary                 ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Kernel Image:${NC}        ${KERNEL_IMAGE}"
echo -e "  ${BOLD}vendor_dlkm.img:${NC}     ${OUT_IMG} (${IMG_SIZE})"
echo -e "  ${BOLD}vendor_dlkm.tar.xz:${NC} ${OUT_TAR} (${TAR_SIZE})"
echo -e "  ${BOLD}AK3 Zip:${NC}             ${OUT_ZIP} (${ZIP_SIZE})"
echo -e "  ${BOLD}Modules in image:${NC}    ${NEW_KO_COUNT} .ko files"
echo -e "  ${BOLD}Loaded modules:${NC}      ${LOAD_COUNT} entries in modules.load"
echo -e "  ${BOLD}DLKM run dir:${NC}        ${RUN_DIR}"
echo ""
echo -e "${GREEN}Flash ${BOLD}levion_kernel.zip${NC}${GREEN} via ADB Sideload / KernelFlasher.${NC}"
echo ""