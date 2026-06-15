#!/usr/bin/env bash
# build_levion.sh — Build Levion kernel for OnePlus 9 (lemonade / SM8350)
#
# Usage:
#   ./build_levion.sh                # full build: kernel + vendor_dlkm.img + kernel.zip
#   ./build_levion.sh --vendor_dlkm  # only regenerate vendor_dlkm.img (uses existing out/modules)
#   ./build_levion.sh --image        # only build the kernel Image (no vendor_dlkm, no zip)
#
# Expected directory layout (script lives inside the kernel source tree):
#   <parent>/
#   ├── Levion_kernel_OP9/     ← kernel source — script lives here
#   │   └── build_levion.sh
#   ├── vendor_dlkm.img        ← stock EROFS image (used as base)
#   └── levion_kernel/         ← AnyKernel3 dir

set -euo pipefail

# ──────────────────────────────────────────────────────────────
# Paths — derived from script location, nothing hardcoded
# ──────────────────────────────────────────────────────────────

KDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # kernel source root
PARENT="$(dirname "${KDIR}")"                           # one level up
STOCK_IMG="${PARENT}/vendor_dlkm.img"                   # stock image sits in parent
AK3_DIR="${PARENT}/levion_kernel"                       # AnyKernel3 dir in parent
BUILD_MODULES_DIR="${KDIR}/out/modules"

# ──────────────────────────────────────────────────────────────
# Parse args
# Default (no args): full build — kernel + vendor_dlkm.img + zip
# --vendor_dlkm   : only regenerate vendor_dlkm.img
# --image         : only build the kernel Image
# ──────────────────────────────────────────────────────────────

MODE="all"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --vendor_dlkm) MODE="vendor_dlkm"; shift ;;
        --image)       MODE="image";       shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

green()  { echo -e "\e[1;32m$*\e[0m"; }
yellow() { echo -e "\e[1;93m$*\e[0m"; }
red()    { echo -e "\e[1;31m$*\e[0m"; }

# ──────────────────────────────────────────────────────────────
# Common make flags
# ──────────────────────────────────────────────────────────────

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

# ══════════════════════════════════════════════════════════════
# KERNEL BUILD  (skipped for --vendor_dlkm)
# ══════════════════════════════════════════════════════════════

if [[ "${MODE}" == "all" || "${MODE}" == "image" ]]; then

    cd "${KDIR}"

    # Step 1 — Submodules
    yellow "[*] Updating submodules..."
    git submodule update --init --recursive
    green "[✓] Submodules ready"

    # Step 2 — Clean
    yellow "[*] Cleaning build tree..."
    make "${MAKE_FLAGS[@]}" clean    || yellow "    [~] clean exited non-zero (ignored)"
    make "${MAKE_FLAGS[@]}" mrproper || yellow "    [~] mrproper exited non-zero (ignored)"
    git status
    green "[✓] Clean done"

    # Step 3 — Defconfig
    yellow "[*] Loading defconfig..."
    make "${MAKE_FLAGS[@]}" vendor/lahaina-qgki_defconfig
    green "[✓] Defconfig loaded"

    # Step 4 — Build kernel + modules
    yellow "[*] Building kernel ($(nproc) threads)..."
    make -j"$(nproc)" "${MAKE_FLAGS[@]}"
    green "[✓] Kernel built"

    # Step 5 — Install modules
    yellow "[*] Installing modules..."
    cd "${KDIR}/out"
    make modules_install INSTALL_MOD_PATH="${PWD}/modules"
    cd "${KDIR}"
    green "[✓] Modules installed → ${BUILD_MODULES_DIR}"

fi

# ══════════════════════════════════════════════════════════════
# VENDOR_DLKM.IMG  (skipped for --image)
# ══════════════════════════════════════════════════════════════

if [[ "${MODE}" == "all" || "${MODE}" == "vendor_dlkm" ]]; then

    yellow "[*] Generating vendor_dlkm.img..."

    if [ ! -f "${STOCK_IMG}" ]; then
        red "[✗] Stock image not found: ${STOCK_IMG}"
        exit 1
    fi

    BUILD_KO_COUNT=$(find "${BUILD_MODULES_DIR}" -type f -name "*.ko" 2>/dev/null | wc -l)
    if [ "${BUILD_KO_COUNT}" -eq 0 ]; then
        yellow "[!] No modules found in ${BUILD_MODULES_DIR} — building them now..."

        cd "${KDIR}"
        git submodule update --init --recursive

        make "${MAKE_FLAGS[@]}" clean    || yellow "    [~] clean exited non-zero (ignored)"
        make "${MAKE_FLAGS[@]}" mrproper || yellow "    [~] mrproper exited non-zero (ignored)"

        make "${MAKE_FLAGS[@]}" vendor/lahaina-qgki_defconfig
        make -j"$(nproc)" "${MAKE_FLAGS[@]}"

        cd "${KDIR}/out"
        make modules_install INSTALL_MOD_PATH="${PWD}/modules"
        cd "${KDIR}"

        BUILD_KO_COUNT=$(find "${BUILD_MODULES_DIR}" -type f -name "*.ko" | wc -l)
        if [ "${BUILD_KO_COUNT}" -eq 0 ]; then
            red "[✗] Build completed but still no .ko files found — aborting"
            exit 1
        fi
        green "[✓] Modules built → ${BUILD_MODULES_DIR} (${BUILD_KO_COUNT} modules)"
    else
        yellow "[*] Found ${BUILD_KO_COUNT} existing modules in ${BUILD_MODULES_DIR}, skipping build"
    fi

    # Scratch dir — auto-deleted on exit
    SCRATCH=$(mktemp -d "${KDIR}/.vendor_dlkm_scratch_XXXXXX")
    trap 'rm -rf "${SCRATCH}"' EXIT

    EXTRACT_DIR="${SCRATCH}/extracted"
    mkdir -p "${EXTRACT_DIR}"

    yellow "    Extracting stock image..."
    fsck.erofs --extract="${EXTRACT_DIR}" --overwrite "${STOCK_IMG}" 2>&1

    MODULES_DIR="${EXTRACT_DIR}/lib/modules"

    # Derive exclude / blocklist from stock
    declare -A STOCK_LOAD_SET BLOCKLIST_SET EXCLUDE_SET

    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        STOCK_LOAD_SET["${entry}"]=1
    done < "${MODULES_DIR}/modules.load"

    if [ -f "${MODULES_DIR}/modules.blocklist" ]; then
        while read -r _ mod; do
            [[ -n "${mod}" ]] && BLOCKLIST_SET["${mod}"]=1
        done < <(grep '^blocklist ' "${MODULES_DIR}/modules.blocklist" || true)
    fi

    for ko in "${MODULES_DIR}"/*.ko; do
        mod_name=$(basename "${ko}" .ko)
        if [[ -z "${STOCK_LOAD_SET[${mod_name}]+x}" && -z "${BLOCKLIST_SET[${mod_name}]+x}" ]]; then
            EXCLUDE_SET["${mod_name}"]=1
        fi
    done

    # Replace .ko files
    rm -f "${MODULES_DIR}"/*.ko
    find "${BUILD_MODULES_DIR}" -type f -name "*.ko" -exec cp -p {} "${MODULES_DIR}/" \;

    if [ -f "${MODULES_DIR}/wlan.ko" ]; then
        mv "${MODULES_DIR}/wlan.ko" "${MODULES_DIR}/qca_cld3_wlan.ko"
        yellow "    Renamed wlan.ko → qca_cld3_wlan.ko"
    fi

    NEW_KO_COUNT=$(find "${MODULES_DIR}" -name "*.ko" | wc -l)
    yellow "    ${NEW_KO_COUNT} modules placed"

    # Strip debug symbols
    if command -v llvm-objcopy &>/dev/null; then
        yellow "    Stripping debug symbols..."
        for ko in "${MODULES_DIR}"/*.ko; do
            llvm-objcopy --strip-debug "${ko}"
        done
    fi

    # depmod
    DEPMOD_STAGING="${SCRATCH}/depmod_staging"
    DEPMOD_VER="0.0"
    DEPMOD_MOD_DIR="${DEPMOD_STAGING}/lib/modules/${DEPMOD_VER}"
    mkdir -p "${DEPMOD_MOD_DIR}"

    cp -p "${MODULES_DIR}"/*.ko "${DEPMOD_MOD_DIR}"/
    touch "${DEPMOD_MOD_DIR}/modules.order" \
          "${DEPMOD_MOD_DIR}/modules.builtin" \
          "${DEPMOD_MOD_DIR}/modules.builtin.modinfo"

    depmod -a -b "${DEPMOD_STAGING}" "${DEPMOD_VER}"

    for f in modules.alias modules.dep modules.softdep; do
        [ -f "${DEPMOD_MOD_DIR}/${f}" ] && cp -p "${DEPMOD_MOD_DIR}/${f}" "${MODULES_DIR}/"
    done

    # Fix paths in modules.dep
    sed -i 's|[^ :]*lib/modules/[^/]*/||g' "${MODULES_DIR}/modules.dep"
    sed -i 's|\([a-zA-Z0-9_.-]*\.ko\)|/vendor_dlkm/lib/modules/\1|g' "${MODULES_DIR}/modules.dep"

    # modules.load
    : > "${MODULES_DIR}/modules.load"
    for ko in "${MODULES_DIR}"/*.ko; do
        mod_name=$(basename "${ko}" .ko)
        if [[ -z "${EXCLUDE_SET[${mod_name}]+x}" && -z "${BLOCKLIST_SET[${mod_name}]+x}" ]]; then
            echo "${mod_name}" >> "${MODULES_DIR}/modules.load"
        fi
    done

    # Build EROFS image
    OUT_IMG="${SCRATCH}/vendor_dlkm_new.img"

    mkfs.erofs \
        --mount-point=/vendor_dlkm \
        --all-root \
        -zlz4 \
        -b4096 \
        -T1230768000 \
        "${OUT_IMG}" \
        "${EXTRACT_DIR}"

    ORIG_SIZE=$(stat --format="%s" "${STOCK_IMG}")
    NEW_SIZE=$(stat  --format="%s" "${OUT_IMG}")

    if [ "${NEW_SIZE}" -le "${ORIG_SIZE}" ]; then
        truncate -s "${ORIG_SIZE}" "${OUT_IMG}"
    else
        red "[!] WARNING: new image (${NEW_SIZE}B) > original partition (${ORIG_SIZE}B)!"
    fi

    fsck.erofs "${OUT_IMG}" 2>&1 && green "    EROFS fsck passed" || { red "[✗] EROFS fsck failed!"; exit 1; }

    mv "${OUT_IMG}" "${STOCK_IMG}"
    green "[✓] vendor_dlkm.img written → ${STOCK_IMG}"

fi

# ══════════════════════════════════════════════════════════════
# KERNEL.ZIP  (only on full build)
# ══════════════════════════════════════════════════════════════

if [[ "${MODE}" == "all" ]]; then

    yellow "[*] Packaging kernel.zip..."

    if [ ! -d "${AK3_DIR}" ]; then
        red "[✗] AnyKernel3 directory not found: ${AK3_DIR}"
        exit 1
    fi

    BUILT_IMAGE="${KDIR}/out/arch/arm64/boot/Image"
    if [ ! -f "${BUILT_IMAGE}" ]; then
        red "[✗] Kernel Image not found: ${BUILT_IMAGE}"
        exit 1
    fi

    # Replace Image
    cp -p "${BUILT_IMAGE}" "${AK3_DIR}/Image"
    green "    Replaced Image"

    # Place vendor_dlkm.img
    cp -p "${STOCK_IMG}" "${AK3_DIR}/vendor_dlkm.img"
    green "    Placed vendor_dlkm.img"

    # Replace vendor ramdisk modules
    VR_MODS="${AK3_DIR}/vendor_ramdisk/lib/modules"
    if [ -d "${VR_MODS}" ]; then
        yellow "    Replacing vendor ramdisk modules..."
        rm -f "${VR_MODS}"/*.ko
        RAMDISK_NAMES=(adsp_loader_dlkm apr_dlkm msm_drm q6_notifier_dlkm q6_pdr_dlkm snd_event_dlkm)
        COPIED=0
        for name in "${RAMDISK_NAMES[@]}"; do
            ko=$(find "${BUILD_MODULES_DIR}" -name "${name}.ko" | head -1)
            if [ -n "${ko}" ]; then
                cp -p "${ko}" "${VR_MODS}/"
                llvm-objcopy --strip-debug "${VR_MODS}/$(basename "${ko}")"
                (( COPIED++ )) || true
            fi
        done
        if [ "${COPIED}" -eq 0 ]; then
            yellow "    [!] No named ramdisk modules found — copying and stripping all built modules"
            find "${BUILD_MODULES_DIR}" -name "*.ko" | while read -r ko; do
                cp -p "${ko}" "${VR_MODS}/"
                llvm-objcopy --strip-debug "${VR_MODS}/$(basename "${ko}")"
            done
        else
            green "    Replaced and stripped ${COPIED} vendor ramdisk modules"
        fi
    else
        yellow "    [!] vendor_ramdisk/lib/modules not found in AK3 dir, skipping"
    fi

    # Zip
    OUT_ZIP="${PARENT}/levion_final.zip"
    cd "${AK3_DIR}"
    zip -r9 "${OUT_ZIP}" . -x ".git/*" -x ".github/*"
    cd "${KDIR}"

    ZIP_SIZE=$(du -sh "${OUT_ZIP}" | cut -f1)
    green "[✓] kernel.zip → ${OUT_ZIP} (${ZIP_SIZE})"

fi

# ──────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────

echo ""
green "[✓] All done!"
[[ "${MODE}" == "all" || "${MODE}" == "image" ]]        && echo "    Kernel Image:     ${KDIR}/out/arch/arm64/boot/Image"
[[ "${MODE}" == "all" || "${MODE}" == "vendor_dlkm" ]]  && echo "    vendor_dlkm.img:  ${STOCK_IMG}"
[[ "${MODE}" == "all" ]]                                 && echo "    Flashable zip:    ${OUT_ZIP}"