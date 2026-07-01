#!/bin/bash
# Build mcuboot + irot for ast2700_evb_ast2700_ssp_cl chainload flow
# Output: out/ast2700_evb_ast2700_ssp_cl/ssp-mcuboot.bin + irot-signed.bin

set -e

BOARD=ast2700_evb_ast2700_ssp_cl/ast2700/ssp
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IROT_DIR=$(cd "${SCRIPT_DIR}/../../.." && pwd)
WORKSPACE_DIR=$(cd "${IROT_DIR}/.." && pwd)
MCUBOOT_DIR=${WORKSPACE_DIR}/bootloader/mcuboot
OUT_DIR=${IROT_DIR}/out/ast2700_evb_ast2700_ssp_cl

echo "=== [1/3] Build mcuboot ==="
cd ${MCUBOOT_DIR}
west build -p always -b ${BOARD} boot/zephyr \
    -- -DCONFIG_BOOT_SIGNATURE_KEY_FILE=\"root-ec-p256.pem\"

echo "=== [2/3] Build irot ==="
cd ${IROT_DIR}
west build -p always -b ${BOARD} apps/aspeed-irot

echo "=== [3/3] Sign irot + collect output ==="
imgtool sign \
    --key ${MCUBOOT_DIR}/root-ec-p256.pem \
    --header-size 0x800 \
    --align 8 \
    --version 1.0.0 \
    --slot-size 0x200000 \
    --load-addr 0x80000 \
    ${IROT_DIR}/build/zephyr/zephyr.bin \
    ${IROT_DIR}/irot-signed.bin

mkdir -p ${OUT_DIR}
cp ${MCUBOOT_DIR}/build/zephyr/zephyr.bin ${OUT_DIR}/ssp-mcuboot.bin
cp ${IROT_DIR}/irot-signed.bin            ${OUT_DIR}/irot-signed.bin

echo "=== Done ==="
ls -lh ${OUT_DIR}/
