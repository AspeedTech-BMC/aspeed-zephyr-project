#!/bin/bash
# Usage: create_bios_pfr_image.sh BIOS_ACTIVE_IMAGE
# Needs pfr_image.py, intel-pfr-signing-utility (hybrid build) and the
# hybrid_*.pem keys in the current directory.
set -e

PLATFORM_NAME="plta"
BIOS_ACTIVE_IMAGE="$1"
if ! test -f "${BIOS_ACTIVE_IMAGE}"; then
    echo "Invalid BIOS active image: $1"
    exit 1
fi

PFM_CONFIG_XML="${PLATFORM_NAME}_bios_pfm_config_p384_mldsa87.xml"
BIOS_CONFIG_XML="${PLATFORM_NAME}_bios_config_p384_mldsa87.xml"
PFM_JSON_FILE="${PLATFORM_NAME}_bios_pfm.json"
PFM_SIGNED_BIN="${PLATFORM_NAME}-pfm.bin.signed"
BIOS_UPDATE_CAPSULE="${PLATFORM_NAME}-bios_cap.bin"
BIOS_SIGNED_UPDATE_CAPSULE="${BIOS_UPDATE_CAPSULE}.signed"
BIOS_IMAGE_TEMP="image-bios-temp"
BIOS_PFR_IMAGE="image-bios-pfr"

# Size unit KB
PFR_IMAGE_SIZE="131072"
PFR_PFM_OFFSET="65408"
PFR_RECOVERY_OFFSET="98304"

rm -f ${BIOS_IMAGE_TEMP} ${BIOS_PFR_IMAGE} ${PLATFORM_NAME}-*.bin*

dd if=/dev/zero bs=1k count=${PFR_IMAGE_SIZE} | tr '\000' '\377' > ${BIOS_IMAGE_TEMP}
dd bs=1k conv=notrunc seek=0 if=${BIOS_ACTIVE_IMAGE} of=${BIOS_IMAGE_TEMP}

python3 pfr_image.py -m ${PFM_JSON_FILE} -p ${PLATFORM_NAME} -i ${BIOS_IMAGE_TEMP} \
    -j 1 -n 0 -b 1 -v 1 -s 1 -a 2 -o ${BIOS_PFR_IMAGE}

./intel-pfr-signing-utility -c ${PFM_CONFIG_XML} -o ${PFM_SIGNED_BIN} ${PLATFORM_NAME}-pfm.bin
cat ${PFM_SIGNED_BIN} ${PLATFORM_NAME}-pbc.bin ${PLATFORM_NAME}-bmc_compressed.bin > ${BIOS_UPDATE_CAPSULE}
./intel-pfr-signing-utility -c ${BIOS_CONFIG_XML} -o ${BIOS_SIGNED_UPDATE_CAPSULE} ${BIOS_UPDATE_CAPSULE}

for f in "${PFM_SIGNED_BIN} ${PFM_CONFIG_XML}" "${BIOS_SIGNED_UPDATE_CAPSULE} ${BIOS_CONFIG_XML}"; do
    set -- $f
    if ./intel-pfr-signing-utility -p $1 -c $2 2>&1 | grep -q ERR; then
        echo "Verify $1 failed"
        exit 1
    fi
done

dd bs=1k conv=notrunc seek=${PFR_PFM_OFFSET} if=${PFM_SIGNED_BIN} of=${BIOS_PFR_IMAGE}
dd bs=1k conv=notrunc seek=${PFR_RECOVERY_OFFSET} if=${BIOS_SIGNED_UPDATE_CAPSULE} of=${BIOS_PFR_IMAGE}

echo "Created ${BIOS_PFR_IMAGE} and ${BIOS_SIGNED_UPDATE_CAPSULE}"
