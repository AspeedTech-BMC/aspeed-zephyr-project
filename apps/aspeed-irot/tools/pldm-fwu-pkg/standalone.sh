#!/bin/bash

MANIFEST=metadata-irot.json
FW_IMAGES=(
	standalone/image-bmc
)
PKG_IMAGE=standalone.pkg

# Unwind the FW_IMAGES into argument
./img.py ${PKG_IMAGE} ${MANIFEST} ${FW_IMAGES[@]}

sha256sum ${FW_IMAGES[@]}
sha384sum ${FW_IMAGES[@]}
