# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

target_include_directories(app PRIVATE
	${CMAKE_CURRENT_LIST_DIR}
	${CMAKE_CURRENT_LIST_DIR}/../mctp
)

target_sources(app PRIVATE
	pldm_transport.c
	pldm_base.c
	pldm_flsh.c
	pldm_platform.c
	pldm.c
	pldm_firmware_update.c
)
