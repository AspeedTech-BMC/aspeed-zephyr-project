# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

zephyr_include_directories(include)
zephyr_include_directories(composite_eat)

target_sources(app
	PRIVATE
	main.c
	psp/loader.c
	psp/loader_shell.c
	state_machine/irot_fsm.c
	state_machine/irot_shell.c
	image/caliptra_soc_manifest.c
	image/caliptra_soc_manifest_v1.c

	cptra/cptra_sample.c
	cptra/cptra_idevid.c
	cptra/cptra_vendor_key.c

	cptra/cptra_mbedtls.c
	cptra/cptra_api.c
	cptra/cptra_ca_certs.c

	mctp/mctp.c
	mctp/mctp_init.c
	mctp/mctp_ctrl.c
	mctp/mctp_ipc.c
	mctp/hal_ipm.c
)

if (CONFIG_COMPOSITE_EAT)
	zephyr_link_libraries(bmc_composite_eat_sdk)
	target_sources(app
		PRIVATE
		mctp/mctp_vdm_pci.c
		composite_eat/attestation_provider_irot.c
		composite_eat/evidence_provider_irot.c
		composite_eat/software_platform.c
	)
endif()

if (CONFIG_SPDM_RESPONDER)
	zephyr_link_libraries(dmtf_libspdm)
	target_sources(app
		PRIVATE
		spdm/spdm_rsp.c
		spdm/lib_caliptra.c
		spdm/watchdog.c
		spdm/ec.c
	)
endif()

if (CONFIG_PLDM)
	target_sources(app
		PRIVATE
		pldm/pldm.c
	)
	if (CONFIG_PLDM_BASE)
		target_sources(app
			PRIVATE
			pldm/pldm_base.c
		)
	endif()
	if (CONFIG_PLDM_FW_UPDATE)
		target_sources(app
			PRIVATE
			pldm/pldm_firmware_update.c
			pldm/pldm_firmware_update_platform.c
			pldm/pldm_fw_update_mbedtls_sha384.c
			pldm/pldm_fw_update_sd_ast2700_image.c
		)
	endif()
	if (CONFIG_PLDM_OEM)
		target_sources(app
			PRIVATE
			pldm/pldm_oem.c
		)
	endif()
endif()
