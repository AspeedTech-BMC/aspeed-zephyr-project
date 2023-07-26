# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

if (CONFIG_CERBERUS)
	set(CERBERUS_ROOT ${ZEPHYR_CURRENT_MODULE_DIR})
	set(CERBERUS_ZEPHYR_DIR ${CMAKE_CURRENT_LIST_DIR})
	set(CERBERUS_CORE_DIR ${CERBERUS_ROOT}/core)
	set(CERBERUS_PLATFORM_DIR ${CERBERUS_ROOT}/projects/zephyr)

	zephyr_interface_library_named(cerberus)
	target_include_directories(cerberus INTERFACE
		${CMAKE_CURRENT_SOURCE_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}/core
		${CMAKE_CURRENT_SOURCE_DIR}/project/zephyr
	)
	zephyr_library()
	zephyr_library_link_libraries(mbedTLS)
	zephyr_library_link_libraries(hrot_hal)
	zephyr_library_include_directories(
		${CERBERUS_ROOT}/core
		${CERBERUS_ROOT}/projects/zephyr
	)

	file(GLOB_RECURSE CERBERUS_CORE_SOURCES "${CERBERUS_ROOT}/core/*.c")
	file(GLOB_RECURSE CERBERUS_PLATFORM_SOURCES "${CERBERUS_PLATFORM_DIR}/*.c")

	zephyr_library_sources(
		${CERBERUS_PLATFORM_SOURCES}

		# attestation
		# ${CERBERUS_CORE_DIR}/attestation/attestation_master.c
		# ${CERBERUS_CORE_DIR}/attestation/attestation_slave.c
		# ${CERBERUS_CORE_DIR}/attestation/aux_attestation.c
		# ${CERBERUS_CORE_DIR}/attestation/pcr.c
		# ${CERBERUS_CORE_DIR}/attestation/pcr_store.c
		# cmd_interface
		# ${CERBERUS_CORE_DIR}/cmd_interface/cerberus_protocol_debug_commands.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cerberus_protocol_diagnostic_commands.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cerberus_protocol_master_commands.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cerberus_protocol_optional_commands.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cerberus_protocol_required_commands.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cmd_authorization.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cmd_channel.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cmd_interface.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cmd_interface_dual_cmd_set.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cmd_interface_slave.c
		${CERBERUS_CORE_DIR}/cmd_interface/cmd_interface_system.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/config_reset.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/counter_manager_registers.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/device_manager.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/session_manager.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/session_manager_ecc.c
		# common
		# ${CERBERUS_CORE_DIR}/common/authorization_allowed.c
		# ${CERBERUS_CORE_DIR}/common/authorization_challenge.c
		# ${CERBERUS_CORE_DIR}/common/authorization_disallowed.c
		${CERBERUS_CORE_DIR}/common/buffer_util.c
		# ${CERBERUS_CORE_DIR}/common/image_header.c
		# ${CERBERUS_CORE_DIR}/common/observable.c
		# crypto
		# ${CERBERUS_CORE_DIR}/crypto/aes_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/base64_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/base64_thread_safe.c
		# ${CERBERUS_CORE_DIR}/crypto/checksum.c
		# ${CERBERUS_CORE_DIR}/crypto/ecc_der_util.c
		# ${CERBERUS_CORE_DIR}/crypto/ecc_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/ecc_thread_safe.c
		${CERBERUS_CORE_DIR}/crypto/hash.c
		# ${CERBERUS_CORE_DIR}/crypto/hash_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/hash_thread_safe.c
		# ${CERBERUS_CORE_DIR}/crypto/kdf.c
		# ${CERBERUS_CORE_DIR}/crypto/rng_dummy.c
		# ${CERBERUS_CORE_DIR}/crypto/rng_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/rng_thread_safe.c
		# ${CERBERUS_CORE_DIR}/crypto/rsa.c
		# ${CERBERUS_CORE_DIR}/crypto/rsa_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/rsa_thread_safe.c
		# ${CERBERUS_CORE_DIR}/crypto/signature_verification_ecc.c
		# ${CERBERUS_CORE_DIR}/crypto/signature_verification_rsa.c
		# ${CERBERUS_CORE_DIR}/crypto/x509_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/x509_thread_safe.c
		# firmware
		# ${CERBERUS_CORE_DIR}/firmware/app_image.c
		# ${CERBERUS_CORE_DIR}/firmware/firmware_component.c
		# ${CERBERUS_CORE_DIR}/firmware/firmware_header.c
		# ${CERBERUS_CORE_DIR}/firmware/firmware_update.c
		# flash
		${CERBERUS_CORE_DIR}/flash/flash_common.c
		# ${CERBERUS_CORE_DIR}/flash/flash_store.c
		# ${CERBERUS_CORE_DIR}/flash/flash_store_encrypted.c
		# ${CERBERUS_CORE_DIR}/flash/flash_updater.c
		${CERBERUS_CORE_DIR}/flash/flash_util.c
		${CERBERUS_CORE_DIR}/flash/spi_flash.c
		# ${CERBERUS_CORE_DIR}/flash/spi_flash_sfdp.c
		# host_fw
		# ${CERBERUS_CORE_DIR}/host_fw/bmc_recovery.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_flash_initialization.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_flash_manager.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_flash_manager_dual.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_flash_manager_single.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_fw_util.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_irq_handler_auth_check.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_irq_handler.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_irq_handler_mask_irqs.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_dual.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_dual_full_bypass.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_filtered.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_observer_pcr.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_single.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_single_full_bypass.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_state_manager.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_state_observer_dirty_reset.c
		# i2c
		# intrusion
		# ${CERBERUS_CORE_DIR}/intrusion/intrusion_manager_async.c
		# ${CERBERUS_CORE_DIR}/intrusion/intrusion_manager.c
		# keystore
		# ${CERBERUS_CORE_DIR}/keystore/keystore_flash.c
		# logging
		${CERBERUS_CORE_DIR}/logging/debug_log.c
		# ${CERBERUS_CORE_DIR}/logging/logging_flash.c
		${CERBERUS_CORE_DIR}/logging/logging_memory.c
		# manifest
		${CERBERUS_CORE_DIR}/manifest/manifest_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/manifest_manager.c
		# ${CERBERUS_CORE_DIR}/manifest/manifest_manager_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/manifest_pcr.c
		# ${CERBERUS_CORE_DIR}/manifest/manifest_verification.c
		# ${CERBERUS_CORE_DIR}/manifest/cfm/cfm_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/cfm/cfm_manager.c
		# ${CERBERUS_CORE_DIR}/manifest/cfm/cfm_manager_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/cfm/cfm_observer_pcr.c
		# ${CERBERUS_CORE_DIR}/manifest/pcd/pcd_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/pcd/pcd_manager.c
		# ${CERBERUS_CORE_DIR}/manifest/pcd/pcd_manager_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/pcd/pcd_observer_pcr.c
		${CERBERUS_CORE_DIR}/manifest/pfm/pfm_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/pfm/pfm_manager.c
		# ${CERBERUS_CORE_DIR}/manifest/pfm/pfm_manager_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/pfm/pfm_observer_pcr.c
		# ${CERBERUS_CORE_DIR}/manifest/pfm/pfm_observer_pending_reset.c
		# mctp
		# ${CERBERUS_CORE_DIR}/mctp/cmd_interface_mctp_control.c
		# ${CERBERUS_CORE_DIR}/mctp/mctp_base_protocol.c
		# ${CERBERUS_CORE_DIR}/mctp/mctp_control_protocol_commands.c
		# ${CERBERUS_CORE_DIR}/mctp/mctp_interface.c
		# recovery
		# ${CERBERUS_CORE_DIR}/recovery/ocp_recovery_device.c
		# ${CERBERUS_CORE_DIR}/recovery/ocp_recovery_device_variable_cms_log.c
		# ${CERBERUS_CORE_DIR}/recovery/ocp_recovery_smbus.c
		# ${CERBERUS_CORE_DIR}/recovery/recovery_image.c
		# ${CERBERUS_CORE_DIR}/recovery/recovery_image_header.c
		# ${CERBERUS_CORE_DIR}/recovery/recovery_image_manager.c
		# ${CERBERUS_CORE_DIR}/recovery/recovery_image_observer_pcr.c
		# ${CERBERUS_CORE_DIR}/recovery/recovery_image_section_header.c
		# riot
		# ${CERBERUS_CORE_DIR}/riot/base64_riot.c
		# ${CERBERUS_CORE_DIR}/riot/ecc_riot.c
		# ${CERBERUS_CORE_DIR}/riot/hash_riot.c
		# ${CERBERUS_CORE_DIR}/riot/riot_core.c
		# ${CERBERUS_CORE_DIR}/riot/riot_core_common.c
		# ${CERBERUS_CORE_DIR}/riot/riot_key_manager.c
		# ${CERBERUS_CORE_DIR}/riot/x509_riot.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotAes128.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotAesTables.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotBase64.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotCrypt.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotDerDec.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotDerEnc.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotEcc.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotHmac.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotKdf.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotSha1.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotSha256.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotX509Bldr.c
		# spi
		# spi_filter
		# ${CERBERUS_CORE_DIR}/spi_filter/spi_filter_interface.c
		# ${CERBERUS_CORE_DIR}/spi_filter/spi_filter_irq_handler.c
		# ${CERBERUS_CORE_DIR}/spi_filter/spi_filter_irq_handler_dirty.c
		# state_manager
		# ${CERBERUS_CORE_DIR}/state_manager/state_manager.c
		# status
		# system
		# ${CERBERUS_CORE_DIR}/system/system.c
		# ${CERBERUS_CORE_DIR}/system/system_state_manager.c
		# testing
		# tpm
		# ${CERBERUS_CORE_DIR}/tpm/tpm.c
	)

	if (CONFIG_CERBERUS_MCTP)
		zephyr_library_sources(
			${CERBERUS_CORE_DIR}/cmd_interface/cmd_channel.c
			${CERBERUS_CORE_DIR}/cmd_interface/cmd_interface.c
			${CERBERUS_CORE_DIR}/cmd_interface/device_manager.c
			${CERBERUS_CORE_DIR}/common/observable.c
			${CERBERUS_CORE_DIR}/crypto/checksum.c
			${CERBERUS_CORE_DIR}/mctp/cmd_interface_mctp_control.c
			${CERBERUS_CORE_DIR}/mctp/mctp_base_protocol.c
			${CERBERUS_CORE_DIR}/mctp/mctp_control_protocol_commands.c
			${CERBERUS_CORE_DIR}/mctp/mctp_interface.c
		)
	endif ()

	zephyr_compile_definitions(
		CMD_ENABLE_ISSUE_REQUEST
		ENABLE_DEBUG_COMMANDS
		ECC_ENABLE_GENERATE_KEY_PAIR
		ECC_ENABLE_ECDH
		HASH_ENABLE_SHA256
		HASH_ENABLE_SHA384
		HASH_ENABLE_SHA1
		X509_ENABLE_CREATE_CERTIFICATES
		X509_ENABLE_AUTHENTICATION
		RSA_ENABLE_PRIVATE_KEY
		RSA_ENABLE_DER_PUBLIC_KEY
		LOGGING_SUPPORT_DEBUG_LOG
	)

endif()

