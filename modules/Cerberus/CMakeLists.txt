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

		# ${CERBERUS_CORE_DIR}/keystore/keystore_flash.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_filtered.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_flash_manager.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_flash_manager_dual.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_state_observer_dirty_reset.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_irq_handler_mask_irqs.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_single_full_bypass.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_dual.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_flash_manager_single.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_fw_util.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_dual_full_bypass.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_single.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_processor_observer_pcr.c
		# ${CERBERUS_CORE_DIR}/host_fw/bmc_recovery.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_flash_initialization.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_irq_handler.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_irq_handler_auth_check.c
		# ${CERBERUS_CORE_DIR}/host_fw/host_state_manager.c
		# ${CERBERUS_CORE_DIR}/attestation/attestation_master.c
		# ${CERBERUS_CORE_DIR}/attestation/pcr_store.c
		# ${CERBERUS_CORE_DIR}/attestation/attestation_slave.c
		# ${CERBERUS_CORE_DIR}/attestation/aux_attestation.c
		# ${CERBERUS_CORE_DIR}/attestation/pcr.c
		# ${CERBERUS_CORE_DIR}/testing/mctp_interface_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_single_test_bypass_mode.c
		# ${CERBERUS_CORE_DIR}/testing/spi_flash_sfdp_test.c
		# ${CERBERUS_CORE_DIR}/testing/pcd_manager_test.c
		# ${CERBERUS_CORE_DIR}/testing/pcr_test.c
		# ${CERBERUS_CORE_DIR}/testing/x509_mbedtls_test.c
		# ${CERBERUS_CORE_DIR}/testing/cerberus_protocol_required_commands_test.c
		# ${CERBERUS_CORE_DIR}/testing/image_header_test.c
		# ${CERBERUS_CORE_DIR}/testing/tpm_test.c
		# ${CERBERUS_CORE_DIR}/testing/pcd_observer_pcr_test.c
		# ${CERBERUS_CORE_DIR}/testing/cmd_channel_test.c
		# ${CERBERUS_CORE_DIR}/testing/recovery_image_section_header_test.c
		# ${CERBERUS_CORE_DIR}/testing/flash_store_encrypted_test.c
		# ${CERBERUS_CORE_DIR}/testing/x509_test.c
		# ${CERBERUS_CORE_DIR}/testing/riot_core_common_test.c
		# ${CERBERUS_CORE_DIR}/testing/manifest_manager_test.c
		# ${CERBERUS_CORE_DIR}/testing/cfm_flash_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_irq_handler_mask_irqs_test.c
		# ${CERBERUS_CORE_DIR}/testing/observable_test.c
		# ${CERBERUS_CORE_DIR}/testing/aes_mbedtls_test.c
		# ${CERBERUS_CORE_DIR}/testing/config_reset_test.c
		# ${CERBERUS_CORE_DIR}/testing/mock/pcd_observer_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/authorization_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/pfm_manager_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/cmd_authorization_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/firmware_update_observer_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/logging_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/cert_device_hw_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/host_processor_observer_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/host_flash_manager_single_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/keystore_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/system_observer_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/recovery_image_manager_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/cfm_observer_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/rsa_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/manifest_cmd_interface_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/key_manifest_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/cfm_manager_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/pcd_manager_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/pfm_observer_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/hash_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/pcd_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/spi_filter_interface_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/flash_master_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/host_irq_handler_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/attestation_master_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/recovery_image_observer_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/session_manager_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/bmc_recovery_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/manifest_manager_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/rng_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/base64_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/spi_filter_irq_handler_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/firmware_update_notification_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/attestation_slave_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/x509_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/host_control_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/recovery_image_cmd_interface_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/observer_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/host_state_observer_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/cfm_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/ecc_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/recovery_image_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/firmware_update_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/cmd_channel_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/cmd_device_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/manifest_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/i2c_master_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/cmd_background_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/aes_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/firmware_update_control_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/cmd_interface_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/state_manager_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/signature_verification_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/app_context_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/host_processor_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/host_flash_manager_dual_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/pfm_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/firmware_image_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/host_flash_manager_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/flash_mfg_filter_handler_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/flash_store_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/host_irq_control_mock.c
		# ${CERBERUS_CORE_DIR}/testing/mock/flash_mock.c
		# ${CERBERUS_CORE_DIR}/testing/riot_key_manager_test.c
		# ${CERBERUS_CORE_DIR}/testing/cmd_interface_slave_test.c
		# ${CERBERUS_CORE_DIR}/testing/debug_log_test.c
		# ${CERBERUS_CORE_DIR}/testing/x509_riot_test.c
		# ${CERBERUS_CORE_DIR}/testing/mctp_interface_control_test.c
		# ${CERBERUS_CORE_DIR}/testing/rsa_mbedtls_test.c
		# ${CERBERUS_CORE_DIR}/testing/pfm_observer_pending_reset_test.c
		# ${CERBERUS_CORE_DIR}/testing/platform_timer_test.c
		# ${CERBERUS_CORE_DIR}/testing/rng_thread_safe_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_fw_util_test.c
		# ${CERBERUS_CORE_DIR}/testing/logging_flash_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_state_observer_dirty_reset_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_flash_manager_dual_test.c
		# ${CERBERUS_CORE_DIR}/testing/aux_attestation_test.c
		# ${CERBERUS_CORE_DIR}/testing/bmc_recovery_test.c
		# ${CERBERUS_CORE_DIR}/testing/base64_thread_safe_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_single_test_soft_reset.c
		# ${CERBERUS_CORE_DIR}/testing/device_manager_test.c
		# ${CERBERUS_CORE_DIR}/testing/spi_flash_test.c
		# ${CERBERUS_CORE_DIR}/testing/base64_riot_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_observer_pcr_test.c
		# ${CERBERUS_CORE_DIR}/testing/pfm_manager_flash_test.c
		# ${CERBERUS_CORE_DIR}/testing/pfm_observer_pcr_test.c
		# ${CERBERUS_CORE_DIR}/testing/flash_updater_test.c
		# ${CERBERUS_CORE_DIR}/testing/pfm_manager_test.c
		# ${CERBERUS_CORE_DIR}/testing/ecc_thread_safe_test.c
		# ${CERBERUS_CORE_DIR}/testing/spi_filter_irq_handler_test.c
		# ${CERBERUS_CORE_DIR}/testing/cfm_manager_flash_test.c
		# ${CERBERUS_CORE_DIR}/testing/riot_core_test.c
		# ${CERBERUS_CORE_DIR}/testing/recovery_image_observer_pcr_test.c
		# ${CERBERUS_CORE_DIR}/testing/base64_test.c
		# ${CERBERUS_CORE_DIR}/testing/cerberus_protocol_master_commands_test.c
		# ${CERBERUS_CORE_DIR}/testing/firmware_component_test.c
		# ${CERBERUS_CORE_DIR}/testing/rsa_thread_safe_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_single_test_recover_active_read_write_data.c
		# ${CERBERUS_CORE_DIR}/testing/manifest_flash_v2_test.c
		# ${CERBERUS_CORE_DIR}/testing/counter_manager_registers_test.c
		# ${CERBERUS_CORE_DIR}/testing/checksum_test.c
		# ${CERBERUS_CORE_DIR}/testing/flash_store_test.c
		# ${CERBERUS_CORE_DIR}/testing/mctp_protocol_test.c
		# ${CERBERUS_CORE_DIR}/testing/hash_thread_safe_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_irq_handler_auth_check_test.c
		# ${CERBERUS_CORE_DIR}/testing/cmd_interface_dual_cmd_set_test.c
		# ${CERBERUS_CORE_DIR}/testing/cerberus_protocol_diagnostic_commands_test.c
		# ${CERBERUS_CORE_DIR}/testing/manifest_verification_test.c
		# ${CERBERUS_CORE_DIR}/testing/pfm_flash_v2_test.c
		# ${CERBERUS_CORE_DIR}/testing/firmware_update_test.c
		# ${CERBERUS_CORE_DIR}/testing/ecc_test.c
		# ${CERBERUS_CORE_DIR}/testing/kdf_test.c
		# ${CERBERUS_CORE_DIR}/testing/logging_memory_test.c
		# ${CERBERUS_CORE_DIR}/testing/attestation_master_test.c
		# ${CERBERUS_CORE_DIR}/testing/hash_riot_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_dual_test_apply_recovery_image.c
		# ${CERBERUS_CORE_DIR}/testing/state_manager_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_state_manager_test.c
		# ${CERBERUS_CORE_DIR}/testing/session_manager_ecc_test.c
		# ${CERBERUS_CORE_DIR}/testing/manifest_flash_test.c
		# ${CERBERUS_CORE_DIR}/testing/pcd_flash_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_test.c
		# ${CERBERUS_CORE_DIR}/testing/authorization_challenge_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_flash_manager_single_test.c
		# ${CERBERUS_CORE_DIR}/testing/cfm_manager_test.c
		# ${CERBERUS_CORE_DIR}/testing/rsa_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_dual_test_recover_active_read_write_data.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_single_test_flash_rollback.c
		# ${CERBERUS_CORE_DIR}/testing/pfm_flash_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_single_full_bypass_test.c
		# ${CERBERUS_CORE_DIR}/testing/pcd_manager_flash_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_irq_handler_test.c
		# ${CERBERUS_CORE_DIR}/testing/hash_mbedtls_test.c
		# ${CERBERUS_CORE_DIR}/testing/attestation_slave_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_dual_test_power_on_reset.c
		# ${CERBERUS_CORE_DIR}/testing/app_image_test.c
		# ${CERBERUS_CORE_DIR}/testing/firmware_header_test.c
		# ${CERBERUS_CORE_DIR}/testing/flash_util_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_dual_test_soft_reset.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_dual_full_bypass_test.c
		# ${CERBERUS_CORE_DIR}/testing/cmd_interface_system_test.c
		# ${CERBERUS_CORE_DIR}/testing/signature_test.c
		# ${CERBERUS_CORE_DIR}/testing/base64_mbedtls_test.c
		# ${CERBERUS_CORE_DIR}/testing/signature_verification_ecc_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_single_test.c
		# ${CERBERUS_CORE_DIR}/testing/system_test.c
		# ${CERBERUS_CORE_DIR}/testing/spi_filter_irq_handler_dirty_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_dual_test_run_time_verification.c
		# ${CERBERUS_CORE_DIR}/testing/cmd_authorization_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_dual_test_bypass_mode.c
		# ${CERBERUS_CORE_DIR}/testing/x509_thread_safe_test.c
		# ${CERBERUS_CORE_DIR}/testing/hash_test.c
		# ${CERBERUS_CORE_DIR}/testing/keystore_flash_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_flash_initialization_test.c
		# ${CERBERUS_CORE_DIR}/testing/cerberus_protocol_optional_commands_test.c
		# ${CERBERUS_CORE_DIR}/testing/authorization_disallowed_test.c
		# ${CERBERUS_CORE_DIR}/testing/rng_mbedtls_test.c
		# ${CERBERUS_CORE_DIR}/testing/manifest_observer_pcr_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_single_test_power_on_reset.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_single_test_apply_recovery_image.c
		# ${CERBERUS_CORE_DIR}/testing/ecc_riot_test.c
		# ${CERBERUS_CORE_DIR}/testing/recovery_image_header_test.c
		# ${CERBERUS_CORE_DIR}/testing/system_state_manager_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_dual_test_flash_rollback.c
		# ${CERBERUS_CORE_DIR}/testing/signature_verification_rsa_test.c
		# ${CERBERUS_CORE_DIR}/testing/cerberus_protocol_debug_commands_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_dual_test.c
		# ${CERBERUS_CORE_DIR}/testing/recovery_image_test.c
		# ${CERBERUS_CORE_DIR}/testing/recovery_image_manager_test.c
		# ${CERBERUS_CORE_DIR}/testing/cfm_observer_pcr_test.c
		# ${CERBERUS_CORE_DIR}/testing/buffer_util_test.c
		# ${CERBERUS_CORE_DIR}/testing/authorization_allowed_test.c
		# ${CERBERUS_CORE_DIR}/testing/aes_test.c
		# ${CERBERUS_CORE_DIR}/testing/spi_filter_test.c
		# ${CERBERUS_CORE_DIR}/testing/pcr_store_test.c
		# ${CERBERUS_CORE_DIR}/testing/flash_common_test.c
		# ${CERBERUS_CORE_DIR}/testing/host_processor_single_test_run_time_verification.c
		# ${CERBERUS_CORE_DIR}/testing/ecc_mbedtls_test.c
		# ${CERBERUS_CORE_DIR}/flash/spi_flash_sfdp.c
		${CERBERUS_CORE_DIR}/flash/flash_common.c
		# ${CERBERUS_CORE_DIR}/flash/flash_updater.c
		${CERBERUS_CORE_DIR}/flash/spi_flash.c
		# ${CERBERUS_CORE_DIR}/flash/flash_store_encrypted.c
		${CERBERUS_CORE_DIR}/flash/flash_util.c
		# ${CERBERUS_CORE_DIR}/flash/flash_store.c
		# ${CERBERUS_CORE_DIR}/logging/logging_flash.c
		${CERBERUS_CORE_DIR}/logging/logging_memory.c
		${CERBERUS_CORE_DIR}/logging/debug_log.c
		# ${CERBERUS_CORE_DIR}/recovery/recovery_image_manager.c
		# ${CERBERUS_CORE_DIR}/recovery/recovery_image_section_header.c
		# ${CERBERUS_CORE_DIR}/recovery/recovery_image.c
		# ${CERBERUS_CORE_DIR}/recovery/recovery_image_observer_pcr.c
		# ${CERBERUS_CORE_DIR}/recovery/recovery_image_header.c
		# ${CERBERUS_CORE_DIR}/state_manager/state_manager.c
		# ${CERBERUS_CORE_DIR}/riot/x509_riot.c
		# ${CERBERUS_CORE_DIR}/riot/ecc_riot.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotSha1.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotHmac.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotEcc.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotDerEnc.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotAesTables.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotX509Bldr.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotDerDec.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotBase64.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotSha256.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotKdf.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotCrypt.c
		# ${CERBERUS_CORE_DIR}/riot/reference/RiotAes128.c
		# ${CERBERUS_CORE_DIR}/riot/riot_core.c
		# ${CERBERUS_CORE_DIR}/riot/base64_riot.c
		# ${CERBERUS_CORE_DIR}/riot/riot_core_common.c
		# ${CERBERUS_CORE_DIR}/riot/hash_riot.c
		# ${CERBERUS_CORE_DIR}/riot/riot_key_manager.c
		# ${CERBERUS_CORE_DIR}/tpm/tpm.c
		# ${CERBERUS_CORE_DIR}/spi_filter/spi_filter_interface.c
		# ${CERBERUS_CORE_DIR}/spi_filter/spi_filter_irq_handler.c
		# ${CERBERUS_CORE_DIR}/spi_filter/spi_filter_irq_handler_dirty.c
		# ${CERBERUS_CORE_DIR}/mctp/mctp_interface.c
		# ${CERBERUS_CORE_DIR}/mctp/mctp_interface_control.c
		# ${CERBERUS_CORE_DIR}/mctp/mctp_protocol.c
		# ${CERBERUS_CORE_DIR}/firmware/firmware_update.c
		# ${CERBERUS_CORE_DIR}/firmware/firmware_header.c
		# ${CERBERUS_CORE_DIR}/firmware/app_image.c
		# ${CERBERUS_CORE_DIR}/firmware/firmware_component.c
		# ${CERBERUS_CORE_DIR}/manifest/manifest_verification.c
		# ${CERBERUS_CORE_DIR}/manifest/pcd/pcd_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/pcd/pcd_manager.c
		# ${CERBERUS_CORE_DIR}/manifest/pcd/pcd_manager_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/pcd/pcd_observer_pcr.c
		# ${CERBERUS_CORE_DIR}/manifest/manifest_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/manifest_manager_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/manifest_manager.c
		# ${CERBERUS_CORE_DIR}/manifest/pfm/pfm_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/pfm/pfm_observer_pcr.c
		# ${CERBERUS_CORE_DIR}/manifest/pfm/pfm_observer_pending_reset.c
		# ${CERBERUS_CORE_DIR}/manifest/pfm/pfm_manager.c
		# ${CERBERUS_CORE_DIR}/manifest/pfm/pfm_manager_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/cfm/cfm_manager_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/cfm/cfm_observer_pcr.c
		# ${CERBERUS_CORE_DIR}/manifest/cfm/cfm_flash.c
		# ${CERBERUS_CORE_DIR}/manifest/cfm/cfm_manager.c
		# ${CERBERUS_CORE_DIR}/manifest/manifest_pcr.c
		# ${CERBERUS_CORE_DIR}/crypto/kdf.c
		# ${CERBERUS_CORE_DIR}/crypto/rsa_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/rng_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/signature_verification_ecc.c
		# ${CERBERUS_CORE_DIR}/crypto/ecc_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/base64_thread_safe.c
		# ${CERBERUS_CORE_DIR}/crypto/hash_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/rsa_thread_safe.c
		# ${CERBERUS_CORE_DIR}/crypto/base64_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/x509_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/checksum.c
		# ${CERBERUS_CORE_DIR}/crypto/hash_thread_safe.c
		# ${CERBERUS_CORE_DIR}/crypto/signature_verification_rsa.c
		${CERBERUS_CORE_DIR}/crypto/hash.c
		# ${CERBERUS_CORE_DIR}/crypto/aes_mbedtls.c
		# ${CERBERUS_CORE_DIR}/crypto/rsa.c
		# ${CERBERUS_CORE_DIR}/crypto/rng_thread_safe.c
		# ${CERBERUS_CORE_DIR}/crypto/x509_thread_safe.c
		# ${CERBERUS_CORE_DIR}/crypto/ecc_thread_safe.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cmd_channel.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/session_manager.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/counter_manager_registers.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/session_manager_ecc.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cerberus_protocol_diagnostic_commands.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/device_manager.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cerberus_protocol_debug_commands.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cmd_authorization.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cmd_interface_system.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cmd_interface_slave.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cmd_interface_dual_cmd_set.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/config_reset.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cerberus_protocol_required_commands.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cerberus_protocol_master_commands.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cmd_interface.c
		# ${CERBERUS_CORE_DIR}/cmd_interface/cerberus_protocol_optional_commands.c
		# ${CERBERUS_CORE_DIR}/system/system_state_manager.c
		# ${CERBERUS_CORE_DIR}/system/system.c
		# ${CERBERUS_CORE_DIR}/common/observable.c
		# ${CERBERUS_CORE_DIR}/common/authorization_allowed.c
		# ${CERBERUS_CORE_DIR}/common/authorization_disallowed.c
		# ${CERBERUS_CORE_DIR}/common/buffer_util.c
		# ${CERBERUS_CORE_DIR}/common/authorization_challenge.c
		# ${CERBERUS_CORE_DIR}/common/image_header.c

	)

	zephyr_compile_definitions(
		ENABLE_DEBUG_COMMANDS
		ECC_ENABLE_GENERATE_KEY_PAIR
		ECC_ENABLE_ECDH
		HASH_ENABLE_SHA256
		HASH_ENABLE_SHA384
		HASH_ENABLE_SHA1
		X509_ENABLE_CREATE_CERTIFICATES
		X509_ENABLE_AUTHENTICATION
	)

endif()

