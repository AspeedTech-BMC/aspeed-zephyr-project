/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/multi_heap/shared_multi_heap.h>
#include <stdlib.h>

LOG_MODULE_REGISTER(pldm_fw_update, LOG_LEVEL_DBG);

#include <mctp.h>
#include <mctp_ctrl.h>
#include <pldm.h>

enum FIRMWARE_COMPONENT {                
	SD_MBEDTLS_SHA384 = 9984, // 0x2700, reserved for user defined component
};

extern uint8_t pldm_fw_update(void *fw_update_param, const int flash_position);

// Juse use this to verify the transmission integrity of PLDM-over-MCTP-over-IPC
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/version.h>

mbedtls_sha512_context sha512_ctx;

uint8_t pldm_mbedtls_sha384_pre_update(void *fw_update_param)
{
	pldm_fw_update_param_t *p = (pldm_fw_update_param_t *)fw_update_param;

	LOG_INF("MBEDTLS SHA384 PRE UPDATE");

	mbedtls_sha512_init(&sha512_ctx);
	mbedtls_sha512_starts(&sha512_ctx, 1);

	// Allocate non-cache memory for one-shot hash calculation
	p->user_data = shared_multi_heap_alloc(SMH_REG_ATTR_NON_CACHEABLE, p->fw_update_cfg.image_size);
	LOG_INF("Allocated non-cache memory for one-shot hash calculation at address 0x%08X, size %u", (uint32_t)p->user_data, p->fw_update_cfg.image_size);

	return 0;
}

uint8_t pldm_mbedtls_sha384_post_update(void *fw_update_param)
{
	pldm_fw_update_param_t *p = (pldm_fw_update_param_t *)fw_update_param;

	uint8_t hash_onfly[64] = { 0 };

	mbedtls_sha512_finish(&sha512_ctx, hash_onfly);
	mbedtls_sha512_free(&sha512_ctx);

	LOG_HEXDUMP_INF(hash_onfly, 48, "POST UPDATE HASH SHA384 ON THE FLY");

#if 0
	uint8_t hash_noncache[64] = { 0 };
	mbedtls_sha512((const uint8_t *)p->user_data, p->fw_update_cfg.image_size, hash_noncache, 1);
	
	LOG_HEXDUMP_INF(hash_noncache, 48, "POST UPDATE HASH SHA384 ONE-SHOT");

	// Compare the two hash output to verify the data integrity of PLDM-over-MCTP-over-IPC transmission
	if (memcmp(hash_onfly, hash_noncache, 48) == 0) {
		LOG_INF("POST UPDATE HASH MATCHED, PLDM-over-MCTP-over-IPC transmission integrity verified");
	} else {
		LOG_ERR("POST UPDATE HASH NOT MATCHED, PLDM-over-MCTP-over-IPC transmission integrity verification failed");
	}
#endif
	// Rekease the non-cache memory after hash calculation
	shared_multi_heap_free(p->user_data);
	p->user_data = NULL;
	return 0;
}


uint8_t pldm_mbedtls_sha384_update(void *fw_update_param)
{
	pldm_fw_update_param_t *p = (pldm_fw_update_param_t *)fw_update_param;

	// Too much log
	// LOG_DBG("MBEDTLS SHA384 UPDATE, data_len: %d", p->data_len);
	
	// Calcuate the hash on the fly
	mbedtls_sha512_update(&sha512_ctx, p->data, p->data_len);

	// Copy to non-cache dram for one-shot hash calculation
	memcpy((uint8_t *)p->user_data + p->data_ofs, p->data, p->data_len);

	pldm_fw_update(fw_update_param, 0);
	return 0;
}

uint8_t pldm_mbedtls_sha384_activate(void *arg)
{
	LOG_INF("MBEDTLS SHA384 ACTIVATE DUMMY");
	return 0;
}

bool pldm_mbedtls_sha384_get_fw_version(void *info_p, uint8_t *buf, uint8_t *len)
{
	// Read from mbedtls version
	uint8_t version_str_len = strlen(MBEDTLS_VERSION_STRING_FULL);
	memcpy(buf, MBEDTLS_VERSION_STRING_FULL, version_str_len);
	*len = version_str_len;

	return true;
}

pldm_fw_update_info_t PLDMUPDATE_FW_CONFIG_TABLE[] = {
	{
		.enable = true,
		.comp_classification = COMP_CLASS_TYPE_FW,
		.comp_identifier = SD_MBEDTLS_SHA384,
		.comp_classification_index = 0x00,
		.pre_update_func = pldm_mbedtls_sha384_pre_update,
		.update_func = pldm_mbedtls_sha384_update,
		.pos_update_func = pldm_mbedtls_sha384_post_update,
		.inf = COMP_UPDATE_VIA_SPI,
		.activate_method = COMP_ACT_SELF,
		.self_act_func = pldm_mbedtls_sha384_activate,
		.get_fw_version_fn = pldm_mbedtls_sha384_get_fw_version,
		.self_apply_work_func = NULL,
		.comp_version_str = NULL,
	}
};

void load_pldmupdate_comp_config(void)
{
	if (comp_config) {                                                                  
		LOG_WRN("PLDM update component table has already been load");               
		return;                                                                     
	}                                                                                   

	comp_config_count = ARRAY_SIZE(PLDMUPDATE_FW_CONFIG_TABLE);                         
	comp_config = PLDMUPDATE_FW_CONFIG_TABLE; 
}

#define CHECK_NULL_ARG_WITH_RETURN(...) 
uint8_t plat_pldm_query_device_identifiers(const uint8_t *buf, uint16_t len, uint8_t *resp,
					   uint16_t *resp_len)
{
	CHECK_NULL_ARG_WITH_RETURN(buf, false);
	CHECK_NULL_ARG_WITH_RETURN(resp, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(resp_len, PLDM_ERROR);

	struct pldm_query_device_identifiers_resp *resp_p =
		(struct pldm_query_device_identifiers_resp *)resp;

	resp_p->completion_code = PLDM_SUCCESS;
	resp_p->descriptor_count = 0x01;

	uint8_t iana[PLDM_FWUP_IANA_ENTERPRISE_ID_LENGTH] = { 0x00, 0x00, 0xA0, 0x15 };

	uint8_t total_size_of_iana_descriptor =
		sizeof(struct pldm_descriptor_tlv) + sizeof(iana) - 1;

	if (sizeof(struct pldm_query_device_identifiers_resp) + total_size_of_iana_descriptor >
	    PLDM_MAX_DATA_SIZE) {
		LOG_ERR("QueryDeviceIdentifiers data length is over PLDM_MAX_DATA_SIZE define size %d",
			PLDM_MAX_DATA_SIZE);
		resp_p->completion_code = PLDM_ERROR;
		return PLDM_ERROR;
	}

	// Allocate data for tlv which including descriptors data
	struct pldm_descriptor_tlv *tlv_ptr = malloc(total_size_of_iana_descriptor);
	if (tlv_ptr == NULL) {
		LOG_ERR("Memory allocation failed!");
		return PLDM_ERROR;
	}

	tlv_ptr->descriptor_type = PLDM_FWUP_IANA_ENTERPRISE_ID;
	tlv_ptr->descriptor_length = PLDM_FWUP_IANA_ENTERPRISE_ID_LENGTH;
	memcpy(tlv_ptr->descriptor_data, iana, sizeof(iana));

	uint8_t *end_of_id_ptr =
		(uint8_t *)resp + sizeof(struct pldm_query_device_identifiers_resp);

	memcpy(end_of_id_ptr, tlv_ptr, total_size_of_iana_descriptor);
	free(tlv_ptr);

	resp_p->device_identifiers_len = total_size_of_iana_descriptor;

	*resp_len = sizeof(struct pldm_query_device_identifiers_resp) +
		    total_size_of_iana_descriptor;

	return PLDM_SUCCESS;
}

