/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <stdlib.h>

LOG_MODULE_REGISTER(pldm_fw_update, LOG_LEVEL_DBG);

#include <mctp.h>
#include <mctp_ctrl.h>
#include <pldm.h>
#include "pldm_fw_update_sd_ast2700_image.h"
#include "pldm_fw_update_mbedtls_sha384.h"

pldm_fw_update_info_t PLDMUPDATE_FW_CONFIG_TABLE[] = {
	{
		.enable = true,
		.comp_classification = COMP_CLASS_TYPE_FW,
		.comp_identifier = SD_AST2700_IMAGE,
		.comp_classification_index = 0x00,
		.pre_update_func = pldm_sd_ast2700_image_pre_update,
		.update_func = pldm_sd_ast2700_image_update,
		.pos_update_func = pldm_sd_ast2700_image_post_update,
		.verify_func = pldm_sd_ast2700_image_verify,
		.inf = COMP_UPDATE_VIA_SPI,
		.activate_method = COMP_ACT_SELF,
		.self_act_func = pldm_sd_ast2700_image_activate,
		.get_fw_version_fn = pldm_sd_ast2700_image_get_fw_version,
		.self_apply_work_func = pldm_sd_ast2700_image_apply,
		.comp_version_str = NULL,
	},
	{
		.enable = true,
		.comp_classification = COMP_CLASS_TYPE_FW,
		.comp_identifier = SD_MBEDTLS_SHA384,
		.comp_classification_index = 0x00,
		.pre_update_func = pldm_mbedtls_sha384_pre_update,
		.update_func = pldm_mbedtls_sha384_update,
		.pos_update_func = pldm_mbedtls_sha384_post_update,
		.verify_func = NULL,
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
