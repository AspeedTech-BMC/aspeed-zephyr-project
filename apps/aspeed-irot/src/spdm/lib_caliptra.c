/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/

#include "hal/library/responder/asymsignlib.h"
#include "hal/library/responder/csrlib.h"
#include "hal/library/responder/measlib.h"
#include "hal/library/responder/key_pair_info.h"
#include "hal/library/responder/psklib.h"
#include "hal/library/responder/setcertlib.h"
#include "hal/library/requester/reqasymsignlib.h"
#include "hal/library/requester/psklib.h"
#include "library/spdm_crypt_lib.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/cptra.h>
#include <zephyr/drivers/misc/aspeed/cptra_ipc.h>

#include <stdlib.h>

LOG_MODULE_REGISTER(spdm_secret);

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
libspdm_return_t libspdm_measurement_collection(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
		void *spdm_context,
#endif
		spdm_version_number_t spdm_version,
		uint8_t measurement_specification,
		uint32_t measurement_hash_algo,
		uint8_t mesurements_index,
		uint8_t request_attribute,
		uint8_t *content_changed,
		uint8_t *device_measurement_count,
		void *device_measurement,
		size_t *device_measurement_size)
{

	struct cptra_quote_pcrs_ia input;
	struct cptra_quote_pcrs_oa output;
	int ret;
	uint32_t total_size_needed = 0;
	uint8_t *output_buffer = (uint8_t *)device_measurement;

	memset(&input, 0, sizeof(struct cptra_quote_pcrs_ia));
	memset(&output, 0, sizeof(struct cptra_quote_pcrs_oa));

	ret = cptra_ipc_transfer(CPTRA_IPCCMD_QUOTE_PCRS, (uint32_t *)&input, sizeof(input),
				 CPTRA_IPC_RX_TYPE_EXTERNAL, (uint32_t *)&output, sizeof(output));
	if (ret) {
		LOG_ERR("caliptra_quote_pcrs is failure, ret:0x%x", ret);
		return LIBSPDM_STATUS_BUSY_PEER;
	} else
		LOG_DBG("caliptra_quote_pcrs is successful");

	switch(mesurements_index) {
	case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS:
		*device_measurement_count = 32;
		break;
	case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS:
		*device_measurement_count = 32;
		total_size_needed = ARRAY_SIZE(output.PCRs)*(sizeof(PcrValue) + sizeof(spdm_measurement_block_dmtf_t));

		if (total_size_needed > *device_measurement_size) {
			LOG_ERR("buffer too small");
			return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
		}

		*device_measurement_size = total_size_needed;
		for (uint8_t i = 0; i < ARRAY_SIZE(output.PCRs); i++) {
			spdm_measurement_block_dmtf_t *measurement_block_dmtf = (spdm_measurement_block_dmtf_t *)output_buffer;
			measurement_block_dmtf->measurement_block_common_header.index = i + 1;
			measurement_block_dmtf->measurement_block_common_header.measurement_specification = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
			measurement_block_dmtf->measurement_block_common_header.measurement_size = sizeof(PcrValue) + sizeof(spdm_measurement_block_dmtf_header_t);
			measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_type = 0x01; //	
			measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_size = sizeof(PcrValue);
			output_buffer += sizeof(spdm_measurement_block_dmtf_t);
			memcpy(output_buffer, &output.PCRs[i], sizeof(PcrValue));
			output_buffer += sizeof(PcrValue);
		}
		LOG_HEXDUMP_INF(device_measurement, total_size_needed, "Measurement Block:");
		break;
	case 1 ... 32:
		// PCR[0] ~ PCR[31]
		*device_measurement_count = 1;

		total_size_needed = sizeof(output.PCRs[0]) + sizeof(spdm_measurement_block_dmtf_t);

		if (total_size_needed > *device_measurement_size) {
			LOG_ERR("buffer too small");
			return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
		}

		*device_measurement_size = total_size_needed;
		spdm_measurement_block_dmtf_t *measurement_block_dmtf = (spdm_measurement_block_dmtf_t *)output_buffer;
		measurement_block_dmtf->measurement_block_common_header.index = mesurements_index;
		measurement_block_dmtf->measurement_block_common_header.measurement_specification = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
		measurement_block_dmtf->measurement_block_common_header.measurement_size = sizeof(output.PCRs[0]) + sizeof(spdm_measurement_block_dmtf_header_t);
		measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_type = 0x01; //	
		measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_size = sizeof(output.PCRs[0]);
		output_buffer += sizeof(spdm_measurement_block_dmtf_t);
		memcpy(output_buffer, &output.PCRs[mesurements_index - 1], sizeof(output.PCRs[0]));

		LOG_HEXDUMP_INF(device_measurement, total_size_needed, "Measurement Block:");
		break;
	default:
		return LIBSPDM_STATUS_MEAS_INVALID_INDEX;
		break;
	}


	return LIBSPDM_STATUS_SUCCESS;
}

bool libspdm_measurement_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
		void *spdm_context,
#endif
		spdm_version_number_t spdm_version,
		uint8_t measurement_specification,
		uint32_t measurement_hash_algo,
		uint8_t measurement_index,
		uint8_t request_attribute,
		void *opaque_data,
		size_t *opaque_data_size)
{
	*opaque_data_size = 0;
	return true;
}

bool libspdm_generate_measurement_summary_hash(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
		void *spdm_context,
#endif
		spdm_version_number_t spdm_version,
		uint32_t base_hash_algo,
		uint8_t measurement_specification,
		uint32_t measurement_hash_algo,
		uint8_t measurement_summary_hash_type,
		uint8_t  *measurement_summary_hash,
		uint32_t measurement_summary_hash_size)
{
	struct cptra_quote_pcrs_ia input;
	struct cptra_quote_pcrs_oa output;
	int ret;

	memset(&input, 0, sizeof(struct cptra_quote_pcrs_ia));
	memset(&output, 0, sizeof(struct cptra_quote_pcrs_oa));

	ret = cptra_ipc_transfer(CPTRA_IPCCMD_QUOTE_PCRS, (uint32_t *)&input, sizeof(input),
				 CPTRA_IPC_RX_TYPE_EXTERNAL, (uint32_t *)&output, sizeof(output));
	if (ret) {
		LOG_ERR("caliptra_quote_pcrs is failure, ret:0x%x", ret);
		return false;
	} else
		LOG_DBG("caliptra_quote_pcrs is successful");

	if (measurement_summary_hash_size < sizeof(output.digest)) {
		LOG_ERR("buffer too small");
		return false;
	}
	memcpy(measurement_summary_hash, output.digest, sizeof(output.digest));

	return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
bool libspdm_challenge_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
		void *spdm_context,
#endif
		spdm_version_number_t spdm_version,
		uint8_t slot_id,
		uint8_t *measurement_summary_hash,
		size_t measurement_summary_hash_size,
		void *opaque_data,
		size_t *opaque_data_size)
{
	*opaque_data_size = 0;
	return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
bool libspdm_encap_challenge_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
		void *spdm_context,
#endif
		spdm_version_number_t spdm_version,
		uint8_t slot_id,
		uint8_t *measurement_summary_hash,
		size_t measurement_summary_hash_size,
		void *opaque_data,
		size_t *opaque_data_size)
{
	return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP
/*Collect the measurement extension log.*/
bool libspdm_measurement_extension_log_collection(
		void *spdm_context,
		uint8_t mel_specification,
		uint8_t measurement_specification,
		uint32_t measurement_hash_algo,
		void **spdm_mel,
		size_t *spdm_mel_size)
{
	return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
bool libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
		void *spdm_context,
#endif
		spdm_version_number_t spdm_version, uint8_t op_code,
		uint16_t req_base_asym_alg,
		uint32_t base_hash_algo, bool is_data_hash,
		const uint8_t *message, size_t message_size,
		uint8_t *signature, size_t *sig_size)
{
	return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

bool libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
		void *spdm_context,
#endif
		spdm_version_number_t spdm_version, uint8_t op_code,
		uint32_t base_asym_algo,
		uint32_t base_hash_algo, bool is_data_hash,
		const uint8_t *message, size_t message_size, // Input
		uint8_t *signature, size_t *sig_size) // Output
{
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_sign_i *sign_input = NULL;
	struct dpe_sign_o *sign_output = NULL;
	int ret;
	size_t sign_len = libspdm_get_asym_signature_size(base_asym_algo);

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	sign_input = (struct dpe_sign_i *)input.data;
	sign_output = (struct dpe_sign_o *)output.data;

	input.data_size = sizeof(struct dpe_sign_i);
	sign_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	sign_input->cmd_hdr.cmd = SIGN;
	sign_input->cmd_hdr.profile = P384Sha384; // TODO: 384 vs 256

	if (is_data_hash) {
		// Input message is a digest
		memcpy(sign_input->digest, message, message_size);
	} else {
		// Need to hash first then copy into sign->digest
		if (base_hash_algo == SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256) {
			libspdm_hash_all(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
					 message, message_size,
					 sign_input->digest);
		} else if (base_hash_algo == SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384) {
			libspdm_hash_all(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
					 message, message_size,
					 sign_input->digest);
		} else {
			return false;
		}
	}

	ret = cptra_ipc_transfer(CPTRA_IPCCMD_INVOKE_DPE_COMMAND,
				 (uint8_t *)&input, sizeof(struct cptra_invoke_dpe_command_ia),
				 CPTRA_IPC_RX_TYPE_EXTERNAL,
				 (uint8_t *)&output, sizeof(struct cptra_invoke_dpe_command_oa));

	LOG_HEXDUMP_DBG(&output, 32, "DPE Cmd Output:");
	LOG_HEXDUMP_DBG(sign_output->signature_r, 48, "signature_r:");
	LOG_HEXDUMP_DBG(sign_output->signature_s, 48, "signature_s:");

	if (ret) {
		LOG_ERR("Failed to send command to caliptra");
		return false;
	} else if (output.fips_status != 0) {
		LOG_ERR("FIPS error from caliptra");
		return false;
	}

	memcpy(signature, sign_output->signature_r, sign_len / 2);
	memcpy(signature + sign_len / 2, sign_output->signature_s, sign_len / 2);

	return true;
}

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
bool libspdm_psk_handshake_secret_hkdf_expand(
		spdm_version_number_t spdm_version,
		uint32_t base_hash_algo,
		const uint8_t *psk_hint,
		size_t psk_hint_size,
		const uint8_t *info,
		size_t info_size,
		uint8_t *out, size_t out_size)
{
	return false;
}

bool libspdm_psk_master_secret_hkdf_expand(
		spdm_version_number_t spdm_version,
		uint32_t base_hash_algo,
		const uint8_t *psk_hint,
		size_t psk_hint_size,
		const uint8_t *info,
		size_t info_size, uint8_t *out,
		size_t out_size)
{
	return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
bool libspdm_is_in_trusted_environment(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
		void *spdm_context
#endif
		)
{
	return true;
}

bool libspdm_write_certificate_to_nvm(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
		void *spdm_context,
#endif
		uint8_t slot_id, const void * cert_chain,
		size_t cert_chain_size,
		uint32_t base_hash_algo, uint32_t base_asym_algo
#if LIBSPDM_SET_CERT_CSR_PARAMS
		, bool *need_reset, bool *is_busy
#endif /* LIBSPDM_SET_CERT_CSR_PARAMS */
		)
{
	return false;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
bool libspdm_gen_csr(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
		void *spdm_context,
#endif
		uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
		const void *request, size_t request_size,
		uint8_t *requester_info, size_t requester_info_length,
		uint8_t *opaque_data, uint16_t opaque_data_length,
		size_t *csr_len, uint8_t *csr_pointer,
		bool is_device_cert_model
#if LIBSPDM_SET_CERT_CSR_PARAMS
		, bool *is_busy, bool *unexpected_request
#endif
		)
{
	return false;
}

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
bool libspdm_gen_csr_ex(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
		void *spdm_context,
#endif
		uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
		const void *request, size_t request_size,
		uint8_t *requester_info, size_t requester_info_length,
		uint8_t *opaque_data, uint16_t opaque_data_length,
		size_t *csr_len, uint8_t *csr_pointer,
		uint8_t req_cert_model,
		uint8_t *csr_tracking_tag,
		uint8_t req_key_pair_id,
		bool overwrite
#if LIBSPDM_SET_CERT_CSR_PARAMS
		, bool *is_busy, bool *unexpected_request
#endif
		)
{
	return false;
}
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
bool libspdm_event_get_types(
		void *spdm_context,
		spdm_version_number_t spdm_version,
		uint32_t session_id,
		void *supported_event_groups_list,
		uint32_t *supported_event_groups_list_len,
		uint8_t *event_group_count)
{
	return false;
}

bool libspdm_event_subscribe(
		void *spdm_context,
		spdm_version_number_t spdm_version,
		uint32_t session_id,
		uint8_t subscribe_type,
		uint8_t subscribe_event_group_count,
		uint32_t subscribe_list_len,
		const void *subscribe_list)
{
	return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP

/**
 * read the key pair info of the key_pair_id.
 *
 * @param  spdm_context               A pointer to the SPDM context.
 * @param  key_pair_id                Indicate which key pair ID's information to retrieve.
 *
 * @param  capabilities               Indicate the capabilities of the requested key pairs.
 * @param  key_usage_capabilities     Indicate the key usages the responder allows.
 * @param  current_key_usage          Indicate the currently configured key usage for the requested key pairs ID.
 * @param  asym_algo_capabilities     Indicate the asymmetric algorithms the Responder supports for this key pair ID.
 * @param  current_asym_algo          Indicate the currently configured asymmetric algorithm for this key pair ID.
 * @param  assoc_cert_slot_mask       This field is a bit mask representing the currently associated certificate slots.
 * @param  public_key_info_len        On input, indicate the size in bytes of the destination buffer to store.
 *                                    On output, indicate the size in bytes of the public_key_info.
 *                                    It can be NULL, if public_key_info is not required.
 * @param  public_key_info            A pointer to a destination buffer to store the public_key_info.
 *                                    It can be NULL, if public_key_info is not required.
 *
 * @retval true  get key pair info successfully.
 * @retval false get key pair info failed.
 **/
bool libspdm_read_key_pair_info(
		void *spdm_context,
		uint8_t key_pair_id,
		uint16_t *capabilities,
		uint16_t *key_usage_capabilities,
		uint16_t *current_key_usage,
		uint32_t *asym_algo_capabilities,
		uint32_t *current_asym_algo,
		uint8_t *assoc_cert_slot_mask,
		uint16_t *public_key_info_len,
		uint8_t *public_key_info)
{
	return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP
bool libspdm_write_key_pair_info(
		void *spdm_context,
		uint8_t key_pair_id,
		uint8_t operation,
		uint16_t desired_key_usage,
		uint32_t desired_asym_algo,
		uint8_t desired_assoc_cert_slot_mask,
		bool *need_reset)
{
	return false;
}
#endif /* #if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP */



void cptra_invoke_dpe_get_certificate_chain(void **cert_chain, uint32_t *chain_size)
{
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_get_certificate_chain_i *get_certificate_chain_input = NULL;
	struct dpe_get_certificate_chain_o *get_certificate_chain_output = NULL;
	uint8_t *certificate_chain = malloc(4096); // Assuming the certificate chain won't exceed 4KB. Adjust as needed.
						    //
	if (certificate_chain == NULL) {
		LOG_ERR("Failed to allocate memory for certificate chain");
		return;
	}
	uint32_t offset = 0;
	int ret;

	LOG_INF("\tTest GetCertificateChain...");

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	/* Set input */
	get_certificate_chain_input = (struct dpe_get_certificate_chain_i *)input.data;
	get_certificate_chain_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	get_certificate_chain_input->cmd_hdr.cmd = GET_CERTIFICATE_CHAIN;
	get_certificate_chain_input->cmd_hdr.profile = P384Sha384;
	get_certificate_chain_output = (struct dpe_get_certificate_chain_o *)output.data;
	input.data_size = sizeof(struct dpe_get_certificate_chain_i);

	do {
		get_certificate_chain_input->offset = offset;
		get_certificate_chain_input->size =
			sizeof(get_certificate_chain_output->cert_chain);

		ret = cptra_ipc_transfer(CPTRA_IPCCMD_INVOKE_DPE_COMMAND,
					 (uint32_t *)&input, sizeof(input),
					 CPTRA_IPC_RX_TYPE_EXTERNAL,
					 (uint32_t *)&output, sizeof(output));
		if (ret) {
			LOG_ERR("caliptra_invoke_dpe_command is failure, ret:0x%x\n", ret);
			break;

		} else {
			LOG_INF("Successful offset=%u size=%u\n", offset,
				get_certificate_chain_output->size);

			memcpy(certificate_chain+offset,
			       get_certificate_chain_output->cert_chain,
			       get_certificate_chain_output->size);

			offset += get_certificate_chain_output->size;
			if (get_certificate_chain_output->size <
			    sizeof(get_certificate_chain_output->cert_chain)) {
				break;
			}
		}

	} while (1);

	*cert_chain = (void *)malloc(offset);
	if (*cert_chain == NULL) {
		LOG_ERR("Failed to allocate memory for certificate chain");
		goto exit;
	}
	memcpy(*cert_chain, certificate_chain, offset);
	*chain_size = offset;
	LOG_HEXDUMP_INF(certificate_chain, 256, "certificate_chain first 256 byte:");

exit:
	free(certificate_chain);
}

bool libspdm_read_responder_public_certificate_chain(
		uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
		size_t *size, void **hash, size_t *hash_size)
{
	/* Get Certificate Chain from Caliptra fisrt */
	void *cert_chain = NULL;
	uint32_t cert_chain_size = 0;
	bool ret = false;

	cptra_invoke_dpe_get_certificate_chain(&cert_chain, &cert_chain_size);
	if (cert_chain == NULL || cert_chain_size == 0) {
		LOG_ERR("Failed to get certificate chain from Caliptra");
		return false;
	}
	
	size_t digest_size = libspdm_get_hash_size(base_hash_algo);
	if (digest_size == 0) {
		LOG_ERR("Unsupported hash algorithm: 0x%08X", base_hash_algo);
		free(cert_chain);
		return false;
	}

	/* Output cert should be organize:
	 * spdm_cert_chain_t + digest + certificate chain
	 */

	uint8_t cert_digest[64];
	ret = libspdm_hash_all(base_hash_algo, cert_chain, cert_chain_size, cert_digest);
	if (!ret) {
		LOG_ERR("Failed to hash certificate chain");
		free(cert_chain);
		return false;
	}

	// Add space for spdm_cert_chain_t header and digest

	*data = malloc(cert_chain_size + sizeof(spdm_cert_chain_t) + digest_size);
	if (*data == NULL) {
		LOG_ERR("Failed to allocate memory for output certificate chain");
		free(cert_chain);
		return false;
	}
	
	uint8_t *output_buffer = (uint8_t *)(*data);
	spdm_cert_chain_t *output_cert_chain_header = (spdm_cert_chain_t *)output_buffer;
	output_cert_chain_header->length = (uint16_t)cert_chain_size + sizeof(spdm_cert_chain_t) + digest_size;
	output_cert_chain_header->reserved = 0;

	output_buffer = output_buffer + sizeof(spdm_cert_chain_t);

	*hash = (uint8_t *)output_buffer;
	*hash_size = digest_size;
	memcpy(*hash, cert_digest, digest_size);

	output_buffer = output_buffer + digest_size;
	memcpy(output_buffer, cert_chain, cert_chain_size);

	*size = cert_chain_size + sizeof(spdm_cert_chain_t) + digest_size;
	free(cert_chain);

	return true;
}
