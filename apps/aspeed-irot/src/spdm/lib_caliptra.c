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
#include "hal/library/responder/measlib.h"
#include "hal/library/responder/keyexlib.h"
#include "library/spdm_crypt_lib.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/cptra.h>
#include <zephyr/drivers/misc/aspeed/cptra_ipc.h>

#include <stdlib.h>

LOG_MODULE_REGISTER(spdm_secret);

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
libspdm_return_t libspdm_measurement_collection(
		void *spdm_context,
		const uint32_t *session_id,
		spdm_version_number_t spdm_version,
		uint8_t measurement_specification,
		uint32_t measurement_hash_algo,
		uint8_t mesurements_index,
		uint8_t request_attribute,
		const uint8_t *requester_nonce,
		uint8_t slot_id_param,
		size_t request_context_size,
		const void *request_context,
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
		void *spdm_context,
		const uint32_t *session_id,
		spdm_version_number_t spdm_version,
		uint8_t measurement_specification,
		uint32_t measurement_hash_algo,
		uint8_t measurement_index,
		uint8_t request_attribute,
		size_t request_context_size,
		const void *request_context,
		void *opaque_data,
		size_t *opaque_data_size)
{
	*opaque_data_size = 0;
	return true;
}

bool libspdm_generate_measurement_summary_hash(
		void *spdm_context,
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
		void *spdm_context,
		spdm_version_number_t spdm_version,
		uint8_t slot_id,
		size_t request_context_size,
		const void *request_context,
		void *opaque_data,
		size_t *opaque_data_size)
{
	*opaque_data_size = 0;
	return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
bool libspdm_key_exchange_rsp_opaque_data(
		void *spdm_context,
		spdm_version_number_t spdm_version,
		uint8_t measurement_hash_type,
		uint8_t slot_id,
		uint8_t session_policy,
		const void *req_opaque_data,
		size_t req_opaque_data_size,
		void *opaque_data,
		size_t *opaque_data_size)
{
	/* false: let libspdm emit the default secured-message version selection */
	return false;
}

bool libspdm_finish_rsp_opaque_data(
		void *spdm_context,
		uint32_t session_id,
		spdm_version_number_t spdm_version,
		uint8_t req_slot_id,
		const void *req_opaque_data,
		size_t req_opaque_data_size,
		void *opaque_data,
		size_t *opaque_data_size)
{
	/* Only consulted for SPDM 1.4+, where false is an error: send no opaque data */
	*opaque_data_size = 0;
	return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */

bool libspdm_responder_data_sign(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t key_pair_id, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t pqc_asym_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    /*
     * Signing is delegated to Caliptra, which owns the private key, so there is
     * no local asym context to allocate or release here.
     */
    void *context = NULL;
    bool result;

    if (is_data_hash) {
        result = libspdm_asym_sign_hash(spdm_version, op_code, base_asym_algo, base_hash_algo,
                                        context,
                                        message, message_size, signature, sig_size);
    } else {
        result = libspdm_asym_sign(spdm_version, op_code, base_asym_algo,
                                   base_hash_algo, context,
                                   message, message_size,
                                   signature, sig_size);
    }

#if LIBSPDM_SECRET_LIB_SIGN_LITTLE_ENDIAN
    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) <= SPDM_MESSAGE_VERSION_11) {
        if (result) {
            libspdm_copy_signature_swap_endian(
                base_asym_algo, signature, *sig_size, signature, *sig_size);
        }
    }
#endif

    return result;
}

/*
 * Only the HAL hooks for capabilities enabled in libspdm_config.h are provided
 * here. MEL, MUT_AUTH, PSK, SET_CERT, CSR, EVENT and GET/SET_KEY_PAIR_INFO are
 * disabled; enabling one of them requires implementing its hooks against the
 * libspdm 4.0 prototypes in include/hal/library.
 */


#define CPTRA_CERT_CHAIN_BUF_SIZE 4096

/*
 * GetCertificateChain only returns the DICE certificates up to the Rt Alias.
 * The DPE leaf certificate for the current context is obtained separately with
 * the CERTIFY_KEY_EXTENDED mailbox command, and is appended to the chain so
 * that the root-to-leaf chain handed to SPDM is complete.
 *
 * Returns the DER size of the leaf certificate on success, 0 otherwise.
 */
uint32_t cptra_get_certify_key_leaf_cert(uint8_t *cert, size_t cert_max_size)
{
	struct cptra_certify_key_extended_ia input;
	struct cptra_certify_key_extended_oa *output;
	struct dpe_certify_key_o *certify_key_resp;
	uint32_t cert_size = 0;
	int ret;

	/* The response holds a certificate of up to 6KB, keep it off the stack */
	output = malloc(sizeof(*output));
	if (!output) {
		LOG_ERR("Failed to allocate CertifyKey response buffer");
		return 0;
	}

	memset(&input, 0, sizeof(input));
	memset(output, 0, sizeof(*output));

	/* All-zero request: default context handle, flags 0, FORMAT_X509, empty label */
	ret = cptra_ipc_transfer(CPTRA_IPCCMD_CERTIFY_KEY_EXTENDED,
				 (uint32_t *)&input, sizeof(input),
				 CPTRA_IPC_RX_TYPE_EXTERNAL,
				 (uint32_t *)output, sizeof(*output));
	if (ret) {
		LOG_ERR("caliptra_certify_key_extended is failure, ret:0x%x", ret);
		goto out;
	}

	certify_key_resp = (struct dpe_certify_key_o *)output->certify_key_resp;
	if (certify_key_resp->rsp_hdr.magic != DPE_RESPONSE_MAGIC ||
	    certify_key_resp->rsp_hdr.status != 0) {
		LOG_ERR("DPE CertifyKey failed, magic:0x%08x status:0x%08x profile:0x%08x",
			certify_key_resp->rsp_hdr.magic, certify_key_resp->rsp_hdr.status,
			certify_key_resp->rsp_hdr.profile);
		goto out;
	}

	if (certify_key_resp->cert_size == 0 ||
	    certify_key_resp->cert_size >
		    sizeof(output->certify_key_resp) - sizeof(struct dpe_certify_key_o) ||
	    certify_key_resp->cert_size > cert_max_size) {
		LOG_ERR("Invalid CertifyKey cert_size:%u", certify_key_resp->cert_size);
		goto out;
	}

	cert_size = certify_key_resp->cert_size;
	memcpy(cert, certify_key_resp->cert, cert_size);
out:
	free(output);
	return cert_size;
}

void cptra_invoke_dpe_get_certificate_chain(void **cert_chain, uint32_t *chain_size)
{
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_get_certificate_chain_i *get_certificate_chain_input = NULL;
	struct dpe_get_certificate_chain_o *get_certificate_chain_output = NULL;
	uint8_t *certificate_chain = malloc(CPTRA_CERT_CHAIN_BUF_SIZE * 2); // Assuming the certificate chain won't exceed 4KB. Adjust as needed.
						    //
	if (certificate_chain == NULL) {
		LOG_ERR("Failed to allocate memory for certificate chain");
		return;
	}
	uint32_t leaf_size;
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

			if (get_certificate_chain_output->size >
			    (CPTRA_CERT_CHAIN_BUF_SIZE*2) - offset) {
				LOG_ERR("Certificate chain exceeds the %u byte buffer",
					(CPTRA_CERT_CHAIN_BUF_SIZE*2));
				goto exit;
			}

			memcpy(certificate_chain + offset,
			       get_certificate_chain_output->cert_chain,
			       get_certificate_chain_output->size);

			offset += get_certificate_chain_output->size;
			if (get_certificate_chain_output->size <
			    sizeof(get_certificate_chain_output->cert_chain)) {
				break;
			}
		}

	} while (1);

	/*
	 * GetCertificateChain already returns the DICE certificates in
	 * root-to-leaf order (LDevID, FMC Alias, Rt Alias). Append the DPE leaf
	 * certificate from CERTIFY_KEY_EXTENDED to complete the chain.
	 */
	leaf_size = cptra_get_certify_key_leaf_cert(certificate_chain + offset,
						    (CPTRA_CERT_CHAIN_BUF_SIZE * 2) - offset);
	if (leaf_size == 0)
		LOG_WRN("No DPE leaf certificate, chain ends at the Rt Alias certificate");

	offset += leaf_size;

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

	/* Without LARGE_RESP_CAP the Length field on the wire is 16 bits */
	if (cert_chain_size + sizeof(spdm_cert_chain_t) + digest_size > UINT16_MAX) {
		LOG_ERR("Certificate chain too large: %u bytes", cert_chain_size);
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
	/*
	 * libspdm 4.0 models the header as a single 32-bit length. Without
	 * LARGE_RESP_CAP (not advertised) the wire format is Length(2) + Reserved(2);
	 * little-endian storage of a value below 64KB yields exactly that.
	 */
	output_cert_chain_header->length = cert_chain_size + sizeof(spdm_cert_chain_t) + digest_size;

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
