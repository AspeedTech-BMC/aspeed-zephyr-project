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
#include <cptra/cptra_api.h>

#include <inttypes.h>
#include <stdlib.h>

#include "spdm/irot_ec.h"

LOG_MODULE_REGISTER(spdm_secret);

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
/*
 * The only measurement reported over SPDM is index 0xFD, the measurement
 * manifest: the complete Caliptra QUOTE_PCRS response (PCR[0..31], nonce,
 * digest, reset counters and the ECDSA signature by Caliptra's FMC Alias key,
 * the key Caliptra signs PCR quotes with) as a raw freeform manifest, so a
 * verifier can check the Caliptra-signed quote on its own.
 *
 * The block is always raw (type bit 7 set), whatever RawBitStreamRequested
 * says: request_attribute is ignored on purpose, because a manifest has no
 * digest form.
 */
#define IROT_MANIFEST_INDEX	SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST
#define IROT_MANIFEST_TYPE	(SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST | \
				 SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM)
#define IROT_MANIFEST_BLOCK_SIZE \
	(sizeof(spdm_measurement_block_dmtf_t) + sizeof(struct cptra_quote_pcrs_oa))
#define IROT_MEASUREMENT_COUNT	1

BUILD_ASSERT(sizeof(((struct cptra_quote_pcrs_ia *)0)->nonce) == SPDM_NONCE_SIZE,
	     "QUOTE_PCRS nonce must carry the SPDM requester nonce");
BUILD_ASSERT(sizeof(struct cptra_quote_pcrs_oa) <= UINT16_MAX - sizeof(spdm_measurement_block_dmtf_header_t),
	     "Quote does not fit in one DMTF measurement block");

/*
 * Ask Caliptra for a signed PCR quote. When the requester supplied a nonce
 * (signed GET_MEASUREMENTS) it is bound into the quote; otherwise it is zero.
 */
static int irot_quote_pcrs(const uint8_t *nonce, struct cptra_quote_pcrs_oa *output)
{
	struct cptra_quote_pcrs_ia input;
	int ret;

	memset(&input, 0, sizeof(input));
	memset(output, 0, sizeof(*output));

	/*
	 * Caliptra hashes the nonce with its eight 32-bit words in reverse order:
	 * digest = SHA384(PCR[0..31] || word-reversed nonce). Pre-reverse the words
	 * so the quote digest is a plain SHA384(PCR[0..31] || requester nonce).
	 * The nonce field Caliptra echoes in the quote is therefore word-reversed.
	 */
	if (nonce) {
		const size_t words = sizeof(input.nonce) / sizeof(uint32_t);

		for (size_t i = 0; i < words; i++)
			memcpy(&input.nonce[i * sizeof(uint32_t)],
			       &nonce[(words - 1 - i) * sizeof(uint32_t)], sizeof(uint32_t));
	}

	ret = cptra_ipc_transfer(CPTRA_IPCCMD_QUOTE_PCRS, (uint32_t *)&input, sizeof(input),
				 CPTRA_IPC_RX_TYPE_EXTERNAL, (uint32_t *)output, sizeof(*output));
	if (ret) {
		LOG_ERR("caliptra_quote_pcrs is failure, ret:0x%x", ret);
		return -1;
	}

	if (output->fips_status != 0) {
		LOG_ERR("FIPS error from caliptra, status:0x%x", output->fips_status);
		return -1;
	}

	LOG_DBG("caliptra_quote_pcrs is successful");
	return 0;
}

/* Write the 0xFD manifest block holding the whole quote; return its size. */
static size_t irot_fill_manifest_block(uint8_t *buf, const struct cptra_quote_pcrs_oa *quote)
{
	spdm_measurement_block_dmtf_t *block = (spdm_measurement_block_dmtf_t *)buf;

	block->measurement_block_common_header.index = IROT_MANIFEST_INDEX;
	block->measurement_block_common_header.measurement_specification =
		SPDM_MEASUREMENT_SPECIFICATION_DMTF;
	block->measurement_block_common_header.measurement_size =
		sizeof(spdm_measurement_block_dmtf_header_t) + sizeof(*quote);
	block->measurement_block_dmtf_header.dmtf_spec_measurement_value_type = IROT_MANIFEST_TYPE;
	block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size = sizeof(*quote);
	memcpy(buf + sizeof(*block), quote, sizeof(*quote));

	return IROT_MANIFEST_BLOCK_SIZE;
}

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
	struct cptra_quote_pcrs_oa quote;
	size_t size;

	/*
	 * libspdm does not initialize this and ORs it into MEASUREMENTS Param2
	 * of signed 1.2+ responses. Measurements are read live from Caliptra on
	 * every request and changes between requests are not tracked, so report
	 * "no detection" (00b) rather than claiming that nothing changed.
	 */
	if (content_changed != NULL)
		*content_changed = SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_NO_DETECTION;

	switch (mesurements_index) {
	case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS:
		/* Count only: no need to ask Caliptra for a quote */
		*device_measurement_count = IROT_MEASUREMENT_COUNT;
		return LIBSPDM_STATUS_SUCCESS;
	case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS:
	case IROT_MANIFEST_INDEX:
		break;
	default:
		return LIBSPDM_STATUS_MEAS_INVALID_INDEX;
	}

	if (IROT_MANIFEST_BLOCK_SIZE > *device_measurement_size) {
		LOG_ERR("buffer too small: need %zu, have %zu", IROT_MANIFEST_BLOCK_SIZE,
			*device_measurement_size);
		return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
	}

	/*
	 * libspdm turns any error other than MEAS_INVALID_INDEX into
	 * ERROR(Unspecified); the specific status here is only for the log.
	 */
	if (irot_quote_pcrs(requester_nonce, &quote))
		return LIBSPDM_STATUS_BUSY_PEER;

	size = irot_fill_manifest_block(device_measurement, &quote);
	*device_measurement_count = IROT_MEASUREMENT_COUNT;
	*device_measurement_size = size;

	LOG_INF("Measurement index 0x%02x: manifest %zu bytes, nonce %s",
		mesurements_index, size, requester_nonce ? "bound" : "zero");
	LOG_HEXDUMP_DBG(device_measurement, size, "Measurement Block:");

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

/*
 * MeasurementSummaryHash per DSP0274: the hash, with the negotiated base hash
 * algorithm, of the concatenated measurement blocks exactly as GET_MEASUREMENTS
 * encodes them.
 *
 * The 0xFD manifest is the only measurement, so TCB and ALL both hash that one
 * block: every reported value is Caliptra PCR state, which is all TCB. It is
 * built from a quote with a zero nonce, i.e. the block an unsigned
 * GET_MEASUREMENTS returns, so a verifier can reproduce the summary.
 *
 * That only holds while Caliptra's quote signature is deterministic for a given
 * input (RFC 6979 style, as observed on hardware) and the PCRs and reset
 * counters do not change. If Caliptra moves to hedged/randomized ECDSA, the
 * block changes on every quote and this summary can no longer be reproduced.
 * Each call costs one Caliptra QUOTE_PCRS (quote + sign).
 */
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
	struct cptra_quote_pcrs_oa quote;
	uint8_t *block;
	size_t size;
	bool result;

	if (measurement_summary_hash_type != SPDM_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH &&
	    measurement_summary_hash_type != SPDM_REQUEST_ALL_MEASUREMENTS_HASH)
		return false;

	if (measurement_summary_hash_size != libspdm_get_hash_size(base_hash_algo)) {
		LOG_ERR("summary hash size %u does not match hash algo 0x%x",
			measurement_summary_hash_size, base_hash_algo);
		return false;
	}

	if (irot_quote_pcrs(NULL, &quote))
		return false;

	block = malloc(IROT_MANIFEST_BLOCK_SIZE);
	if (!block) {
		LOG_ERR("Failed to allocate measurement summary buffer");
		return false;
	}

	size = irot_fill_manifest_block(block, &quote);
	result = libspdm_hash_all(base_hash_algo, block, size, measurement_summary_hash);
	free(block);

	if (!result)
		LOG_ERR("Failed to hash measurement block");

	return result;
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
     * no local asym context to allocate or release here; the marker routes the
     * request to Caliptra in ec.c.
     */
    void *context = &irot_caliptra_identity_key;
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

/*
 * Build the SPDM certificate chain for slot 0 (DSP0274 "Certificate chain
 * format"):
 *
 *   Length | Reserved | RootHash | ASPEED root CA | ASPEED sub CA | IDevID |
 *   LDevID | FMC Alias | Rt Alias | DPE leaf
 *
 * The chain starts at the ASPEED root CA, so it is self-contained, and the sub
 * CA that issued this part's IDevID is included so a verifier holding only the
 * ASPEED root can validate every link. RootHash is the hash of the root CA
 * certificate, which is what a requester matches against its trust anchors.
 * Both CA certificates come from the cache that cptra_load_certificate()
 * fills during iRoT init, before MCTP (and so SPDM) starts.
 *
 * hash and hash_size are optional.
 */
bool libspdm_read_responder_public_certificate_chain(
		uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
		size_t *size, void **hash, size_t *hash_size)
{
	void *root_ca = NULL, *sub_ca = NULL, *cptra_chain = NULL;
	uint32_t root_ca_size = 0, sub_ca_size = 0, cptra_chain_size = 0;
	spdm_cert_chain_t *header;
	size_t digest_size, total_size;
	uint8_t *out;
	bool ret = false;

	if (data == NULL || size == NULL)
		return false;

	*data = NULL;

	digest_size = libspdm_get_hash_size(base_hash_algo);
	if (digest_size == 0) {
		LOG_ERR("Unsupported hash algorithm: 0x%08X", base_hash_algo);
		return false;
	}

	if (cptra_get_cached_certificate(CPTRA_CACHED_ASPEED_ROOT_CA_CERT, &root_ca,
					 &root_ca_size)) {
		LOG_ERR("ASPEED root CA certificate is not available");
		goto out;
	}

	if (cptra_get_cached_certificate(CPTRA_CACHED_ASPEED_SUB_CA_CERT, &sub_ca,
					 &sub_ca_size)) {
		LOG_ERR("No ASPEED sub CA matches this part's IDevID issuer");
		goto out;
	}

	cptra_invoke_dpe_get_certificate_chain(&cptra_chain, &cptra_chain_size);
	if (cptra_chain == NULL || cptra_chain_size == 0) {
		LOG_ERR("Failed to get certificate chain from Caliptra");
		goto out;
	}

	total_size = sizeof(spdm_cert_chain_t) + digest_size + root_ca_size + sub_ca_size +
		     cptra_chain_size;
	/* Without LARGE_RESP_CAP the Length field on the wire is 16 bits */
	if (total_size > UINT16_MAX) {
		LOG_ERR("Certificate chain too large: %zu bytes", total_size);
		goto out;
	}

	*data = malloc(total_size);
	if (*data == NULL) {
		LOG_ERR("Failed to allocate memory for output certificate chain");
		goto out;
	}

	out = (uint8_t *)*data;
	header = (spdm_cert_chain_t *)out;
	/*
	 * libspdm 4.0 models the header as a single 32-bit length. Without
	 * LARGE_RESP_CAP (not advertised) the wire format is Length(2) + Reserved(2);
	 * little-endian storage of a value below 64KB yields exactly that.
	 */
	header->length = total_size;
	out += sizeof(spdm_cert_chain_t);

	/* RootHash: hash of the root certificate, not of the whole chain */
	if (!libspdm_hash_all(base_hash_algo, root_ca, root_ca_size, out)) {
		LOG_ERR("Failed to hash the root CA certificate");
		free(*data);
		*data = NULL;
		goto out;
	}
	if (hash != NULL)
		*hash = out;
	if (hash_size != NULL)
		*hash_size = digest_size;
	out += digest_size;

	memcpy(out, root_ca, root_ca_size);
	out += root_ca_size;
	memcpy(out, sub_ca, sub_ca_size);
	out += sub_ca_size;
	memcpy(out, cptra_chain, cptra_chain_size);

	*size = total_size;
	LOG_INF("SPDM certificate chain: %zu bytes (root CA %" PRIu32 ", sub CA %" PRIu32
		", Caliptra %" PRIu32 ")",
		total_size, root_ca_size, sub_ca_size, cptra_chain_size);
	ret = true;
out:
	free(root_ca);
	free(sub_ca);
	free(cptra_chain);
	return ret;
}
