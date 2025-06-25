/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/random/random.h>
#include <stdlib.h>
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm, CONFIG_LOG_DEFAULT_LEVEL);

static mbedtls_x509_crt system_root_ca;

int random_callback(void *context, unsigned char *output, size_t output_len)
{
	sys_rand_get(output, output_len);
	return 0;
}

void *spdm_context_create(void)
{
	struct spdm_context *context = (struct spdm_context *)malloc(sizeof(struct spdm_context));

	if (context == NULL) {
		LOG_ERR("Failed to allocate memory for context");
		return NULL;
	}

	context->release_connection_data = NULL;
	context->connection_state = SPDM_STATE_NOT_READY;

	context->local.version.version_number_entry_count = 3;
	context->local.version.version_number_selected = SPDM_VERSION_10;
	context->local.version.version_number_entry[0] = SPDM_VERSION_12 << SPDM_VERSION_NUMBER_ENTRY_SHIFT_BIT;
	context->local.version.version_number_entry[1] = SPDM_VERSION_11 << SPDM_VERSION_NUMBER_ENTRY_SHIFT_BIT;
	context->local.version.version_number_entry[2] = SPDM_VERSION_10 << SPDM_VERSION_NUMBER_ENTRY_SHIFT_BIT;

	context->remote.version.version_number_entry_count = 0;
	context->remote.version.version_number_selected = SPDM_VERSION_10;
	context->remote.version.version_number_entry[0] = 0;
	context->remote.version.version_number_entry[1] = 0;
	context->remote.version.version_number_entry[2] = 0;

	/* Set CT to 32768us due to mbedtls ecdsa */
	context->local.capabilities.ct_exponent = 15;
#if defined(CONFIG_SECURE_CONNECTION_REQUESTER) || defined(CONFIG_SECURE_CONNECTION_RESPONDER)
	context->local.capabilities.flags = SPDM_CHAL_CAP | SPDM_CERT_CAP | SPDM_MEAS_CAP_SIG |
		SPDM_KEY_EX_CAP | SPDM_KEY_UPD_CAP | SPDM_HBEAT_CAP | SPDM_ENCRYPT_CAP |
		SPDM_MAC_CAP | SPDM_PSK_CAP | SPDM_HANDSHAKE_IN_THE_CLEAR_CAP;

	/*
	 * SPDM_ENCAP_CAP and SPDM_MUT_AUTH_CAP should be set at the same time
	 * for Mutual Authentication
	 */
	context->local.capabilities.flags |= (SPDM_MUT_AUTH_CAP | SPDM_ENCAP_CAP);
#else
	context->local.capabilities.flags = SPDM_CHAL_CAP | SPDM_CERT_CAP | SPDM_MEAS_CAP_SIG;
#endif
	context->local.capabilities.data_transfer_size = 256;
	context->local.capabilities.max_spdm_msg_size = 256;

	context->local.algorithms.length = 0;
	context->local.algorithms.measurement_spec_sel = SPDM_MEASUREMENT_BLOCK_DMTF_SPEC;
#if defined(CONFIG_SECURE_CONNECTION_REQUESTER) || defined(CONFIG_SECURE_CONNECTION_RESPONDER)
	context->local.algorithms.other_param_sel = GENERAL_OPAQUE_DATA_MODE;
#else
	context->local.algorithms.other_param_sel = 0;
#endif
	context->local.algorithms.measurement_hash_algo = SPDM_ALGORITHMS_MEAS_HASH_TPM_ALG_SHA_384;
	context->local.algorithms.base_asym_sel =  SPDM_ALGORITHMS_BASE_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
	context->local.algorithms.base_hash_sel = SPDM_ALGORITHMS_BASE_HASH_TPM_ALG_SHA_384;
	context->local.algorithms.ext_asym_sel_count = 0;
	context->local.algorithms.ext_hash_sel_count = 0;
	context->local.algorithms.ext_asym_sel[0] = 0;
	context->local.algorithms.ext_hash_sel[0] = 0;

	context->local.certificate.slot_mask = 0;
	context->remote.certificate.slot_mask = 0;
	for (size_t i = 0; i < 8; ++i) {
		context->local.certificate.certs[i].size = 0;
		context->local.certificate.certs[i].data = NULL;
		mbedtls_x509_crt_init(&context->local.certificate.certs[i].chain);

		context->remote.certificate.certs[i].size = 0;
		context->remote.certificate.certs[i].data = NULL;
		mbedtls_x509_crt_init(&context->remote.certificate.certs[i].chain);
	}

	context->get_measurement = NULL;

	spdm_buffer_init(&context->message_a, 0);
#if defined(SPDM_TRANSCRIPT)
	spdm_buffer_init(&context->message_b, 0);
	spdm_buffer_init(&context->message_c, 0);
#else
	spdm_context_reset_m1m2_hash(context);
#endif

	mbedtls_sha512_init(&context->l1l2_context);
	mbedtls_sha512_starts(&context->l1l2_context, /* is384 */ 1);

	mbedtls_ecp_keypair_init(&context->key_pair);

	context->random_callback = random_callback;

	return (void *)context;
}

void spdm_context_release(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;

	for (size_t slot_id = 0; slot_id < 8; ++slot_id) {
		if (context->local.certificate.certs[slot_id].data) {
			free(context->local.certificate.certs[slot_id].data);
			context->local.certificate.certs[slot_id].data = NULL;
			context->local.certificate.certs[slot_id].size = 0;
		}
		if (context->remote.certificate.certs[slot_id].data) {
			free(context->remote.certificate.certs[slot_id].data);
			context->remote.certificate.certs[slot_id].data = NULL;
			context->remote.certificate.certs[slot_id].size = 0;
		}
		mbedtls_x509_crt_free(&context->local.certificate.certs[slot_id].chain);
		mbedtls_x509_crt_free(&context->remote.certificate.certs[slot_id].chain);
	}

	mbedtls_ecp_keypair_free(&context->key_pair);
	spdm_buffer_release(&context->message_a);
#if defined(SPDM_TRANSCRIPT)
	spdm_buffer_release(&context->message_b);
	spdm_buffer_release(&context->message_c);
#else
	/* TODO: Assuming the hash algorithm is SHA384 */
	mbedtls_sha512_free(&context->m1m2_context);
#endif
	/* TODO: Assuming the hash algorithm is SHA384 */
	mbedtls_sha512_free(&context->l1l2_context);
	if (context->release_connection_data)
		context->release_connection_data(context);
	free(context);
}

bool is_root_cert(uint8_t *cert_data, uint16_t len)
{
	mbedtls_x509_crt cert;
	int ret = false;

	mbedtls_x509_crt_init(&cert);
	ret = mbedtls_x509_crt_parse_der(&cert, cert_data, len);
	if (ret) {
		LOG_ERR("mbedtls_x509_crt_parse_der return failure, ret = %x", -ret);
		ret = false;
		goto out;
	}

	if (cert.issuer_raw.len != cert.subject_raw.len)
		goto out;

	if (memcmp(cert.issuer_raw.p, cert.subject_raw.p, cert.issuer_raw.len))
		goto out;

	ret = true;
out:
	mbedtls_x509_crt_free(&cert);

	return ret;
}

int get_root_cert_len(uint8_t *cert_data, uint16_t cert_len, uint8_t **root_cert)
{
	uint8_t *tmp;
	uint8_t *current_cert;
	int ret;
	size_t asn1_len;
	size_t ca_cert_len;

	current_cert = cert_data;
	while (true) {
		tmp = current_cert;
		ret = mbedtls_asn1_get_tag(
			&tmp, cert_data + cert_len, &asn1_len,
			MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		if (ret != 0) {
			LOG_ERR("mbedtls_asn1_get_tag failed, ret = %x", ret);
			return -1;
		}
		ca_cert_len = asn1_len + (tmp - cert_data);

		if (is_root_cert(current_cert, ca_cert_len)) {
			*root_cert = current_cert;
			return ca_cert_len;
		}

		current_cert += ca_cert_len;
		if (current_cert >= cert_data + cert_len)
			return -1;
	}

	return -1;
}

int spdm_load_certificate(void *ctx, bool remote, uint8_t slot_id, void *cert_data, uint16_t cert_len)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_certificate_info *cert_info = &context->local.certificate;
	int len;
	uint8_t *root_cert = NULL;

	if (remote)
		cert_info = &context->remote.certificate;

	if (slot_id > 7) {
		LOG_ERR("Invalid slot_id[%d]", slot_id);
		return -1;
	}

	if (cert_info->slot_mask & (1<<slot_id)) {
		LOG_ERR("Slot_id[%d] already occupied, slot_mask[%x]", slot_id, cert_info->slot_mask);
		return -1;
	}

	/* TODO: Copy certificate or just assign the pointer? */
	cert_info->slot_mask |= 1 << slot_id;

	cert_info->certs[slot_id].data = malloc(cert_len + 4 + 48);
	if (cert_info->certs[slot_id].data == NULL) {
		LOG_ERR("Failed to allocate for certificate (%d)", cert_len);
		return -1;
	}
	memcpy(cert_info->certs[slot_id].data + 4 + 48, cert_data, cert_len);
	cert_info->certs[slot_id].size = cert_len + 4 + 48;
	cert_info->certs[slot_id].data[0] = (cert_len + 4 + 48) & 0xff;
	cert_info->certs[slot_id].data[1] = ((cert_len + 4 + 48) >> 8) & 0xff;
	/* Hash the  Root Cert */
	len = get_root_cert_len(cert_data, cert_len, &root_cert);
	if (len < 0) {
		LOG_ERR("Can't find root cert from the certificate chain");
		return -1;
	}
	LOG_DBG("root cert len = %d", len);
	mbedtls_sha512(root_cert, len, cert_info->certs[slot_id].data + 4, 1);

	mbedtls_sha512(cert_info->certs[slot_id].data, cert_info->certs[slot_id].size,
		cert_info->certs[slot_id].digest, 1);

	return 0;
}

#if defined(CONFIG_BOARD_AST1060_DCSCM_DICE) || defined(CONFIG_BOARD_AST1060_DUAL_FLASH_DICE)
int spdm_append_certificate_chain(void *ctx, bool remote, uint8_t slot_id, void *cert_data, uint16_t cert_len)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_certificate_info *cert_info = &context->local.certificate;
	uint16_t old_chain_len, new_chain_len;
	uint8_t *tmp;

	if (remote)
		cert_info = &context->remote.certificate;

	if (slot_id > 7) {
		LOG_ERR("Invalid slot_id[%d]", slot_id);
		return -1;
	}

	if ((cert_info->slot_mask & (1<<slot_id)) == 0) {
		// Slot is not occupied, to use spdm_load_certificate instead
		return spdm_load_certificate(ctx, remote, slot_id, cert_data, cert_len);
	}

	// To reallocate memory for existed certificate chain and new certificate
	old_chain_len = cert_info->certs[slot_id].size;
	new_chain_len = old_chain_len + cert_len;
	tmp = malloc(new_chain_len);
	if (tmp == NULL) {
		LOG_ERR("Failed to allocate the memory (%d)", new_chain_len);
		return -1;
	}
	// To move data to new buffer and release old buffer
	memcpy(tmp, cert_info->certs[slot_id].data, old_chain_len);
	free(cert_info->certs[slot_id].data);
	cert_info->certs[slot_id].data = tmp;
	memcpy(&tmp[old_chain_len], cert_data, cert_len);
	cert_info->certs[slot_id].size = new_chain_len;
	cert_info->certs[slot_id].data[0] = (new_chain_len) & 0xff;
	cert_info->certs[slot_id].data[1] = ((new_chain_len) >> 8) & 0xff;

	/*
	 * This function is used to append alias certificate to
	 * certificate chain so we don't need to calculate the root
	 * cert hash again.
	 */
	mbedtls_sha512(cert_info->certs[slot_id].data, cert_info->certs[slot_id].size,
		cert_info->certs[slot_id].digest, 1);

	return 0;
}
#endif

int spdm_load_root_certificate(void *cert_data, uint16_t cert_len)
{
	/* Root Certificate */
	return mbedtls_x509_crt_parse_der_nocopy(&system_root_ca, cert_data, cert_len);
}

mbedtls_x509_crt *spdm_get_root_certificate(void)
{
	return &system_root_ca;
}

int append_next_certificate(mbedtls_x509_crt *crt_chain, uint8_t *current_cert, size_t current_cert_len)
{
	mbedtls_x509_crt *new_crt, *last_ca_crt;
	int ret, flags;

	new_crt = calloc(1, sizeof(mbedtls_x509_crt));
	if (new_crt == NULL) {
		LOG_ERR("Failed to allocate crt (%d)", sizeof(mbedtls_x509_crt));
		return -1;
	}

	mbedtls_x509_crt_init(new_crt);
	ret = mbedtls_x509_crt_parse_der_nocopy(new_crt, current_cert, current_cert_len);
	if (ret < 0) {
		mbedtls_x509_crt_free(new_crt);
		free(new_crt);
		return -1;
	}

	/* find the last CA certificate from certificate chain */
	last_ca_crt = crt_chain;
	while (last_ca_crt->next)
		last_ca_crt = last_ca_crt->next;

	ret = mbedtls_x509_crt_verify(new_crt, last_ca_crt, NULL, NULL, &flags, NULL, NULL);

	/* if new certificate is verified, to append it */
	if (ret == 0)
		last_ca_crt->next = new_crt;
	else {
		mbedtls_x509_crt_free(new_crt);
		free(new_crt);
	}

	return ret;
}

size_t spdm_context_base_hash_size(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	size_t ret = -1;

	switch (context->remote.algorithms.base_hash_sel) {
	case SPDM_ALGORITHMS_BASE_HASH_TPM_ALG_SHA_384:
		ret = 48;
		break;
	default:
		LOG_ERR("Unsupported base_hash_sel = %x", context->remote.algorithms.base_hash_sel);
		break;
	}

	return ret;
}

size_t spdm_context_base_algo_size(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	size_t ret = -1;

	switch (context->remote.algorithms.base_asym_sel) {
	case SPDM_ALGORITHMS_BASE_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
		ret = 48 * 2;
		break;
	default:
		LOG_ERR("Unsupported base_asym_sel = %x", context->remote.algorithms.base_asym_sel);
		break;
	}

	return ret;

}

size_t spdm_context_measurement_hash_size(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	size_t ret = -1;

	switch (context->remote.algorithms.base_hash_sel) {
	case SPDM_ALGORITHMS_MEAS_HASH_TPM_ALG_SHA_384:
		ret = 48;
		break;
	default:
		LOG_ERR("Unsupported measurement_hash_sel = %x", context->remote.algorithms.base_hash_sel);
		break;
	}

	return ret;
}

void spdm_context_reset_m1m2_hash(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;

	mbedtls_sha512_free(&context->m1m2_context);
	mbedtls_sha512_init(&context->m1m2_context);
	mbedtls_sha512_starts(&context->m1m2_context, /* is384 */ 1);
}

void spdm_context_update_m1m2_hash(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;

	LOG_HEXDUMP_DBG((const unsigned char *)&req_msg->header, sizeof(req_msg->header), "M1M2 Append REQ Header");
	LOG_HEXDUMP_DBG((const unsigned char *)req_msg->buffer.data, req_msg->buffer.write_ptr, "M1M2 Append REQ Payload");
	LOG_HEXDUMP_DBG((const unsigned char *)&rsp_msg->header, sizeof(rsp_msg->header), "M1M2 Append RSP Header");
	LOG_HEXDUMP_DBG((const unsigned char *)rsp_msg->buffer.data, rsp_msg->buffer.write_ptr, "M1M2 Append RSP Payload");
	mbedtls_sha512_update(&context->m1m2_context,
			(const unsigned char *)&req_msg->header,
			sizeof(req_msg->header));
	mbedtls_sha512_update(&context->m1m2_context,
			(const unsigned char *)req_msg->buffer.data,
			req_msg->buffer.write_ptr);
	mbedtls_sha512_update(&context->m1m2_context,
			(const unsigned char *)&rsp_msg->header,
			sizeof(rsp_msg->header));
	mbedtls_sha512_update(&context->m1m2_context,
			(const unsigned char *)rsp_msg->buffer.data,
			rsp_msg->buffer.write_ptr);
}

void spdm_context_reset_l1l2_hash(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;

	mbedtls_sha512_free(&context->l1l2_context);
	mbedtls_sha512_init(&context->l1l2_context);
	mbedtls_sha512_starts(&context->l1l2_context, /* is384 */ 1);

	LOG_DBG("RESET L1L2 BUFFER");
}

void spdm_context_update_l1l2_hash_buffer(void *ctx, void *buf)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_buffer *buffer = (struct spdm_buffer *)buf;

	LOG_HEXDUMP_DBG(buffer->data, buffer->write_ptr, "UPDATE L1L2 BUFFER VCA");

	mbedtls_sha512_update(&context->l1l2_context, buffer->data, buffer->write_ptr);
}

void spdm_context_update_l1l2_hash(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;

	LOG_HEXDUMP_DBG(&req_msg->header, sizeof(req_msg->header),
			"UPDATE L1L2 req_msg->header");
	LOG_HEXDUMP_DBG((const unsigned char *)req_msg->buffer.data, req_msg->buffer.write_ptr,
			"UPDATE L1L2 req_msg->buffer");
	LOG_HEXDUMP_DBG(&rsp_msg->header, sizeof(rsp_msg->header),
			"UPDATE L1L2 rsp_msg->header");
	LOG_HEXDUMP_DBG((const unsigned char *)rsp_msg->buffer.data, rsp_msg->buffer.write_ptr,
			"UPDATE L1L2 rsp_msg->buffer");
	mbedtls_sha512_update(&context->l1l2_context,
			(const unsigned char *)&req_msg->header,
			sizeof(req_msg->header));
	mbedtls_sha512_update(&context->l1l2_context,
			(const unsigned char *)req_msg->buffer.data,
			req_msg->buffer.write_ptr);
	mbedtls_sha512_update(&context->l1l2_context,
			(const unsigned char *)&rsp_msg->header,
			sizeof(rsp_msg->header));
	mbedtls_sha512_update(&context->l1l2_context,
			(const unsigned char *)rsp_msg->buffer.data,
			rsp_msg->buffer.write_ptr);
}


