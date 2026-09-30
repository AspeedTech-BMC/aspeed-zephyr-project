#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <cptra/cptra_api.h>
#include <cptra/cptra_ca_certs.h>
#include <zephyr/drivers/cptra.h>
#include <zephyr/drivers/ipm.h>
#include <zephyr/drivers/misc/aspeed/cptra_ipc.h>
#include <zephyr/logging/log.h>
#include <zephyr/crypto/hash.h>
#include <image/caliptra_soc_manifest.h>
#include <mbedtls/sha512.h>

LOG_MODULE_REGISTER(cptra_api, LOG_LEVEL_DBG);

// Refactor this function into init, update and final function.
int cptra_sha384_init(void)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint8_t *p8_ssp_in = (uint8_t *)IPC_CHANNEL_1_SSP_IN_ADDR;
	int ipccmd = CPTRA_IPCCMD_SHA384_DIGEST;
	struct cptra_hash_ctx ctx;
	uint32_t data[2];
	int ret;
	/* Prepare tx data to bootmcu */
	data[0] = IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	data[1] = IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

	// Hash Init
	p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	p8_ssp_in = (uint8_t *)IPC_CHANNEL_1_SSP_IN_ADDR;
	memset(&ctx, 0, sizeof(ctx));
	ipccmd = CPTRA_IPCCMD_SHA384_INIT;
	ctx.algo = CRYPTO_HASH_ALGO_SHA384;
	{
		/* Copy input data structure into shared memory */
		memcpy(p8_ssp_in, &ctx, sizeof(struct cptra_hash_ctx));
		p8_ssp_in += sizeof(struct cptra_hash_ctx);

		ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
		if (ret) {
			LOG_ERR("cptra_ipc_trigger:0x%x is failure, ret:0x%x", ipccmd, ret);
			goto end;
		} else
			LOG_DBG("cptra_ipc_trigger:0x%x is successful", ipccmd);
		cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &ret, sizeof(ret));
	}
	
	return 0;
end:
	return ret;

}

int cptra_sha384_update(const char *msg, int msg_size)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint8_t *p8_ssp_in = (uint8_t *)IPC_CHANNEL_1_SSP_IN_ADDR;
	int ipccmd = CPTRA_IPCCMD_SHA384_DIGEST;
	struct cptra_hash_ctx ctx;
	uint32_t data[2];
	int ret;
	/* Prepare tx data to bootmcu */
	data[0] = IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	data[1] = IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

	// Hash Update
	int chunk_size = 4096 - sizeof(struct cptra_hash_ctx), offset = 0;
	while (offset < msg_size) {
		p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
		p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
		p8_ssp_in = (uint8_t *)IPC_CHANNEL_1_SSP_IN_ADDR;
		memset(&ctx, 0, sizeof(ctx));
		ipccmd = CPTRA_IPCCMD_SHA384_UPDATE;
		int current_chunk_size = MIN(chunk_size, msg_size - offset);
		ctx.algo = CRYPTO_HASH_ALGO_SHA384;
		ctx.in_len = current_chunk_size;
		ctx.in_buf = p8_bmcu_in + sizeof(struct cptra_hash_ctx);
		memcpy(p8_ssp_in, &ctx, sizeof(struct cptra_hash_ctx));
		p8_ssp_in += sizeof(struct cptra_hash_ctx);
		memcpy(p8_ssp_in, msg + offset, current_chunk_size);
		ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
		if (ret) {
			LOG_ERR("cptra_ipc_trigger:0x%x is failure, ret:0x%x", ipccmd, ret);
			goto end;
		} else
			LOG_DBG("cptra_ipc_trigger:0x%x is successful", ipccmd);
		cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, &ret, sizeof(ret));
		offset += current_chunk_size;
	}
	
	return 0;
end:
	return ret;
}

int cptra_sha384_final(uint8_t *output, int output_size)
{
	uint8_t *p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint8_t *p8_ssp_in = (uint8_t *)IPC_CHANNEL_1_SSP_IN_ADDR;
	int ipccmd = CPTRA_IPCCMD_SHA384_DIGEST;
	struct cptra_hash_ctx ctx;
	uint32_t data[2];
	int ret;
	/* Prepare tx data to bootmcu */
	data[0] = IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	data[1] = IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

	// Hash Finish
	p8_bmcu_out = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;
	p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	p8_ssp_in = (uint8_t *)IPC_CHANNEL_1_SSP_IN_ADDR;
	memset(&ctx, 0, sizeof(ctx));
	ipccmd = CPTRA_IPCCMD_SHA384_FINAL;
	ctx.algo = CRYPTO_HASH_ALGO_SHA384;
	ctx.out_len = output_size;
	ctx.out_buf = p8_bmcu_out;
	/* Copy input data structure into shared memory */
	memcpy(p8_ssp_in, &ctx, sizeof(struct cptra_hash_ctx));
	p8_ssp_in += sizeof(struct cptra_hash_ctx);
	/* Copy input data into shared memory */
	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		LOG_ERR("cptra_ipc_trigger:0x%x is failure, ret:0x%x", ipccmd, ret);
		goto end;
	} else
		LOG_DBG("cptra_ipc_trigger:0x%x is successful", ipccmd);
	cptra_ipc_receive(CPTRA_IPC_RX_TYPE_EXTERNAL, output, output_size);

	LOG_DBG("%s", __func__);

	return 0;
end:
	return ret;
}

int cptra_sha384(const char *msg, int msg_size, uint8_t *output, int output_size)
{
#if defined(CONFIG_SKIP_CPTRA_FW_VERIFICATION)
	// using mbedtls sha384 implementation to replace cptra sha384 for testing purpose when fw verification is skipped.
	LOG_WRN("FW verification is skipped, bypassing %s", __func__);
	mbedtls_sha512((const unsigned char *)msg, msg_size, output, 1);
	return 0;
#endif
	int ret = cptra_sha384_init();
	if (ret) {
		LOG_ERR("cptra_sha384_init failed, ret:0x%x", ret);
		goto end;
	}

	ret = cptra_sha384_update(msg, msg_size);
	if (ret) {
		LOG_ERR("cptra_sha384_update failed, ret:0x%x", ret);
		goto end;
	}

	ret = cptra_sha384_final(output, output_size);
	if (ret) {
		LOG_ERR("cptra_sha384_final failed, ret:0x%x", ret);
		goto end;
	}
end:
	return ret;
}


int cptra_verify_ecdsa_hashed(
		const uint8_t *pubx, const uint8_t *puby,
		const uint8_t *msg, size_t msg_len,
		const uint8_t *sig_r, const uint8_t *sig_s)
{
#if defined(CONFIG_SKIP_CPTRA_FW_VERIFICATION)
	LOG_WRN("FW verification is skipped, bypassing %s", __func__);
	return 0;
#endif
	int ipccmd = CPTRA_IPCCMD_ECDSA384_SIGNATURE_VERIFY;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_ecdsa_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret;

	/* Prepare tx data to bootmcu */
	p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	p8_bmcu_in += sizeof(struct cptra_ecdsa_ctx);

	/* Public Key X */
	ctx.qx = p8_bmcu_in; p8_bmcu_in += 48; ctx.qx_len = 48;
	/* Public Key Y */
	ctx.qy = p8_bmcu_in; p8_bmcu_in += 48; ctx.qy_len = 48;
	/* Signature R */
	ctx.r = p8_bmcu_in; p8_bmcu_in += 48; ctx.r_len = 48;
	/* Signature S */
	ctx.s = p8_bmcu_in; p8_bmcu_in += 48; ctx.s_len = 48;
	/* Message Hash */
	ctx.m = p8_bmcu_in; p8_bmcu_in += msg_len; ctx.m_len = msg_len;

	uint8_t *p8_ssp_in = (uint8_t *)IPC_CHANNEL_1_SSP_IN_ADDR;
	memcpy(p8_ssp_in, &ctx, sizeof(struct cptra_ecdsa_ctx));
	p8_ssp_in += sizeof(struct cptra_ecdsa_ctx);
	memcpy(p8_ssp_in, pubx, 48); p8_ssp_in += 48;
	memcpy(p8_ssp_in, puby, 48); p8_ssp_in += 48;
	memcpy(p8_ssp_in, sig_r, 48); p8_ssp_in += 48;
	memcpy(p8_ssp_in, sig_s, 48); p8_ssp_in += 48;
	memcpy(p8_ssp_in, msg, msg_len); p8_ssp_in += msg_len;


	uint32_t data[2];
	data[0] = IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	data[1] = IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

	LOG_INF("BMCU_IN_ADDR:0x%x, BMCU_OUT_ADDR:0x%x", data[0], data[1]);

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		LOG_ERR("cptra_ipc_trigger:0x%x is failure, ret:0x%x", ipccmd, ret);
		return -1;
	}

	LOG_DBG("cptra_ipc_trigger:%x is successful", ipccmd);

	cptra_ipc_receive(CPTRA_IPC_RX_TYPE_INTERNAL, &ret, sizeof(ret));

	if (ret == 0) {
		LOG_DBG(" result expected (pass), Pass");
	} else {
		LOG_ERR(" result unexpected (ret=%d), Failed", ret);
		return -1;
	}

	return 0;
}

int cptra_verify_ecdsa(
		const uint8_t *pubx, const uint8_t *puby,
		const uint8_t *msg, size_t msg_len,
		const uint8_t *sig_r, const uint8_t *sig_s)
{
#if defined(CONFIG_SKIP_CPTRA_FW_VERIFICATION)
	LOG_WRN("FW verification is skipped, bypassing %s", __func__);
	return 0;
#endif
	uint8_t hash[48];
	int ret;

	ret = cptra_sha384(msg, msg_len, hash, sizeof(hash));
	if (ret) {
		LOG_ERR("cptra_sha384 failed, ret:0x%x", ret);
		return -1;
	}

	LOG_HEXDUMP_DBG(hash, sizeof(hash), "Digested hash");

	ret = cptra_verify_ecdsa_hashed(pubx, puby, hash, sizeof(hash), sig_r, sig_s);
	if (ret) {
		LOG_ERR("cptra_verify_ecdsa_hashed failed, ret:0x%x", ret);
		return -1;
	}

	return 0;
}

int cptra_verify_lms_hashed(
		const uint8_t *public_key,
		const uint8_t *msg, size_t msg_len,
		const uint8_t *signature)
{
#if defined(CONFIG_SKIP_CPTRA_FW_VERIFICATION)
	LOG_WRN("FW verification is skipped, bypassing %s", __func__);
	return 0;
#endif
	int ipccmd = CPTRA_IPCCMD_LMS_SIGNATURE_VERIFY;
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	struct cptra_lms_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret;

	/* Prepare tx data to bootmcu */
	p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	p8_bmcu_in += sizeof(struct cptra_lms_ctx);

	ctx.pub_key_id = p8_bmcu_in; 		p8_bmcu_in += 16;
	ctx.pub_key_digest = p8_bmcu_in; 	p8_bmcu_in += 24;
	ctx.sig_ots = p8_bmcu_in; 		p8_bmcu_in += 1252;
	ctx.sig_tree_path = p8_bmcu_in; 	p8_bmcu_in += 360;

	struct cptra_pqc_pub_key *pub_key = (struct cptra_pqc_pub_key *)public_key;
	struct cptra_pqc_signature *sig = (struct cptra_pqc_signature *)signature;
	ctx.pub_key_tree_type 	= __builtin_bswap32(pub_key->lms.tree_type);
	ctx.pub_key_ots_type 	= __builtin_bswap32(pub_key->lms.ots_type);
	ctx.pub_key_id_len 	= 16;
	ctx.pub_key_digest_len 	= 24;
	ctx.sig_q 		= __builtin_bswap32(sig->lms_sig.q);
	ctx.sig_ots_len 	= 1252;
	ctx.sig_tree_type 	= __builtin_bswap32(sig->lms_sig.tree_type);
	ctx.sig_tree_path_len 	= 360;

	uint8_t *p8_ssp_in = (uint8_t *)IPC_CHANNEL_1_SSP_IN_ADDR;
	memcpy(p8_ssp_in, &ctx, sizeof(struct cptra_lms_ctx));
	p8_ssp_in += sizeof(struct cptra_lms_ctx);

	memcpy(p8_ssp_in, pub_key->lms.id, 16);
	p8_ssp_in += 16;
	memcpy(p8_ssp_in, pub_key->lms.digest, 24);
	p8_ssp_in += 24;
	memcpy(p8_ssp_in, sig->lms_sig.ots, 1252);
	p8_ssp_in += 1252;
	memcpy(p8_ssp_in, sig->lms_sig.tree_path, 360);
	p8_ssp_in += 360;

	uint32_t data[2];
	data[0] = IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	data[1] = IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

	LOG_INF("BMCU_IN_ADDR:0x%x, BMCU_OUT_ADDR:0x%x", data[0], data[1]);

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		LOG_ERR("cptra_ipc_trigger:0x%x is failure, ret:0x%x", ipccmd, ret);
		return -1;
	}

	LOG_DBG("cptra_ipc_trigger:%x is successful", ipccmd);

	cptra_ipc_receive(CPTRA_IPC_RX_TYPE_INTERNAL, &ret, sizeof(ret));

	if (ret == 0) {
		LOG_DBG(" result expected (pass), Pass");
	} else {
		LOG_ERR(" result unexpected (ret=%d), Failed", ret);
		return -1;
	}

	return 0;
}

int cptra_verify_lms(
		const uint8_t *public_key,
		const uint8_t *msg, size_t msg_len,
		const uint8_t *signature)
{
#if defined(CONFIG_SKIP_CPTRA_FW_VERIFICATION)
	LOG_WRN("FW verification is skipped, bypassing %s", __func__);
	return 0;
#endif
	uint8_t hash[48];
	int ret;

	ret = cptra_sha384(msg, msg_len, hash, sizeof(hash));
	if (ret) {
		LOG_ERR("cptra_sha384 failed, ret:0x%x", ret);
		return -1;
	}

	LOG_HEXDUMP_DBG(hash, sizeof(hash), "Digested hash");

	ret = cptra_verify_lms_hashed(public_key, hash, sizeof(hash), signature);
	if (ret) {
		LOG_ERR("cptra_verify_lms_hashed failed, ret:0x%x", ret);
		return -1;
	}

	return 0;
}

int cptra_get_cert_chain(void **cert_chain, size_t *cert_chain_size)
{
	return 0;
}

int cptra_set_auth_manifest(const struct cptra_set_auth_manifest_ia *input)
{
#if defined(CONFIG_SKIP_CPTRA_FW_VERIFICATION)
	LOG_WRN("FW verification is skipped, bypassing %s", __func__);
	return 0;
#endif
	struct cptra_set_auth_manifest_ia *input_buf;
	struct cptra_set_auth_manifest_oa *output_buf;
	int ret;

	if (input == NULL) {
		return -EINVAL;
	}

	input_buf = malloc(sizeof(*input_buf));
	output_buf = malloc(sizeof(*output_buf));
	if (input_buf == NULL || output_buf == NULL) {
		free(input_buf);
		free(output_buf);
		return -ENOMEM;
	}

	memcpy(input_buf, input, sizeof(*input_buf));
	memset(output_buf, 0, sizeof(*output_buf));

	ret = cptra_ipc_transfer(CPTRA_IPCCMD_SET_AUTH_MANIFEST,
				 input_buf, sizeof(*input_buf),
				 CPTRA_IPC_RX_TYPE_EXTERNAL,
				 output_buf, sizeof(*output_buf));
	free(input_buf);
	free(output_buf);
	if (ret) {
		LOG_ERR("set_auth_manifest failed, ret:0x%x", ret);
		return ret;
	}

	return 0;
}

int cptra_authorize_and_stash(uint32_t fw_id, uint8_t digest[48], bool skip_stash)
{
#if defined(CONFIG_SKIP_CPTRA_FW_VERIFICATION)
	LOG_WRN("FW verification is skipped, bypassing %s", __func__);
	return 0;
#endif
	struct cptra_authorize_and_stash_ia *input;
	struct cptra_authorize_and_stash_oa *output;
	int ret;

	LOG_INF("Caliptra IPC authorize_and_stash...");

	input = malloc(sizeof(*input));
	output = malloc(sizeof(*output));
	if (input == NULL || output == NULL) {
		free(input);
		free(output);
		return -ENOMEM;
	}

	memset(input, 0, sizeof(*input));
	memset(output, 0, sizeof(*output));

	memcpy(input->fw_id, &fw_id, sizeof(fw_id));
	memcpy(input->measurement, digest, sizeof(input->measurement));
	input->svn = 3;
	input->flags = 0;
	input->source = 0;

	/* Set input data */
	input->source = InRequest;
	if (skip_stash) {
		input->flags |= BIT(0); // SKIP_STASH
	}

	ret = cptra_ipc_transfer(CPTRA_IPCCMD_AUTHORIZE_AND_STASH,
				 input, sizeof(*input),
				 CPTRA_IPC_RX_TYPE_EXTERNAL,
				 output, sizeof(*output));

	if (ret) {
		LOG_ERR("  Send IPC Caliptra authorize_and_stash is failure, ret:0x%x", ret);
		goto out;
	} else
		LOG_DBG("  Send IPC Caliptra authorize_and_stash is successful");

	LOG_DBG("  output: chksum=0x%x, fips_status=0x%x", output->chksum, output->fips_status);
	LOG_DBG("  auth_req_result: 0x%x", output->auth_req_result);

	if (output->auth_req_result != AUTHORIZE_IMAGE) {
		LOG_ERR("  authorize image failed, auth_req_result: 0x%x", output->auth_req_result);
		LOG_HEXDUMP_ERR(digest, 48, "  Image digest");
		ret = output->auth_req_result;
		goto out;
	}

	LOG_INF("%s: Pass", __func__);
	ret = 0;
out:
	free(input);
	free(output);
	if (ret) {
		LOG_INF("%s: Failed", __func__);
	}
	return ret;
}

static struct cert_info {
	uint8_t data[4096];
	uint32_t length;
} caliptra_cached_certificate[CPTRA_CACHED_MAX];

static void cptra_get_rt_alias_cert(struct cert_info *cached_cert)
{
	struct cptra_get_rt_alias_cert_ia input;
	struct cptra_get_rt_alias_cert_oa output;
	int ret;

	LOG_INF("Test caliptra_get_rt_alias_cert...");

	memset(&input, 0, sizeof(struct cptra_get_rt_alias_cert_ia));
	memset(&output, 0, sizeof(struct cptra_get_rt_alias_cert_oa));

	ret = cptra_ipc_transfer(CPTRA_IPCCMD_GET_RT_ALIAS_CERT,
				 (uint32_t *)&input, sizeof(input),
				 CPTRA_IPC_RX_TYPE_EXTERNAL,
				 (uint32_t *)&output, sizeof(output));

	if (ret) {
		LOG_ERR("caliptra_get_rt_alias_cert is failure, ret:0x%x", ret);
		goto end;
	} else
		LOG_DBG("caliptra_get_rt_alias_cert is successful");

	LOG_DBG("output: chksum:0x%x, fips_status:0x%x",
		output.chksum, output.fips_status);
	LOG_HEXDUMP_DBG(output.data, output.data_size, "rt_alias_cert:");

	memcpy(cached_cert->data, output.data, output.data_size);
	cached_cert->length = output.data_size;

	LOG_INF("%s: Pass", __func__);
	return;
end:
	LOG_INF("%s: Failed", __func__);
}

static void cptra_get_fmc_alias_cert(struct cert_info *cached_cert)
{
	struct cptra_get_fmc_alias_cert_ia input;
	struct cptra_get_fmc_alias_cert_oa output;
	int ret;

	LOG_INF("Test caliptra_get_fmc_alias_cert...");

	memset(&input, 0, sizeof(struct cptra_get_fmc_alias_cert_ia));
	memset(&output, 0, sizeof(struct cptra_get_fmc_alias_cert_oa));

	ret = cptra_ipc_transfer(CPTRA_IPCCMD_GET_FMC_ALIAS_CERT,
				 (uint32_t *)&input, sizeof(input),
				 CPTRA_IPC_RX_TYPE_EXTERNAL,
				 (uint32_t *)&output, sizeof(output));

	if (ret) {
		LOG_ERR("caliptra_get_fmc_alias_cert is failure, ret:0x%x", ret);
		goto end;
	} else
		LOG_DBG("caliptra_get_fmc_alias_cert is successful");

	LOG_DBG("output: chksum:0x%x, fips_status:0x%x",
		output.chksum, output.fips_status);
	LOG_HEXDUMP_DBG(output.data, output.data_size, "fmc_alias_cert:");

	memcpy(cached_cert->data, output.data, output.data_size);
	cached_cert->length = output.data_size;

	LOG_INF("%s: Pass", __func__);
	return;
end:
	LOG_INF("%s: Failed", __func__);
}

static void cptra_get_ldev_cert(struct cert_info *cached_cert)
{
	struct cptra_get_ldev_cert_ia input;
	struct cptra_get_ldev_cert_oa output;
	int ret;

	LOG_INF("Test caliptra_get_ldev_cert...");

	memset(&input, 0, sizeof(struct cptra_get_ldev_cert_ia));
	memset(&output, 0, sizeof(struct cptra_get_ldev_cert_oa));

	ret = cptra_ipc_transfer(CPTRA_IPCCMD_GET_LDEV_CERT,
				 (uint32_t *)&input, sizeof(input),
				 CPTRA_IPC_RX_TYPE_EXTERNAL,
				 (uint32_t *)&output, sizeof(output));

	if (ret) {
		LOG_ERR("caliptra_get_ldev_cert is failure, ret:0x%x", ret);
		goto end;
	} else
		LOG_DBG("caliptra_get_ldev_cert is successful");

	LOG_DBG("output: chksum:0x%x, fips_status:0x%x",
		output.chksum, output.fips_status);
	LOG_HEXDUMP_DBG(output.data, output.data_size, "ldev_cert:");

	memcpy(cached_cert->data, output.data, output.data_size);
	cached_cert->length = output.data_size;

	LOG_INF("%s: Pass", __func__);
	return;
end:
	LOG_INF("%s: Failed", __func__);
}

/* Caliptra returns the whole DICE chain; 4 certs of ~0.5-1KB each. */
#define CPTRA_CERT_CHAIN_MAX		4096U

/*
 * Decode one DER TLV at buf. Returns the tag and reports the header and content
 * lengths, or -1 if the TLV is malformed or runs past avail.
 */
static int cptra_der_tlv(const uint8_t *buf, uint32_t avail, uint32_t *header_len,
			 uint32_t *content_len)
{
	uint32_t length;
	uint32_t header;
	uint8_t count;

	if (avail < 2)
		return -1;

	if ((buf[1] & 0x80) == 0) {
		/* Short form: length is the low 7 bits. */
		header = 2;
		length = buf[1];
	} else {
		count = buf[1] & 0x7f;
		/* Indefinite length is not valid DER, and >4 bytes overflows. */
		if (count == 0 || count > 4 || avail < (uint32_t)2 + count)
			return -1;

		header = 2 + count;
		length = 0;
		for (uint8_t i = 0; i < count; i++)
			length = (length << 8) | buf[2 + i];
	}

	if (length > avail - header)
		return -1;

	*header_len = header;
	*content_len = length;
	return buf[0];
}

/*
 * Return the raw DER of the issuer or subject Name of an X.509 certificate,
 * SEQUENCE header included, so two names can be compared as bytes.
 *
 *   Certificate ::= SEQUENCE { tbsCertificate SEQUENCE {
 *       [0] version OPTIONAL, serialNumber INTEGER, signature SEQUENCE,
 *       issuer Name, validity SEQUENCE, subject Name, ... } ... }
 *
 * Only the fields ahead of the wanted Name are walked; nothing is validated
 * beyond what is needed to find it.
 */
static const uint8_t *cptra_der_name(const uint8_t *cert, uint32_t cert_len, bool want_subject,
				     uint32_t *name_len)
{
	const uint8_t *cursor;
	uint32_t remaining;
	uint32_t header;
	uint32_t content;
	int tag;
	/* Names to step over before the wanted one starts. */
	int skips = want_subject ? 2 : 0;

	/* Certificate SEQUENCE */
	tag = cptra_der_tlv(cert, cert_len, &header, &content);
	if (tag != 0x30)
		return NULL;
	cursor = cert + header;
	remaining = content;

	/* tbsCertificate SEQUENCE */
	tag = cptra_der_tlv(cursor, remaining, &header, &content);
	if (tag != 0x30)
		return NULL;
	cursor += header;
	remaining = content;

	/* [0] EXPLICIT version, optional */
	tag = cptra_der_tlv(cursor, remaining, &header, &content);
	if (tag < 0)
		return NULL;
	if (tag == 0xa0) {
		cursor += header + content;
		remaining -= header + content;
	}

	/* serialNumber INTEGER */
	tag = cptra_der_tlv(cursor, remaining, &header, &content);
	if (tag != 0x02)
		return NULL;
	cursor += header + content;
	remaining -= header + content;

	/* signature AlgorithmIdentifier, then issuer; for the subject also step
	 * over issuer and validity.
	 */
	do {
		tag = cptra_der_tlv(cursor, remaining, &header, &content);
		if (tag != 0x30)
			return NULL;
		cursor += header + content;
		remaining -= header + content;
	} while (skips--);

	/* The wanted Name starts here. */
	tag = cptra_der_tlv(cursor, remaining, &header, &content);
	if (tag != 0x30)
		return NULL;

	*name_len = header + content;
	return cursor;
}

/*
 * Return the total length of the DER certificate at the head of buf, or 0 if
 * buf does not hold one complete certificate.
 */
static uint32_t cptra_der_cert_length(const uint8_t *buf, uint32_t avail)
{
	uint32_t header;
	uint32_t content;

	if (cptra_der_tlv(buf, avail, &header, &content) != 0x30 || content == 0)
		return 0;

	return header + content;
}

/*
 * Fetch the DPE certificate chain. Caliptra serves it in pages, so keep asking
 * until a short page ends it.
 */
static int cptra_get_dpe_cert_chain(uint8_t *chain, uint32_t capacity, uint32_t *chain_size)
{
	struct cptra_invoke_dpe_command_ia *input = NULL;
	struct cptra_invoke_dpe_command_oa *output = NULL;
	struct dpe_get_certificate_chain_i *chain_input;
	struct dpe_get_certificate_chain_o *chain_output;
	uint32_t offset = 0;
	int ret;

	input = (struct cptra_invoke_dpe_command_ia *)malloc(sizeof(*input));
	output = (struct cptra_invoke_dpe_command_oa *)malloc(sizeof(*output));
	if (!input || !output) {
		LOG_ERR("Failed to allocate DPE command buffers");
		ret = -1;
		goto out;
	}

	chain_input = (struct dpe_get_certificate_chain_i *)input->data;
	chain_output = (struct dpe_get_certificate_chain_o *)output->data;

	do {
		memset(input, 0, sizeof(*input));
		memset(output, 0, sizeof(*output));

		input->data_size = sizeof(struct dpe_get_certificate_chain_i);
		chain_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
		chain_input->cmd_hdr.cmd = GET_CERTIFICATE_CHAIN;
		chain_input->cmd_hdr.profile = P384Sha384;
		chain_input->offset = offset;
		chain_input->size = sizeof(chain_output->cert_chain);

		ret = cptra_ipc_transfer(CPTRA_IPCCMD_INVOKE_DPE_COMMAND,
					 (uint32_t *)input, sizeof(*input),
					 CPTRA_IPC_RX_TYPE_EXTERNAL,
					 (uint32_t *)output, sizeof(*output));
		if (ret) {
			LOG_ERR("caliptra_invoke_dpe_command is failure, ret:0x%x", ret);
			goto out;
		}

		if (output->fips_status != 0) {
			LOG_ERR("FIPS error from caliptra, status:0x%x", output->fips_status);
			ret = -1;
			goto out;
		}

		if (chain_output->rsp_hdr.magic != DPE_RESPONSE_MAGIC ||
		    chain_output->rsp_hdr.status != 0) {
			LOG_ERR("DPE GetCertificateChain failed, magic:0x%08x status:0x%08x",
				chain_output->rsp_hdr.magic, chain_output->rsp_hdr.status);
			ret = -1;
			goto out;
		}

		if (chain_output->size > sizeof(chain_output->cert_chain) ||
		    chain_output->size > capacity - offset) {
			LOG_ERR("DPE certificate chain does not fit, offset:%u size:%u",
				offset, chain_output->size);
			ret = -1;
			goto out;
		}

		memcpy(&chain[offset], chain_output->cert_chain, chain_output->size);
		offset += chain_output->size;

		/* A short page is the last one. */
		if (chain_output->size < sizeof(chain_output->cert_chain))
			break;
	} while (offset < capacity);

	*chain_size = offset;
	ret = 0;
out:
	free(input);
	free(output);
	return ret;
}

/*
 * The IDevID certificate is the first entry of the DPE certificate chain, and
 * it is only there once the BootMCU has pushed it in with POPULATE_IDEV_CERT
 * (see cptra_populate_idevid()). When it has not, Caliptra starts the chain at
 * LDevID, so compare against the already-cached LDevID to avoid caching the
 * wrong certificate. This relies on CPTRA_CACHED_LDEVID_CERT being loaded
 * first; cptra_load_certificate() does so.
 */
static void cptra_get_idev_cert(struct cert_info *cached_cert)
{
	const struct cert_info *ldev_cert =
		&caliptra_cached_certificate[CPTRA_CACHED_LDEVID_CERT];
	uint8_t *chain = NULL;
	uint32_t chain_size = 0;
	uint32_t cert_size;
	uint32_t count = 0;

	LOG_INF("Test caliptra_get_idev_cert...");

	chain = (uint8_t *)malloc(CPTRA_CERT_CHAIN_MAX);
	if (!chain) {
		LOG_ERR("Failed to allocate certificate chain buffer");
		goto end;
	}

	if (cptra_get_dpe_cert_chain(chain, CPTRA_CERT_CHAIN_MAX, &chain_size))
		goto end;

	LOG_HEXDUMP_DBG(chain, chain_size, "certificate_chain:");

	/* Count the entries so the chain layout shows up in the log. */
	for (uint32_t offset = 0; offset < chain_size; offset += cert_size) {
		cert_size = cptra_der_cert_length(&chain[offset], chain_size - offset);
		if (cert_size == 0) {
			LOG_ERR("Malformed DER at offset %u of %u", offset, chain_size);
			goto end;
		}
		count++;
	}

	cert_size = cptra_der_cert_length(chain, chain_size);
	LOG_INF("DPE certificate chain: %u bytes, %u certificates, first is %u bytes",
		chain_size, count, cert_size);

	if (cert_size > sizeof(cached_cert->data)) {
		LOG_ERR("idev_cert is %u bytes, cache slot holds %u", cert_size,
			(uint32_t)sizeof(cached_cert->data));
		goto end;
	}

	if (ldev_cert->length == cert_size &&
	    memcmp(chain, ldev_cert->data, cert_size) == 0) {
		LOG_WRN("Chain starts at LDevID, IDevID is not populated");
		goto end;
	}

	LOG_HEXDUMP_DBG(chain, cert_size, "idev_cert:");

	memcpy(cached_cert->data, chain, cert_size);
	cached_cert->length = cert_size;

	free(chain);
	LOG_INF("%s: Pass", __func__);
	return;
end:
	free(chain);
	LOG_INF("%s: Failed", __func__);
}
/*
 * Fetch the DPE leaf certificate with DPE CertifyKey. This is deliberately not
 * cached: CertifyKey certifies the key of the current DPE context, so the
 * certificate is only valid for as long as that context is, and a stale copy
 * would no longer match the key that signs the token. Callers take ownership of
 * *cert_data and free it, as with cptra_get_cached_certificate().
 */
int cptra_get_dpe_leaf_certificate(void **cert_data, uint32_t *cert_size)
{
	/*
	struct cptra_certify_key_extended_oa {
		uint32_t chksum;
		uint32_t fips_status;
		uint8_t certify_key_resp[2176]; // should be 6272
	};
	*/

	struct cptra_certify_key_extended_oa_ext {
		uint32_t chksum;
		uint32_t fips_status;
		uint8_t certify_key_resp[6272]; // should be 6272
	};

	struct cptra_certify_key_extended_ia *input = NULL;
	struct cptra_certify_key_extended_oa_ext *output = NULL;
	struct dpe_certify_key_o *certify_key_resp;
	uint32_t size;
	int ret = -1;

	if (!cert_data || !cert_size)
		return -1;

	*cert_data = NULL;
	*cert_size = 0;

	input = (struct cptra_certify_key_extended_ia *)malloc(sizeof(*input));
	output = (struct cptra_certify_key_extended_oa_ext *)malloc(sizeof(*output));
	if (!input || !output) {
		LOG_ERR("Failed to allocate CertifyKey buffers");
		goto out;
	}

	memset(input, 0, sizeof(*input));
	memset(output, 0, sizeof(*output));

	/* All-zero request: default context handle, flags 0, FORMAT_X509, empty label */
	ret = cptra_ipc_transfer(CPTRA_IPCCMD_CERTIFY_KEY_EXTENDED,
				 (uint32_t *)input, sizeof(*input),
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
		ret = -1;
		goto out;
	}

	size = certify_key_resp->cert_size;
	if (size == 0 ||
	    size > sizeof(output->certify_key_resp) - sizeof(struct dpe_certify_key_o)) {
		LOG_ERR("Invalid CertifyKey cert_size:%u", size);
		ret = -1;
		goto out;
	}

	*cert_data = malloc(size);
	if (*cert_data == NULL) {
		LOG_ERR("Failed to allocate %u bytes for the DPE leaf certificate", size);
		ret = -1;
		goto out;
	}

	memcpy(*cert_data, certify_key_resp->cert, size);
	*cert_size = size;
	ret = 0;
out:
	free(input);
	free(output);
	return ret;
}

static void cptra_load_static_cert(struct cert_info *cached_cert, const uint8_t *der,
				   uint32_t der_len, const char *name)
{
	if (der_len == 0) {
		LOG_WRN("%s is not provisioned, skipping", name);
		return;
	}

	if (der_len > sizeof(cached_cert->data)) {
		LOG_ERR("%s is %u bytes, cache slot holds %u", name, der_len,
			(uint32_t)sizeof(cached_cert->data));
		return;
	}

	memcpy(cached_cert->data, der, der_len);
	cached_cert->length = der_len;

	LOG_INF("%s: Pass (%u bytes)", name, der_len);
}

/*
 * Pick the sub CA that issued this part's IDevID and cache it, so the cached
 * chain reads root CA -> sub CA -> IDevID. The peer sub CAs share an issuer but
 * have distinct subject names, so matching the IDevID issuer against each
 * subject tells them apart. Names are compared as raw DER, which is exact:
 * every certificate here comes out of the same PKI tooling, so the encodings
 * match byte for byte.
 */
static void cptra_select_sub_ca(struct cert_info *cached_cert)
{
	const struct cert_info *idev_cert =
		&caliptra_cached_certificate[CPTRA_CACHED_IDEVID_CERT];
	const uint8_t *issuer;
	uint32_t issuer_len = 0;

	if (idev_cert->length == 0) {
		LOG_WRN("No IDevID certificate, cannot select a sub CA");
		return;
	}

	issuer = cptra_der_name(idev_cert->data, idev_cert->length, false, &issuer_len);
	if (!issuer) {
		LOG_ERR("Failed to read the IDevID issuer name");
		return;
	}

	for (uint32_t i = 0; i < cptra_aspeed_sub_ca_count; i++) {
		const struct cptra_ca_cert *candidate = &cptra_aspeed_sub_ca[i];
		const uint8_t *subject;
		uint32_t subject_len = 0;

		if (candidate->len == 0)
			continue;

		subject = cptra_der_name(candidate->der, candidate->len, true, &subject_len);
		if (!subject) {
			LOG_ERR("Failed to read the %s subject name", candidate->name);
			continue;
		}

		if (subject_len != issuer_len || memcmp(subject, issuer, issuer_len) != 0)
			continue;

		if (candidate->len > sizeof(cached_cert->data)) {
			LOG_ERR("%s is %u bytes, cache slot holds %u", candidate->name,
				candidate->len, (uint32_t)sizeof(cached_cert->data));
			return;
		}

		memcpy(cached_cert->data, candidate->der, candidate->len);
		cached_cert->length = candidate->len;

		LOG_INF("%s issued the IDevID, cached as the sub CA (%u bytes)",
			candidate->name, candidate->len);
		return;
	}

	LOG_WRN("No known sub CA matches the IDevID issuer");
	LOG_HEXDUMP_WRN(issuer, issuer_len, "idev issuer:");
}

int cptra_load_certificate()
{
	cptra_load_static_cert(&caliptra_cached_certificate[CPTRA_CACHED_ASPEED_ROOT_CA_CERT],
			       cptra_aspeed_root_ca_der, cptra_aspeed_root_ca_der_len,
			       "aspeed_root_ca_cert");
	cptra_get_rt_alias_cert(&caliptra_cached_certificate[CPTRA_CACHED_RT_ALIAS_CERT]);
	cptra_get_fmc_alias_cert(&caliptra_cached_certificate[CPTRA_CACHED_FMC_ALIAS_CERT]);
	cptra_get_ldev_cert(&caliptra_cached_certificate[CPTRA_CACHED_LDEVID_CERT]);
	cptra_get_idev_cert(&caliptra_cached_certificate[CPTRA_CACHED_IDEVID_CERT]);
	cptra_select_sub_ca(&caliptra_cached_certificate[CPTRA_CACHED_ASPEED_SUB_CA_CERT]);

	return 0;
}

int cptra_get_cached_certificate(int cert, void** cert_data, uint32_t *cert_size)
{
	if (cert < 0 || cert >= CPTRA_CACHED_MAX)
		return -1;

	if (caliptra_cached_certificate[cert].length == 0)
		return -1;

	*cert_data = malloc(caliptra_cached_certificate[cert].length);
	if (*cert_data == NULL)
		return -1;

	*cert_size = caliptra_cached_certificate[cert].length;
	memcpy(*cert_data, caliptra_cached_certificate[cert].data, *cert_size);
	return 0;
}

