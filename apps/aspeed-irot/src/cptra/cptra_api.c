#include <string.h>
#include <stdlib.h>
#include <cptra/cptra_api.h>
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

