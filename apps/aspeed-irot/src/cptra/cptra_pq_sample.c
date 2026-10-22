/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2026 ASPEED Technology Inc.
 */

/* Shell tests for the Caliptra rt-1.3.0 PQ/MLDSA87 commands */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/device.h>
#include <zephyr/drivers/cptra.h>
#include <zephyr/drivers/ipm.h>
#include <zephyr/drivers/ipm_ast.h>
#include <zephyr/drivers/misc/aspeed/cptra_ipc.h>
#include <zephyr/shell/shell.h>

#include <cptra/cptra_api.h>
#include "cptra_pq_testvec.h"

#define PQ_IPC_NODE		DT_NODELABEL(ipc1_bootmcu)

/* POPULATE_PQ_CERT sample, same as the caliptra-sw tests */
#define PQ_SAMPLE_CERT_SIZE	64
#define PQ_SAMPLE_CERT_BYTE	0xa5

#define PQ_MLDSA87_PUB_KEY_LEN	2592

/* certify_key_resp of CERTIFY_KEY_EXTENDED_MLDSA87 */
struct pq_certify_key_resp {
	struct dpe_rsp_header rsp_hdr;
	uint8_t new_context_handle[16];
	uint8_t pubkey[PQ_MLDSA87_PUB_KEY_LEN];
	uint32_t cert_size;
	uint8_t cert[];
};

struct pq_dpe_buf {
	struct cptra_invoke_dpe_mldsa87_command_ia in;
	struct cptra_invoke_dpe_mldsa87_command_oa out;
};

/*
 * bootmcu may write up to the whole output struct, so a command runs
 * only when both its input and output fit in the shared memory.
 */
static int pq_shmem_check(const struct shell *sh, size_t ilen,
			  size_t olen)
{
	const struct device *ipm = DEVICE_DT_GET(PQ_IPC_NODE);
	int tx, rx;

	if (!device_is_ready(ipm))
		return -ENODEV;

	tx = ast_ipm_max_tx_shmem_size(ipm, IPC_CHANNEL_ID_CPTRA);
	rx = ast_ipm_max_rx_shmem_size(ipm, IPC_CHANNEL_ID_CPTRA);
	if (tx > 0 && rx > 0 && ilen <= (size_t)tx &&
	    olen <= (size_t)rx)
		return 0;

	shell_warn(sh, "IPC shmem too small: in %zu/%d, out %zu/%d",
		   ilen, tx, olen, rx);
	return -ENOSPC;
}

static int pq_transfer(const struct shell *sh, enum cptra_ipc_cmd cmd,
		       void *in, size_t ilen, void *out, size_t olen)
{
	int ret;

	ret = pq_shmem_check(sh, ilen, olen);
	if (ret)
		return ret;

	return cptra_api_transfer(cmd, in, ilen,
				  CPTRA_IPC_RX_TYPE_EXTERNAL,
				  out, olen);
}

static int pq_dpe_check(const struct shell *sh,
			const struct dpe_rsp_header *hdr)
{
	if (hdr->magic == DPE_RESPONSE_MAGIC && hdr->status == 0)
		return 0;

	shell_error(sh, "DPE error: magic 0x%08x, status 0x%x",
		    hdr->magic, hdr->status);
	return -EIO;
}

/* Clear the buffer and fill the DPE command header */
static void *pq_dpe_cmd(struct pq_dpe_buf *dpe, uint32_t cmd,
			uint32_t size)
{
	struct dpe_cmd_header *hdr;

	memset(dpe, 0, sizeof(*dpe));
	hdr = (struct dpe_cmd_header *)dpe->in.data;
	hdr->magic = DPE_COMMAND_MAGIC;
	hdr->cmd = cmd;
	hdr->profile = Mldsa87;
	dpe->in.data_size = size;

	return dpe->in.data;
}

static int pq_invoke_dpe(const struct shell *sh,
			 struct pq_dpe_buf *dpe)
{
	int ret;

	ret = pq_transfer(sh, CPTRA_IPCCMD_INVOKE_DPE_MLDSA87_COMMAND,
			  &dpe->in, sizeof(dpe->in),
			  &dpe->out, sizeof(dpe->out));
	if (ret)
		return ret;

	return pq_dpe_check(sh,
			    (struct dpe_rsp_header *)dpe->out.data);
}

static int pq_set_pq_seed(const struct shell *sh)
{
	struct cptra_set_pq_seed_ia in;
	struct cptra_set_pq_seed_oa out = { 0 };

	/* Same test seed as aspeed-app */
	memset(in.seed, 0x42, sizeof(in.seed));

	return pq_transfer(sh, CPTRA_IPCCMD_SET_PQ_SEED,
			   &in, sizeof(in), &out, sizeof(out));
}

static int pq_get_pq_info(const struct shell *sh)
{
	struct cptra_get_pq_info_ia in;
	struct cptra_get_pq_info_oa *out;
	int ret;

	out = calloc(1, sizeof(*out));
	if (!out)
		return -ENOMEM;

	ret = pq_transfer(sh, CPTRA_IPCCMD_GET_PQ_INFO,
			  &in, sizeof(in), out, sizeof(*out));
	if (!ret) {
		shell_print(sh, "PQ public key:");
		shell_hexdump(sh, out->pq_pub_key,
			      sizeof(out->pq_pub_key));
	}

	free(out);
	return ret;
}

static int pq_get_pq_csr(const struct shell *sh)
{
	struct cptra_get_pq_csr_ia in;
	struct cptra_get_pq_csr_oa *out;
	int ret;

	out = calloc(1, sizeof(*out));
	if (!out)
		return -ENOMEM;

	ret = pq_transfer(sh, CPTRA_IPCCMD_GET_PQ_CSR,
			  &in, sizeof(in), out, sizeof(*out));
	if (!ret) {
		shell_print(sh, "PQ CSR: %u bytes", out->data_size);
		if (out->data_size <= sizeof(out->data))
			shell_hexdump(sh, out->data, out->data_size);
	}

	free(out);
	return ret;
}

static int pq_mldsa87_verify(const struct shell *sh)
{
	const struct mldsa87_verify_testvec *tv;
	struct cptra_mldsa87_verify_ia *in;
	struct cptra_mldsa87_verify_oa out;
	enum cptra_ipc_cmd cmd;
	uint8_t digest[48];
	int ret;

	/* Check before the digest is loaded into SHA acc */
	ret = pq_shmem_check(sh, sizeof(*in), sizeof(out));
	if (ret)
		return ret;

	in = malloc(sizeof(*in));
	if (!in)
		return -ENOMEM;

	cmd = CPTRA_IPCCMD_MLDSA87_SIGNATURE_VERIFY;
	for (size_t i = 0; i < ARRAY_SIZE(mldsa87_verify_tv); i++) {
		tv = &mldsa87_verify_tv[i];

		/* The command reads the digest from SHA acc */
		cptra_api_lock();
		ret = cptra_sha384(tv->msg, tv->msg_size, digest,
				   sizeof(digest));
		if (ret) {
			cptra_api_unlock();
			break;
		}

		memset(in, 0, sizeof(*in));
		memset(&out, 0, sizeof(out));
		memcpy(in->pub_key, tv->pub_key, sizeof(in->pub_key));
		memcpy(in->signature, tv->signature,
		       sizeof(in->signature));

		ret = pq_transfer(sh, cmd, in, sizeof(*in),
				  &out, sizeof(out));
		cptra_api_unlock();
		if (tv->result != (ret == 0)) {
			shell_error(sh, "TV %zu: expected %s", i,
				    tv->result ? "pass" : "fail");
			ret = -EBADMSG;
			break;
		}
		ret = 0;
	}

	free(in);
	return ret;
}

static int pq_invoke_dpe_mldsa87(const struct shell *sh)
{
	struct dpe_get_profile_o *rsp;
	struct pq_dpe_buf *dpe;
	int ret;

	dpe = malloc(sizeof(*dpe));
	if (!dpe)
		return -ENOMEM;

	pq_dpe_cmd(dpe, GET_PROFILE,
		   sizeof(struct dpe_get_profile_i));
	ret = pq_invoke_dpe(sh, dpe);
	if (!ret) {
		rsp = (struct dpe_get_profile_o *)dpe->out.data;
		shell_print(sh, "Profile %u, version %u.%u",
			    rsp->rsp_hdr.profile, rsp->major_version,
			    rsp->minor_version);
	}

	free(dpe);
	return ret;
}

static int pq_get_pq_cert(const struct shell *sh)
{
	static const char tbs[] = "PQ cert TBS sample";
	struct cptra_get_pq_cert_ia *in;
	struct cptra_get_pq_cert_oa *out;
	int ret = -ENOMEM;

	in = calloc(1, sizeof(*in));
	out = calloc(1, sizeof(*out));
	if (!in || !out)
		goto end;

	in->tbs_size = sizeof(tbs) - 1;
	memcpy(in->tbs, tbs, in->tbs_size);
	/* Not a valid signature, only the DER is assembled */
	memset(in->signature, 0xa5, sizeof(in->signature));

	ret = pq_transfer(sh, CPTRA_IPCCMD_GET_PQ_CERT,
			  in, sizeof(*in), out, sizeof(*out));
	if (!ret) {
		shell_print(sh, "PQ cert: %u bytes", out->cert_size);
		if (out->cert_size <= sizeof(out->cert))
			shell_hexdump(sh, out->cert, out->cert_size);
	}

end:
	free(out);
	free(in);
	return ret;
}

static bool pq_has_sample_cert(const uint8_t *buf, uint32_t len)
{
	uint32_t run = 0;

	for (uint32_t i = 0; i < len; i++) {
		run = (buf[i] == PQ_SAMPLE_CERT_BYTE) ? run + 1 : 0;
		if (run == PQ_SAMPLE_CERT_SIZE)
			return true;
	}

	return false;
}

static int pq_populate_pq_cert(const struct shell *sh)
{
	struct cptra_populate_pq_cert_ia *in;
	struct cptra_populate_pq_cert_oa out = { 0 };
	struct dpe_get_certificate_chain_i *gc;
	struct dpe_get_certificate_chain_o *rsp;
	struct pq_dpe_buf *dpe = NULL;
	int ret = -ENOMEM;

	in = calloc(1, sizeof(*in));
	if (!in)
		goto end;

	in->cert_size = PQ_SAMPLE_CERT_SIZE;
	memset(in->cert, PQ_SAMPLE_CERT_BYTE, PQ_SAMPLE_CERT_SIZE);

	ret = pq_transfer(sh, CPTRA_IPCCMD_POPULATE_PQ_CERT,
			  in, sizeof(*in), &out, sizeof(out));
	if (ret)
		goto end;

	/* The populated cert must be in the MLDSA87 cert chain */
	dpe = malloc(sizeof(*dpe));
	if (!dpe) {
		ret = -ENOMEM;
		goto end;
	}

	gc = pq_dpe_cmd(dpe, GET_CERTIFICATE_CHAIN, sizeof(*gc));
	rsp = (struct dpe_get_certificate_chain_o *)dpe->out.data;
	gc->offset = 0;
	/* DPE max chunk size */
	gc->size = sizeof(rsp->cert_chain);

	ret = pq_invoke_dpe(sh, dpe);
	if (ret)
		goto end;

	if (rsp->size > sizeof(rsp->cert_chain)) {
		ret = -EBADMSG;
		goto end;
	}

	shell_print(sh, "Cert chain: %u bytes", rsp->size);
	if (!pq_has_sample_cert(rsp->cert_chain, rsp->size)) {
		shell_error(sh, "Populated cert not in cert chain");
		ret = -ENOENT;
	}

end:
	free(dpe);
	free(in);
	return ret;
}

static int pq_certify_key_ext_mldsa87(const struct shell *sh)
{
	struct cptra_certify_key_extended_mldsa87_ia in = { 0 };
	struct cptra_certify_key_extended_mldsa87_oa *out;
	struct pq_certify_key_resp *resp;
	int ret;

	out = calloc(1, sizeof(*out));
	if (!out)
		return -ENOMEM;

	/* All-zero request: default context, flags 0, X.509 */
	ret = pq_transfer(sh,
			  CPTRA_IPCCMD_CERTIFY_KEY_EXTENDED_MLDSA87,
			  &in, sizeof(in), out, sizeof(*out));
	if (ret)
		goto end;

	resp = (struct pq_certify_key_resp *)out->certify_key_resp;
	if (out->size < sizeof(*resp) ||
	    out->size > sizeof(out->certify_key_resp)) {
		shell_error(sh, "Invalid resp size %u", out->size);
		ret = -EBADMSG;
		goto end;
	}

	ret = pq_dpe_check(sh, &resp->rsp_hdr);
	if (ret)
		goto end;

	shell_print(sh, "Resp %u bytes, cert %u bytes", out->size,
		    resp->cert_size);
	shell_print(sh, "Public key:");
	shell_hexdump(sh, resp->pubkey, sizeof(resp->pubkey));
	if (resp->cert_size <= out->size - sizeof(*resp)) {
		shell_print(sh, "Cert:");
		shell_hexdump(sh, resp->cert, resp->cert_size);
	}

end:
	free(out);
	return ret;
}

static int pq_sign_with_exported_mldsa(const struct shell *sh)
{
	static const char msg[] = "MLDSA87 sign test message";
	struct dpe_derive_context_exported_cdi_o *dc_rsp;
	struct cptra_sign_with_exported_mldsa_ia *in = NULL;
	struct cptra_sign_with_exported_mldsa_oa *out = NULL;
	struct dpe_derive_context_i *dc;
	struct pq_dpe_buf *dpe;
	int ret = -ENOMEM;

	dpe = malloc(sizeof(*dpe));
	if (!dpe)
		goto end;

	/* Get an exported CDI handle from the MLDSA87 DPE */
	dc = pq_dpe_cmd(dpe, DERIVE_CONTEXT, sizeof(*dc));
	dc->flags = EXPORT_CDI | CREATE_CERTIFICATE |
		    RETAIN_PARENT_CONTEXT;

	ret = pq_invoke_dpe(sh, dpe);
	if (ret)
		goto end;

	in = calloc(1, sizeof(*in));
	out = calloc(1, sizeof(*out));
	if (!in || !out) {
		ret = -ENOMEM;
		goto end;
	}

	dc_rsp = (struct dpe_derive_context_exported_cdi_o *)
		 dpe->out.data;
	memcpy(in->exported_cdi_handle, dc_rsp->exported_cdi,
	       sizeof(in->exported_cdi_handle));
	in->sign_mode = SIGN_WITH_EXPORTED_MLDSA_MODE_DATA;
	in->message_size = sizeof(msg) - 1;
	memcpy(in->message, msg, in->message_size);

	ret = pq_transfer(sh, CPTRA_IPCCMD_SIGN_WITH_EXPORTED_MLDSA,
			  in, sizeof(*in), out, sizeof(*out));
	if (!ret) {
		shell_print(sh, "Derived public key:");
		shell_hexdump(sh, out->derived_pubkey,
			      sizeof(out->derived_pubkey));
		shell_print(sh, "Signature:");
		shell_hexdump(sh, out->signature,
			      sizeof(out->signature));
	}

end:
	free(out);
	free(in);
	free(dpe);
	return ret;
}

struct pq_test {
	const char *name;
	int (*fn)(const struct shell *sh);
};

/*
 * set_pq_seed enables PQC mode and must run first; it fails when run
 * again before Caliptra is reset.
 */
static const struct pq_test pq_tests[] = {
	{ "set_pq_seed", pq_set_pq_seed },
	{ "get_pq_info", pq_get_pq_info },
	{ "get_pq_csr", pq_get_pq_csr },
	{ "mldsa87_verify", pq_mldsa87_verify },
	{ "invoke_dpe_mldsa87", pq_invoke_dpe_mldsa87 },
	{ "get_pq_cert", pq_get_pq_cert },
	{ "populate_pq_cert", pq_populate_pq_cert },
	{ "certify_key_ext_mldsa87", pq_certify_key_ext_mldsa87 },
	{ "sign_with_exported_mldsa", pq_sign_with_exported_mldsa },
};

static int pq_run(const struct shell *sh, const struct pq_test *t)
{
	int ret;

	shell_print(sh, "%s: Start...", t->name);
	ret = t->fn(sh);
	if (ret == -ENOSPC)
		shell_warn(sh, "%s: Skipped", t->name);
	else if (ret)
		shell_error(sh, "%s: Failed (%d)", t->name, ret);
	else
		shell_print(sh, "%s: Pass", t->name);

	return ret;
}

/* argv[0] is the subcommand name */
static int cmd_pq_test(const struct shell *sh, size_t argc,
		       char **argv)
{
	ARG_UNUSED(argc);

	for (size_t i = 0; i < ARRAY_SIZE(pq_tests); i++) {
		if (strcmp(argv[0], pq_tests[i].name) == 0)
			return pq_run(sh, &pq_tests[i]);
	}

	return -EINVAL;
}

static int cmd_pq_all(const struct shell *sh, size_t argc,
		      char **argv)
{
	int failed = 0, skipped = 0;
	int ret;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	for (size_t i = 0; i < ARRAY_SIZE(pq_tests); i++) {
		ret = pq_run(sh, &pq_tests[i]);
		if (ret == -ENOSPC)
			skipped++;
		else if (ret)
			failed++;
	}

	shell_print(sh, "Done: %d failed, %d skipped",
		    failed, skipped);
	return failed ? -EIO : 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_cptra_pq,
	SHELL_CMD(all, NULL, "Run all PQ tests", cmd_pq_all),
	SHELL_CMD(set_pq_seed, NULL, "SET_PQ_SEED, run first",
		  cmd_pq_test),
	SHELL_CMD(get_pq_info, NULL, "GET_PQ_INFO", cmd_pq_test),
	SHELL_CMD(get_pq_csr, NULL, "GET_PQ_CSR", cmd_pq_test),
	SHELL_CMD(mldsa87_verify, NULL, "MLDSA87_SIGNATURE_VERIFY",
		  cmd_pq_test),
	SHELL_CMD(invoke_dpe_mldsa87, NULL,
		  "INVOKE_DPE_MLDSA87 GetProfile", cmd_pq_test),
	SHELL_CMD(get_pq_cert, NULL, "GET_PQ_CERT", cmd_pq_test),
	SHELL_CMD(populate_pq_cert, NULL, "POPULATE_PQ_CERT",
		  cmd_pq_test),
	SHELL_CMD(certify_key_ext_mldsa87, NULL,
		  "CERTIFY_KEY_EXTENDED_MLDSA87", cmd_pq_test),
	SHELL_CMD(sign_with_exported_mldsa, NULL,
		  "SIGN_WITH_EXPORTED_MLDSA", cmd_pq_test),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(cptra_pq, &sub_cptra_pq,
		   "Caliptra rt-1.3.0 PQ test commands", NULL);
