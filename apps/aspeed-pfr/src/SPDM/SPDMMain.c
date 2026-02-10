/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>

#include <soc.h>
#include <zephyr/portability/cmsis_os2.h>
#include <zephyr/storage/flash_map.h>

#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMMctpBinding.h"
#include "SPDM/SPDMSession.h"

// Root CA
#include "Certificates/ca.cert.der.h"
#include "Certificates/ca1.cert.der.h"
#include "Certificates/inter.cert.der.h"
#include "Certificates/inter1.cert.der.h"

// Private/Public key pair
#include "Certificates/end_responder.key.der.h"
#include "Certificates/end_requester.key.der.h"

// Certificate Chain
#include "Certificates/bundle_responder.certchain.der.h"
#include "Certificates/bundle_responder.certchain1.der.h"
#include "Certificates/certificate_utils.h"
#if defined(CONFIG_SECURE_CONNECTION_REQUESTER)
#include "Certificates/bundle_requester.certchain.der.h"
#include "Certificates/bundle_requester.certchain1.der.h"
#endif
#include "SPDM/ResponseCmd/GetMeasurementImpl.h"


LOG_MODULE_REGISTER(spdm, CONFIG_LOG_DEFAULT_LEVEL);

#if defined(CONFIG_ASPEED_DICE)
int load_responder_cert(struct spdm_context *context, cert_info *info, uint32_t cert_offset, uint8_t slot_num);
int load_responder_key(struct spdm_context *context, cert_info *info);
#endif

bool init_requester_context(struct spdm_context *context, SPDM_MEDIUM medium,
	uint8_t bus, uint8_t dst_sa, uint8_t dst_eid, bool load_key)
{
	int ret;

	ret = spdm_mctp_init_req(context, medium, bus, dst_sa, dst_eid);
	if (ret == 0) {
		LOG_ERR("spdm_mctp_init_req return failed");
		return false;
	}

	if (load_key) {
#if defined(CONFIG_SECURE_CONNECTION_REQUESTER)
#if defined(CONFIG_ASPEED_DICE)
		static cert_info info NON_CACHED_BSS_ALIGN16;

		ret = load_responder_cert(context, &info, DEVID_CERT_OFFSET, 0);
		if (ret)
			return false;
		ret = load_responder_key(context, &info);
		if (ret)
			return false;

#else
		spdm_load_certificate(context, false, 0, bundle_requester_certchain_der,
				bundle_requester_certchain_der_len);
		spdm_load_certificate(context, false, 1, bundle_requester_certchain1_der,
				bundle_requester_certchain1_der_len);

		/* Set private/public key pair for signing */
		ret = mbedtls_ecp_group_load(&context->key_pair.MBEDTLS_PRIVATE(grp),
				MBEDTLS_ECP_DP_SECP384R1);
		LOG_DBG("mbedtls_ecp_group_load ret=%x", -ret);
		ret = mbedtls_mpi_read_binary(&context->key_pair.MBEDTLS_PRIVATE(d),
				end_requester_key_der + 8, 48);
		LOG_DBG("mbedtls_mpi_read_binary ret=%x", -ret);
		ret = mbedtls_ecp_point_read_binary(&context->key_pair.MBEDTLS_PRIVATE(grp),
				&context->key_pair.MBEDTLS_PRIVATE(Q),
				end_requester_key_der + end_requester_key_der_len - 97, 97);
		LOG_DBG("mbedtls_ecp_point_read_binary ret=%x", -ret);

		ret = mbedtls_ecp_check_pub_priv(
				&context->key_pair,
				&context->key_pair,
				context->random_callback,
				context);
		LOG_DBG("mbedtls_ecp_check_pub_priv ret=%x", -ret);
#endif
#endif
	}

	context->release_connection_data = spdm_mctp_release_req;

	return true;
}

#if defined(CONFIG_ASPEED_DICE)
int load_responder_cert(struct spdm_context *context, cert_info *info, uint32_t cert_offset, uint8_t slot_num)
{
	const struct flash_area *area_measured = NULL;
	int ret;
	mbedtls_sha256_context sha_ctx;
	uint8_t cal_hash[32];

	ret = flash_area_open(FIXED_PARTITION_ID(certificate_partition), &area_measured);
	if (ret) {
		LOG_ERR("Failed to open certificate partition, ret = %d", -ret);
		return -1;
	}

	flash_area_read(area_measured, cert_offset, info, sizeof(cert_info));
	if (info->magic != CERT_DATA_MAGIC) {
		LOG_ERR("Magic number (%x) is invalid", info->magic);
		return -1;
	}

	mbedtls_sha256_init(&sha_ctx);
	mbedtls_sha256_starts(&sha_ctx, 0 /* SHA-256 */);
	mbedtls_sha256_update(&sha_ctx, info->cert, info->len);
	mbedtls_sha256_finish(&sha_ctx, cal_hash);
	mbedtls_sha256_free(&sha_ctx);

	if (memcmp(cal_hash, info->hash, 32)) {
		LOG_ERR("Certificate chain hash is not matched");
		LOG_HEXDUMP_ERR(info->hash, 32, "Expected hash");
		LOG_HEXDUMP_ERR(cal_hash, 32, "Calculated hash");
		return -1;
	}

	if (cert_offset == ALIAS_CERT_OFFSET) {
		/*
		 * To append Alias cert to the DevID cert chain because Alias cert
		 * is signed by DevID cert
		 */
		if (spdm_append_certificate_chain(context, false, slot_num, info->cert,
			info->len))
			return -1;
	} else {
		if (spdm_load_certificate(context, false, slot_num, info->cert, info->len))
			return -1;
	}

	LOG_INF("SPDM responder certificate #%d is %s", slot_num,
		(cert_offset == ALIAS_CERT_OFFSET)?"appended":"loaded");
	return 0;
}

int load_responder_key(struct spdm_context *context, cert_info *info)
{
	int ret;
	uint8_t *ptr = (uint8_t *)ALIAS_PRI_KEY_ADDR;

	ret = load_responder_cert(context, info, ALIAS_CERT_OFFSET, 0);
	if (ret)
		return -1;

	ret = mbedtls_ecp_group_load(&context->key_pair.MBEDTLS_PRIVATE(grp),
			MBEDTLS_ECP_DP_SECP384R1);
	LOG_INF("mbedtls_ecp_group_load ret=%x", -ret);
	LOG_HEXDUMP_DBG(ptr, 48+1, "Alias pri key");
	ret = mbedtls_mpi_read_binary(&context->key_pair.MBEDTLS_PRIVATE(d),
			ptr + 1, 48);
	LOG_INF("mbedtls_mpi_read_binary ret=%x", -ret);

	ret = mbedtls_ecp_point_read_binary(&context->key_pair.MBEDTLS_PRIVATE(grp),
			&context->key_pair.MBEDTLS_PRIVATE(Q), info->pub_key, 97);
	LOG_HEXDUMP_DBG(info->pub_key, 97, "Alias pub key");
	LOG_INF("mbedtls_ecp_point_read_binary ret=%x", -ret);

	ret = mbedtls_ecp_check_pub_priv(&context->key_pair, &context->key_pair,
			context->random_callback, context);
	LOG_INF("mbedtls_ecp_check_pub_priv ret=%x", -ret);

	return 0;
}
#endif

void init_responder_context(struct spdm_context *context)
{
	int ret;

	register_get_measurement(context);

#if defined(CONFIG_ASPEED_DICE)
	static cert_info info NON_CACHED_BSS_ALIGN16;

	ret = load_responder_cert(context, &info, DEVID_CERT_OFFSET, 0);
	if (ret)
		return;
	ret = load_responder_key(context, &info);
	if (ret)
		return;
#else
	// Only load the leaf certificate for now
	spdm_load_certificate(context, false, 0, bundle_responder_certchain_der, bundle_responder_certchain_der_len);
	spdm_load_certificate(context, false, 1, bundle_responder_certchain1_der, bundle_responder_certchain1_der_len);
//	spdm_load_certificate(context, false, 0, devid_cert_der, devid_cert_der_len);
//	spdm_load_certificate(context, false, 1, alias_cert_der, alias_cert_der_len);

	ret = mbedtls_ecp_group_load(&context->key_pair.MBEDTLS_PRIVATE(grp),
			MBEDTLS_ECP_DP_SECP384R1);
	LOG_INF("mbedtls_ecp_group_load ret=%x", -ret);
	ret = mbedtls_mpi_read_binary(&context->key_pair.MBEDTLS_PRIVATE(d),
			end_responder_key_der + 8, 48);
	LOG_INF("mbedtls_mpi_read_binary ret=%x", -ret);
	ret = mbedtls_ecp_point_read_binary(&context->key_pair.MBEDTLS_PRIVATE(grp),
			&context->key_pair.MBEDTLS_PRIVATE(Q),
			end_responder_key_der + end_responder_key_der_len - 97, 97);
	LOG_INF("mbedtls_ecp_point_read_binary ret=%x", -ret);

	ret = mbedtls_ecp_check_pub_priv(&context->key_pair, &context->key_pair, context->random_callback, context);
	LOG_INF("mbedtls_ecp_check_pub_priv ret=%x", -ret);
#endif
}


#define SPDM_REQUESTER_PRIO 4
#define SPDM_REQUESTER_STACK_SIZE 8192
extern void spdm_requester_main(void *ctx, void *b, void *c);
extern void spdm_attester_main(void *ctx, void *b, void *c);
K_THREAD_STACK_DEFINE(spdm_requester_stack, SPDM_REQUESTER_STACK_SIZE);
struct k_thread spdm_requester_thread_data;
k_tid_t spdm_requester_tid;

struct spdm_context *context_rsp_oo;

void init_spdm(void)
{
	struct spdm_context *context_rsp = spdm_context_create();

	mbedtls_x509_crt_init(spdm_get_root_certificate());
	spdm_load_root_certificate(ca_cert_der, ca_cert_der_len);
	spdm_load_root_certificate(inter_cert_der, inter_cert_der_len);
	spdm_load_root_certificate(ca1_cert_der, ca1_cert_der_len);
	spdm_load_root_certificate(inter1_cert_der, inter1_cert_der_len);

#if defined(CONFIG_PFR_SPDM_RESPONDER)
	init_responder_context(context_rsp);
	context_rsp_oo = context_rsp;
#endif
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	spdm_requester_tid = k_thread_create(
			&spdm_requester_thread_data,
			spdm_requester_stack,
			K_THREAD_STACK_SIZEOF(spdm_requester_stack),
			//spdm_requester_main,
			spdm_attester_main,
			NULL, NULL, NULL,
			SPDM_REQUESTER_PRIO, 0, K_NO_WAIT);
	k_thread_name_set(spdm_requester_tid, "SPDM REQ");

	extern osEventFlagsId_t spdm_attester_event;

	spdm_attester_event = osEventFlagsNew(NULL);
#endif
}

#if defined(CONFIG_SHELL)
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
#include <zephyr/shell/shell.h>
#include <zephyr/portability/cmsis_os2.h>
void spdm_request_tick(void);
static int cmd_spdm_run(const struct shell *shell, size_t argc, char **argv)
{
	spdm_run_attester();
	return 0;
}

static int cmd_spdm_stop(const struct shell *shell, size_t argc, char **argv)
{
	spdm_stop_attester();
	return 0;
}

static int cmd_spdm_enable(const struct shell *shell, size_t argc, char **argv)
{
	spdm_enable_attester();
	return 0;
}

static int cmd_spdm_get(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t event = spdm_get_attester();

	shell_print(shell, "SPDM Event=%08x", event);
	return 0;
}

static int cmd_spdm_tick(const struct shell *shell, size_t argc, char **argv)
{
	spdm_request_tick();
	return 0;
}

#if defined(CONFIG_SECURE_CONNECTION_RESPONDER) || defined(CONFIG_SECURE_CONNECTION_REQUESTER)
extern void spdm_session_init_session_table(void);
extern struct spdm_session_context *spdm_session_get_from_table(int index);
static int cmd_spdm_clean_sess_tbl(const struct shell *shell, size_t argc, char **argv)
{
	spdm_session_init_session_table();
	return 0;
}

static int cmd_spdm_get_sess_info(const struct shell *shell, size_t argc, char **argv)
{
	int tbl_idx;
	struct spdm_session_context *info;

	tbl_idx = strtol(argv[1], NULL, 10);
	if (tbl_idx > SPDM_MAX_SESSION || tbl_idx <= 0) {
		shell_print(shell, "Invalid session index");
		return -1;
	}
	info = spdm_session_get_from_table(tbl_idx - 1);

	if (info) {
		shell_print(shell, "Session      = %s", (info->valid_session)?"valid":"invalid");
		shell_print(shell, "Session ID   = %08x", info->session_id);
		shell_print(shell, "Session Type = %d", info->session_type);
		if (info->valid_session) {
			shell_print(shell, "encryption_key_req");
			shell_hexdump(shell, info->encryption_key_req,
					sizeof(info->encryption_key_req));
			shell_print(shell, "encryption_salt_req");
			shell_hexdump(shell, info->encryption_salt_req,
					sizeof(info->encryption_salt_req));
			shell_print(shell, "encryption_key_rsp");
			shell_hexdump(shell, info->encryption_key_rsp,
					sizeof(info->encryption_key_rsp));
			shell_print(shell, "encryption_salt_rsp");
			shell_hexdump(shell, info->encryption_salt_rsp,
					sizeof(info->encryption_salt_rsp));
			shell_print(shell, "sequence_number_req = 0x%llx",
					info->sequence_number_req);
			shell_print(shell, "sequence_number_rsp = 0x%llx",
					info->sequence_number_rsp);
			shell_print(shell, "last access time = 0x%llx",
					info->last_access_time);
		}
	}
	return 0;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(sub_spdm_cmds,
	SHELL_CMD(enable, NULL, "Stop attestation", cmd_spdm_enable),
	SHELL_CMD(run, NULL, "Run attestation", cmd_spdm_run),
	SHELL_CMD(stop, NULL, "Stop attestation", cmd_spdm_stop),
	SHELL_CMD(get, NULL, "Stop attestation", cmd_spdm_get),
	SHELL_CMD(tick, NULL, "Tick", cmd_spdm_tick),
#if defined(CONFIG_SECURE_CONNECTION_RESPONDER) || defined(CONFIG_SECURE_CONNECTION_REQUESTER)
	SHELL_CMD(clean_sess_tbl, NULL, "Clean Session Table", cmd_spdm_clean_sess_tbl),
	SHELL_CMD_ARG(get_sess_info, NULL, "Get Session Info", cmd_spdm_get_sess_info, 2, 0),
#endif
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(spdm, &sub_spdm_cmds, "SPDM Commands", NULL);
#endif
#endif
