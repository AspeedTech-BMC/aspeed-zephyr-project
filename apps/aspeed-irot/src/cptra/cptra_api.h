#pragma once

#include <stdint.h>
#include <stddef.h>
#include <zephyr/drivers/cptra.h>

enum {
	CPTRA_CACHED_ASPEED_ROOT_CA_CERT = 0,
	CPTRA_CACHED_ASPEED_SUB_CA_CERT,
	CPTRA_CACHED_IDEVID_CERT,
	CPTRA_CACHED_LDEVID_CERT,
	CPTRA_CACHED_FMC_ALIAS_CERT,
	CPTRA_CACHED_RT_ALIAS_CERT,
	CPTRA_CACHED_MAX,
};

int cptra_sha384_init(void);
int cptra_sha384_update(const char *msg, int msg_size);
int cptra_sha384_final(uint8_t *output, int output_size);

int cptra_sha384(const char *msg, int msg_size, uint8_t *output, int output_size);

int cptra_verify_ecdsa(
		const uint8_t *pubx, const uint8_t *puby,
		const uint8_t *msg, size_t msg_len,
		const uint8_t *sig_r, const uint8_t *sig_s);

int cptra_verify_lms(
		const uint8_t *public_key,
		const uint8_t *msg, size_t msg_len,
		const uint8_t *signature);

int cptra_get_cert_chain(void **cert_chain, size_t *cert_chain_size);

int cptra_set_auth_manifest(const struct cptra_set_auth_manifest_ia *input);

int cptra_authorize_and_stash(uint32_t fw_id, uint8_t digest[48], bool skip_stash);
int cptra_get_cached_certificate(int cert, void** cert_data, uint32_t *cert_size);

/*
 * The DPE leaf certificate is fetched on demand rather than cached; see the
 * definition. The caller frees *cert_data.
 */
int cptra_get_dpe_leaf_certificate(void **cert_data, uint32_t *cert_size);
