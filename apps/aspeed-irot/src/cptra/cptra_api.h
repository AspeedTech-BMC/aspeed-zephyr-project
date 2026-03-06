#pragma once

#include <stdint.h>
#include <stddef.h>

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
