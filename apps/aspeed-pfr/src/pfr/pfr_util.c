/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <logging/log.h>

// #include "pfr_util.h"
#include "flash/flash_wrapper.h"
#include "flash/flash_util.h"
#include "state_machine/common_smc.h"
#include "pfr_common.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include <sys/reboot.h>
#include <crypto/ecdsa_structs.h>
#include <crypto/ecdsa.h>
#include "mbedtls/ecdsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#undef DEBUG_PRINTF
#if 1
#define DEBUG_PRINTF LOG_INF
#else
#define DEBUG_PRINTF(...)
#endif

int pfr_spi_read(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	int status = 0;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.device_id[0] = device_id; // assign the flash device id,  0:spi1_cs0, 1:spi2_cs0 , 2:spi2_cs1, 3:spi2_cs2, 4:fmc_cs0, 5:fmc_cs1
	spi_flash->spi.base.read(&spi_flash->spi, address, data, data_length);
	return Success;
}

int pfr_spi_write(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	int status = 0;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.device_id[0] = device_id; // assign the flash device id,  0:spi1_cs0, 1:spi2_cs0 , 2:spi2_cs1, 3:spi2_cs2, 4:fmc_cs0, 5:fmc_cs1
	spi_flash->spi.base.write(&spi_flash->spi, address, data, data_length);
	return Success;
}

int pfr_spi_erase_4k(uint8_t device_id, uint32_t address)
{
	int status = 0;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.device_id[0] = device_id; // assign the flash device id,  0:spi1_cs0, 1:spi2_cs0 , 2:spi2_cs1, 3:spi2_cs2, 4:fmc_cs0, 5:fmc_cs1
	spi_flash->spi.base.sector_erase(&spi_flash->spi, address);
	return Success;
}

int pfr_spi_erase_block(uint8_t device_id, uint32_t address)
{
	int status = 0;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.device_id[0] = device_id; // assign the flash device id,  0:spi1_cs0, 1:spi2_cs0 , 2:spi2_cs1, 3:spi2_cs2, 4:fmc_cs0, 5:fmc_cs1
	spi_flash->spi.base.block_erase(&spi_flash->spi, address);
	return Success;
}

int pfr_spi_erase_region(uint8_t device_id,
		bool support_block_erase, uint32_t start_addr, uint32_t nbytes)
{
	uint32_t erase_addr = start_addr;
	uint32_t end_addr = start_addr + nbytes;

	while (erase_addr < end_addr) {
		if (support_block_erase && ((end_addr - erase_addr) >= BLOCK_SIZE) &&
				!(erase_addr & 0xffff)) {
			if (pfr_spi_erase_block(device_id, erase_addr))
				return Failure;
			erase_addr += BLOCK_SIZE;
		} else {
			if (pfr_spi_erase_4k(device_id, erase_addr))
				return Failure;
			erase_addr += PAGE_SIZE;
		}
	}

	return Success;
}

int pfr_spi_get_block_size(uint8_t device_id)
{
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();
	int block_sz;

	spi_flash->spi.device_id[0] = device_id; // assign the flash device id,  0:spi1_cs0, 1:spi2_cs0 , 2:spi2_cs1, 3:spi2_cs2, 4:fmc_cs0, 5:fmc_cs1
	spi_flash->spi.base.get_block_size(&spi_flash->spi, &block_sz);
	return block_sz;
}

int pfr_spi_page_read_write(uint8_t device_id, uint32_t source_address, uint32_t target_address)
{
	int status = 0;
	uint8_t buffer[PAGE_SIZE] = {0};

	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.device_id[0] = device_id; // assign the flash device id,  0:spi1_cs0, 1:spi2_cs0 , 2:spi2_cs1, 3:spi2_cs2, 4:fmc_cs0, 5:fmc_cs1
	spi_flash->spi.base.read(&spi_flash->spi, source_address, buffer, PAGE_SIZE);
	spi_flash->spi.base.write(&spi_flash->spi, target_address, buffer, PAGE_SIZE);

	return Success;
}

int pfr_spi_page_read_write_between_spi(uint8_t source_flash, uint32_t *source_address, uint8_t target_flash, uint32_t *target_address)
{
	int status = 0;
	uint32_t index1, index2;
	uint8_t buffer[MAX_READ_SIZE];

	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();


	for (index1 = 0; index1 < (PAGE_SIZE / MAX_READ_SIZE); index1++) {
		spi_flash->spi.device_id[0] = source_flash; // assign the flash device id,  0:spi1_cs0, 1:spi2_cs0 , 2:spi2_cs1, 3:spi2_cs2, 4:fmc_cs0, 5:fmc_cs1
		spi_flash->spi.base.read(&spi_flash->spi, *source_address, buffer, MAX_READ_SIZE);

		for (index2 = 0; index2 < (MAX_READ_SIZE / MAX_WRITE_SIZE); index2++) {
			spi_flash->spi.device_id[0] = target_flash;
			spi_flash->spi.base.write(&spi_flash->spi, *target_address, &buffer[index2 * MAX_WRITE_SIZE], MAX_WRITE_SIZE);

			*target_address += MAX_WRITE_SIZE;
		}

		*source_address += MAX_READ_SIZE;
	}

	return Success;
}

int pfr_spi_region_read_write_between_spi(uint8_t src_dev, uint32_t src_addr,
		uint8_t dest_dev, uint32_t dest_addr, size_t length)
{
	int i, status = 0;
	uint32_t index1, index2;
	uint8_t buffer[PAGE_SIZE];
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	for (i = 0; i < length / PAGE_SIZE; i++) {
		spi_flash->spi.device_id[0] = src_dev;
		spi_flash->spi.base.read(&spi_flash->spi, src_addr, buffer, PAGE_SIZE);
		spi_flash->spi.device_id[0] = dest_dev;
		spi_flash->spi.base.write(&spi_flash->spi, dest_addr, buffer, PAGE_SIZE);
		src_addr += PAGE_SIZE;
		dest_addr += PAGE_SIZE;
	}

	return Success;
}

// calculates sha for dataBuffer
int get_buffer_hash(struct pfr_manifest *manifest, uint8_t *data_buffer, uint8_t length, uint8_t *hash_out)
{
	if (manifest->hash_curve == secp256r1) {
		manifest->hash->start_sha256(manifest->hash);
		manifest->hash->calculate_sha256(manifest->hash, data_buffer, length, hash_out, SHA256_HASH_LENGTH);
	} else if (manifest->hash_curve == secp384r1) {
	} else  {
		return Failure;
	}

	return Success;
}

int esb_ecdsa_verify(struct pfr_manifest *manifest, uint32_t digest[], uint8_t pub_key[],
		     uint8_t signature[], uint8_t *auth_pass)
{
	*auth_pass = true;

	return Success;
}

// Calculate hash digest
int get_hash(struct manifest *manifest, struct hash_engine *hash_engine, uint8_t *hash_out, size_t hash_length)
{
	int status = 0;

	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *)manifest;

	if (pfr_manifest == NULL || hash_engine == NULL ||
	    hash_out == NULL || hash_length < SHA256_HASH_LENGTH ||
	    (hash_length > SHA256_HASH_LENGTH && hash_length < SHA384_HASH_LENGTH)) {
		return Failure;
	}
	flash_hash_contents(pfr_manifest->flash, pfr_manifest->pfr_hash->start_address, pfr_manifest->pfr_hash->length, pfr_manifest->hash, pfr_manifest->pfr_hash->type, hash_out, hash_length);

	return Success;
}

// print buffer
void print_buffer(uint8_t *string, uint8_t *buffer, uint32_t length)
{

	DEBUG_PRINTF("%s ", string);

	for (int i = 0; i < length; i++)
		DEBUG_PRINTF(" %x", buffer[i]);

	DEBUG_PRINTF("");
}

// compare buffer
int compare_buffer(uint8_t *buffer1, uint8_t *buffer2, uint32_t length)
{
	return (memcmp(buffer1, buffer2, length));
}

// reverse byte array
void reverse_byte_array(uint8_t *data_buffer, uint32_t length)
{
	uint8_t temp = 0;

	for (int i = 0, j = length; i < length / 2; i++, j--) {
		temp = data_buffer[i];
		data_buffer[i] = data_buffer[j];
		data_buffer[j] = temp;
	}
}

static int mbedtls_ecdsa_verify_middlelayer(struct pfr_pubkey *pubkey,
					    const uint8_t *digest, uint8_t *signature_r,
					    uint8_t *signature_s)
{
	mbedtls_ecdsa_context ctx_verify;
	mbedtls_mpi r, s;
	uint8_t hash[SHA256_HASH_LENGTH];
	int ret = 0;
	char z = 1;

	mbedtls_ecdsa_init(&ctx_verify);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	// print_buffer("ECDSA X: ", pubkey->x, pubkey->length);
	// print_buffer("ECDSA Y: ", pubkey->y, pubkey->length);
	// print_buffer("ECDSA R: ", signature_r, pubkey->length);
	// print_buffer("ECDSA S: ", signature_s, pubkey->length);
	// print_buffer("ECDSA D: ", digest, pubkey->length);

	mbedtls_mpi_read_binary(&ctx_verify.Q.X, pubkey->x, pubkey->length /*SHA256_HASH_LENGTH*/);

	mbedtls_mpi_read_binary(&ctx_verify.Q.Y, pubkey->y, pubkey->length /*SHA256_HASH_LENGTH*/);

	mbedtls_mpi_read_binary(&ctx_verify.Q.Z, &z, 1);

	mbedtls_mpi_read_binary(&r, signature_r, pubkey->length /*SHA256_HASH_LENGTH*/);

	mbedtls_mpi_read_binary(&s, signature_s, pubkey->length /*SHA256_HASH_LENGTH*/);

	mbedtls_ecp_group_load(&ctx_verify.grp, MBEDTLS_ECP_DP_SECP256R1);
	memcpy(hash, digest, pubkey->length /*SHA256_HASH_LENGTH*/);
	ret = mbedtls_ecdsa_verify(&ctx_verify.grp, hash, SHA256_HASH_LENGTH,
				   &ctx_verify.Q, &r, &s);

	mbedtls_ecdsa_free(&ctx_verify);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);

	// DEBUG_PRINTF("ECDSA:%d", ret);

	return ret;

}

/**
 * Verify that a calculated digest matches a signature.
 *
 * @param verification The verification context to use for checking the signature.
 * @param digest The digest to verify.
 * @param digest_length The length of the digest.
 * @param signature The signature to compare against the digest.
 * @param sig_length The length of the signature.
 *
 * @return 0 if the digest matches the signature or an error code.
 */
int verify_signature(struct signature_verification *verification, const uint8_t *digest,
		     size_t length, const uint8_t *signature, size_t sig_length)
{
	int status = Success;

	struct pfr_manifest *manifest = (struct pfr_manifest *)verification;
	// uint8_t signature_r[SHA256_HASH_LENGTH];
	// uint8_t signature_s[SHA256_HASH_LENGTH];
	// memcpy(&signature_r[0],&signature[0],length);
	// memcpy(&signature_s[0],&signature[length],length);

	status = mbedtls_ecdsa_verify_middlelayer(manifest->verification->pubkey,
							     digest,
							     manifest->verification->pubkey->signature_r,
							     manifest->verification->pubkey->signature_s);

	return status;
}


int pfr_cpld_update_reboot(void)
{
	DEBUG_PRINTF("system going reboot ...\n");

#if (CONFIG_KERNEL_SHELL_REBOOT_DELAY > 0)
	k_sleep(K_MSEC(CONFIG_KERNEL_SHELL_REBOOT_DELAY));
#endif

	sys_reboot(SYS_REBOOT_COLD);

	CODE_UNREACHABLE;

	return -1;
}
