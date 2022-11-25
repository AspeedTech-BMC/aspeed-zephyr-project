/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <soc.h>
#include <storage/flash_map.h>
#include <mbedtls/sha256.h>
#include <drivers/flash.h>
#include "cert_verify.h"
#include "fw_update/fw_update.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

LOG_MODULE_REGISTER(cert, CONFIG_LOG_DEFAULT_LEVEL);

#define DEVID_CERT_AREA_OFFSET        0
#define ALIAS_CERT_AREA_OFFSET        0x2000
#define CERT_AREA_SIZE                0x2000

static uint8_t cert_buf[CERT_AREA_SIZE] NON_CACHED_BSS_ALIGN16;
static uint8_t devid_pub_key[ECDSA384_PUBLIC_KEY_SIZE] = {0};
mbedtls_x509_crt leaf_cert;
mbedtls_x509_crt root_cert;

PFR_DEVID_CERT_INFO *get_certificate_info(void)
{
	const struct flash_area *fa = NULL;
	PFR_DEVID_CERT_INFO *devid_cert_info;
	PFR_CERT_INFO *cert_info;
	uint8_t cert_hash[SHA256_HASH_LENGTH];

	if (flash_area_open(FLASH_AREA_ID(certificate), &fa)) {
		LOG_ERR("Failed to open certificate region");
		return NULL;
	}

	if (flash_area_read(fa, DEVID_CERT_AREA_OFFSET, cert_buf, sizeof(cert_buf))) {
		LOG_ERR("Failed to read certificate(s) from flash");
		goto error;
	}

	devid_cert_info = (PFR_DEVID_CERT_INFO *)cert_buf;
	cert_info = &devid_cert_info->cert;

	if (cert_info->magic != CERT_INFO_MAGIC_NUM) {
		LOG_ERR("Invalid magic number");
		goto error;
	}

	mbedtls_sha256(cert_info->data, cert_info->length, cert_hash, 0);

	if (memcmp(cert_hash, cert_info->hash, SHA256_HASH_LENGTH)) {
		LOG_ERR("Device ID certificate hash mismatch");
		LOG_HEXDUMP_ERR(cert_info->hash, sizeof(cert_hash), "Expected :");
		LOG_HEXDUMP_ERR(cert_hash, sizeof(cert_hash), "Actual :");
		goto error;
	}

	memcpy(devid_pub_key, devid_cert_info->pubkey, ECDSA384_PUBLIC_KEY_SIZE);

	return devid_cert_info;
error:
	flash_area_close(fa);
	return NULL;
}

// Test function
#if 1
// read certificate chain from BMC's SPI 0xd320000
// certificate chain size = 1645 bytes
#define CERT_CHAIN_LENGTH 1645

uint8_t *get_certificate_chain(uint32_t *cert_chain_len)
{
	const struct device *dev = device_get_binding("spi1_cs0");
	uint8_t *cert_chain;
	uint32_t cert_addr = 0xd320000;
	flash_read(dev, cert_addr, cert_buf, CERT_AREA_SIZE);
	cert_chain = cert_buf;
	*cert_chain_len = CERT_CHAIN_LENGTH;

	return cert_chain;
}
#endif

void generate_cert_info(PFR_CERT_INFO *cert_info, uint8_t *cert_chain, uint32_t cert_chain_len)
{
	cert_info->magic = CERT_INFO_MAGIC_NUM;
	cert_info->length = cert_chain_len;
	memset(cert_info->data, 0, sizeof(cert_info->data));
	memcpy(cert_info->data, cert_chain, cert_chain_len);
	mbedtls_sha256(cert_info->data, cert_info->length, cert_info->hash, 0);
}

int write_cert_chain(uint8_t *cert_chain, uint32_t cert_chain_len)
{
	const struct flash_area *fa = NULL;
	PFR_DEVID_CERT_INFO devid_cert_info = {0};
	devid_cert_info.cert_type = CERT_TYPE;
	memcpy(devid_cert_info.pubkey, devid_pub_key, sizeof(devid_cert_info.pubkey));
	generate_cert_info(&devid_cert_info.cert, cert_chain, cert_chain_len);

	if (flash_area_open(FLASH_AREA_ID(certificate), &fa)) {
		LOG_ERR("Failed to open certificate region");
		return -1;
	}

	flash_area_erase(fa, DEVID_CERT_AREA_OFFSET, CERT_AREA_SIZE);
	flash_area_write(fa, DEVID_CERT_AREA_OFFSET, &devid_cert_info, sizeof(devid_cert_info));
	flash_area_close(fa);

	return 0;
}

int verify_certificate(uint8_t *cert_chain, uint32_t cert_chain_len)
{
	uint32_t asn1_len;
	uint32_t current_cert_len;
	uint32_t flags;
	uint8_t current_index = 0;
	const uint8_t *current_cert = cert_chain;
	const uint8_t *tmp_ptr;
	int ret;

	mbedtls_x509_crt_init(&root_cert);
	mbedtls_x509_crt_init(&leaf_cert);

	/* Verify the certificate */
	while (true) {
		tmp_ptr = current_cert;
		ret = mbedtls_asn1_get_tag(
				(uint8_t **)&tmp_ptr, cert_chain + cert_chain_len, &asn1_len,
				MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		if (ret != 0) {
			break;
		}

		current_cert_len = asn1_len + (tmp_ptr - current_cert);

		// Certificate Chain = Root CA + Intermediate Cert + Leaf Certi
		if (current_index < 2) {
			ret = mbedtls_x509_crt_parse_der_nocopy(
					&root_cert, current_cert, current_cert_len);
			if (ret < 0) {
				// Parse Certificate Chain DER failed
				ret = -1;
				LOG_ERR("Failed to parse root ca");
				goto cleanup;
			}
		} else {
			ret = mbedtls_x509_crt_parse_der_nocopy(
					&leaf_cert, current_cert, current_cert_len);
			if (ret < 0) {
				// Parse Certificate Chain DER failed
				ret = -1;
				LOG_ERR("Failed to parse leaf certificate");
				goto cleanup;
			}
		}

		current_cert = current_cert + current_cert_len;
		current_index++;
	}


	ret = mbedtls_x509_crt_verify(&leaf_cert, &root_cert, NULL, NULL, &flags, NULL, NULL);
	if (ret < 0 || flags != 0) {
		// Verify Failed
		LOG_ERR("Certificate chain verification failed");
		ret = -1;
		goto cleanup;
	}

	LOG_INF("Certificate chain verify successful");
	ret = 0;

cleanup:
	mbedtls_x509_crt_free(&root_cert);
	mbedtls_x509_crt_free(&leaf_cert);
	return ret;
}

void cleanup_cert_info(void)
{
	memset(cert_buf, 0, sizeof(cert_buf));
	memset(devid_pub_key, 0, sizeof(devid_pub_key));
}

