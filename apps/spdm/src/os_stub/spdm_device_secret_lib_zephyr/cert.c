#include <stdlib.h>
#include <logging/log.h>

LOG_MODULE_DECLARE(spdm_secret);

#include <library/spdm_common_lib.h>
#include <library/spdm_crypt_lib.h>
#include <hal/library/memlib.h>
#include <hal/library/cryptlib/cryptlib_cert.h>

#include "cert.h"

#include "ecp256/ca.cert.der.h"
#include "ecp256/bundle_responder.certchain.der.h"

#include "ecp384/ca.cert.der.h"
#include "ecp384/bundle_responder.certchain.der.h"

/* public cert*/

#if 0
bool libspdm_read_responder_public_certificate_chain(
	uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
	size_t *size, void **hash, size_t *hash_size)
{
	bool res = false;
	uint8_t *cert_der = NULL;
	size_t cert_der_size = 0;
	spdm_cert_chain_t *cert_chain = NULL;
	size_t cert_chain_size;
	size_t digest_size;
	const uint8_t *root_cert;
	size_t root_cert_len;
	bool is_requester_cert = false, is_device_cert_model = true;

	switch (base_asym_algo) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
		cert_der = ecp256_bundle_responder_certchain_der;
		cert_der_size = ecp256_bundle_responder_certchain_der_len;
		res = true;
		break;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
		cert_der = ecp384_bundle_responder_certchain_der;
		cert_der_size = ecp384_bundle_responder_certchain_der_len;
		res = true;
		break;
	}

	if (!res) {
		LOG_ERR("Not supported algorithm");
		goto cleanup;
	}
	digest_size = libspdm_get_hash_size(base_hash_algo);
	cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + cert_der_size;
	cert_chain = (spdm_cert_chain_t *)malloc(cert_chain_size);
	cert_chain->length = (uint16_t)cert_chain_size;
	cert_chain->reserved = 0;

	res = libspdm_verify_cert_chain_data(
		cert_der, cert_der_size,
		base_asym_algo, base_hash_algo,
		is_requester_cert, is_device_cert_model);

	if (!res) {
		LOG_ERR("Failed to verify cert chain data");
		goto cleanup;
	}

	res = libspdm_x509_get_cert_from_cert_chain(
		cert_der, cert_der_size, 0,
		&root_cert, &root_cert_len);
	if (!res) {
		LOG_ERR("Failed to get root cert from cert chain");
		goto cleanup;
	}

	res = libspdm_hash_all(base_hash_algo, cert_der, cert_der_size,
			(uint8_t *)(cert_chain + 1));
	if (!res) {
		LOG_ERR("Failed to hash the chain");
		goto cleanup;
	}
	libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
		  cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
		  cert_der, cert_der_size);
	*data = cert_chain;
	*size = cert_chain_size;
	*hash = cert_chain + 1;
	*hash_size = digest_size;
	return res;
cleanup:
	free(cert_chain);
	return false;
}
#else
bool libspdm_read_responder_public_certificate_chain(
	uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
	size_t *size, void **hash, size_t *hash_size)
{
	bool res;
	void *file_data;
	size_t file_size;
	spdm_cert_chain_t *cert_chain = NULL;
	size_t cert_chain_size;
	const uint8_t *root_cert;
	size_t root_cert_len;
	size_t digest_size;
	bool is_requester_cert;
	bool is_device_cert_model;

	is_requester_cert = false;

	/*defalut is true*/
	is_device_cert_model = true;

	*data = NULL;
	*size = 0;
	if (hash != NULL) {
		*hash = NULL;
	}
	if (hash_size != NULL) {
		*hash_size = 0;
	}

	if (base_asym_algo == 0) {
		return false;
	}

	switch (base_asym_algo) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
		file_data = ecp256_bundle_responder_certchain_der;
		file_size = ecp256_bundle_responder_certchain_der_len;
		res = true;
		break;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
		file_data = ecp384_bundle_responder_certchain_der;
		file_size = ecp384_bundle_responder_certchain_der_len;
		res = true;
		break;
	default:
		res = false;
		break;
	}

	if (!res) {
		LOG_ERR("Unsupported base_asym_algo=%08x base_hash_algo=%08x", base_asym_algo, base_hash_algo);
		goto cleanup;
	}

	digest_size = libspdm_get_hash_size(base_hash_algo);

	cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
	cert_chain = (void *)malloc(cert_chain_size);
	if (cert_chain == NULL) {
		LOG_ERR("Failed to alloc memory size=%d", cert_chain_size);
		return false;
	}
	cert_chain->length = (uint16_t)cert_chain_size;
	cert_chain->reserved = 0;

	res = libspdm_verify_cert_chain_data(file_data, file_size,
				      base_asym_algo, base_hash_algo,
				      is_requester_cert, is_device_cert_model);
	if (!res) {
		LOG_ERR("Failed libspdm_verify_cert_chain_data");
		goto cleanup;
	}


	/* Get Root Certificate and calculate hash value*/

	res = libspdm_x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
					     &root_cert_len);
	if (!res) {
		LOG_ERR("Failed libspdm_x509_get_cert_from_cert_chain");
		goto cleanup;
	}

	res = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
			(uint8_t *)(cert_chain + 1));
	if (!res) {
		LOG_ERR("Failed libspdm_hash_all");
		goto cleanup;
	}
	libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
		  cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
		  file_data, file_size);

	*data = cert_chain;
	*size = cert_chain_size;
	if (hash != NULL) {
		*hash = (cert_chain + 1);
	}
	if (hash_size != NULL) {
		*hash_size = digest_size;
	}

	return true;
cleanup:
	free(cert_chain);
	return false;
}
#endif
/*This alias cert chain is partial, from root CA to device certificate CA.*/
bool libspdm_read_responder_public_certificate_chain_alias_cert_till_dev_cert_ca(
	uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
	size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_responder_public_certificate_chain_per_slot(
	uint8_t slot_id, uint32_t base_hash_algo, uint32_t base_asym_algo,
	void **data, size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_requester_public_certificate_chain(
	uint32_t base_hash_algo, uint16_t req_base_asym_alg, void **data,
	size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_responder_root_public_certificate(uint32_t base_hash_algo,
						    uint32_t base_asym_algo,
						    void **data, size_t *size,
						    void **hash,
						    size_t *hash_size)
{
	bool res = false;
	spdm_cert_chain_t *cert_chain = NULL;
	size_t cert_chain_size;
	size_t digest_size;
	size_t cert_der_size = 0;
	uint8_t *cert_der = NULL;

	switch(base_asym_algo) {
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
		cert_der = ecp256_ca_cert_der;
		cert_der_size = ecp256_ca_cert_der_len;
		res = true;
		break;
	case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
		cert_der = ecp384_ca_cert_der;
		cert_der_size = ecp384_ca_cert_der_len;
		res = true;
		break;
	}

	if (res) {
		digest_size = libspdm_get_hash_size(base_hash_algo);
		cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + cert_der_size;
		cert_chain = (spdm_cert_chain_t *)malloc(cert_chain_size);
		cert_chain->length = (uint16_t)cert_chain_size;
		cert_chain->reserved = 0;
		res = libspdm_hash_all(base_hash_algo, cert_der, cert_der_size,
			(uint8_t *)(cert_chain + 1));
		if (res) {
			libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
				cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
				cert_der, cert_der_size);
			*data = cert_chain;
			*size = cert_chain_size;
			*hash = cert_chain + 1;
			*hash_size = digest_size;
		}
	}

	return res;
}

bool libspdm_read_responder_root_public_certificate_slot(uint8_t slot_id,
							 uint32_t base_hash_algo,
							 uint32_t base_asym_algo,
							 void **data, size_t *size,
							 void **hash,
							 size_t *hash_size);

bool libspdm_read_requester_root_public_certificate(uint32_t base_hash_algo,
						    uint16_t req_base_asym_alg,
						    void **data, size_t *size,
						    void **hash,
						    size_t *hash_size);

bool libspdm_read_responder_public_certificate_chain_by_size(
	uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t CertId,
	void **data, size_t *size, void **hash,
	size_t *hash_size);

bool libspdm_read_responder_root_public_certificate_by_size(
	uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t CertId,
	void **data, size_t *size, void **hash,
	size_t *hash_size);

bool libspdm_read_responder_public_key(
	uint32_t base_asym_algo, void **data, size_t *size);

bool libspdm_read_requester_public_key(
	uint16_t req_base_asym_alg, void **data, size_t *size);

