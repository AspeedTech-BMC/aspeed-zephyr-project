/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_CERBERUS_PFR)
#include <logging/log.h>
#include "KeystoreManager.h"
#include "flash/flash_aspeed.h"
#include "common/common.h"
#include "AspeedStateMachine/common_smc.h"
#include <storage/flash_map.h>
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_util.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int keystore_save_key(struct keystore *store, int id, const uint8_t *key, size_t length)
{
	uint8_t storebuf[KeyStoreKeyMaxLen] = { 0 };
	uint16_t storebuf_index = 0;
	uint32_t base_addr;
	int status = 0;

	if (length > KEY_MAX_LENGTH) {
		LOG_ERR("%s: key too long(0x%x)", __func__, length);
		return KEYSTORE_KEY_TOO_LONG;
	}

	base_addr = id * KeyStoreKeyMaxLen;
	if (base_addr > (FLASH_AREA_SIZE(key) - KEY_MAX_LENGTH)) {
		LOG_ERR("%s: insufficient storage", __func__);
		return KEYSTORE_INSUFFICIENT_STORAGE;
	}

	//store key ID
	storebuf[storebuf_index++] = id;

	//store key length low byte
	storebuf[storebuf_index++] = (length & 0xFF);

	//store key length high byte
	storebuf[storebuf_index++] = ((length >> 8) & 0xFF);

	//store key data to buffer
	for (storebuf_index = KeyStoreHdrLen; storebuf_index < (length + KeyStoreHdrLen); storebuf_index++) {
		//for buffer ,the key should be store after header
		//for input key, the index should be start from 0
		storebuf[storebuf_index] = key[storebuf_index - KeyStoreHdrLen];
	}

	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.state->device_id[0] = ROT_INTERNAL_KEY; // Internal UFM SPI

	LOG_INF("%s: write addr = 0x%x, length = 0x%0x", __func__, base_addr, KeyStoreKeyMaxLen);
	LOG_HEXDUMP_DBG(storebuf, KeyStoreKeyMaxLen, "keystore buffer:");

	status = spi_flash->spi.base.write((struct flash *)&spi_flash->spi, base_addr, (uint8_t *)storebuf, KeyStoreKeyMaxLen);
	if (status != KeyStoreKeyMaxLen) {
		LOG_ERR("%s: key write error", __func__);
		return KEYSTORE_SAVE_FAILED;
	}

	return Success;
}

int keystore_load_key(struct keystore *store, int id, uint8_t **key, size_t *length)
{
	uint32_t BaseAddr;
	uint8_t StoreBuf[KeyStoreHdrLen] = {0};
	uint16_t StoreBufLen;
	struct Keystore_Header *KeyStorePkgHdr;
	int status;

	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.state->device_id[0] = ROT_INTERNAL_KEY; // Internal UFM SPI
	BaseAddr = id * KeyStoreKeyMaxLen;

	status = spi_flash->spi.base.read((struct flash *)&spi_flash->spi, BaseAddr, (uint8_t *)&StoreBuf, KeyStoreHdrLen);

	if (status != Success) {
		LOG_ERR("KeyStore_Load_key load header fail, Flash read status= %x", status);
		return status;	// failed to load key header from SPI
	}

	KeyStorePkgHdr = (struct Keystore_Header *)&StoreBuf[0];

	if ((KeyStorePkgHdr->key_length == 0xFF) && (KeyStorePkgHdr->key_id == 0xFF)) {
		status = KEYSTORE_NO_KEY;
		return status;
	}

	*length = KeyStorePkgHdr->key_length;
	StoreBufLen = KeyStorePkgHdr->key_length;

	//store key from flash part
	status = spi_flash->spi.base.read((struct flash *)&spi_flash->spi, BaseAddr + KeyStoreHdrLen, (uint8_t *)key, StoreBufLen);
	if (status != Success) {
		LOG_ERR("KeyStore_Load_key load key fail, Flash read status= %x", status);
		status = KEYSTORE_LOAD_FAILED;
	}

	return status;
}

int keystore_erase_key(struct keystore *store, int id)
{
	uint8_t StoreBuf[KeySectionSize] = {0};
	uint32_t BaseAddr;
	uint32_t WipeOutIndex;
	int status;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.state->device_id[0] = ROT_INTERNAL_KEY; // Internal UFM SPI
	BaseAddr = KeyStoreOffset_0;

	status = spi_flash->spi.base.read((struct flash *)&spi_flash->spi, BaseAddr, (uint8_t *)&StoreBuf, KeySectionSize);
	if (status) {
		LOG_ERR("KeyStore_Erase_key load key section fail, Flash read status= %x", status);
		return status;	// failed to load key header from SPI
	}

	status = spi_flash->spi.base.sector_erase((struct flash *)&spi_flash->spi, BaseAddr);

	if (status) {
		LOG_ERR("KeyStore_Erase_key key section erase fail, Flash erase status= %x", status);
		return status;	// failed to load key header from SPI
	}

	WipeOutIndex = id * KeyStoreKeyMaxLen;

	memset(&StoreBuf[WipeOutIndex], 0xff, KeyStoreKeyMaxLen);

	status = spi_flash->spi.base.write((struct flash *)&spi_flash->spi, BaseAddr, (uint8_t *)&StoreBuf, KeySectionSize);
	if (status != Success) {
		//Spi write suppose to return write Length
		LOG_ERR("KeyStore_Erase_key buffer store fail, write status= %x", status);
		status = KEYSTORE_SAVE_FAILED;
	} else {
		status = 0;
	}

	return status;
}

int keystore_erase_all_keys(struct keystore *store)
{
	uint32_t BaseAddr;
	int status;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.state->device_id[0] = ROT_INTERNAL_KEY; // Internal UFM SPI
	BaseAddr = KeyStoreOffset_0;
	status = spi_flash->spi.base.sector_erase((struct flash *)&spi_flash->spi, BaseAddr);

	if (status != Success)
		LOG_ERR("KeyStore_Erase_All_Keys key section erase fail, Flash erase status= %x", status);

	return status;
}

int keystoreManager_init(struct Keystore_Manager *key_store)
{
	if (key_store == NULL)
		return KEYSTORE_INVALID_ARGUMENT;

	memset(key_store, 0, sizeof(struct keystore));
	key_store->base.save_key = keystore_save_key;
	key_store->base.load_key = keystore_load_key;
	key_store->base.erase_key = keystore_erase_key;
	key_store->base.erase_all_keys = keystore_erase_all_keys;

	return 0;
}

int keystore_get_key_id(struct keystore *store, uint8_t *key, int *key_id, int *last_key_id)
{
	struct Keystore_Header *keystore_header;
	uint8_t store_buf[KeyStoreHdrLen] = {0};
	uint8_t key_buffer[KEY_MAX_LENGTH];
	uint32_t base_addr;
	int status;
	int id = 0;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.state->device_id[0] = ROT_INTERNAL_KEY; // Internal UFM SPI

	while (id < KEY_MAX_NUMBER) {
		base_addr = id * KeyStoreKeyMaxLen;

		status = spi_flash->spi.base.read((struct flash *)&spi_flash->spi, base_addr, (uint8_t *)store_buf, KeyStoreHdrLen);
		if (status != Success) {
			LOG_ERR("%s: read header failed(0x%x)", __func__, status);
			return KEYSTORE_LOAD_FAILED;
		}

		keystore_header = (struct Keystore_Header *)store_buf;
		if ((keystore_header->key_length == 0xFFFF) || (keystore_header->key_id == 0xFF)) {
			LOG_INF("%s: keystore no this key", __func__);
			*key_id = id; // index to save this key
			return KEYSTORE_NO_KEY;
		}

		if (keystore_header->key_length > KEY_MAX_LENGTH) {
			LOG_ERR("%s: key too long(0x%x)", __func__, keystore_header->key_length);
			return KEYSTORE_KEY_TOO_LONG;
		}

		//store key from flash part
		status = spi_flash->spi.base.read((struct flash *)&spi_flash->spi, base_addr + KeyStoreHdrLen, (uint8_t *)key_buffer, keystore_header->key_length);
		if (status != Success) {
			LOG_ERR("%s: read key failed(%x)", __func__, status);
			return KEYSTORE_LOAD_FAILED;
		}

		// Compare key and key_buffer
		status = compare_buffer(key, key_buffer, keystore_header->key_length);
		if (status == Success) {
			*key_id = keystore_header->key_id;
			return Success;
		}

		*last_key_id = id;
		id++;
	}

	return KEYSTORE_UNSUPPORTED_ID;
}

int keystore_save_root_key(struct rsa_public_key *pub_key)
{
	int status = 0;
	uint16_t StoreBufIndex;
	uint16_t BaseAddr = KeyStoreOffset_200;
	int rootkey_contain_size = 2 + pub_key->mod_length + sizeof(pub_key->exponent);
	uint8_t StoreBuf[KEY_MAX_LENGTH + 2 + sizeof(pub_key->exponent)] = { 0 };


	if (pub_key->mod_length > KEY_MAX_LENGTH) {
		status = KEYSTORE_KEY_TOO_LONG;
		return status;
	}

	//store key length low byte
	StoreBufIndex = 0;
	StoreBuf[StoreBufIndex] = (pub_key->mod_length & 0xFF);

	//store key length high byte
	StoreBufIndex = 1;
	StoreBuf[StoreBufIndex] = ((pub_key->mod_length >> 8) & 0xFF);

	//store key data to buffer
	for (StoreBufIndex = 2; StoreBufIndex < (pub_key->mod_length + 2); StoreBufIndex++) {
		//for buffer ,the key should be store after header
		//for input key, the index should be start from 0
		StoreBuf[StoreBufIndex] = pub_key->modulus[StoreBufIndex - 2];
	}

	// store exponent
	StoreBufIndex = pub_key->mod_length + 2;
	StoreBuf[StoreBufIndex] = (pub_key->exponent & 0xFF);

	StoreBufIndex = pub_key->mod_length + 3;
	StoreBuf[StoreBufIndex] = ((pub_key->exponent >> 8) & 0xFF);

	StoreBufIndex = pub_key->mod_length + 4;
	StoreBuf[StoreBufIndex] = ((pub_key->exponent >> 16) & 0xFF);

	StoreBufIndex = pub_key->mod_length + 5;
	StoreBuf[StoreBufIndex] = ((pub_key->exponent >> 24) & 0xFF);

	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.state->device_id[0] = ROT_INTERNAL_INTEL_STATE; // Root Key save to Intel State

	status = spi_flash->spi.base.write((struct flash *)&spi_flash->spi, BaseAddr, (uint8_t *)StoreBuf, rootkey_contain_size);

	if (status != rootkey_contain_size) {
		LOG_ERR("key write error");
		status = KEYSTORE_SAVE_FAILED;
	} else {
		LOG_INF("key write success");
		status = Success;
	}

	return status;
}

int keystore_get_root_key(struct rsa_public_key *pub_key)
{
	int status = Success;
	uint16_t BaseAddr = KeyStoreOffset_200;
	uint16_t key_length;
	uint32_t modules_address;
	uint32_t exponent_address;

	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.state->device_id[0] = ROT_INTERNAL_INTEL_STATE; // Root Key save to Intel State

	//Key Length
	status = spi_flash->spi.base.read((struct flash *)&spi_flash->spi, BaseAddr, (uint8_t *)&key_length, sizeof(key_length));
	if (status != Success)
		return Failure;

	pub_key->mod_length = key_length;
	modules_address = BaseAddr + sizeof(key_length);
	//rsa_key_module
	status = spi_flash->spi.base.read((struct flash *)&spi_flash->spi, modules_address, pub_key->modulus, key_length);

	pub_key->mod_length = key_length;
	exponent_address = BaseAddr + sizeof(key_length) + key_length;

	//rsa_key_exponent
	status = spi_flash->spi.base.read((struct flash *)&spi_flash->spi, exponent_address, (uint8_t *)&pub_key->exponent, sizeof(pub_key->exponent));

	return status;
}
#endif
