/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>
#include "common.h"

struct flash flashDevice;
struct flash_master flashMaster;			/**< Flash master for the PFM flash. */
struct hash_engine hashEngine;				/**< Hashing engine for validation. */
struct host_state_manager hostStateManager;
struct manifest_flash manifestFlash;
struct pfm_flash pfmFlash;					/**< PFM instance under test. */
struct pfm_manager_flash pfmManagerFlash;
struct signature_verification signatureVerification;	/**< PFM signature verification. */
struct spi_flash spiFlash;					/**< Flash where the PFM is stored. */
struct rsa_engine_wrapper rsaEngineWrapper;
struct I2CSlave_engine_wrapper I2cSlaveEnginWrapper;

// Zephyr Ported structures
struct spi_engine_wrapper spiEngineWrapper;
struct flash_master_wrapper flashEngineWrapper;
struct spi_filter_engine_wrapper spiFilterEngineWrapper;

uint8_t hashStorage[hashStorageLength];

bool gBootCheckpointReceived = false;
int gBMCWatchDogTimer = -1;
int gPCHWatchDogTimer = -1;
uint32_t gMaxTimeout = MAX_BIOS_BOOT_TIME;

struct flash *getFlashDeviceInstance()
{
	flashDevice = spiEngineWrapper.spi.base;
	
	return &flashDevice;
}

struct flash_master *getFlashMasterInstance()
{
	return &flashMaster;
}

struct hash_engine *get_hash_engine_instance()
{
	return &hashEngine;
}

struct host_state_manager *getHostStateManagerInstance()
{
	return &hostStateManager;
}

struct manifest_flash *getManifestFlashInstance()
{
	return &manifestFlash;
}

struct pfm_flash *getPfmFlashInstance()
{
	return &pfmFlash;
}

struct pfm_manager_flash *getPfmManagerFlashInstance()
{
	return &pfmManagerFlash;
}

struct signature_verification *getSignatureVerificationInstance()
{
	return &signatureVerification;
}

struct spi_flash *getSpiFlashInstance()
{
	return &spiFlash;
}

struct rsa_engine_wrapper *getRsaEngineInstance()
{
	return &rsaEngineWrapper;
}

struct spi_engine_wrapper *getSpiEngineWrapper()
{
	return &spiEngineWrapper;
}

struct flash_master_wrapper *getFlashEngineWrapper()
{
	return &flashEngineWrapper;
}

struct I2CSlave_engine_wrapper *getI2CSlaveEngineInstance()
{
	return &I2cSlaveEnginWrapper.base;
}

uint8_t *getNewHashStorage()
{
	memset(hashStorage, 0, hashStorageLength);

	return hashStorage;
}

struct spi_filter_engine_wrapper *getSpiFilterEngineWrapper()
{
	return &spiFilterEngineWrapper;
}
