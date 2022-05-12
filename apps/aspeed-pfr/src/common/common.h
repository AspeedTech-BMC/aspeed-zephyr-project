/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ZEPHYR_ASPEED_PFR_SRC_COMMON_COMMON_H_
#define ZEPHYR_ASPEED_PFR_SRC_COMMON_COMMON_H_

/* Cerberus Includes*/
#include <common/signature_verification.h>

#include <crypto/aes.h>
#include <crypto/base64.h>
#include <crypto/ecc.h>
#include <crypto/hash.h>
#include <crypto/rng.h>
#include <crypto/rsa.h>
#include <crypto/x509.h>

#include <crypto/rsa_wrapper.h>
#include <crypto/signature_verification_rsa_wrapper.h>

#include <flash/flash.h>
#include <flash/flash_master.h>
#include <flash/spi_flash.h>

#include <flash/flash_wrapper.h>
#include <spi_filter/spi_filter_wrapper.h>


#include <keystore/keystore.h>

#include <manifest/manifest.h>
#include <manifest/pfm/pfm_flash.h>
#include <manifest/pfm/pfm_manager_flash.h>

#include <i2c/I2C_wrapper.h>

#define hashStorageLength 256

struct flash *getFlashDeviceInstance();
struct flash_master *getFlashMasterInstance();
struct hash_engine *get_hash_engine_instance();
struct host_state_manager *getHostStateManagerInstance();
struct pfm_flash *getPfmFlashInstance();
struct signature_verification *getSignatureVerificationInstance();
struct spi_flash *getSpiFlashInstance();
struct rsa_engine_wrapper *getRsaEngineInstance();
struct I2CSlave_engine_wrapper *getI2CSlaveEngineInstance();
struct spi_filter_engine_wrapper *getSpiFilterEngineWrapper();

#endif /* ZEPHYR_ASPEED_PFR_SRC_COMMON_COMMON_H_ */

#define MAX_BIOS_BOOT_TIME 300
