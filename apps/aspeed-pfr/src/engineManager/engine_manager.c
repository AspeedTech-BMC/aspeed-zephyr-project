/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <logging/log.h>
#include <zephyr.h>
#include <device.h>
#include <logging/log.h>
#include <drivers/i2c/pfr/i2c_filter.h>

#include "Smbus_mailbox/Smbus_mailbox.h"
#include "crypto/hash_wrapper.h"
#include "engine_manager.h"
#include "include/definitions.h"
#include "common/common.h"
#include "imageVerification/image_verify.h"
#include "intel_pfr/intel_pfr_verification.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "manifestProcessor/manifestProcessor.h"
#include "flash/flash_wrapper.h"
#include "gpio/gpio_aspeed.h"

LOG_MODULE_REGISTER(engine, CONFIG_LOG_DEFAULT_LEVEL);

uint8_t signature[RSA_MAX_KEY_LENGTH];          /**< Buffer for the manifest signature. */
uint8_t platform_id[256];                       /**< Cache for the platform ID. */

#define SPIM_NUM  4

static int initialize_I2cSlave(/*struct engine_instances *engineInstances*/)
{
	int status = I2C_Slave_wrapper_init(getI2CSlaveEngineInstance());
	return status;
}


static int initialize_crypto(/*struct engine_instances *engineInstances*/)
{
	int status = 0;

	status = hash_wrapper_init(get_hash_engine_instance());
	if (status)
		return status;

	status = rsa_wrapper_init(getRsaEngineInstance());

	return status;
}

static int initialize_flash(void)
{
	int status = flash_master_wrapper_init(getFlashEngineWrapper());
	if (status)
		return status;

	status = flash_wrapper_init(getSpiEngineWrapper(), getFlashEngineWrapper());

	return status;
}

int initialize_pfm_flash(void)
{
	int status = 0;

	status = pfm_flash_init(getPfmFlashInstance(), getFlashDeviceInstance(), get_hash_engine_instance(), PFM_FLASH_MANIFEST_ADDRESS, signature, RSA_MAX_KEY_LENGTH, platform_id, sizeof(platform_id));

	return status;
}

int initializeEngines(void)
{
	int status = 0;

	status = initialize_flash();
	assert(status == 0);
	status = initialize_crypto();
	assert(status == 0);
#ifdef CONFIG_CERBERUS_PFR
	status = signature_verification_init(getSignatureVerificationInstance());
	assert(status == 0);
#endif
	status = initialize_I2cSlave();
	assert(status == 0);
#ifdef CONFIG_CERBERUS_PFR
	status = initialize_pfm_flash();
#endif

	return status;
}

void uninitializeEngines(void)
{
	pfm_flash_release(getPfmFlashInstance());
}

#if defined(CONFIG_SEAMLESS_UPDATE)
void apply_fvm_spi_protection(struct spi_engine_wrapper *spi_flash, uint32_t fvm_addr)
{
	uint32_t fvm_offset = fvm_addr + PFM_SIG_BLOCK_SIZE;
	uint32_t fvm_body_offset = fvm_offset + sizeof(FVM_STRUCTURE);
	FVM_STRUCTURE fvm;
	PFM_SPI_DEFINITION spi_def;
	uint32_t fvm_body_end_addr;

	spi_flash->spi.device_id[0] = PCH_SPI;
	spi_flash->spi.base.read(&spi_flash->spi, fvm_offset, &fvm, sizeof(FVM_STRUCTURE));
	fvm_body_end_addr = fvm_offset + fvm.Length;

	while(fvm_body_offset < fvm_body_end_addr) {
		spi_flash->spi.base.read(&spi_flash->spi, fvm_body_offset, &spi_def,
				sizeof(PFM_SPI_DEFINITION));
		if (spi_def.PFMDefinitionType == SPI_REGION) {
			if (spi_def.ProtectLevelMask.ReadAllowed) {
				Set_SPI_Filter_RW_Region(PCH_SPI_MONITOR, SPI_FILTER_READ_PRIV,
						SPI_FILTER_PRIV_ENABLE, spi_def.RegionStartAddress,
						(spi_def.RegionEndAddress - spi_def.RegionStartAddress));
				LOG_INF("SPI_ID[2] fvm read enable 0x%08x to 0x%08x",
					spi_def.RegionStartAddress,
					spi_def.RegionEndAddress);
			} else {
				Set_SPI_Filter_RW_Region(PCH_SPI_MONITOR, SPI_FILTER_READ_PRIV,
						SPI_FILTER_PRIV_DISABLE, spi_def.RegionStartAddress,
						(spi_def.RegionEndAddress - spi_def.RegionStartAddress));
				LOG_INF("SPI_ID[2] fvm read disable 0x%08x to 0x%08x",
					spi_def.RegionStartAddress,
					spi_def.RegionEndAddress);
			}

			if (spi_def.ProtectLevelMask.WriteAllowed) {
				Set_SPI_Filter_RW_Region(PCH_SPI_MONITOR, SPI_FILTER_WRITE_PRIV,
						SPI_FILTER_PRIV_ENABLE, spi_def.RegionStartAddress,
						(spi_def.RegionEndAddress - spi_def.RegionStartAddress));
				LOG_INF("SPI_ID[2] fvm write enable 0x%08x to 0x%08x",
					spi_def.RegionStartAddress,
					spi_def.RegionEndAddress);
			} else {
				Set_SPI_Filter_RW_Region(PCH_SPI_MONITOR, SPI_FILTER_WRITE_PRIV,
						SPI_FILTER_PRIV_DISABLE, spi_def.RegionStartAddress,
						(spi_def.RegionEndAddress - spi_def.RegionStartAddress));
				LOG_INF("SPI_ID[2] fvm write disable 0x%08x to 0x%08x",
					spi_def.RegionStartAddress,
					spi_def.RegionEndAddress);
			}

			if (spi_def.HashAlgorithmInfo.SHA256HashPresent) {
				fvm_body_offset += sizeof(PFM_SPI_DEFINITION) + SHA256_SIZE;
			} else if (spi_def.HashAlgorithmInfo.SHA384HashPresent) {
				fvm_body_offset += sizeof(PFM_SPI_DEFINITION) + SHA384_SIZE;
			} else {
				fvm_body_offset += SPI_REGION_DEF_MIN_SIZE;
			}
		} else if (spi_def.PFMDefinitionType == FVM_CAP) {
			fvm_body_offset += sizeof(FVM_CAPABLITIES);
		} else {
			break;
		}
	}
}
#endif

void apply_pfm_protection(int spi_device_id)
{

	int status = 0;
	static char *spim_devs[SPIM_NUM] = {
		"spi_m1",
		"spi_m2",
		"spi_m3",
		"spi_m4"
	};

	status = spi_filter_wrapper_init(getSpiFilterEngineWrapper());
	struct spi_filter_engine_wrapper *spi_filter = getSpiFilterEngineWrapper();

	spi_filter->dev_id = spi_device_id;  // 0: BMC , 1: PCH

	// read PFR_Manifest
	status = initializeEngines();
	status = initializeManifestProcessor();

	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();
	uint8_t pfm_length[4];
	uint32_t pfm_read_address;

	if (spi_device_id == BMC_SPI)
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, (uint8_t *)&pfm_read_address, sizeof(pfm_read_address));
	else if (spi_device_id == PCH_SPI)
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&pfm_read_address, sizeof(pfm_read_address));

	// Block 0 + Block 1 = 1024 (0x400); PFM data(PFM Body = 0x20)
	uint32_t pfm_region_Start = pfm_read_address + 0x400 + 0x20;
	int default_region_length = 40;
	uint32_t region_start_address;
	uint32_t region_end_address;
	// Table 2-14  get Length
	uint32_t addr_size_of_pfm = pfm_read_address + 0x400 + 0x1c;
	int region_length;
	// cerberus define region_id start from 1
	int region_id = 1;
	uint8_t region_record[40];
#if defined(CONFIG_SEAMLESS_UPDATE)
	PFM_FVM_ADDRESS_DEFINITION *fvm_def;
#endif

#if defined(CONFIG_BMC_DUAL_FLASH)
	int flash_size;
#endif

	// assign the flash device id,  0:spi1_cs0, 1:spi2_cs0 , 2:spi2_cs1, 3:spi2_cs2, 4:fmc_cs0, 5:fmc_cs1
	spi_flash->spi.device_id[0] = spi_device_id;
	spi_flash->spi.base.read(&spi_flash->spi, addr_size_of_pfm, pfm_length, 4);

	int pfm_record_length = (pfm_length[0] & 0xff) | (pfm_length[1] << 8 & 0xff00) | (pfm_length[2] << 16 & 0xff0000) | (pfm_length[3] << 24 & 0xff000000);

	bool done = false;
	// TODO: Clear all setting before apply new setting

	while (!done) {
		/* Read PFM Record */
		spi_flash->spi.base.read(&spi_flash->spi, pfm_region_Start, region_record, default_region_length);
		switch(region_record[0]) {
		case SPI_REGION:
			/* SPI Region: 0x01 */
			/* Region protect level mask:
			 * 0b00000001: Protect: Read allowed
			 * 0b00000010: Protect: Write allowed
			 * 0b00000100: Recover: recover on first recovery
			 * 0b00001000: Recover: recover on second recovery
			 * 0b00010000: Recover: Recover on third recovery
			 * 0b11100000: Reserved
			 */

			region_start_address = (region_record[8] & 0xff) | (region_record[9] << 8 & 0xff00) |
				(region_record[10] << 16 & 0xff0000) | (region_record[11] << 24 & 0xff000000);
			region_end_address = (region_record[12] & 0xff) | (region_record[13] << 8 & 0xff00) |
				(region_record[14] << 16 & 0xff0000) | (region_record[15] << 24 & 0xff000000);

#if defined(CONFIG_BMC_DUAL_FLASH)
			spi_flash->spi.base.get_device_size((struct flash *)&spi_flash->spi, &flash_size);
			if (region_start_address >= flash_size && region_end_address >= flash_size) {
				region_start_address -= flash_size;
				region_end_address -= flash_size;
				spi_device_id = BMC_SPI_2;
			}
#endif
			region_length = region_end_address - region_start_address;
			if (region_record[1] & 0x02) {
				/* Write allowed region */
				spi_filter->base.set_filter_rw_region(&spi_filter->base,
						region_id, region_start_address, region_end_address);
				region_id++;
				LOG_INF("SPI_ID[%d] write enable  0x%08x to 0x%08x",
					spi_device_id, region_start_address, region_end_address);
			} else {
				/* Write not allowed region */
				// Cerberus did not support write not allowed setting
				Set_SPI_Filter_RW_Region(spim_devs[spi_device_id],
						SPI_FILTER_WRITE_PRIV, SPI_FILTER_PRIV_DISABLE,
						region_start_address, region_length);
				LOG_INF("SPI_ID[%d] write disable 0x%08x to 0x%08x",
					spi_device_id, region_start_address, region_end_address);
			}

			if (region_record[1] & 0x01) {
				/* Read allowed region */
				// Cerberus did not support read disabled
				Set_SPI_Filter_RW_Region(spim_devs[spi_device_id],
						SPI_FILTER_READ_PRIV, SPI_FILTER_PRIV_ENABLE,
						region_start_address, region_length);
				LOG_INF("SPI_ID[%d] read  enable  0x%08x to 0x%08x",
					spi_device_id, region_start_address, region_end_address);
			} else {
				/* Read not allowed region */
				// Cerberus did not support read disabled
				Set_SPI_Filter_RW_Region(spim_devs[spi_device_id],
						SPI_FILTER_READ_PRIV, SPI_FILTER_PRIV_DISABLE,
						region_start_address, region_length);
				LOG_INF("SPI_ID[%d] read  disable 0x%08x to 0x%08x",
					spi_device_id, region_start_address, region_end_address);
			}

			/* Hash Algorhtm 2 bytes:
			 * 0b00000001: SHA256 present
			 * 0b00000010: SHA384 present
			 * 0b00000100: SHA512 present
			 * Otherwise: Reserved
			 */
			if (region_record[2] & 0x01)
				pfm_region_Start = pfm_region_Start + 48;
			else if (region_record[2] & 0x02)
				pfm_region_Start = pfm_region_Start + 64;
			else if (region_record[2] & 0x04)
				pfm_region_Start = pfm_region_Start + 80;
			else
				pfm_region_Start = pfm_region_Start + 16;
			break;
		case SMBUS_RULE:
			/* SMBus Rule Definition: 0x02 */
			LOG_INF("SMBus Rule Bus[%d] RuleId[%d] DeviceAddr[%x]",
					region_record[5], region_record[6], region_record[7]);
			LOG_HEXDUMP_INF(&region_record[8], 32, "Whitelist: ");

			if (region_record[5] > 0 && region_record[5] < 6 && region_record[6] > 0 && region_record[6] < 17) {
				// Valid Bus ID should be 1~5 and reflect to I2C_FILTER_0 ~ I2C_FILTER_4
				// Valid Rule ID should be 1~16 and refect to I2C Filter Driver Rule 0~15

				char bus_dev_name[] = "I2C_FILTER_x";
				bus_dev_name[11] = (region_record[5] - 1) + '0';
				const struct device *flt_dev = device_get_binding(bus_dev_name);
				if (flt_dev) {
					status = ast_i2c_filter_en(
							flt_dev,
							true,
							true,
							0,
							0);
					LOG_DBG("ast_i2c_filter_en ret=%d", status);
					// The i2c device address in the manifest is 8-bit format.
					// It should be 7-bit format for i2c filter api.
					uint8_t slave_addr = region_record[7] >> 1;
					status = ast_i2c_filter_update(
							flt_dev,
							region_record[6] - 1, // Rule ID
							slave_addr,           // Device Address
							&region_record[8]     // cmd_whitelist
							);
					LOG_DBG("ast_i2c_filter_update ret=%d", status);
				} else {
					LOG_ERR("%s device not found", bus_dev_name);
				}
			} else {
				LOG_HEXDUMP_ERR(region_record, 40, "Invalid Bus ID or Rule ID");
			}

			pfm_region_Start += sizeof(PFM_SMBUS_RULE);;
			break;
#if defined(CONFIG_SEAMLESS_UPDATE)
		case FVM_ADDR_DEF:
			fvm_def = (PFM_FVM_ADDRESS_DEFINITION *)region_record;
			apply_fvm_spi_protection(spi_flash, fvm_def->FVMAddress);
			pfm_region_Start += sizeof(PFM_FVM_ADDRESS_DEFINITION);
			break;
#endif
		default:
			done = true;
			break;
		}
		if (pfm_region_Start >= pfm_read_address + 0x400 + pfm_record_length)
			break;
	}

	spi_filter->base.enable_filter(spi_filter, true);
}

