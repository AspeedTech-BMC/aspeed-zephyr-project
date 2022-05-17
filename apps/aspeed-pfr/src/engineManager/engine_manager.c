/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>

#include "engine_manager.h"
#include "include/definitions.h"
#include "common/common.h"
#include "imageVerification/image_verify.h"
#include "intel_pfr/intel_pfr_verification.h"
#include "intel_pfr/intel_pfr_provision.h"

uint8_t signature[RSA_MAX_KEY_LENGTH];          /**< Buffer for the manifest signature. */
uint8_t platform_id[256];                       /**< Cache for the platform ID. */

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
	int status = 0;

	status = flash_master_wrapper_init(getFlashMasterInstance());
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
	status = signature_verification_init(getSignatureVerificationInstance());
	assert(status == 0);
	status = initialize_I2cSlave();
	assert(status == 0);
	status = initialize_pfm_flash();

	return status;
}

void uninitializeEngines(void)
{
	pfm_flash_release(getPfmFlashInstance());
}

void init_SPI_RW_Region(int spi_device_id)
{

	int status = 0;
	static char *spim_devs[4] = {
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
	uint8_t *data;
	uint8_t pfm_length[4];
	uint32_t pfm_read_address;

	if (spi_device_id == 0)
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, &pfm_read_address, sizeof(pfm_read_address));
	else if (spi_device_id == 1)
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, &pfm_read_address, sizeof(pfm_read_address));

	uint32_t pfm_region_Start = pfm_read_address + 0x400 + 0x20;  // Block 0 + Block 1 = 1024 (0x400); PFM data(PFM Body = 0x20)
	int default_region_length = 16;
	uint32_t region_start_address;
	uint32_t region_end_address;
	uint32_t addr_size_of_pfm = pfm_read_address + 0x400 + 0x1c;    // Table 2-14  get Length
	int region_length;
	int region_id = 1;                                              // cerberus define region_id start from 1
	uint8_t region_record[16];

	spi_flash->spi.device_id[0] = spi_device_id;                    // assign the flash device id,  0:spi1_cs0, 1:spi2_cs0 , 2:spi2_cs1, 3:spi2_cs2, 4:fmc_cs0, 5:fmc_cs1
	spi_flash->spi.base.read(&spi_flash->spi, addr_size_of_pfm, pfm_length, 4);

	int pfm_record_length = (pfm_length[0] & 0xff) | (pfm_length[1] << 8 & 0xff00) | (pfm_length[2] << 16 & 0xff0000) | (pfm_length[3] << 24 & 0xff000000);

	while (true) {
		spi_flash->spi.base.read(&spi_flash->spi, pfm_region_Start, region_record, default_region_length);
		if (region_record[0] == 0x01) {
			if ((region_record[1] & 0x02) == 0x02) {
				region_start_address = (region_record[8] & 0xff) | (region_record[9] << 8 & 0xff00) | (region_record[10] << 16 & 0xff0000) | (region_record[11] << 24 & 0xff000000);
				region_end_address = (region_record[12] & 0xff) | (region_record[13] << 8 & 0xff00) | (region_record[14] << 16 & 0xff0000) | (region_record[15] << 24 & 0xff000000);
				region_length = region_end_address - region_start_address;
				spi_filter->base.set_filter_rw_region(&spi_filter->base, region_id, region_start_address, region_end_address);
				region_id++;

			}

			if ((region_record[1] & 0x01) != 0x01) {

				region_start_address = (region_record[8] & 0xff) | (region_record[9] << 8 & 0xff00) | (region_record[10] << 16 & 0xff0000) | (region_record[11] << 24 & 0xff000000);
				region_end_address = (region_record[12] & 0xff) | (region_record[13] << 8 & 0xff00) | (region_record[14] << 16 & 0xff0000) | (region_record[15] << 24 & 0xff000000);
				region_length = region_end_address - region_start_address;
				Set_SPI_Filter_RW_Region(spim_devs[spi_device_id], SPI_FILTER_READ_PRIV, SPI_FILTER_PRIV_DISABLE, region_start_address, region_length);  // Cerberus did not support read disabled

			}

			if ((region_record[2] & 0x01) == 0x01)
				pfm_region_Start = pfm_region_Start + 48;
			else
				pfm_region_Start = pfm_region_Start + 16;
		} else
			break;
		if (pfm_region_Start > pfm_read_address + 0x400 + pfm_record_length)
			break;
	}

	spi_filter->base.enable_filter(spi_filter, true);
}
