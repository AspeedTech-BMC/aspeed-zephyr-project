/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include "common/common.h"
#include "flash/flash_wrapper.h"
#include "AspeedStateMachine/common_smc.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_definitions.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#endif
#include "pfr/pfr_util.h"
#include "Smbus_mailbox/Smbus_mailbox.h"


int get_cpld_status(uint8_t *data, uint32_t data_length)
{
	int status;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.state->device_id[0] = ROT_INTERNAL_STATE; // Internal UFM SPI
	status = spi_flash->spi.base.read((struct flash *)&spi_flash->spi, 0, data, data_length);

	return Success;
}

int set_cpld_status(uint8_t *data, uint32_t data_length)
{

	int status;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.state->device_id[0] = ROT_INTERNAL_STATE; // Internal UFM SPI
	status = pfr_spi_erase_4k(ROT_INTERNAL_STATE, 0);
	status = spi_flash->spi.base.write((struct flash *)&spi_flash->spi, 0, data, data_length);

	return Success;
}

int ufm_read(uint32_t ufm_id, uint32_t offset, uint8_t *data, uint32_t data_length)
{

	if (ufm_id == PROVISION_UFM)
		return get_provision_data_in_flash(offset, data, data_length);
	else if (ufm_id == UPDATE_STATUS_UFM)
		return get_cpld_status(data, data_length);
	else
		return Failure;
}

int ufm_write(uint32_t ufm_id, uint32_t offset, uint8_t *data, uint32_t data_length)
{

	if (ufm_id == PROVISION_UFM)
		return set_provision_data_in_flash(offset, data, data_length);
	else if (ufm_id == UPDATE_STATUS_UFM)
		return set_cpld_status(data, data_length);
	else
		return Failure;
}

int ufm_erase(uint32_t ufm_id)
{
	if (ufm_id == PROVISION_UFM)
		return pfr_spi_erase_4k(ROT_INTERNAL_INTEL_STATE, 0);
	else if (ufm_id == UPDATE_STATUS_UFM)
		return pfr_spi_erase_4k(ROT_INTERNAL_STATE, 0);
	else
		return Failure;
}
