/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <zephyr/storage/flash_map.h>
#include <mbedtls/sha512.h>
#include <soc.h>
#include <zephyr/portability/cmsis_os2.h>
#include "SPDM/SPDMCommon.h"
#include "GetMeasurementImpl.h"

LOG_MODULE_REGISTER(spdm_meas, CONFIG_LOG_DEFAULT_LEVEL);

int get_measurement_by_index(uint8_t measurement_index, uint8_t *measurement,
	size_t *meas_offset, size_t *remain_size, size_t *measurement_size)
{
	/* Calculate specific measurement */
	const struct flash_area *area_measured = NULL;
	size_t area_size = 0;
	int ret;
	measurement_block_header *meas_block_header;
	dmtf_measurement_spec_header *dmtf_meas_header;

	if (*remain_size < (SHA384_DIGEST_LENGTH + sizeof(measurement_block_header)
			+ sizeof(dmtf_measurement_spec_header))) {
		LOG_ERR("Buffer size (%d) is not enough", *remain_size);
		*measurement_size = 0;
		return -1;
	}

	/* Measurement blocks
	 * 1: MCUBoot bootloader, measured by secure boot engine (ROT) if DICE is enabled
	 * 2: Primary firmware, measured by MCUBoot bootloader (COT1)
	 * 3: Secondary firmware, measured by MCUBoot bootloader (COT2)
	 */

	LOG_INF("MEASURE Index[%d]", measurement_index);
	switch (measurement_index) {
#if defined(CONFIG_ASPEED_DICE)
	case 1:
		ret = flash_area_open(FIXED_PARTITION_ID(mcuboot_partition), &area_measured);
		area_size = FIXED_PARTITION_SIZE(mcuboot_partition);
		break;
#if FIXED_PARTITION_EXISTS(active_partition)
	case 2:
		ret = flash_area_open(FIXED_PARTITION_ID(active_partition), &area_measured);
		area_size = FIXED_PARTITION_SIZE(active_partition);
		break;
#endif
#if FIXED_PARTITION_EXISTS(recovery_partition)
	case 3:
		ret = flash_area_open(FIXED_PARTITION_ID(recovery_partition), &area_measured);
		area_size = FIXED_PARTITION_SIZE(recovery_partition);
		break;
#endif
#else
#if FIXED_PARTITION_EXISTS(active_partition)
	case 1:
		ret = flash_area_open(FIXED_PARTITION_ID(active_partition), &area_measured);
		area_size = FIXED_PARTITION_SIZE(active_partition);
		break;
#endif
#if FIXED_PARTITION_EXISTS(recovery_partition)
	case 2:
		ret = flash_area_open(FIXED_PARTITION_ID(recovery_partition), &area_measured);
		area_size = FIXED_PARTITION_SIZE(recovery_partition);
		break;
#endif
#endif
	default:
		ret = -1;
		break;
	}

	if (ret != 0) {
		LOG_ERR("Failed to open flash area");
		*measurement_size = 0;
		return -1;
	}

	mbedtls_sha512_context sha_ctx;
	size_t offset = 0, read_size;
	static uint8_t buffer[4096] NON_CACHED_BSS_ALIGN16;

	mbedtls_sha512_init(&sha_ctx);
	mbedtls_sha512_starts(&sha_ctx, 1 /* SHA-384 */);
	while (offset < area_size) {
		read_size = (area_size - offset) > sizeof(buffer) ?
			sizeof(buffer) : (area_size - offset);
		ret = flash_area_read(area_measured, offset, buffer, read_size);
		if (ret != 0) {
			LOG_ERR("flash_area_read offset=0x%x read_size=%d ret=%d",
				offset, read_size, ret);
			break;
		}
		mbedtls_sha512_update(&sha_ctx, buffer, read_size);
		offset += read_size;
	}
	flash_area_close(area_measured);

	/* Measurement block:
	 * 0x00 - Index, Shall represent the index of the measurement
	 * 0x01 - MeasurementSpecification (Bit[0] DMTF MeasurementSpec)
	 * 0x02 - MeasurementSize in bytes
	 * 0x04 - Measurement
	 *	  0x00 - DMTFSpecMeasurementValueType
	 *		 Bit[7]:   0b Hash, 1b Raw bit stream
	 *		 Bit[6:0]: 00h Immutable ROM
	 *			   01h Mutable firmware
	 *			   02h Hardware configuration, such as straps, debug modes
	 *			   03h Firmware configuration, such as configurable firmware policy
	 *	  0x01 - DMTFSpecMeasurementValueSize, uint16_t
	 *	  0x03 - DMTFSpecMeasureMentValue
	 */
	meas_block_header = (measurement_block_header *)&measurement[*meas_offset];
	meas_block_header->index = measurement_index;
	meas_block_header->measurement_spec = SPDM_MEASUREMENT_BLOCK_DMTF_SPEC;
	meas_block_header->measurement_size =
		SHA384_DIGEST_LENGTH + sizeof(dmtf_measurement_spec_header);
	*meas_offset += sizeof(measurement_block_header);

	dmtf_meas_header = (dmtf_measurement_spec_header *)&measurement[*meas_offset];
	dmtf_meas_header->value_type = SPDM_MEASUREMENT_BLOCK_DMTF_TYPE_MUTABLE_FIRMWARE;
	dmtf_meas_header->measurement_size = SHA384_DIGEST_LENGTH;
	*meas_offset += sizeof(dmtf_measurement_spec_header);

	mbedtls_sha512_finish(&sha_ctx, measurement + *meas_offset);
	mbedtls_sha512_free(&sha_ctx);

	*measurement_size = meas_block_header->measurement_size;
	LOG_HEXDUMP_DBG(dmtf_meas_header,
		meas_block_header->measurement_size, "Measurement SHA-384:");

	*meas_offset += SHA384_DIGEST_LENGTH;
	*remain_size -= *measurement_size;
	*measurement_size = *remain_size;

	return 0;
}

__weak int get_measurement_manifest(uint8_t *measurement, size_t *measurement_size)
{
	measurement_block_header *meas_block_header;
	dmtf_measurement_spec_header *dmtf_meas_header;
	char buffer[100];
	int len;

	len = snprintf(buffer, sizeof(buffer), "This implementation is used for demonstration."
		" User shall replace this implementation.");
	len++; // for null-end

	if (*measurement_size < len + sizeof(measurement_block_header) +
				sizeof(dmtf_measurement_spec_header)) {
		LOG_ERR("Buffer size (%d) is not enough", *measurement_size);
		*measurement_size = 0;
		return -1;
	}

	meas_block_header = (measurement_block_header *)measurement;
	meas_block_header->index = SPDM_MEASUREMENT_OPERATION_MANIFEST;
	meas_block_header->measurement_spec = SPDM_MEASUREMENT_BLOCK_DMTF_SPEC;
	meas_block_header->measurement_size =
		len + sizeof(dmtf_measurement_spec_header);

	dmtf_meas_header = (dmtf_measurement_spec_header *)
			(measurement + sizeof(measurement_block_header));
	dmtf_meas_header->value_type = SPDM_MEASUREMENT_BLOCK_DMTF_TYPE_RAW_STREAM |
				SPDM_MEASUREMENT_BLOCK_DMTF_TYPE_MANIFEST;
	dmtf_meas_header->measurement_size = len;

	memcpy(measurement + sizeof(measurement_block_header) + sizeof(dmtf_measurement_spec_header),
		buffer, len);

	*measurement_size = len + sizeof(measurement_block_header) +
				sizeof(dmtf_measurement_spec_header);
	return 0;
}

int get_device_mode(uint8_t *measurement, size_t *measurement_size)
{
	measurement_block_header *meas_block_header;
	dmtf_measurement_spec_header *dmtf_meas_header;
	measurement_device_mode_block *device_mode_block;

	if (*measurement_size < sizeof(measurement_device_mode_block) +
				sizeof(measurement_block_header) +
				sizeof(dmtf_measurement_spec_header)) {
		LOG_ERR("Buffer size (%d) is not enough", *measurement_size);
		*measurement_size = 0;
		return -1;
	}

	meas_block_header = (measurement_block_header *)measurement;
	meas_block_header->index = SPDM_MEASUREMENT_OPERATION_DEVICE_MODE;
	meas_block_header->measurement_spec = SPDM_MEASUREMENT_BLOCK_DMTF_SPEC;
	meas_block_header->measurement_size =
		sizeof(measurement_device_mode_block) + sizeof(dmtf_measurement_spec_header);

	dmtf_meas_header = (dmtf_measurement_spec_header *)
			(measurement + sizeof(measurement_block_header));
	dmtf_meas_header->value_type = SPDM_MEASUREMENT_BLOCK_DMTF_TYPE_RAW_STREAM |
				SPDM_MEASUREMENT_BLOCK_DMTF_TYPE_DEVICE_MODE;
	dmtf_meas_header->measurement_size = sizeof(measurement_device_mode_block);

	device_mode_block = (measurement_device_mode_block *)
			(measurement + sizeof(measurement_block_header) +
			sizeof(dmtf_measurement_spec_header));
	// Indicates support for reporting device in normal operational mode
	device_mode_block->OperationalModeCapabilities = BIT(2);
	device_mode_block->OperationalModeState = BIT(2);
	// There is no debug mode in current code base
	device_mode_block->DeviceModeCapabilities = 0;
	device_mode_block->DeviceModeState = 0;
	*measurement_size = sizeof(measurement_device_mode_block) +
				sizeof(measurement_block_header) +
				sizeof(dmtf_measurement_spec_header);

	return 0;
}

int get_measurement(void *context,
		uint8_t measurement_index, uint8_t *measurement_count,
		uint8_t *measurement, size_t *measurement_size)
{
	size_t offset = 0, remain_size = *measurement_size;
	uint8_t i, total_block_count;

#if defined(CONFIG_ASPEED_DICE)
	// for mcuboot, active, recovery
	total_block_count = 3;
#else
	// for active, recovery
	total_block_count = 2;
#endif
	*measurement_count = 0;

	switch (measurement_index) {
	case SPDM_MEASUREMENT_OPERATION_TOTAL_NUMBER:
		/* Return the number of measurements in count */
		*measurement_count = total_block_count;
		*measurement_size = 0;
		break;
	case SPDM_MEASUREMENT_OPERATION_MANIFEST:
		if (get_measurement_manifest(measurement, measurement_size)) {
			*measurement_count = 0;
			return -1;
		}
		*measurement_count = 1;
		break;
	case SPDM_MEASUREMENT_OPERATION_DEVICE_MODE:
		if (get_device_mode(measurement, measurement_size)) {
			*measurement_count = 0;
			return -1;
		}
		*measurement_count = 1;
		break;
	case SPDM_MEASUREMENT_OPERATION_ALL_MEASUREMENTS:
		/* Calculate all measurements */
		for (i = 0 ; i < total_block_count; i++) {
			if (get_measurement_by_index(i + 1, measurement,
				&offset, &remain_size, measurement_size)) {
				*measurement_count = 0;
				return -1;
			}
			(*measurement_count)++;
		}
		*measurement_size = offset;
		break;
	default:
		if (measurement_index > total_block_count) {
			LOG_ERR("Index %d is not supported", measurement_index);
			return -1;
		}
		if (get_measurement_by_index(measurement_index, measurement,
			&offset, &remain_size, measurement_size)) {
			*measurement_count = 0;
			return -1;
		}
		*measurement_count = 1;
		*measurement_size = offset;
		break;
	}

	return 0;
}

void register_get_measurement(struct spdm_context *context)
{
	context->get_measurement = get_measurement;
}

