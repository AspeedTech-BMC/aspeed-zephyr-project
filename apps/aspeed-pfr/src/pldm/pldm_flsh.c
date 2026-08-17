/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/logging/log.h>

#include "pldm_flsh.h"

LOG_MODULE_REGISTER(pfr_pldm_flsh, CONFIG_LOG_DEFAULT_LEVEL);

#define FLSH_HEADER_VERSION 0x0002
#define FLSH_CALIPTRA_ID 0x00000000
#define FLSH_SOC_MANIFEST_ID 0x00000001
#define FLSH_MCU_RUNTIME_ID 0x00000002
#define FLSH_MAX_IMAGE_COUNT 127

struct flsh_header {
	uint16_t version;
	uint16_t image_count;
	uint32_t image_headers_offset;
	uint32_t header_checksum;
} __packed;

struct flsh_image_header {
	uint32_t identifier;
	uint32_t offset;
	uint32_t size;
	uint32_t image_checksum;
	uint32_t image_header_checksum;
} __packed;

static uint32_t flsh_checksum(const uint8_t *data, size_t length)
{
	uint32_t sum = 0;

	for (size_t i = 0; i < length; ++i)
		sum += data[i];

	return 0u - sum;
}

static bool flsh_range_valid(size_t total, uint32_t offset, uint32_t length)
{
	return ((uint64_t)offset + length) <= total;
}

int pfr_pldm_flsh_validate(const uint8_t *image, size_t image_size)
{
	const struct flsh_header *header;
	const struct flsh_image_header *toc;
	size_t toc_size;
	uint64_t previous_end;
	bool has_caliptra = false;
	bool has_manifest = false;
	bool has_mcu = false;

	if ((image == NULL) || (image_size < sizeof(*header)))
		return -EINVAL;

	header = (const struct flsh_header *)image;
	if ((header->version != FLSH_HEADER_VERSION) || (header->image_count == 0) ||
	    (header->image_count > FLSH_MAX_IMAGE_COUNT)) {
		LOG_ERR("Invalid FLSH header: version=%u image_count=%u",
			header->version, header->image_count);
		return -EINVAL;
	}

	if (flsh_checksum(image, offsetof(struct flsh_header, header_checksum)) !=
	    header->header_checksum) {
		LOG_ERR("FLSH header checksum mismatch");
		return -EBADMSG;
	}

	toc_size = (size_t)header->image_count * sizeof(*toc);
	if ((header->image_headers_offset < sizeof(*header)) ||
	    !flsh_range_valid(image_size, header->image_headers_offset, toc_size)) {
		LOG_ERR("FLSH image table is out of range");
		return -EINVAL;
	}
	toc = (const struct flsh_image_header *)(image + header->image_headers_offset);
	previous_end = (uint64_t)header->image_headers_offset + toc_size;

	for (uint16_t i = 0; i < header->image_count; ++i) {
		const struct flsh_image_header *entry = &toc[i];

		if (flsh_checksum((const uint8_t *)entry,
				  offsetof(struct flsh_image_header, image_header_checksum)) !=
		    entry->image_header_checksum) {
			LOG_ERR("FLSH TOC checksum mismatch at index %u", i);
			return -EBADMSG;
		}
		if (!flsh_range_valid(image_size, entry->offset, entry->size)) {
			LOG_ERR("FLSH image %08x is out of range", entry->identifier);
			return -EINVAL;
		}
		if (entry->offset < previous_end) {
			LOG_ERR("FLSH image %08x overlaps header or prior image",
				entry->identifier);
			return -EINVAL;
		}
		if (flsh_checksum(image + entry->offset, entry->size) != entry->image_checksum) {
			LOG_ERR("FLSH image checksum mismatch: id=%08x", entry->identifier);
			return -EBADMSG;
		}
		previous_end = (uint64_t)entry->offset + entry->size;

		has_caliptra |= entry->identifier == FLSH_CALIPTRA_ID;
		has_manifest |= entry->identifier == FLSH_SOC_MANIFEST_ID;
		has_mcu |= entry->identifier == FLSH_MCU_RUNTIME_ID;
	}

	if (!has_caliptra || !has_manifest || !has_mcu) {
		LOG_ERR("FLSH missing mandatory image: cptra=%d manifest=%d mcu=%d",
			has_caliptra, has_manifest, has_mcu);
		return -ENOENT;
	}

#if defined(CONFIG_PFR_PLDM_INTEGRITY_ONLY_VERIFY)
	LOG_WRN("FLSH passed integrity checks; signer authentication is unavailable on CM4 MCI");
	return 0;
#else
	LOG_ERR("FLSH integrity passed, but authenticated verification is unavailable");
	return -ENOTSUP;
#endif
}
