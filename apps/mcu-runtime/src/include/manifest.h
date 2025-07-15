/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) ASPEED Technology Inc.
 */
#ifndef _MANIFEST_H
#define _MANIFEST_H

#include <fit.h>
#include <stdint.h>

#include <zephyr/drivers/cptra.h>

#define CPTRA_FLASH_IMG_MAGIC (0x48534C46)

#define CPTRA_SYS_LOAD_ADDR     (void *)(CONFIG_SYS_LOAD_ADDR)
#define CPTRA_SYS_LOAD_SIZE     (0x4000000)
#define CPTRA_SYS_LOAD_ADDR_END (void *)(CONFIG_SYS_LOAD_ADDR + 0x4000000)

#define CPTRA_ECDSA384_VFY_PKT(_r, _s)                                                             \
	.r = (char *)(_r), .s = (char *)(_s), .m_len = 48, .r_len = 48, .s_len = 48,

#define CPTRA_ECDSA384_NIST_P384_CURVE(_x, _y)                                                     \
	.curve_id = ECC_CURVE_NIST_P384, .qx = (char *)(_x), .qy = (char *)(_y),

enum {
	CPTRA_FMC_FW_ID = 0x01,
	CPTRA_ATF_FW_ID = 0x0a,
	CPTRA_OPTEE_FW_ID = 0x0b,
	CPTRA_UBOOT_FW_ID = 0x0c,
	CPTRA_SSP_FW_ID = 0x0d,
	CPTRA_TSP_FW_ID = 0x0e,
};

enum cptra_error_code {
	CPTRA_SUCCESS = 0,
	CPTRA_ERR_INVALID_PARAMETER,
	CPTRA_ERR_UNSUPPORT_BOOT_DEV,
	CPTRA_ERR_READ_HDR,
	CPTRA_ERR_HDR_MAGIC_MISMATCH,
	CPTRA_ERR_EXCEED_MAX_IMG_COUNT,
	CPTRA_ERR_READ_CHKSUM,
	CPTRA_ERR_READ_IMG_INFO,
	CPTRA_ERR_READ_FULL_IMG,
	CPTRA_ERR_HDR_CHKSUM,
	CPTRA_ERR_PAYLOAD_CHKSUM,
	CPTRA_ERR_SOC_MANIFEST_NO_INFO,
	CPTRA_ERR_SOC_MANIFEST_READ_ERROR,
	CPTRA_ERR_SOC_MANIFEST_MAGIC_MISMATCH,
	CPTRA_ERR_SOC_MANIFEST_VFY,
	CPTRA_ERR_SOC_MANIFEST_SVN_VFY,
	CPTRA_ERR_SOC_MANIFEST_VER_MISMATCH,
	CPTRA_ERR_SHA384_CAL,
	CPTRA_ERR_IMAGE_VFY_UNKNOWN_ERROR,
	CPTRA_ERR_IMAGE_VFY_MBOX_ERROR,
	CPTRA_ERR_IMAGE_VFY_FWID_MISMATCH,
	CPTRA_ERR_IMAGE_VFY_HASH_MISMATCH,
	CPTRA_ERR_IMAGE_LOAD_INVALID_PARAM,
	CPTRA_ERR_IMAGE_LOAD,
	CPTRA_ERR_IMAGE_READ,
	CPTRA_ERR_IMAGE_SIZE_INVALID = -1,
	CPTRA_ERR_IMAGE_OFFSET_INVALID = -2,
};

struct cptra_manifest_hdr {
	uint32_t magic;
	uint16_t hdr_ver;
	uint16_t img_count;
} __attribute__((__packed__));

struct cptra_checksum_info {
	uint32_t hdr_checksum;
	uint32_t payload_checksum;
} __attribute__((__packed__));

struct cptra_image_info {
	uint32_t identifier;
	uint32_t offset;
	uint32_t size;
} __attribute__((__packed__));

struct cptra_manifest_aspeed_preamble {
	uint32_t manifest_marker;
	uint32_t preamble_size;
	uint32_t manifest_version;
	uint32_t manifest_sec_version;
	uint32_t manifest_flags;
	uint32_t manifest_vendor_ecc384_key[24];
	uint32_t manifest_vendor_lms_key[12];
	uint32_t manifest_vendor_ecc384_sig[24];
	uint32_t manifest_vendor_LMS_sig[405];
	uint32_t manifest_owner_ecc384_key[24];
	uint32_t manifest_owner_lms_key[12];
	uint32_t manifest_owner_ecc384_sig[24];
	uint32_t manifest_owner_LMS_sig[405];
	uint32_t manifest_owner_svn_ecc384_sig[24];
	uint32_t manifest_owner_svn_LMS_sig[405];
	uint32_t metadata_vendor_ecc384_sig[24];
	uint32_t metadata_vendor_LMS_sig[405];
	uint32_t metadata_owner_ecc384_sig[24];
	uint32_t metadata_owner_LMS_sig[405];
} __attribute__((__packed__, __aligned__(4)));

struct cptra_manifest_aspeed_svn {
	uint32_t ver;
	uint32_t sec_ver;
	uint32_t flags;
	uint32_t manifest_owner_ecc384_key[24];
	uint32_t manifest_owner_lms_key[12];
} __attribute__((__packed__));

struct cptra_soc_manifest {
	struct cptra_manifest_aspeed_preamble preamble;
	uint32_t ime_count;
	struct cptra_manifest_ime imc[CPTRA_IMC_ENTRY_COUNT];
} __attribute__((__packed__, __aligned__(4)));

struct cptra_image_context {
	struct cptra_manifest_hdr *hdr;
	struct cptra_checksum_info *chk;
	struct cptra_image_info *img_info;
	struct cptra_soc_manifest *soc_manifest;
};

struct cptra_load_info {
	/**
	 * read_sector - Number of bytes read from the device
	 * write_sector - Number of bytes written to the buffer
	 *
	 * Manifest load operations reads the manifest from the device
	 * and writes it to a buffer.
	 */
	int read_sector;
	int write_sector;
	int size;

	/**
	 * read() - Read from device
	 *
	 * @load: Information about the load state
	 * @sector: Sector number to read from (each @load->bl_len bytes)
	 * @count: Number of sectors to read
	 * @buf: Buffer to read into
	 * @return number of sectors read, 0 on error
	 */
	uint32_t (*read)(struct fit_load_info *load, uint32_t sector, uint32_t count, void *buf);
};

static inline void *cptra_manifest_buffer_addr(uint32_t offset)
{
	/* Return the address where the manifest buffer should be loaded */
	return (void *)(CONFIG_SYS_LOAD_ADDR + offset);
}

int cptra_load_image(enum boot_mode_type boot_mode, struct cptra_image_context *ctx);
int cptra_verify_soc_manifest(struct cptra_soc_manifest *manifest);
int cptra_verify_soc_manifest_ver(struct cptra_soc_manifest *manifest);
int cptra_verify_image(uint8_t *img, uint32_t img_size, struct cptra_manifest_ime *ime);
void board_manifest_image_post_process(struct cptra_manifest_ime *ime);

char *cptra_ime_get_image_name(struct cptra_manifest_ime *ime);
int cptra_soc_manifest_offset(struct cptra_image_context *ctx);
int cptra_ime_image_offset(struct cptra_image_context *ctx, struct cptra_manifest_ime *ime);
int cptra_ime_image_size(struct cptra_image_context *ctx, struct cptra_manifest_ime *ime);
bool cptra_ime_loadable_image(struct cptra_manifest_ime *ime);
uintptr_t cptra_ime_get_load_addr(struct cptra_manifest_ime *ime);
int cptra_ime_load_image(void *img_bin, uint32_t img_size, struct cptra_manifest_ime *ime);

#endif /* _MANIFEST_H */
