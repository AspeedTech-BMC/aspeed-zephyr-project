/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _MANIFEST_H
#define _MANIFEST_H

#include <stdint.h>

#include <zephyr/drivers/cptra.h>

#define CPTRA_FLASH_IMG_MAGIC (0x48534C46)

#define CPTRA_SYS_LOAD_ADDR     (void *)(CONFIG_SYS_LOAD_ADDR)
#define CPTRA_SYS_LOAD_SIZE     (0x400000)
#define CPTRA_SRAM_BUF_SIZE     (16 * 1024)
#define CPTRA_OWNER_CPTRA_ECC_PUBK_X_OFFSET (0xE44)
#define CPTRA_OWNER_CPTRA_ECC_PUBK_Y_OFFSET (0xE74)
#define CPTRA_OWNER_CPTRA_LMS_PUBK_OFFSET   (0xEA4)

#define CPTRA_AUTH_MANIFEST_MARKER_1X 0x41544D4E /* "ATMN" in big endian*/
#define CPTRA_AUTH_MANIFEST_MARKER_2X 0x324D5441 /* 'ATM2' in little endian*/

#ifdef CONFIG_CPTRA_2X_LAYOUT
#define CPTRA_AUTH_MANIFEST_MARKER CPTRA_AUTH_MANIFEST_MARKER_2X
#else
#define CPTRA_AUTH_MANIFEST_MARKER CPTRA_AUTH_MANIFEST_MARKER_1X
#endif

#define CPTRA_ECDSA384_VFY_PKT(_r, _s)                                                             \
	.r = (char *)(_r), .s = (char *)(_s), .m_len = 48, .r_len = 48, .s_len = 48,

#define CPTRA_ECDSA384_NIST_P384_CURVE(_x, _y)                                                     \
	.curve_id = ECC_CURVE_NIST_P384, .qx = (char *)(_x), .qy = (char *)(_y),

#define CPTRA_INIT_LOADER(_loader, _base, _size)                                                   \
	(_loader)->base = (uintptr_t)(_base);                                                      \
	(_loader)->limit = (uintptr_t)(_base) + (_size);                                           \
	(_loader)->read_sector = 0;                                                                \
	(_loader)->write_sector = 0;                                                               \
	(_loader)->size = 0;

/* Define caliptra image identifier */
#ifndef CONFIG_CPTRA_2X_LAYOUT
#define CPTRA_SOC_MANIFEST_HDR_ID (0x0002)
#define CPTRA_FMC_HDR_ID          (0x0003)
#else
#define CPTRA_SOC_MANIFEST_HDR_ID (0x0001)
#define CPTRA_FMC_HDR_ID          (0x0002)
#endif
#define CPTRA_DDR4_IMEM_HDR_ID    (0x1000)
#define CPTRA_DDR4_DMEM_HDR_ID    (0x1001)
#define CPTRA_DDR4_2D_IMEM_HDR_ID (0x1002)
#define CPTRA_DDR4_2D_DMEM_HDR_ID (0x1003)
#define CPTRA_DDR5_IMEM_HDR_ID    (0x1004)
#define CPTRA_DDR5_DMEM_HDR_ID    (0x1005)
#define CPTRA_DP_FW_HDR_ID        (0x1006)
#define CPTRA_UEFI_HDR_ID         (0x1007)
#define CPTRA_ATF_HDR_ID          (0x1008)
#define CPTRA_OPTEE_HDR_ID        (0x1009)
#define CPTRA_UBOOT_HDR_ID        (0x100A)
#define CPTRA_SSP_HDR_ID          (0x100B)
#define CPTRA_TSP_HDR_ID          (0x100C)

/* 0x14bc0000(sram end) - 0x800 (2k csr) - 0x400 (1k imc for 2700 A2) -0x10000 (64k for Hash buffer)*/
#define AST_HASH_BUFFER (0x14baf400)
#define CONFIG_AST_LOADER_TEMP_BUF_SIZE          (0x10000)  // 64k temp buffer for image loading and verification in SRAM stask
#define CONFIG_AST_LOADER_DRAM_TEMP_BUF_MAX_SIZE (0x500000) // 5M temp buffer for image loading and verification in DRAM

enum {
	CPTRA_MANIFEST_FW_ID = 0x00,
	CPTRA_FMC_FW_ID = 0x01,
	CPTRA_DDR4_IMEM_FW_ID = 0x02,
	CPTRA_DDR4_DMEM_FW_ID = 0x03,
	CPTRA_DDR4_2D_IMEM_FW_ID = 0x04,
	CPTRA_DDR4_2D_DMEM_FW_ID = 0x05,
	CPTRA_DDR5_IMEM_FW_ID = 0x06,
	CPTRA_DDR5_DMEM_FW_ID = 0x07,
	CPTRA_DP_FW_FW_ID = 0x08,
	CPTRA_UEFI_FW_ID = 0x09,
	CPTRA_ATF_FW_ID = 0x0a,
	CPTRA_OPTEE_FW_ID = 0x0b,
	CPTRA_UBOOT_FW_ID = 0x0c,
	CPTRA_SSP_FW_ID = 0x0d,
	CPTRA_TSP_FW_ID = 0x0e,
};

enum cptra_error_code {
	CPTRA_SUCCESS = 0,
	CPTRA_ERR_EXCEED_MEMORY_LIMIT,
	CPTRA_ERR_INVALID_PARAMETER,
	CPTRA_ERR_ABB_LOADER_NOT_READY,
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
	CPTRA_ERR_SOC_MANIFEST_ECC_SVN_VFY,
	CPTRA_ERR_SOC_MANIFEST_LMS_SVN_VFY,
	CPTRA_ERR_SOC_MANIFEST_VER_MISMATCH,
	CPTRA_ERR_SOC_MANIFEST_CPTRA_RT_NOT_READY,
	CPTRA_ERR_SHA384_CAL,
	CPTRA_ERR_IMAGE_VFY_UNKNOWN_ERROR,
	CPTRA_ERR_IMAGE_VFY_MBOX_ERROR,
	CPTRA_ERR_IMAGE_VFY_FWID_MISMATCH,
	CPTRA_ERR_IMAGE_VFY_CPTRA_RT_NOT_READY,
	CPTRA_ERR_IMAGE_VFY_HASH_MISMATCH,
	CPTRA_ERR_IMAGE_LOAD_INVALID_PARAM,
	CPTRA_ERR_IMAGE_LOAD,
	CPTRA_ERR_IMAGE_READ,
	CPTRA_ERR_IMAGE_SIZE_INVALID = -1,
	CPTRA_ERR_IMAGE_OFFSET_INVALID = -2,
};

#ifndef CONFIG_CPTRA_2X_LAYOUT
struct cptra_manifest_hdr {
	uint32_t magic;
	uint16_t hdr_ver;
	uint16_t img_count;
} __attribute__((__packed__, __aligned__(4)));

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
#else
struct cptra_manifest_hdr {
	uint32_t magic;
	uint16_t hdr_ver;
	uint16_t img_count;
	uint32_t image_headers_offset;
} __attribute__((__packed__, __aligned__(4)));

struct cptra_checksum_info {
	uint32_t hdr_checksum;
} __attribute__((__packed__));

struct cptra_image_info {
	uint32_t identifier;
	uint32_t offset;
	uint32_t size;
	uint32_t image_checksum;
	uint32_t image_info_checksum;
} __attribute__((__packed__));

struct cptra_manifest_aspeed_preamble {
	uint32_t manifest_marker;
	uint32_t preamble_size;
	uint32_t manifest_version;
	uint32_t manifest_sec_version;
	uint32_t manifest_flags;
	uint32_t manifest_vendor_ecc384_key[24];
	uint32_t manifest_vendor_pqc_key[648];

	uint32_t manifest_vendor_ecc384_sig[24];
	uint32_t manifest_vendor_pqc_sig[1157];

	uint32_t manifest_owner_ecc384_key[24];
	uint32_t manifest_owner_pqc_key[648];

	uint32_t manifest_owner_ecc384_sig[24];
	uint32_t manifest_owner_pqc_sig[1157];

	uint32_t metadata_vendor_ecc384_sig[24];
	uint32_t metadata_vendor_pqc_sig[1157];
	uint32_t metadata_owner_ecc384_sig[24];
	uint32_t metadata_owner_pqc_sig[1157];
} __attribute__((__packed__, __aligned__(4)));

#endif

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
#ifdef CONFIG_CPTRA_2X_LAYOUT
	uint8_t reserved[104]; // padding to make size aligned to 256 bytes
#endif
} __attribute__((__packed__, __aligned__(4)));

struct cptra_image_context {
	struct cptra_manifest_hdr *hdr;
	struct cptra_checksum_info *chk;
	struct cptra_image_info *img_info;
	struct cptra_soc_manifest *soc_manifest;
};

struct cptra_soc_manifest_verify_buf {
	struct cptra_soc_manifest manifest;
	struct cptra_set_auth_manifest_ia auth_input;
	struct cptra_set_auth_manifest_oa output;
} __attribute__((__packed__, __aligned__(4)));

uint32_t cptra_manifest_start_offset(void);
int cptra_verify_abb_loader(void);
int cptra_load_abb_image(void);
int cptra_get_abb_imginfo(uint32_t fw_id, uint32_t *ofst, uint32_t *size);
bool cptra_manifest_sec_en(void);
int cptra_verify_soc_manifest(struct cptra_soc_manifest_verify_buf *verify_buf, uint32_t verify_buf_size);
int cptra_verify_soc_manifest_ver(struct cptra_soc_manifest *manifest);
int cptra_verify_image(uint8_t *img, uint32_t img_size, uint32_t fw_id);
void board_manifest_image_post_process(uint32_t fw_id);
bool is_ast2700_a1(void);
bool is_ast2700_a2(void);
bool cptra_rt_ready(void);

bool cptra_ime_loadable_image(struct cptra_soc_manifest *man,
							  uint32_t fw_id);
char *cptra_ime_get_image_name(uint32_t fw_id);
int cptra_ime_image_offset(struct cptra_image_context *ctx, uint32_t fw_id);
int cptra_ime_image_size(struct cptra_image_context *ctx, uint32_t fw_id);
uintptr_t cptra_ime_get_load_addr(uint32_t fw_id);
bool cptra_find_fw_id_by_identifier(uint32_t identifier, uint32_t *fw_id);
struct cptra_manifest_ime *cptra_get_ime_by_fw_id(struct cptra_soc_manifest *man,
												  uint32_t fw_id);

#endif /* _MANIFEST_H */
