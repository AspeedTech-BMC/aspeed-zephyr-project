/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include <image/firmware_manifest.h>

/* Caliptra SOC Manifest Common Structure */
#define AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT 127

struct cptra_ecc_pub_key {
	uint8_t x[48];
	uint8_t y[48];
} __attribute__((packed));

struct cptra_ecc_signature {
	uint8_t r[48];
	uint8_t s[48];
} __attribute__((packed));

struct cptra_lms_pub_key {
	uint32_t tree_type;
	uint32_t ots_type;
	uint8_t id[16];
	uint8_t digest[24];
} __attribute__((packed));

struct cptra_lms_signature {
	uint32_t q;
	uint8_t ots[1252];
	uint32_t tree_type;
	uint8_t tree_path[360];
} __attribute__((packed));

struct cptra_pqc_pub_key {
	union {
		uint8_t data[2592];
		struct {
			uint32_t tree_type;
			uint32_t ots_type;
			uint8_t id[16];
			uint8_t digest[24];
		} lms;
	};
} __attribute__((packed));

struct cptra_pqc_signature {
	union{
		uint8_t data[4628];
		struct {
			uint32_t q;
			uint8_t ots[1252];
			uint32_t tree_type;
			uint8_t tree_path[360];
		} lms_sig;
	};
} __attribute__((packed));

/* Copy from mcu-runtime/src/manifest.h */
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
#define CPTRA_KERNEL_HDR_ID       (0x100D)

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
	CPTRA_KERNEL_FW_ID = 0x0f,
};
/* Copy from mcu-runtime/src/manifest_image.c */

/* Define caliptra image load address */
#define CPTRA_NO_LOAD_ADDR    (0x00000000)
#define CPTRA_ATF_LOAD_ADDR   (CONFIG_ATF_LOAD_ADDR)
#define CPTRA_OPTEE_LOAD_ADDR (CONFIG_OPTEE_LOAD_ADDR)
#define CPTRA_UBOOT_LOAD_ADDR (CONFIG_UBOOT_LOAD_ADDR)
#define CPTRA_TSP_LOAD_ADDR   (CONFIG_TSP_LOAD_ADDR)
#define CPTRA_KERNEL_LOAD_ADDR   (CONFIG_KERNEL_LOAD_ADDR)

/* Define caliptra image loadable property */
#define CPTRA_LOADABLE_MASK GENMASK(31, 30)
#define CPTRA_BOOTMCU_LOADABLE (1)
#define CPTRA_SSP_LOADABLE (2)

#define CPTRA_IMC_STORED_ADDR (0x14bbf400) /*FOR 2700 A2 ROM*/

struct cptra_load_image {
	char *name;
	uint32_t identifier;
	uint32_t fw_id;
	uintptr_t load_addr;
};

static struct cptra_load_image cptra_image_list[] = {
	{ "manifest", CPTRA_SOC_MANIFEST_HDR_ID, CPTRA_MANIFEST_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "mcu_fmc", CPTRA_FMC_HDR_ID, CPTRA_FMC_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "ddr4_imem", CPTRA_DDR4_IMEM_HDR_ID, CPTRA_DDR4_IMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "ddr4_dmem", CPTRA_DDR4_DMEM_HDR_ID, CPTRA_DDR4_DMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "ddr4_2d_imem", CPTRA_DDR4_2D_IMEM_HDR_ID, CPTRA_DDR4_2D_IMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "ddr4_2d_dmem", CPTRA_DDR4_2D_DMEM_HDR_ID, CPTRA_DDR4_2D_DMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "ddr5_imem", CPTRA_DDR5_IMEM_HDR_ID, CPTRA_DDR5_IMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "ddr5_dmem", CPTRA_DDR5_DMEM_HDR_ID, CPTRA_DDR5_DMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "dp_fw", CPTRA_DP_FW_HDR_ID, CPTRA_DP_FW_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "uefi", CPTRA_UEFI_HDR_ID, CPTRA_UEFI_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "atf", CPTRA_ATF_HDR_ID, CPTRA_ATF_FW_ID, CPTRA_ATF_LOAD_ADDR},
	{ "optee", CPTRA_OPTEE_HDR_ID, CPTRA_OPTEE_FW_ID, CPTRA_OPTEE_LOAD_ADDR},
	{ "uboot", CPTRA_UBOOT_HDR_ID, CPTRA_UBOOT_FW_ID, CPTRA_UBOOT_LOAD_ADDR},
	{ "ssp", CPTRA_SSP_HDR_ID, CPTRA_SSP_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "tsp", CPTRA_TSP_HDR_ID, CPTRA_TSP_FW_ID, CPTRA_TSP_LOAD_ADDR},
	{ "kernel", CPTRA_KERNEL_HDR_ID, CPTRA_KERNEL_FW_ID, CPTRA_KERNEL_LOAD_ADDR},
};

/* End of Caliptra SOC Manifest Common Structure */
