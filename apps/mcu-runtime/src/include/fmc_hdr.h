/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#ifndef __FMC_HDR_H__
#define __FMC_HDR_H__

#include <stdint.h>

#define HDR_MAGIC		0x48545341	/* ASTH */

enum prebuilt_type {
	PBT_END_MARK = 0x0,

	PBT_DDR4_PMU_TRAIN_IMEM,
	PBT_DDR4_PMU_TRAIN_DMEM,
	PBT_DDR4_2D_PMU_TRAIN_IMEM,
	PBT_DDR4_2D_PMU_TRAIN_DMEM,
	PBT_DDR5_PMU_TRAIN_IMEM,
	PBT_DDR5_PMU_TRAIN_DMEM,
	PBT_DP_FW,
	PBT_UEFI_X64_AST2700,
	PBT_RK384_PUB_KEY,
	PBT_RK256_PUB_KEY,
	PBT_RSA4096_PUB_KEY,
	PBT_RSA3072_PUB_KEY,
	PBT_RSA2048_PUB_KEY,

	PBT_NUM
};

/* header ver 1.0 */
struct fmc_hdr_preamble_v1 {
	uint32_t magic;
	uint32_t version;
};

struct fmc_hdr_body_v1 {
	uint32_t fmc_size;
	union {
		struct {
			uint32_t type;
			uint32_t size;
		} pbs[0];
		uint32_t raz[29];
	};
};

struct fmc_hdr_v1 {
	struct fmc_hdr_preamble_v1 preamble;
	struct fmc_hdr_body_v1 body;
};

/* header ver 2.0 */
#define HDR_ECC_SIGN_LEN	96		/* ECDSA384 r and s */
#define HDR_LMS_SIGN_LEN	1620		/* LMS N24/H15/W4 */
#define HDR_DGST_LEN		48		/* SHA384 */

struct fmc_hdr_preamble_v2 {
	uint32_t magic;
	uint32_t version;
	uint32_t ecc_key_idx;
	uint32_t lms_key_idx;
	uint8_t ecc_sig[HDR_ECC_SIGN_LEN];
	uint8_t lms_sig[HDR_LMS_SIGN_LEN];
	uint32_t raz[15];
};

struct fmc_hdr_body_v2 {
	uint32_t fmc_svn;
	uint32_t fmc_size;
	uint8_t dgst[HDR_DGST_LEN];
	union {
		struct {
			uint32_t type;
			uint32_t size;
			uint8_t dgst[HDR_DGST_LEN];
		} pbs[0];
		uint32_t raz[178];
	};
};

struct fmc_hdr_v2 {
	struct fmc_hdr_preamble_v2 preamble;
	struct fmc_hdr_body_v2 body;
};

int fmc_hdr_get_prebuilt(uint32_t type, uint32_t *ofst, uint32_t *size, uint8_t *dgst);

#endif
