/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SOC_FMC_IMAGE_H
#define _SOC_FMC_IMAGE_H

#include <zephyr/smf.h>
#include <fit.h>
#include <manifest.h>
#include <stor.h>

/* User defined object */
struct soc_fmc_object {
	/* This must be first */
	struct smf_ctx ctx;
	struct fit_image_info fit_image;
	struct manifest_image_info man_image;
	/* Events */
	struct k_event smf_event;
	int32_t events;
	enum boot_mode_type boot_mode;
	int (*stor_copy)(uint32_t *dest, uint32_t src, uint32_t len);
	/* Other state specific data add here */
};

extern struct soc_fmc_object soc_fmc_obj;

#endif
