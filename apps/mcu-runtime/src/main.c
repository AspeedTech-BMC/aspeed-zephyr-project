// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <soc.h>
#include <zephyr/sd/sd.h>
#include <zephyr/sd/mmc.h>
#include <sdram_ast2700.h>
#include <dp_ast2700.h>
#include <pci_ast2700.h>
#include <platform.h>
#include <soc_fmc.h>
#include <fit.h>
#include <spi.h>
#include <ufs.h>
#include <manifest.h>
#include <mmc.h>
#include <abr.h>
#include <stor.h>
#include <ssp_tsp_ast2700.h>
#include <scu_ast2700.h>
#include <sli.h>

#include <zephyr/logging/log.h>
#define LOG_MODULE_NAME			aspeed_soc_fmc
LOG_MODULE_REGISTER(LOG_MODULE_NAME, CONFIG_SOC_FMC_LOG_LEVEL);

#define sector_count 32
#define sector_size  512 /* subsystem should set all cards to 512 byte blocks */
#define buf_size     (sector_size * sector_count)

static bool bootmcu_boot2fw;
static bool has_pspfw;
static bool has_sspfw;
static bool has_tspfw;

void board_fit_image_post_process(const void *fit, int node, void **p_image, size_t *p_size)
{
	uint64_t ep_arm;
	uint8_t arch;
	uint8_t type;
	uint8_t os;
	uint64_t ep;
	uint64_t load_addr;
	const char *name;
	int len;

	fit_image_get_arch(fit, node, &arch);
	fit_image_get_type(fit, node, &type);
	fit_image_get_os(fit, node, &os);
	fit_image_get_entry(fit, node, &ep);
	name = fdt_getprop(fit, node, "description", &len);

	/* BootMCU firmware recognized */
	if (arch == IH_ARCH_RISCV && type == IH_TYPE_FIRMWARE) {
		bootmcu_boot2fw = true;
		return;
	}

	if (strncmp(name, "SSP", 3) == 0) {
		fit_image_get_load(fit, node, &load_addr);
		ssp_init(load_addr);
		has_sspfw = true;
		return;
	}

	if (strncmp(name, "TSP", 3) == 0) {
		fit_image_get_load(fit, node, &load_addr);
		tsp_init(load_addr);
		has_tspfw = true;
		return;
	}

	/* convert to Arm view */
	ep_arm = ((uint64_t)ep - 0x80000000) | 0x400000000ULL;

	switch (os) {
	case IH_OS_ARM_TRUSTED_FIRMWARE:
		has_pspfw = true;
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR0);
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR1);
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR2);
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR3);
		break;
	case IH_OS_U_BOOT:
		sys_write64(ep_arm, SCU0_CPU_SMP_EP0);
		break;
	default:
		break;
	}
}

void board_manifest_image_post_process(struct cptra_manifest_ime *ime)
{
	uintptr_t ep = cptra_ime_get_load_addr(ime);
	uint64_t ep_arm = 0;

	/* convert to Arm view */
	ep_arm = ((uint64_t)ep - 0x80000000) | 0x400000000ULL;

	switch (ime->fw_id) {
	case CPTRA_ATF_FW_ID:
		has_pspfw = true;
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR0);
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR1);
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR2);
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR3);
		break;
	case CPTRA_UBOOT_FW_ID:
		sys_write64(ep_arm, SCU0_CPU_SMP_EP0);
		break;
	case CPTRA_SSP_FW_ID:
		ssp_init(ep);
		has_sspfw = true;
		break;
	case CPTRA_TSP_FW_ID:
		tsp_init(ep);
		has_tspfw = true;
		break;
	default:
		break;
	}
}

#define ASPEED_UFS_PATH_AXI	(0x12c080e4)

void board_prepare_for_boot(void)
{
	/* for v7 FPGA only to switch to uart12. */
	if (IS_ENABLED(CONFIG_ASPEED_FPGA)) {
		sys_write32(SCU0_HWSTRAP_DIS_CPU, SCU0_HW_STRAP1_CLR);
	}

	sys_write32(1, ASPEED_UFS_PATH_AXI);

	if (has_pspfw) {
		/* clean up secondary entries */
		sys_write64(0x0, SCU0_CPU_SMP_EP1);
		sys_write64(0x0, SCU0_CPU_SMP_EP2);
		sys_write64(0x0, SCU0_CPU_SMP_EP3);

		/* release CA35 reset */
		sys_write32(0x1, SCU0_CA35_REL);
	}

	/* release SSP reset */
	if (has_sspfw) {
		ssp_enable();
	}

	/* release TSP reset */
	if (has_tspfw) {
		tsp_enable();
	}
}

enum aspeed_soc_fmc_state {
	SLI_INIT_F,
	BOOT_MODE,
	SPI_INIT,
	EMMC_INIT,
	UFS_INIT,
	RECOVERY_UART_INIT,
	RECOVERY_I2C_INIT,
	RECOVERY_I3C_INIT,
	RECOVERY_USB_INIT,
	DRAM_INIT,
	PCI_INIT,
	DP_INIT,
	SLI_INIT_R,
	IMAGE_LOAD,
	CPU_BOOT,
	REBOOT,
	RUNTIME,
};
/* User defined object */
struct soc_fmc_object soc_fmc_obj;

static const struct smf_state soc_fmc_states[];

static void soc_fmc_sli_init_f(void *o)
{
	struct soc_fmc_object *s_obj = (struct soc_fmc_object *)o;

	sli_init_f();
	smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[BOOT_MODE]);
}

static void soc_fmc_sli_init_r(void *o)
{
	struct soc_fmc_object *s_obj = (struct soc_fmc_object *)o;

	sli_init_r();
	smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[DRAM_INIT]);
}

static void soc_fmc_boot_mode(void *o)
{
	struct soc_fmc_object *s_obj = (struct soc_fmc_object *)o;

	s_obj->boot_mode = boot_mode();
	LOG_DBG("Boot Mode: [%d]", s_obj->boot_mode);

	switch (s_obj->boot_mode) {
	case BOOT_DEV_SPI:
		s_obj->stor_copy = &spi_copy;
		smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[SPI_INIT]);
		break;
	case BOOT_DEV_MMC:
		s_obj->stor_copy = &mmc_copy;
		smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[EMMC_INIT]);
		break;
	case BOOT_DEV_UFS:
		s_obj->stor_copy = &ufs_read;
		smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[UFS_INIT]);
		break;
	case BOOT_DEV_UART:
		smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[RECOVERY_UART_INIT]);
		break;
	case BOOT_DEV_USB:
		smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[RECOVERY_USB_INIT]);
		break;
	case BOOT_DEV_I2C:
		smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[RECOVERY_I2C_INIT]);
		break;
	case BOOT_DEV_I3C:
		smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[RECOVERY_I3C_INIT]);
		break;
	default:
		smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[REBOOT]);
		break;
	}
}

static void soc_fmc_spi_init(void *o)
{
	struct soc_fmc_object *s_obj = (struct soc_fmc_object *)o;

	spi_init(abr_get_id());
	smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[DP_INIT]);

}

static void soc_fmc_emmc_init(void *o)
{
	struct soc_fmc_object *s_obj = (struct soc_fmc_object *)o;

	mmc_init(abr_get_id());
	smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[DP_INIT]);

}

static void soc_fmc_ufs_init(void *o)
{
	struct soc_fmc_object *s_obj = (struct soc_fmc_object *)o;

	ufs_init(abr_get_id());
	smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[DP_INIT]);
}

static void soc_fmc_dram_run(void *o)
{
	struct soc_fmc_object *s_obj = (struct soc_fmc_object *)o;

	dram_init();
	smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[PCI_INIT]);
}

static void soc_fmc_pci_run(void *o)
{
	struct soc_fmc_object *s_obj = (struct soc_fmc_object *)o;

	pci_init();
	smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[IMAGE_LOAD]);
}

static void soc_fmc_dp_run(void *o)
{
	struct soc_fmc_object *s_obj = (struct soc_fmc_object *)o;

	dp_init();
	smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[SLI_INIT_R]);
}

static void soc_fmc_image_load_run(void *o)
{
	struct soc_fmc_object *s_obj = (struct soc_fmc_object *)o;

	/* Load the image */
	if (IS_ENABLED(CONFIG_CPTRA_MANIFEST)) {
		if (cptra_load_image(s_obj->boot_mode, &s_obj->bundle_image) != 0) {
			LOG_ERR("Failed to load bundle image");
			smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[REBOOT]);
			return;
		}
	} else {
		if (fit_load_image(s_obj->boot_mode, &s_obj->fit_image) < 0) {
			LOG_ERR("Failed to load FIT image");
			smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[REBOOT]);
			return;
		}
	}

	LOG_DBG("soc_fmc_image_load_run");
	smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[CPU_BOOT]);
}

static void soc_fmc_cpuboot(void *o)
{
	struct soc_fmc_object *s_obj = (struct soc_fmc_object *)o;

	board_prepare_for_boot();

	LOG_DBG("soc_fmc_cpuboot");
	smf_set_state(SMF_CTX(s_obj), &soc_fmc_states[RUNTIME]);
}

static void soc_fmc_runtime(void *o)
{
//	LOG_DBG("soc_fmc_runtime");
}

/* Populate state table */
static const struct smf_state soc_fmc_states[] = {
	[SLI_INIT_F] = SMF_CREATE_STATE(NULL, soc_fmc_sli_init_f, NULL, NULL, NULL),
	[BOOT_MODE] = SMF_CREATE_STATE(NULL, soc_fmc_boot_mode, NULL, NULL, NULL),
	[SPI_INIT] = SMF_CREATE_STATE(NULL, soc_fmc_spi_init, NULL, NULL, NULL),
	[EMMC_INIT] = SMF_CREATE_STATE(NULL, soc_fmc_emmc_init, NULL, NULL, NULL),
	[UFS_INIT] = SMF_CREATE_STATE(NULL, soc_fmc_ufs_init, NULL, NULL, NULL),
	[DRAM_INIT] = SMF_CREATE_STATE(NULL, soc_fmc_dram_run, NULL, NULL, NULL),
	[PCI_INIT] = SMF_CREATE_STATE(NULL, soc_fmc_pci_run, NULL, NULL, NULL),
	[DP_INIT] = SMF_CREATE_STATE(NULL, soc_fmc_dp_run, NULL, NULL, NULL),
	[SLI_INIT_R] = SMF_CREATE_STATE(NULL, soc_fmc_sli_init_r, NULL, NULL, NULL),
	[IMAGE_LOAD] = SMF_CREATE_STATE(NULL, soc_fmc_image_load_run, NULL, NULL, NULL),
	[CPU_BOOT] = SMF_CREATE_STATE(NULL, soc_fmc_cpuboot, NULL, NULL, NULL),
	[REBOOT] = SMF_CREATE_STATE(NULL, NULL, NULL, NULL, NULL),
	[RUNTIME] = SMF_CREATE_STATE(NULL, soc_fmc_runtime, NULL, NULL, NULL),
};

int main(void)
{
	int err;

	printf("Aspeed SoC FMC %s\n", CONFIG_BOARD_TARGET);

	/* en low secure for uartdbg */
	sys_write32(0x100, 0x14c02010);

	/* Set initial state */
	smf_set_initial(SMF_CTX(&soc_fmc_obj), &soc_fmc_states[SLI_INIT_F]);

	/* Run the state machine */
	while (1) {
		/* State machine terminates if a non-zero value is returned */
		err = smf_run_state(SMF_CTX(&soc_fmc_obj));
		if (err) {
			/* handle return code and terminate state machine */
			break;
		}
	}

	return 0;
}
