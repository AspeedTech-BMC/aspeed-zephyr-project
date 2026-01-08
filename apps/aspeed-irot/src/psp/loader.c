/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>

LOG_MODULE_REGISTER(psp_loader, LOG_LEVEL_DBG);

#define writel(value, addr)	(*(volatile uint32_t *)(addr) = (value))
#define readl(addr)		(*(volatile uint32_t *)(addr))

#define SCU0_REG		0x72c02000

#define ASPEED_CPU_CA35_RVBAR0 (0x12C02110 + 0x60000000)
#define ASPEED_CPU_CA35_RVBAR1 (0x12C02114 + 0x60000000)
#define ASPEED_CPU_CA35_RVBAR2 (0x12C02118 + 0x60000000)
#define ASPEED_CPU_CA35_RVBAR3 (0x12C0211c + 0x60000000)

#define ASPEED_CPU_SMP_EP0 (0x12C02780 + 0x60000000)
#define ASPEED_CPU_SMP_EP1 (0x12C02788 + 0x60000000)
#define ASPEED_CPU_SMP_EP2 (0x12C02790 + 0x60000000)
#define ASPEED_CPU_SMP_EP3 (0x12C02798 + 0x60000000)

#define ASPEED_CPU_CA35_REL (0x12C0210C + 0x60000000)

struct image_info {
	char *name;
	uint32_t dst;
	uint32_t src;
	uint32_t len;
};

struct image_info image_tbl[] = {
	// Name,  dram_dest,  flash_src,  len
	{"ATF",   0x04000000, 0x00200000, 0x10000},    // 64KB
	{"UBOOT", 0x05880000, 0x00210000, 0x100000}, // 1MB
	{"TEE",   0x04080000, 0x00310000, 0x80000},    // 512KB
};

void aspeed_prepare_for_boot(void)
{
	/* Given CA35 reset vector */
	writel(0x43000000, (void *)ASPEED_CPU_CA35_RVBAR0);
	writel(0x43000000, (void *)ASPEED_CPU_CA35_RVBAR1);
	writel(0x43000000, (void *)ASPEED_CPU_CA35_RVBAR2);
	writel(0x43000000, (void *)ASPEED_CPU_CA35_RVBAR3);

	writel(0x00000000, (void *)ASPEED_CPU_SMP_EP0);
	writel(0x00000004, (void *)(ASPEED_CPU_SMP_EP0 + 4));
	writel(0x00000000, (void *)ASPEED_CPU_SMP_EP1);
	writel(0x00000000, (void *)(ASPEED_CPU_SMP_EP1 + 4));
	writel(0x00000000, (void *)ASPEED_CPU_SMP_EP2);
	writel(0x00000000, (void *)(ASPEED_CPU_SMP_EP2 + 4));
	writel(0x00000000, (void *)ASPEED_CPU_SMP_EP3);
	writel(0x00000000, (void *)(ASPEED_CPU_SMP_EP3 + 4));

	/* Release CA35 */
	writel(1, (void *)ASPEED_CPU_CA35_REL);
}

/*
   uint64_t ast27xx_soc_virt_addr_to_phy_addr(uintptr_t addr)
   {
   return ((uint64_t)readl(SCU0_REG + 0x168) << 4) + addr;
   }
   */

uint32_t fwspi_flash_read(uint32_t flash_addr, void *ram_dest, uint32_t size)
{
	const struct device *flash_dev;

	flash_dev = device_get_binding("fmc@0");
	if (!flash_dev) {
		LOG_ERR("Flash device not found");
		return 0;
	}

	if (flash_read(flash_dev, flash_addr, ram_dest, size) != 0) {
		LOG_ERR("Flash read failed");
		return 0;
	}

	return size;
}

int aspeed_load_image(const char *name)
{
	uint32_t dst;
	uint32_t src;
	uint32_t len;
	uint32_t ret;
	int i;

	LOG_INF("Loading images...");

	for (i = 0; i < ARRAY_SIZE(image_tbl); i++) {
		if (strcmp(name, image_tbl[i].name) != 0 && strcmp(name, "all") != 0) {
			continue;
		}
		dst = image_tbl[i].dst;
		src = image_tbl[i].src;
		len = image_tbl[i].len;
		LOG_INF("Image[%d]: %s dst=%08x src=%08x len=%08x", i, image_tbl[i].name, dst, src, len);

		ret = fwspi_flash_read(src, (void *)dst, len);
		if (ret != len) {
			LOG_ERR("Failed to load image %s from flash", image_tbl[i].name);
			return 1;
		}
	}
	return 0;
}

