/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <platform.h>
#include <zephyr/logging/log.h>
#include <chip.h>
#include <dma.h>
#include <mac_ast2700.h>
#include <usb.h>

LOG_MODULE_REGISTER(dma, CONFIG_SOC_FMC_LOG_LEVEL);

struct dma_engine {
	const char *name;
	int (*stop)(struct ast_chip *chip);
};

static int mac_dma_stop(struct ast_chip *chip)
{
	sys_write32(0, ASPEED_IO_MAC0_BASE + MACCR);
	sys_write32(0, ASPEED_IO_MAC1_BASE + MACCR);

	return 0;
}

/*
 * A warm/SoC reset whose WDT reset mask doesn't cover a given IP's
 * reset domain can leave that IP's DMA/bus-master engine running
 * across the reset, letting it keep writing into DRAM on the next
 * boot cycle. Each entry here aborts one such engine defensively,
 * before the loader or anything else touches DRAM.
 *
 * Add an entry per IP as it gains a confirmed abort sequence; skip
 * IPs whose bus-master can't be independently stopped from this
 * bootloader (e.g. no register handle on the block, or reset
 * polarity not yet verified against the chip's init sequence).
 */
static const struct dma_engine dma_engines[] = {
	{ "MAC", mac_dma_stop },
	{ "USB EHCI", usb_ehci_stop },
	{ "USB UHCI", usb_uhci_stop },
	{ "USB XHCI", usb_xhci_stop },
	{ "USB VHUB", usb_vhub_stop },
};

int dma_stop(struct ast_chip *chip)
{
	uint32_t i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(dma_engines); i++) {
		ret = dma_engines[i].stop(chip);
		if (ret)
			LOG_WRN("%s dma stop failed: %d", dma_engines[i].name, ret);
	}

	return 0;
}
