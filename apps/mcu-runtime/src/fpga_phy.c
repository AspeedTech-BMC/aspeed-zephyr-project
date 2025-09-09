/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sdram_ast2700.h"

#define SCU_CPU_PINMUX1                 (SCU0_REG + 0x400)

void fpga_phy_init(struct sdramc *sdramc)
{
	struct sdramc_regs *regs = sdramc->regs;

	/* adjust CLK4RX delay */
	sys_write32(0x10f, SCU_CPU_PINMUX1);
	sys_write32(0x30f, SCU_CPU_PINMUX1);

	/* adjust DQS window */
	sys_write32(0x18, (uint32_t)&regs->testcfg);

	/* assert DFI reset */
	sys_write32(DRAMC_DFICFG_RESET | DRAMC_DFICFG_WD_POL, (uint32_t)&regs->dcfg);

	//mdelay(1);
	k_busy_wait(1000);

	/* power up control (switch power FSM) */
	sys_write32(DRAMC_MCTL_PHY_RESET, (uint32_t)&regs->mctl);
	sys_write32(DRAMC_MCTL_PHY_RESET | DRAMC_MCTL_PHY_POWER_ON, (uint32_t)&regs->mctl);
	sys_write32(DRAMC_MCTL_PHY_POWER_ON, (uint32_t)&regs->mctl);

	//mdelay(1);
	k_busy_wait(1000);

	/* de-assert DFI reset */
	//clrbits(le32, (uint32_t)&regs->dcfg, DRAMC_DFICFG_RESET);
	sys_write32(sys_read32((uint32_t)&regs->dcfg) & ~DRAMC_DFICFG_RESET, (uint32_t)&regs->dcfg);

	//mdelay(1);
	k_busy_wait(1000);

	/* DFI start */
	//setbits(le32, (uint32_t)&regs->mctl, DRAMC_MCTL_PHY_INIT_START);
	sys_write32(sys_read32((uint32_t)&regs->mctl) | DRAMC_MCTL_PHY_INIT_START, (uint32_t)&regs->mctl);

	/* query phy init done */
	while (!(sys_read32((uint32_t)&regs->intr_status) & DRAMC_IRQSTA_PHY_INIT_DONE))
		;

	sys_write32(DRAMC_IRQSTA_PHY_INIT_DONE, (uint32_t)&regs->intr_clear);
}

#if defined(ASPEED_FPGA_DDR_CALI)
int fpga_dq_shift_cali(void)
{
	int i, err, dq[128 + 16], dq_left_0, dq_right_0;
	uint32_t shift_val = 0x100;
	uint32_t shift_en = (1 << 9);
	uint32_t bistcfg;
	int flag = 0, found = 0;

	sys_write32(0x0f, SCU_CPU_PINMUX1);
	sys_write32(0x20f, SCU_CPU_PINMUX1);

	bistcfg = FIELD_PREP(DRAMC_BISTCFG_PMODE, BIST_PMODE_CRC)
		| FIELD_PREP(DRAMC_BISTCFG_BMODE, BIST_BMODE_RW_SWITCH)
		| DRAMC_BISTCFG_ENABLE;
	dramc_bist(0, 0x10000, bistcfg, 200);

	sys_write32(0x0f, SCU_CPU_PINMUX1);
	sys_write32(0x20f, SCU_CPU_PINMUX1);

	for (i = 0; i < 128 + 16; i++) {
		sys_write32(shift_val, SCU_CPU_PINMUX1);
		sys_write32(shift_en | shift_val, SCU_CPU_PINMUX1);

		err = dramc_bist(0, 0x1000000, bistcfg, 200);
		if (err) {
			printf("0");
			dq[i] = 0;
		} else {
			printf("1");
			dq[i] = 1;
			found = 1;
		}
	}

	printf("\n");
	if (!found) {
		printf("No window found !!!\n");
		return 1;
	}

	for (i = 0; i < 128 + 16; i++) {
		if (dq[i] && !flag) {
			printf("left=%d\n", i);
			dq_left_0 = i;
			flag = 1;
		} else if (!dq[i] && flag) {
			printf("right=%d\n", i);
			dq_right_0 = i;
			flag = 0;
		}
	}

	printf("dq left delay=%d\n", dq_left_0 - 16 + 1);
	printf("dq right delay=%d\n", dq_right_0 - 16 + 1);
	printf("dq center delay= %d\n", ((dq_right_0 + dq_left_0) / 2) - 16 + 1);
	printf("\n");

	return 0;
}
#endif
