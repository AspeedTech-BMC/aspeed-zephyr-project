// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#include <sdram_ast2700.h>
#include <zephyr/logging/log.h>
#include <ast_loader.h>

LOG_MODULE_REGISTER(sdram_phy, CONFIG_SOC_FMC_LOG_LEVEL);

#define DWC_PHY_IMEM_OFFSET	(0x50000)
#define DWC_PHY_DMEM_OFFSET	(0x58000)
#define SCU0_DDR_PHY_CLOCK	BIT(11)
#define SCU0_CLOCK_STOP_CLR_REG	(SCU0_REG + 0x244)

void dwc_decode_streaming_message(void);
#define DWC_UCTWRITEPROTSHADOW		BIT(0)
#define DWC_UCTSHADOWREGS		(0xd0004)
#define DWC_DCTWRITEPROT		(0xd0031)
#define DWC_UCTWRITEONLYSHADOW		(0xd0032)
#define	DWC_UCTWRITEPROT		(0xc0033)
#define DWC_UCTDATWRITEONLYSHADOW	(0xd0034)

void dwc_get_mailbox(const int mode, uint32_t *mail)
{
	/* 1. Poll the UctWriteProtShadow, looking for a 0 */
	while (dwc_ddrphy_apb_rd(DWC_UCTSHADOWREGS) & DWC_UCTWRITEPROTSHADOW)
		;

	/* 2. When a 0 is seen, read the UctWriteOnlyShadow register to get the major message number. */
	*mail = dwc_ddrphy_apb_rd(DWC_UCTWRITEONLYSHADOW) & 0xffff;

	/* 3. If reading a streaming or SMBus message, also read the UctDatWriteOnlyShadow register. */
	if (mode)
		*mail |= ((dwc_ddrphy_apb_rd(DWC_UCTDATWRITEONLYSHADOW) & 0xffff) << 16);

	/* 4. Write the DctWriteProt to 0 to acknowledge the reception of the message */
	dwc_ddrphy_apb_wr(DWC_DCTWRITEPROT, 0);

	/* 5. Poll the UctWriteProtShadow, looking for a 1 */
	while (!(dwc_ddrphy_apb_rd(DWC_UCTSHADOWREGS) & DWC_UCTWRITEPROTSHADOW))
		;

	/* 6. When a 1 is seen, write the DctWriteProt to 1 to complete the protocol */
	dwc_ddrphy_apb_wr(DWC_DCTWRITEPROT, 1);
}

void dwc_init_mailbox(void)
{
	dwc_ddrphy_apb_wr(DWC_DCTWRITEPROT, 1);
	dwc_ddrphy_apb_wr(DWC_UCTWRITEPROT, 1);
}

uint32_t dwc_readMsgBlock(const uint32_t addr_half)
{
	uint32_t data_word;

	data_word = dwc_ddrphy_apb_rd_32b((addr_half >> 1) << 1);

	if (addr_half & 0x1)
		data_word = data_word >> 16;
	else
		data_word &= 0xffff;

	return data_word;
}

#define DWC_PHY_DDR4_MB_PMU_REV		(0x58001)
#define DWC_PHY_DDR4_MB_RESULT		(0x5800a)
#define DWC_PHY_DDR5_MB_PMU_REV		(0x58001)
#define DWC_PHY_DDR5_MB_RESULT		(0x58007)
#define DWC_PHY_DDR5_MB_RESULT_ADR	(0x5800a)

int dwc_ddrphy_phyinit_userCustom_H_readMsgBlock(int train2D)
{
	uint32_t  message;

	if (is_ddr4()) {
		/* 2. Check pass */
		message = dwc_readMsgBlock(DWC_PHY_DDR4_MB_RESULT);
		if (message & 0xff)
			LOG_DBG("%s: Training Failure index (0x%x)\n", __func__, message);
		else
			LOG_DBG("%s: %dD Training Passed\n", __func__, train2D ? 2 : 1);
	} else {
		/* 2. Check pass / Failure of the training (CsTestFail) */
		message = dwc_readMsgBlock(DWC_PHY_DDR5_MB_RESULT);
		if (message & 0xff00)
			LOG_DBG("%s: Training Failure index (0x%x)\n", __func__, message);
		else
			LOG_DBG("%s: DDR5 1D/2D Training Passed\n", __func__);

		/* 3. Read ResultAddrOffset */
		message = dwc_readMsgBlock(DWC_PHY_DDR5_MB_RESULT_ADR);
		LOG_DBG("%s: Result Address Offset (0x%x)\n", __func__, message);
	}

	return 0;
}

void dwc_ddrphy_phyinit_userCustom_A_bringupPower(void)
{
}

void dwc_ddrphy_phyinit_userCustom_B_startClockResetPhy(struct sdramc *sdramc)
{
	struct sdramc_regs *regs = sdramc->regs;

	/*
	 * 1. Drive PwrOkIn to 0. Note: Reset, DfiClk, and APBCLK can be X.
	 * 2. Start DfiClk and APBCLK
	 * 3. Drive Reset to 1 and PRESETn_APB to 0.
	 * Note: The combination of PwrOkIn=0 and Reset=1 signals a cold reset to the PHY.
	 */
	sys_write32(DRAMC_MCTL_PHY_RESET, (uint32_t)&regs->mctl);
	k_busy_wait(2);

	/*
	 * 5. Drive PwrOkIn to 1. Once the PwrOkIn is asserted (and Reset is still asserted),
	 * DfiClk synchronously switches to any legal input frequency.
	 */
	sys_write32(DRAMC_MCTL_PHY_RESET | DRAMC_MCTL_PHY_POWER_ON, (uint32_t)&regs->mctl);
	k_busy_wait(2);

	/*
	 * 7. Drive Reset to 0. Note: All DFI and APB inputs must be driven at valid reset states
	 * before the deassertion of Reset.
	 */
	sys_write32(DRAMC_MCTL_PHY_POWER_ON, (uint32_t)&regs->mctl);
	k_busy_wait(2);

	/*
	 * 9. Drive PRESETn_APB to 1 to de-assert reset on the ABP bus.
	 * 10. The PHY is now in the reset state and is ready to accept APB transactions.
	 */
}

void dwc_ddrphy_phyinit_userCustom_overrideUserInput(void)
{
}

void dwc_ddrphy_phyinit_userCustom_customPostTrain(void)
{
}

void dwc_ddrphy_phyinit_userCustom_E_setDfiClk(int a)
{
	dwc_init_mailbox();
}

#if defined(CONFIG_ASPEED_PHY_TRAINING_MESSAGE)
void dwc_decode_streaming_message(void)
{
	u32 str, msg, msg2, count, i;

	dwc_get_mailbox(1, &msg);

	printf("\n");
	printf("Message:\n");
	printf("0x%x\n", msg);

	str = (msg & 0xffff0000) >> 16;
	count = msg & 0xffff;

	printf("Para:\n");
	for (i = 0; i < count; i++) {
		dwc_get_mailbox(1, &msg2);
		printf("0x%x ", msg2);
	}

	printf("\n");
}
#endif

#define DWC_PHY_MB_START_STREAM_MSG	0x8
#define DWC_PHY_MB_TRAIN_SUCCESS	0x7
#define DWC_PHY_MB_TRAIN_FAIL		0xff
void dwc_ddrphy_phyinit_userCustom_G_waitFwDone(void)
{
	uint32_t message = 0, mail;

	while (message != DWC_PHY_MB_TRAIN_SUCCESS && message != DWC_PHY_MB_TRAIN_FAIL) {
		dwc_get_mailbox(0, &mail);
		message = mail & 0xffff;

		if (IS_ENABLED(CONFIG_ASPEED_PHY_TRAINING_MESSAGE)) {
			if (message == DWC_PHY_MB_START_STREAM_MSG)
				dwc_decode_streaming_message();
		}
	}
}

void dwc_ddrphy_phyinit_userCustom_J_enterMissionMode(struct sdramc *sdramc)
{
	struct sdramc_regs *regs = sdramc->regs;
	uint32_t val;

	/*
	 * 1. Set the PHY input clocks to the desired frequency.
	 * 2. Initialize the PHY to mission mode by performing DFI Initialization.
	 * Please see the DFI specification for more information. See the DFI frequency bus encoding in section <XXX>.
	 * Note: The PHY training firmware initializes the DRAM state. if skip
	 * training is used, the DRAM state is not initialized.
	 */

	sys_write32(0xffffffff, (uint32_t)&regs->intr_mask);

	sys_write32(0x0, (uint32_t)&regs->dcfg); // [16] reset=0

	if (!is_ddr4()) {
		dwc_ddrphy_apb_wr(0xd0000, 0);		// DWC_DDRPHYA_APBONLY0_MicroContMuxSel
		dwc_ddrphy_apb_wr(0x20240, 0x3900);	// DWC_DDRPHYA_MASTER0_base0_D5ACSMPtr0lat0
		dwc_ddrphy_apb_wr(0x900da, 8);		// DWC_DDRPHYA_INITENG0_base0_SequenceReg0b59s0
		dwc_ddrphy_apb_wr(0xd0000, 1);		// DWC_DDRPHYA_APBONLY0_MicroContMuxSel
	}

	/* phy init start */
	val = sys_read32((uint32_t)&regs->mctl);
	val = val | DRAMC_MCTL_PHY_INIT_START;
	sys_write32(val, (uint32_t)&regs->mctl);

	/* wait phy complete */
	while ((sys_read32((uint32_t)&regs->intr_status) & DRAMC_IRQSTA_PHY_INIT_DONE) != DRAMC_IRQSTA_PHY_INIT_DONE)
		;

	sys_write32(0xffff, (uint32_t)&regs->intr_clear);

	while (sys_read32((uint32_t)&regs->intr_status))
		;

	if (!is_ddr4()) {
		dwc_ddrphy_apb_wr(0xd0000, 0);		// DWC_DDRPHYA_APBONLY0_MicroContMuxSel
		dwc_ddrphy_apb_wr(0x20240, 0x4300);	// DWC_DDRPHYA_MASTER0_base0_D5ACSMPtr0lat0
		dwc_ddrphy_apb_wr(0x900da, 0);		// DWC_DDRPHYA_INITENG0_base0_SequenceReg0b59s0
		dwc_ddrphy_apb_wr(0xd0000, 1);		// DWC_DDRPHYA_APBONLY0_MicroContMuxSel
	}
}

int dwc_ddrphy_phyinit_userCustom_D_loadIMEM(const int train2D)
{
	uint32_t imem_base = DWC_PHY_IMEM_OFFSET;
	int fw;
	int type;
	int ret = 0;

	LOG_DBG("%s %d\n", __func__, train2D);

	type = is_ddr4();

	fw = (type ? (train2D ? CPTRA_DDR4_2D_IMEM_FW_ID: CPTRA_DDR4_IMEM_FW_ID) : CPTRA_DDR5_IMEM_FW_ID);

	ast_loader_load_image(fw, (void *)(DRAMC_PHY_BASE + 2 * imem_base), 0);

	return ret;
}

int dwc_ddrphy_phyinit_userCustom_F_loadDMEM(const int pState, const int train2D)
{
	uint32_t dmem_base = DWC_PHY_DMEM_OFFSET;
	int fw;
	int type;
	int ret = 0;

	LOG_DBG("%s %d\n", __func__, train2D);

	type = is_ddr4();

	fw = (type ? (train2D ? CPTRA_DDR4_2D_DMEM_FW_ID: CPTRA_DDR4_DMEM_FW_ID) : CPTRA_DDR5_DMEM_FW_ID);

	ast_loader_load_image(fw, (void *)(DRAMC_PHY_BASE + 2 * dmem_base), 0);
	return ret;
}

void dwc_phy_init(struct sdramc *sdramc)
{
	// enable ddrphy free-run clock
	sys_write32(SCU0_DDR_PHY_CLOCK, SCU0_CLOCK_STOP_CLR_REG);

	if (is_ddr4()) {
		LOG_DBG("%s: Starting ddr4 training\n", __func__);
		#include "dwc_ddrphy_phyinit_ddr4-3200-nodimm-train2D.c"
	} else {
		LOG_DBG("%s: Starting ddr5 training\n", __func__);
		#include "dwc_ddrphy_phyinit_ddr5-3200-nodimm-train2D.c"
	}
}
