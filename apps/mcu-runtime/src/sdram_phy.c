// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#include <sdram_ast2700.h>
#include <stor.h>
#include <soc_fmc.h>
#include <fmc_hdr.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(sdram_phy, CONFIG_SOC_FMC_LOG_LEVEL);

#define DWC_PHY_IMEM_OFFSET	(0x50000)
#define DWC_PHY_DMEM_OFFSET	(0x58000)
#define SCU0_DDR_PHY_CLOCK	BIT(11)
#define SCU0_CLOCK_STOP_CLR_REG	(SCU0_REG + 0x244)

struct train_bin dwc_train[DRAM_TYPE_MAX][2] = {
	{{0, 0, 0, 0}, {0, 0, 0, 0}},
	{{0, 0, 0, 0}, {0, 0, 0, 0}},
};

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
struct dwc_streaming_msg {
	uint32_t id;
	char desc[150];
};

struct dwc_streaming_msg dwc_ddr5_msg[] = {
//{0x00000000, "Anib eyes are not overlapping\n"},
//{0x00010002, "PMU4: Signal %d CSn %d: "},
//{0x00020001, "%08x"},
//{0x00030000, "\n"},
//{0x00040004, "PMU4: Signal %d CSn %d passing region (%d, %d)\n"},
//{0x00050001, "No passing region for Anib %d ATx\n"},
//{0x00060002, "PMU5: Anib %d ATx final delay %d\n"},
//{0x00070001, "PMU5: Anib %d ATx NOT TRAINED\n"},
//{0x00080002, "PMU5: Anib %d ATx NOT TRAINED - changing delay for center value of %d\n"},
//{0x00090001, "No passing region for Anib %d ATu\n"},
//{0x000a0002, "PMU5: Anib %d ATu final delay %d\n"},
//{0x000b0001, "PMU5: Anib %d ATu NOT TRAINED\n"},
//{0x000c0002, "PMU5: Anib %d ATu NOT TRAINED - changing delay for center value of %d\n"},
//{0x000d0002, "PMU1: Initialize DRAM PRBS seed0 0x%04x seed1 0x%04x\n"},
//{0x000e0004, "PMU: Dbyte swizzle settings for TG %d differ between Dbyte %d and %d for DRAM DQ %d\n"},
//{0x000f0000, "PMU: Error: start address of ACSM MPR read sequence must be aligned on even acsm addr position\n"},
//{0x00100000, "PMU1: loading 2D acsm sequence\n"},
//{0x00110000, "PMU1: loading 1D acsm sequence\n"},
//{0x00120002, "PMU3: %d memclocks @ %d to get half of 300ns\n"},
//{0x00130002, "PMU1: Initialize PRBS generator Poly 0x%04x, seed 0x%04x\n"},
//{0x00140000, "PMU3: Running 1D search for left eye edge\n"},
//{0x00150001, "PMU1: In Phase Left Edge Search cs %d\n"},
//{0x00160001, "PMU1: Out of Phase Left Edge Search cs %d\n"},
//{0x00170000, "PMU3: Running 1D search for right eye edge\n"},
//{0x00180001, "PMU1: In Phase Right Edge Search cs %d\n"},
//{0x00190001, "PMU1: Out of Phase Right Edge Search cs %d\n"},
//{0x001a0001, "PMU1: mxRdLat training pstate %d\n"},
//{0x001b0001, "PMU4: mxRdLat search for cs %d\n"},
//{0x001c0001, "PMU0: MaxRdLat non consistant DtsmLoThldXingInd 0x%03x\n"},
//{0x001d0003, "PMU4: CS %d Dbyte %d worked with DFIMRL = %d DFICLKs\n"},
//{0x001e0004, "PMU3: MaxRdLat Read Lane err mask for csn %d, DFIMRL %2d DFIClks, dbyte %d = 0x%03x\n"},
//{0x001f0003, "PMU3: MaxRdLat Read Lane err mask for csn %d DFIMRL %2d, All dbytes = 0x%03x\n"},
//{0x00200003, "PMU3: MaxRdLat Read Lane err mask for csn %d DFIMRL %2d, channel A dbytes = 0x%03x\n"},
//{0x00210003, "PMU3: MaxRdLat Read Lane err mask for csn %d DFIMRL %2d, channel B dbytes = 0x%03x\n"},
//{0x00220001, "PMU: Error: CS%d failed to find a DFIMRL setting that worked for all bytes during MaxRdLat training\n"},
//{0x00230002, "PMU3: Smallest passing DFIMRL for all dbytes in CS%d = %d DFIClks\n"},
//{0x00240001, "PMU: Error: CS%d failed to find a DFIMRL setting that worked for channel A bytes during MaxRdLat training\n"},
//{0x00250002, "PMU3: Smallest passing DFIMRL for channel A dbytes in CS%d = %d DFIClks\n"},
//{0x00260001, "PMU: Error: CS%d failed to find a DFIMRL setting that worked for channel B bytes during MaxRdLat training\n"},
//{0x00270002, "PMU3: Smallest passing DFIMRL for channel B dbytes in CS%d = %d DFIClks\n"},
//{0x00280000, "PMU: Error: No passing DFIMRL value found for any chip select during MaxRdLat training\n"},
//{0x00290000, "PMU: Error: No passing DFIMRL value found for any chip select for channel A during MaxRdLat training\n"},
//{0x002a0000, "PMU: Error: No passing DFIMRL value found for any chip select for channel B during MaxRdLat training\n"},
//{0x002b0002, "PMU2: TXDQ delayLeft[%2d] = %3d (DISCONNECTED)\n"},
//{0x002c0002, "PMU2: TXDQ delayLeft[%2d] = %3d\n"},
//{0x002d0004, "PMU2: TXDQ delayLeft[%2d] = %3d oopScaled = %3d selectOop %d\n"},
//{0x002e0002, "PMU2: TXDQ delayRight[%2d] = %3d (DISCONNECTED)\n"},
//{0x002f0002, "PMU2: TXDQ delayRight[%2d] = %3d\n"},
//{0x00300004, "PMU2: TXDQ delayRight[%2d] = %3d oopScaled = %3d selectOop %d\n"},
//{0x00310004, "PMU4: Fault Tolerance: tg %d dbyte %d lane %d TxDqDly passing region is too small (width = %d), the DQ lane is now disable\n"},
//{0x00320003, "PMU: Error: Dbyte %d lane %d txDqDly passing region is too small (width = %d)\n"},
{0x00330000, "PMU4: TxDqDly Passing Regions (EyeLeft EyeRight -> EyeCenter) Units=1/32 UI\n"},
//{0x00340002, "PMU4: DB %d Lane %d: (DISCONNECTED)\n"},
//{0x00350005, "PMU4: DB %d Lane %d: %3d %3d -> %3d\n"},
//{0x00360002, "PMU3: Running 1D search csn %d for DM Right/NotLeft(%d) eye edge\n"},
//{0x00370002, "PMU3: WrDq DM byte%2d avgDly 0x%04x\n"},
//{0x00380002, "PMU1: WrDq DM byte%2d with Errcnt %d\n"},
//{0x00390002, "PMU4: Fault Tolerance: rank %d Dbyte %d txDqDly DM training did not start inside the eye, both nibble are now disable\n"},
{0x003a0001, "PMU: Error: Dbyte %d txDqDly DM training did not start inside the eye\n"},
{0x003b0000, "PMU4: DM TxDqDly Passing Regions (EyeLeft EyeRight -> EyeCenter) Units=1/32 UI\n"},
//{0x003c0002, "PMU4: DB %d Lane %d: (DISCONNECTED)\n"},
//{0x003d0005, "PMU4: DB %d Lane %d: %3d %3d -> %3d\n"},
//{0x003e0004, "PMU4: Fault Tolerance: rank %d Dbyte %d lane %d txDqDly DM passing region is too small (width = %d), both nibble are now disable\n"},
//{0x003f0003, "PMU: Error: Dbyte %d lane %d txDqDly DM passing region is too small (width = %d)\n"},
//{0x00400004, "PMU3: Errcnt for MRD/MWD search nib %2d delay = (%d, 0x%02x) = %d\n"},
//{0x00410000, "PMU3: Precharge all open banks\n"},
//{0x00420002, "PMU: Error: Dbyte %d nibble %d found multiple working coarse delay setting for MRD/MWD\n"},
//{0x00430000, "PMU4: MRD Passing Regions (coarseVal, fineLeft fineRight -> fineCenter)\n"},
//{0x00440000, "PMU4: MWD Passing Regions (coarseVal, fineLeft fineRight -> fineCenter)\n"},
//{0x00450004, "PMU10: Warning: DB %d nibble %d has multiple working coarse positions, %d and %d, choosing the smaller delay\n"},
//{0x00460003, "PMU: Error: Dbyte %d nibble %d MRD/MWD passing region is too small (width = %d)\n"},
//{0x00470006, "PMU4: DB %d nibble %d: %3d, %3d %3d -> %3d\n"},
//{0x00480004, "PMU5: Start MRD/nMWD %d for csn %d, min_coarse_dly %d, max_coarse_step %d\n"},
//{0x00490001, "PMU1: MRD/MRW training trial with RCD CmdDly %d\n"},
//{0x004a0001, "PMU5: MRD/MRW training is converging with RCD CmdDly %d\n"},
//{0x004b0001, "PMU: Error: MRD/MWD training is not converging on rank %d after trying all possible RCD CmdDly\n"},
//{0x004c0002, "PMU2: RXDQS delayLeft[%2d] = %3d (DISCONNECTED)\n"},
//{0x004d0006, "PMU2: RXDQS delayLeft[%2d] = %3d delayOop[%2d] = %3d OopScaled %4d, selectOop %d\n"},
//{0x004e0002, "PMU2: RXDQS delayRight[%2d] = %3d (DISCONNECTED)\n"},
//{0x004f0006, "PMU2: RXDQS delayRight[%2d] = %3d delayOop[%2d] = %4d OopScaled %4d, selectOop %d\n"},
//{0x00500000, "PMU4: RxClkDly Passing Regions (EyeLeft EyeRight -> EyeCenter)\n"},
//{0x00510002, "PMU4: DB %d nibble %d: (DISCONNECTED)\n"},
//{0x00520005, "PMU4: DB %d nibble %d: %3d %3d -> %3d\n"},
//{0x00530004, "PMU4: Fault Tolerance: tg %d Dbyte %d nibble %d RxClkDly passing region is too small (width = %d), the nibble is now disable\n"},
{0x00540003, "PMU: Error: Dbyte %d nibble %d rxClkDly passing region is too small (width = %d)\n"},
{0x00550003, "PMU4: Eye largest blob area %d from %d to %d\n"},
{0x0056001f, "PMU4: %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d >%3d< %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d\n"},
//{0x00570001, " %3d"},
//{0x00580000, "\n"},
{0x00590005, "PMU4: d5_2d_set_margin csn %d isTx %d isVref %d margin chan0 %d chan1 %d\n"},
{0x005a0003, "PMU4: -------- 2D Read Scanning TG %d (CS 0x%x) Lanes 0x%03x --------\n"},
//{0x005b0005, "PMU1: -- DB%d L%d rxClkDlyVal = %d, minVref = %d, maxVref = %d\n"},
{0x005c0004, "PMU4: -- DB%d L%d -- centers: delay = %d, voltage = %d\n"},
//{0x005d0002, "PMU1: -- realOffsetDly = %d, delayOffset = %d\n"},
{0x005e0002, "PMU3: d5_rx_2d_data_acquisition rank %d clkDlyIter %d\n"},
//{0x005f0003, "PMU4: Fault Tolerance: tg %d dbyte %d lane %d RxPBDly had no passing region, the DQ lane is now disable\n"},
//{0x00600003, "PMU: Error: D5 rd2D no passing region for rank %d, db %d, lane %d\n"},
//{0x00610002, "PMU: Error: Wrong PBDly seed 0x%04x results in too small RxClkDly 0x%04x\n"},
//{0x00620004, "PMU3: d5_rx_2d_data_optimization tg %d db %d lane %d RxPBDly %d\n"},
//{0x00630004, "PMU3: d5_rx_2d_data_optimization tg %d db %d lane %d RxPBDly %d\n"},
//{0x00640004, "PMU4: d5_rx_2d_get_rank_compound_eye tg %d lane %d center voltage %d delay offset %d\n"},
//{0x00650003, "PMU4: d5_rx_2d_get_rank_compound_eye tg %d lane %d to %d before Blob filtering\n"},
//{0x00660005, "PMU4: d5_rx_2d_get_lane_compound_eye tg %d lane %d center delay %d delay offset %d centerOffset %d\n"},
//{0x00670001, "PMU4: d5_rx_2d_get_lane_compound_eye lane %d before Blob filtering\n"},
//{0x00680003, "PMU4: d5_rx_2d_rank_RxClkDly_optimization compound eye tg %d nib %d center delay %d\n"},
//{0x00690004, "PMU1: d5_rx_2d_data_optimization tg %d nib %d sumDW %d sumW %d\n"},
//{0x006a0002, "PMU4: Fault Tolerance: tg %d nib %d RxClkDly had no passing region, the nibble is now disable\n"},
{0x006b0002, "PMU: Error: tg %d nib %d RxClkDly had no passing region\n"},
//{0x006c0003, "PMU3: d5_rx_2d_data_optimization tg %d nib %d RxClkDly %d\n"},
//{0x006d0002, "PMU4: d5_rx_2d_data_vref_optimization compound eye %d center delay %d\n"},
//{0x006e0004, "PMU1: D5 rd2D optimisation db %d lane %d Vref %d eye-width %d\n"},
//{0x006f0005, "PMU1: D5 rd2D optimisation csn %d db %d lane %d min Vref %d max Vref %d\n"},
//{0x00700004, "PMU1: D5 rd2D optimisation db %d lane %d sumVEW %d sumEW %d\n"},
//{0x00710002, "PMU4: Fault Tolerance: db %d lane %d vrefDAC had no passing region, the DQ lane is now disable on all rank\n"},
//{0x00720002, "PMU: Error: db %d lane %d vrefDAC had no passing region\n"},
//{0x00730003, "PMU3: D5 rd2D optimisation db %d lane %d Vref %d\n"},
//{0x00740004, "PMU4: Start d5_rx_2d_tap_dfe nb_tap %d dly_incdec %d vref_incdec %d coeff_step_mode %d\n"},
//{0x00750003, "PMU4: Start d5_rx_2d_tap_dfe tap %d coeff_step_inc %d coeff_step_max %d\n"},
//{0x00760004, "PMU4: d5_rx_2d_tap_dfe tap %d db %d lane %d RxDFETapCtrl 0x%0x\n"},
{0x00770004, "PMU4: Start d5_rx_2d dly_incdec %d vref_incdec %d dfe %d dac %d\n"},
{0x00780003, "PMU4: -------- 2D Write Scanning TG %d (CS 0x%x) Lanes 0x%03x --------\n"},
{0x00790004, "PMU4: -- DB%d L%d -- centers: delay = %d, voltage = %d\n"},
//{0x007a0003, "PMU1: -- realOffsetDly = %d, leftPos = %d, center = %d\n"},
//{0x007b0001, "PMU5: <<KEY>> 0 messageBlock VrefDqR%d <<KEY>> MR10(7:0)\n"},
//{0x007c0000, "PMU5: <<KEY>> 0 data buffer VrefDQ <<KEY>> PG[2]RWE[7:0]\n"},
//{0x007d0002, "PMU3: Run data acquisition for vref 0x%02x for rank %d\n"},
//{0x007e0001, "PMU3: Run data acquisition for txDqDly iter 0x%02x\n"},
//{0x007f0004, "PMU3: Start data acquisition for rank %d dstep %d vstep %d dfe %d\n"},
//{0x00800005, "PMU1: D5 wr2D optimisation rank %d db %d lane %d sumDW %d sumW %d\n"},
{0x00810003, "PMU4: Fault Tolerance: tg %d dbyte %d lane %d TxDqDly had no passing region, the DQ lane is now disable\n"},
{0x00820002, "PMU: Error: dbyte %d lane %d TxDqDly had no passing region\n"},
{0x00830004, "PMU3: D5 wr2D optimisation rank %d db %d lane %d TxDqDly 0x%04x\n"},
//{0x00840004, "PMU4: d5_tx_2d_get_dram_compound_eye tg %d lane %d center delay %d centerOffset %d\n"},
//{0x00850003, "PMU4: d5_tx_2d_get_dram_compound_eye tg %d lane %d to %d before Blob filtering\n"},
//{0x00860005, "PMU1: D5 wr2D optimisation rank %d db %d lane %d best Vref %d width %d\n"},
//{0x00870005, "PMU1: D5 wr2D optimisation rank %d db %d lane %d Vref %d eye-width %d\n"},
//{0x00880003, "PMU4: d5_tx_2d_rank_vrefDq_optimization rank %d compound eye %d center delay %d\n"},
//{0x00890004, "PMU1: D5 wr2D optimisation rank %d compound eye %d Vref %d eye-width %d\n"},
//{0x008a0004, "PMU1: D5 wr2D optimisation rank %d nib %d sumVEW %d sumEW %d\n"},
//{0x008b0002, "PMU4: Fault Tolerance: tg %d nib %d vrefDQ had no passing region, the nibble for this DRAM is now disable\n"},
{0x008c0001, "PMU: Error: nib %d vrefDQ had no passing region\n"},
{0x008d0003, "PMU4: D5 wr2D optimisation rank %d nib %d Vref %d\n"},
//{0x008e0005, "PMU4: Start d5_tx_2d_rank_dfe csn %d nb_tap %d dly_incdec %d vref_incdec %d bias_step_mode %d\n"},
//{0x008f0004, "PMU3: Set Gain bias [0x%02x, 0x%02x] on DM lane %d of each DRAM on rank %d\n"},
//{0x00900004, "PMU3: Set Gain bias [0x%02x, 0x%02x] on DQ lane %d of each DRAM on rank %d\n"},
//{0x00910005, "PMU3: Start d5_tx_2d_rank_dfe csn %d tap %d dly_incdec %d vref_incdec %d bias_step_mode %d\n"},
//{0x00920004, "PMU3: Set tap %d bias 0x%2x on DM lane %d of each DRAM on rank %d\n"},
//{0x00930004, "PMU3: Set tap %d bias 0x%2x on DQ lane %d of each DRAM on rank %d\n"},
//{0x00940007, "PMU4: rank %d tap %d bias 0x%2x on DB %d DQ %d improve eye area to %d from %d\n"},
//{0x00950004, "PMU4: Set mr %d nib %d to 0x%2x via PDA on rank %d\n"},
//{0x00960002, "PMU3: Set mr %d via PDA on rank %d\n"},
//{0x00970004, "PMU4: Set mr %d nib %d to 0x%2x via PDA on rank %d\n"},
//{0x00980004, "PMU4: Set mr %d nib %d to 0x%2x via PDA on rank %d\n"},
//{0x00990004, "PMU4: Set mr %d nib %d to 0x%2x via PDA on rank %d\n"},
//{0x009a0004, "PMU4: Set mr %d nib %d to 0x%2x via PDA on rank %d\n"},
//{0x009b0002, "PMU3: Set mr %d via PDA on rank %d\n"},
//{0x009c0004, "PMU3: Start d5_tx_2d dly_incdec %d vref_incdec %d csn %d dfe %d\n"},
{0x009d0003, "PMU3: D5 wr2D optimisation rank %d db %d lane DM TxDqDly 0x%04x\n"},
//{0x009e0001, "PMU3: Starting MRD training for csn %d\n"},
//{0x009f0001, "PMU3: Starting MWD training for csn %d\n"},
//{0x00a00003, "PMU3: Errcnt for search nib %2d delay = 0x%02x = %d\n"},
//{0x00a10001, "PMU4: MRD Passing Regions for csn %d (fineLeft fineRight -> fineCenter)\n"},
//{0x00a20001, "PMU4: MWD Passing Regions for csn %d (fineLeft fineRight -> fineCenter)\n"},
//{0x00a30005, "PMU4: DB %d nibble %d: %3d %3d -> %3d\n"},
//{0x00a40003, "PMU: Error: Dbyte %d nibble %d MRD passing region is too small (width = %d)\n"},
//{0x00a50003, "PMU: Error: Dbyte %d nibble %d MWD passing region is too small (width = %d)\n"},
//{0x00a60001, "PMU5: MRD CS%d RCWE4 RCWE5\n"},
//{0x00a70001, "PMU5: MWD CS%d RCWE6 RCWE7\n"},
//{0x00a80003, "PMU5: DB%d     0x%02x  0x%02x\n"},
//{0x00a90004, "PMU10: In Quick Rd2D csn=%d dimm=%d pstate=%d vref step=%d\n"},
//{0x00aa0002, "PMU0: goodbar = %d for RDWR_BLEN %d\n"},
//{0x00ab0001, "PMU3: RxClkDly = %d\n"},
//{0x00ac0005, "PMU0: db %d l %d absLane %d -> bottom %d top %d\n"},
//{0x00ad0009, "PMU3: BYTE %d - %3d %3d %3d %3d %3d %3d %3d %3d\n"},
//{0x00ae0000, "PMU4: VrefDAC Passing Regions (width center)\n"},
//{0x00af0003, "PMU4: Fault Tolerance: tg %d dbyte %d lane %d's per-lane vrefDAC's had no passing region, the DQ lane is now disable\n"},
//{0x00b00002, "PMU: Error: dbyte %d lane %d's per-lane vrefDAC's had no passing region\n"},
//{0x00b10004, "PMU4: DB %d Lane %d: %d %d\n"},
//{0x00b20002, "PMU0: goodbar = %d for RDWR_BLEN %d\n"},
//{0x00b30004, "PMU3: db%d l%d saw %d issues at rxClkDly %d\n"},
//{0x00b40003, "PMU3: db%d l%d first saw a pass->fail edge at rxClkDly %d\n"},
//{0x00b50002, "PMU3: lane %d PBD = %d\n"},
//{0x00b60003, "PMU3: db%d l%d first saw a DBI pass->fail edge at rxClkDly %d\n"},
//{0x00b70003, "PMU2: db%d l%d already passed rxPBD = %d\n"},
//{0x00b80003, "PMU0: db%d l%d, PBD = %d\n"},
//{0x00b90003, "PMU4: Fault Tolerance: tg %d dbyte %d lane %d failed read deskew, the DQ lane is now disable\n"},
//{0x00ba0002, "PMU: Error: dbyte %d lane %d failed read deskew\n"},
//{0x00bb0003, "PMU0: db%d l%d, inc PBD = %d\n"},
//{0x00bc0003, "PMU1: Running lane deskew on pstate %d csn %d rdDBIEn %d\n"},
//{0x00bd0000, "PMU5: <<KEY>> states\n"},
//{0x00be0003, "PMU1: Running lane deskew on pstate %d csn %d rdDBIEn %d\n"},
//{0x00bf0001, "PMU4: Adjusting PBD by %d\n"},
//{0x00c00008, "PMU4: db%d nib%d goal=%2d, centers = %2d %2d %2d %2d %2d\n"},
//{0x00c10000, "PMU5: <<KEY>> 0 RxPBDly <<KEY>> 1 Delay Unit ~= 7ps\n"},
//{0x00c20000, "PMU1: Message block contents\n"},
//{0x00c30000, "PMU1: Message block contents\n"},
//{0x00c40002, "PMU1: AcsmCsMapCtrl%02d 0x%04x\n"},
//{0x00c50002, "PMU1: AcsmCsMapCtrl%02d 0x%04x\n"},
//{0x00c60001, "PMU: Error: Wrong PMU image loaded. message Block DramType = 0x%02x, but image built for D4U Type\n"},
//{0x00c70001, "PMU: Error: Wrong PMU image loaded. message Block DramType = 0x%02x, but image built for D4R Type\n"},
//{0x00c80001, "PMU: Error: Wrong PMU image loaded. message Block DramType = 0x%02x, but image built for D4LR Type\n"},
//{0x00c90000, "PMU: Error: Both 2t timing mode and ddr4 geardown mode specifed in the messageblock's PhyCfg and MR3 fields. Only one can be enabled\n"},
{0x00ca0003, "PMU10: PHY TOTALS - NUM_DBYTES %d NUM_NIBBLES %d NUM_ANIBS %d\n"},
{0x00cb0008, "PMU10: CSA=0x%02X, CSB=0x%02X, TSTAGES=0x%04X, HDTOUT=%d, PHYCFG=0x%02X MMISC=0x%02X D5MISC=0x%02X DRAMFreq=%dMT DramType=DDR5\n"},
//{0x00cc0008, "PMU10: CS=0x%02X, TSTAGES=0x%04X, HDTOUT=%d, 2T=%d, MMISC=%d AddrMirror=%d DRAMFreq=%dMT DramType=%d\n"},
//{0x00cd0008, "PMU10: Pstate%d MRS MR0=0x%04X MR1=0x%04X MR2=0x%04X MR3=0x%04X MR4=0x%04X MR5=0x%04X MR6=0x%04X\n"},
//{0x00ce0008, "PMU10: NVDIMM 0x%0x MRS MR0=0x%04X MR1=0x%04X MR2=0x%04X MR3=0x%04X MR4=0x%04X MR5=0x%04X MR6=0x%04X\n"},
{0x00cf0005, "PMU10: Pstate%d MRS MR0=0x%04X MR2=0x%04X MR3=0x%04X MR8=0x%04X\n"},
//{0x00d00002, "PMU1: AcsmOdtCtrl%02d 0x%02x\n"},
//{0x00d10002, "PMU1: AcsmCsMapCtrl%02d 0x%04x\n"},
//{0x00d20000, "PMU1: HwtCAMode set\n"},
//{0x00d30000, "PMU: Error: start address of ACSM RxEn sequence must be aligned on even acsm addr position\n"},
//{0x00d40001, "PMU3: DDR4 infinite preamble enter/exit mode %d\n"},
//{0x00d50001, "PMU3: DDR5 infinite preamble enter/exit mode %d\n"},
//{0x00d60002, "PMU1: In rxenb_train() csn=%d pstate=%d\n"},
//{0x00d70003, "PMU4: Fault Tolerance: RxEn rank %d cannot find DQS rising edge on Dbyte %d nibble %d, this nibble is now disable\n"},
//{0x00d80001, "PMU: Error: Dbyte %d couldn't find the rising edge of DQS during RxEn Training\n"},
//{0x00d90000, "PMU3: RxEn aligning to first rising edge of burst\n"},
{0x00da0001, "PMU4: Decreasing RxEn delay by %d fine step to allow full capture of reads\n"},
//{0x00db0001, "PMU4: Search MRE Coarse Delay = 0x%x\n"},
//{0x00dc0001, "PMU3: Search MRE Fine Delay = %d\n"},
//{0x00dd0003, "PMU3: Errcnt for MRE nib %2d delay = %2d is %d\n"},
//{0x00de0002, "PMU3: MRE nibble %d sampled a 1 at data buffer delay %d\n"},
//{0x00df0003, "PMU4: MRE nibble %d saw a 0 to 1 transition at data buffer delay coarse %d fine %d\n"},
//{0x00e00001, "PMU: Error: Failed MRE for nib %d\n"},
//{0x00e10001, "PMU4: MRE nibble %d assume delay fine 0 coarse 0\n"},
//{0x00e20001, "PMU5: MRE CS%d RCWE0 RCWE2 RCWE3\n"},
//{0x00e30004, "PMU5: DB%d     0x%02x  0x%02x  0x%02x\n"},
//{0x00e40001, "PMU3: MREP Delay = %d\n"},
//{0x00e50003, "PMU3: Errcnt for MREP nib %2d delay = %2d is %d\n"},
//{0x00e60002, "PMU3: MREP nibble %d sampled a 1 at data buffer delay %d\n"},
//{0x00e70002, "PMU3: MREP nibble %d saw a 0 to 1 transition at data buffer delay %d\n"},
//{0x00e80000, "PMU2:  MREP did not find a 0 to 1 transition for all nibbles. Failing nibbles assumed to have rising edge close to fine delay 63\n"},
//{0x00e90002, "PMU2:  Rising edge found in alias window, setting rxDly for nibble %d = %d\n"},
//{0x00ea0002, "PMU: Error: Failed MREP for nib %d with %d one\n"},
//{0x00eb0003, "PMU2:  Rising edge not found in alias window with %d one, leaving rxDly for nibble %d = %d\n"},
//{0x00ec0002, "PMU3: Training DIMM %d CSn %d\n"},
{0x00ed0005, "PMU4: CSn %d Channel %d isCA %d isVref %d margin %d\n"},
//{0x00ee0002, "PMU20: CA training for CA%d converge to center 0x%03x, which is too large, assume 0xff\n"},
//{0x00ef0003, "PMU4: Fault Tolerance: CS/CA Train %d for dev %d will only look PHY DQ %d\n"},
//{0x00f00003, "PMU1: CS dev %d passed at delay %d. Rising edge was at %d\n"},
//{0x00f10000, "PMU4: WARNING: CS train did not find a rising edge for all devices.\n"},
//{0x00f20002, "PMU4: Fault Tolerance: CS Train %d cannot find left edge on device %d\n"},
//{0x00f30002, "PMU1: CSn %d max CS left edge %d\n"},
//{0x00f40002, "PMU1: CS dev %d offset %d\n"},
//{0x00f50004, "PMU1: CSn %d Channel %d Dly 0x%02x CS train feedback %d\n"},
//{0x00f60005, "PMU1: CSn %d Channel %d Dly 0x%02x dev %d CS train feedback 0x%04x\n"},
//{0x00f70004, "PMU1: CSn %d Channel %d Dly 0x%02x CS train feedback %d\n"},
{0x00f80002, "PMU5: Chan %d CSn %d: "},
{0x00f90001, "%08x"},
{0x00fa0000, "\n"},
{0x00fb0004, "PMU5: CSn %d Channel %d CS train passing region (%d, %d)\n"},
{0x00fc0003, "PMU: Error: CSn %d Channel %d CS train passing region is too small (width = %d)\n"},
{0x00fd0003, "PMU5: Channel %d rank %d CS init delay 0x%04x\n"},
{0x00fe0006, "PMU1: CSn %d Channel %d Dly 0x%02x dev %d CA %d train feedback 0x%04x\n"},
{0x00ff0005, "PMU1: CSn %d Channel %d Signal CA%d Dly 0x%02x CA train feedback %d\n"},
{0x01000004, "PMU5: CSn %d Channel %d Signal CA%d final VrefCA 0x%04x\n"},
{0x01010003, "PMU5: CSn %d Channel %d Signal CA%d: "},
{0x01020001, "%08x"},
{0x01030000, "\n"},
{0x01040005, "PMU5: CSn %d Channel %d Signal CA%d CA train passing region (%d, %d)\n"},
{0x01050004, "PMU: Error: CSn %d Channel %d Signal A%d CA train passing region is too small (width = %d)\n"},
{0x01060003, "PMU4: -- CA%d -- centers: delay = %d voltage = %d\n"},
{0x01070004, "PMU1: CSn %d Channel %d Vref %d CS train feedback %d\n"},
{0x01080002, "PMU5: CSn %d Channel %d: "},
{0x01090001, "%08x"},
{0x010a0000, "\n"},
{0x010b0004, "PMU5: CSn %d Channel %d VrefCS train passing region (%d, %d)\n"},
{0x010c0003, "PMU: Error: CSn %d Channel %d VrefCS train passing region is too small (width = %d)\n"},
{0x010d0003, "PMU5: CSn %d Channel %d final VrefCS 0x%04x\n"},
{0x010e0006, "PMU1: CSn %d Channel %d Signal CA%d Vref %d CA train feedback cnt=%d status=%d\n"},
{0x010f0003, "PMU5: CSn %d Channel %d Signal CA%d: "},
{0x01100001, "%08x"},
{0x01110000, "\n"},
//{0x01120005, "PMU5: CSn %d Channel %d Signal CA%d VrefCA train passing region (%d, %d)\n"},
//{0x01130004, "PMU: Error: CSn %d Channel %d Signal CA%d VrefCA train passing region is too small (width = %d)\n"},
//{0x01140004, "PMU5: CSn %d Channel %d Signal CA%d final VrefCA 0x%04x\n"},
//{0x01150002, "PMU4: -------- CA DFE Scanning CS 0x%x Channel %d --------\n"},
//{0x01160006, "PMU4: Signal CA%d Gain %d Tap %d Bias %d VrefCA passing region (%d, %d)\n"},
//{0x01170003, "PMU: Error: RCD CA DFE training failed for CS 0x%x Channel %d CA%d (no open eye was found)\n"},
//{0x01180008, "PMU5: CS 0x%x Channel %d CA%d DFE gain %d tap %d trained bias: %d with passing region (%d, %d)\n"},
//{0x01190003, "PMU: Error: RCD CA DFE training could not calculate trained VrefCA center for CS 0x%x Channel %d CA%d\n"},
//{0x011a0004, "PMU5: CSn %d Channel %d Signal CA%d final VrefCA 0x%04x\n"},
//{0x011b0003, "PMU5: Channel %d Cs %d individual Cs optimal delay 0x%04x\n"},
{0x011c0003, "PMU5: Channel %d dimm %d Cs final delay 0x%04x\n"},
//{0x011d0003, "PMU5: Channel %d dimm %d CS init delay 0x%04x\n"},
{0x011e0003, "PMU5: Channel %d rank %d CS init delay 0x%04x\n"},
//{0x011f0002, "PMU20: CA training for CA%d converge to center 0x%03x, which is too large, assume 0xff\n"},
{0x01200004, "PMU5: Rank %d Channel %d CA%d temp delay 0x%04x\n"},
//{0x01210004, "PMU3: Channel %d CS%d CA%d is current min delta delay %d\n"},
//{0x01220004, "PMU3: Channel %d CS%d CA%d is current max delta delay %d\n"},
{0x01230003, "PMU4: Channel %d rank %d CS/CK delta delay %d\n"},
//{0x01240002, "PMU4: DIMM %d CK delta delay %d\n"},
//{0x01250002, "PMU5: DIMM %d CK final delay 0x%04x\n"},
//{0x01260003, "PMU5: Channel %d CS%d CK final delay 0x%04x\n"},
{0x01270004, "PMU5: Channel %d rank-pair %d CS average delay 0x%04x average delta %d\n"},
{0x01280003, "PMU5: Channel %d rank-pair %d CS final delay 0x%04x\n"},
{0x01290005, "PMU5: CSn %d Channel %d Signal CA%d CA train adjusted passing region (%d, %d)\n"},
{0x012a0003, "PMU5: Channel %d CA%d final delay 0x%04x\n"},
//{0x012b0001, "PMU5: tCSH_SRexit 30ns in MCLK is %d\n"},
//{0x012c0003, "PMU5: CSn %d Channel %d RCD CS final delay %d\n"},
//{0x012d0003, "PMU5: CSn %d Channel %d RCD CA final delay %d\n"},
//{0x012e0004, "PMU4: CSn %d Channel %d RCD isCA %d margin %d\n"},
//{0x012f0005, "PMU1: CSn %d Channel %d Dly 0x%02x dev %d RCD CS train feedback 0x%04x\n"},
//{0x01300002, "PMU5: Chan %d CSn %d: "},
//{0x01310001, "%08x"},
//{0x01320000, "\n"},
//{0x01330005, "PMU5: CSn %d Channel %d RCD CS train passing region (%d, %d), center %d\n"},
//{0x01340003, "PMU5: Error: CSn %d Channel %d RCD CS train passing region is too small (width = %d), assume 0 as center\n"},
//{0x01350000, "PMU: Error: start address of ACSM RCD_CA sequence must be aligned on even acsm addr position\n"},
//{0x01360005, "PMU1: CSn %d Channel %d Signal CA%d Dly 0x%02x RCD CA train feedback %d\n"},
//{0x01370003, "PMU5: Chan %d CSn %d CA%02d: "},
//{0x01380001, "%08x"},
//{0x01390000, "\n"},
//{0x013a0005, "PMU5: CSn %d Channel %d Signal CA%d RCD CA train passing region (%d, %d)\n"},
//{0x013b0003, "PMU5: Error: CSn %d Channel %d RCD CA train margin is too small (width = %d), assume 0 as center\n"},
//{0x013c0001, "PMU4: Set VrefCS/VrefCA per DRAM on rank %d using PDA\n"},
//{0x013d0000, "PMU3: Resetting DRAM\n"},
//{0x013e0002, "PMU5: DIMM%d CK init delay 0x%04x\n"},
{0x013f0003, "PMU5: Channel %d DIMM%d CK init delay 0x%04x\n"},
//{0x01400001, "PMU4: Writing DDR5 RCD RC%02X\n"},
//{0x01410000, "PMU3: Resetting DRAM\n"},
//{0x01420000, "PMU3: setup for RCD initalization\n"},
//{0x01430000, "PMU3: pmu_exit_SR from dev_init()\n"},
//{0x01440000, "PMU3: initializing RCD\n"},
//{0x01450000, "PMU2: Starting PPR\n"},
//{0x01460002, "PMU: Error: specified bank (BG:%d BA:%d) is not available for PPR\n"},
//{0x01470000, "PMU10: **** Executing 2D Image ****\n"},
//{0x01480002, "PMU10: **** Start DDR4 Training. PMU Firmware Revision 0x%04x (%d) ****\n"},
{0x01490002, "PMU10: **** Start DDR5 Training. PMU Firmware Revision 0x%04x (%d) ****\n"},
//{0x014a0000, "PMU: Error: Mismatched internal revision between DCCM and ICCM images\n"},
//{0x014b0001, "PMU10: **** Testchip %d Specific Firmware ****\n"},
//{0x014c0000, "PMU1: LRDIMM with EncodedCS mode, one DIMM\n"},
//{0x014d0000, "PMU1: LRDIMM with EncodedCS mode, two DIMMs\n"},
//{0x014e0000, "PMU1: RDIMM with EncodedCS mode, one DIMM\n"},
//{0x014f0000, "PMU2: Starting LRDIMM MREP training for all ranks\n"},
//{0x01500000, "PMU2: LRDIMM MREP training for all ranks completed\n"},
//{0x01510000, "PMU2: Starting LRDIMM DWL training for all ranks\n"},
//{0x01520000, "PMU2: LRDIMM DWL training for all ranks completed\n"},
//{0x01530000, "PMU2: Starting LRDIMM MRD training for all ranks\n"},
//{0x01540000, "PMU2: LRDIMM MRD training for all ranks completed\n"},
//{0x01550000, "PMU2: Starting RXEN training for all ranks\n"},
//{0x01560000, "PMU2: Starting write leveling fine delay training for all ranks\n"},
//{0x01570000, "PMU2: Starting LRDIMM MWD training for all ranks\n"},
//{0x01580000, "PMU2: LRDIMM MWD training for all ranks completed\n"},
//{0x01590000, "PMU2: Starting write leveling fine delay training for all ranks\n"},
//{0x015a0000, "PMU2: Starting D5 RdDqs 1D2D training for all ranks\n"},
//{0x015b0000, "PMU2: Starting D5 RdDqs training for all ranks\n"},
//{0x015c0000, "PMU2: Starting read deskew training\n"},
//{0x015d0000, "PMU2: Starting SI friendly 1d RdDqs training for all ranks\n"},
//{0x015e0000, "PMU2: Starting 2d WrDq training for all ranks\n"},
//{0x015f0000, "PMU2: Starting 1d WrDq training for all ranks\n"},
//{0x01600000, "PMU2: Starting write leveling coarse delay training for all ranks\n"},
//{0x01610000, "PMU2: Starting 1d WrDq training for all ranks\n"},
//{0x01620000, "PMU2: Starting again read deskew training but with PRBS\n"},
//{0x01630000, "PMU2: Starting 1D read deskew training but with PRBS\n"},
//{0x01640000, "PMU2: Starting 1d RdDqs training for all ranks\n"},
//{0x01650000, "PMU2: Starting 1d WrDq training for all ranks\n"},
//{0x01660000, "PMU2: Starting 1d RdDqs training for all ranks\n"},
//{0x01670000, "PMU2: Starting again 1d WrDq training for all ranks\n"},
//{0x01680000, "PMU2: Starting MaxRdLat training\n"},
//{0x01690000, "PMU2: Starting 2d RdDqs training for all ranks\n"},
//{0x016a0000, "PMU2: Starting 2d WrDq training for all ranks\n"},
//{0x016b0000, "PMU2: Starting 2d RdDqs training for all ranks\n"},
{0x016c0004, "PMU4: csn %d nib %d MR%d Val = 0x%x\n"},
{0x016d0002, "PMU4: Set ResultAddrOffset to 0x%x for addr 0x%x\n"},
{0x016e0005, "PMU4: dimm %d page %d db %d RCW%x Val = 0x%x\n"},
{0x016f0004, "PMU4: dimm %d page 2 db %d RCW%x Val = 0x%x\n"},
{0x01700004, "PMU4: csn %d nib %d MR%d Val = 0x%x\n"},
{0x01710004, "PMU4: csn %d nib %d BCW%2x Val = 0x%x\n"},
{0x01720000, "PMU: Error: EnabledDQsChA must be > 0\n"},
{0x01730000, "PMU: Error: EnabledDQsChB must be > 0\n"},
{0x01740002, "PMU3: getMRVal read %x from nibble %d\n"},
{0x01750002, "PMU4: DB%d rwe8 = %d\n"},
{0x01760002, "PMU4: DB%d rwec = %d\n"},
{0x01770002, "PMU4: DB%d rwe9 = %d\n"},
{0x01780002, "PMU4: DB%d rwed = %d\n"},
{0x01790002, "PMU4: Nibble %d dqs2dq = %d/64 UI\n"},
{0x017a0002, "PMU4: Nibble %d dqs2dq is overwrite with user provided value %d/64 UI\n"},
{0x017b0003, "PMU3: Setting coarse delay in AT_Dly chiplet %d from 0x%02x to 0x%02x\n"},
{0x017c0003, "PMU3: Clearing coarse delay in AT_Dly chiplet %d from 0x%02x to 0x%02x\n"},
{0x017d0000, "PMU3: Performing DDR4 geardown sync sequence\n"},
{0x017e0000, "PMU1: Enter DDR5 self refresh\n"},
{0x017f0000, "PMU1: Exit DDR5 self refresh\n"},
{0x01800001, "PMU5: tCSH_SRexit 20ns in MCLK is %d\n"},
{0x01810000, "PMU1: Enter self refresh\n"},
{0x01820000, "PMU1: Exit self refresh\n"},
{0x01830000, "PMU: Error: No dbiDisable without d4\n"},
{0x01840001, "PMU1: DDR4 update Rx DBI Setting disable %d\n"},
{0x01850001, "PMU1: DDR4 update 2nCk WPre Setting disable %d\n"},
{0x01860005, "PMU1: read_delay: db%d lane%d delays[%2d] = 0x%02x (max 0x%02x)\n"},
{0x01870004, "PMU1: read_delay: db%d lane%d delays[%2d] = 0x%02x (NOT CONNECTED)\n"},
{0x01880004, "PMU1: write_delay: db%d lane%d delays[%2d] = 0x%04x\n"},
{0x01890001, "PMU5: ID=%d -- db0  db1  db2  db3  db4  db5  db6  db7  db8  db9 --\n"},
{0x018a000b, "PMU5: [%d]:0x %4x %4x %4x %4x %4x %4x %4x %4x %4x %4x\n"},
{0x018b0003, "PMU2: dump delays - pstate=%d dimm=%d csn=%d\n"},
{0x018c0000, "PMU3: Printing Mid-Training Delay Information\n"},
{0x018d0001, "PMU5: CS%d <<KEY>> 0 TrainingCntr <<KEY>> coarse(15:10) fine(9:0)\n"},
{0x018e0001, "PMU5: CS%d <<KEY>> 0 RxEnDly, 1 RxClkDly <<KEY>> coarse(10:6) fine(5:0)\n"},
{0x018f0001, "PMU5: CS%d <<KEY>> 0 TxDqsDly, 1 TxDqDly <<KEY>> coarse(9:6) fine(5:0)\n"},
{0x01900001, "PMU5: CS%d <<KEY>> 0 RxPBDly <<KEY>> 1 Delay Unit ~= 7ps\n"},
{0x01910000, "PMU5: all CS <<KEY>> 0 DFIMRL <<KEY>> Units = DFI clocks\n"},
{0x01920000, "PMU5: all CS <<KEY>> VrefDACs <<KEY>> DAC(6:0)\n"},
{0x01930000, "PMU5: all CS <<KEY>> VrefDACs <<KEY>> DAC(6:0)\n"},
{0x01940000, "PMU: Error: getMaxRxen() failed to find largest rxen nibble delay\n"},
{0x01950003, "PMU2: getMaxRxen(): maxDly %d maxTg %d maxNib %d\n"},
{0x01960003, "PMU2: getRankMaxRxen(): maxDly %d Tg %d maxNib %d\n"},
{0x01970000, "PMU1: skipping CDD calculation in 2D image\n"},
//{0x01980001, "PMU3: Calculating CDDs for pstate %d\n"},
//{0x01990003, "PMU3: rxFromDly[%d][%d] = %d\n"},
//{0x019a0003, "PMU3: rxToDly  [%d][%d] = %d\n"},
//{0x019b0003, "PMU3: rxDly    [%d][%d] = %d\n"},
//{0x019c0003, "PMU3: txDly    [%d][%d] = %d\n"},
//{0x019d0003, "PMU3: allFine CDD_RR_%d_%d = %d\n"},
//{0x019e0003, "PMU3: allFine CDD_WW_%d_%d = %d\n"},
//{0x019f0003, "PMU3: CDD_RR_%d_%d = %d\n"},
//{0x01a00003, "PMU3: CDD_WW_%d_%d = %d\n"},
//{0x01a10003, "PMU3: allFine CDD_RW_%d_%d = %d\n"},
//{0x01a20003, "PMU3: allFine CDD_WR_%d_%d = %d\n"},
//{0x01a30003, "PMU3: CDD_RW_%d_%d = %d\n"},
//{0x01a40003, "PMU3: CDD_WR_%d_%d = %d\n"},
//{0x01a50004, "PMU3: F%dBC2x_B%d_D%d = 0x%02x\n"},
//{0x01a60004, "PMU3: F%dBC3x_B%d_D%d = 0x%02x\n"},
//{0x01a70004, "PMU3: F%dBC4x_B%d_D%d = 0x%02x\n"},
//{0x01a80004, "PMU3: F%dBC5x_B%d_D%d = 0x%02x\n"},
//{0x01a90004, "PMU3: F%dBC8x_B%d_D%d = 0x%02x\n"},
//{0x01aa0004, "PMU3: F%dBC9x_B%d_D%d = 0x%02x\n"},
//{0x01ab0004, "PMU3: F%dBCAx_B%d_D%d = 0x%02x\n"},
//{0x01ac0004, "PMU3: F%dBCBx_B%d_D%d = 0x%02x\n"},
{0x01ad0000, "PMU10: Entering context_switch_postamble\n"},
{0x01ae0003, "PMU10: context_switch_postamble is enabled for DIMM %d, RC0A=0x%x, RC3x=0x%x\n"},
{0x01af0000, "PMU10: Setting bcw fspace 0\n"},
{0x01b00001, "PMU10: Sending BC0A = 0x%x\n"},
{0x01b10001, "PMU10: Sending BC6x = 0x%x\n"},
{0x01b20001, "PMU10: Sending RC0A = 0x%x\n"},
{0x01b30001, "PMU10: Sending RC3x = 0x%x\n"},
{0x01b40001, "PMU10: Sending RC0A = 0x%x\n"},
{0x01b50001, "PMU1: enter_lp3: DEBUG: pstate = %d\n"},
{0x01b60001, "PMU1: enter_lp3: DEBUG: dfifreqxlat_pstate = %d\n"},
{0x01b70001, "PMU1: enter_lp3: DEBUG: pllbypass = %d\n"},
{0x01b80001, "PMU1: enter_lp3: DEBUG: forcecal = %d\n"},
{0x01b90001, "PMU1: enter_lp3: DEBUG: pllmaxrange = 0x%x\n"},
{0x01ba0001, "PMU1: enter_lp3: DEBUG: dacval_out = 0x%x\n"},
{0x01bb0001, "PMU1: enter_lp3: DEBUG: pllctrl3 = 0x%x\n"},
{0x01bc0000, "PMU3: Loading DRAM with BIOS supplied MR values and entering self refresh prior to exiting PMU code.\n"},
{0x01bd0002, "PMU4: Set PptCtlStatic for db %d to 0x%04x\n"},
{0x01be0002, "PMU3: Setting DataBuffer function space of dimmcs 0x%02x to %d\n"},
{0x01bf0003, "PMU4: Setting cs 0x%0x RCW FxRC%Xx = 0x%02x\n"},
{0x01c00003, "PMU4: Setting cs 0x%0x RCW FxRC%02X = 0x%02x\n"},
{0x01c10003, "PMU4: Setting cs 0x%0x space 1 RCW FxRC%Xx = 0x%02x\n"},
{0x01c20003, "PMU4: Setting cs 0x%0x space 1 RCW FxRC%02X = 0x%02x\n"},
{0x01c30004, "PMU4: Setting cs 0x%0x space %d RCW FxRC%Xx = 0x%02x\n"},
{0x01c40004, "PMU4: Setting cs 0x%0x space %d RCW FxRC%02X = 0x%02x\n"},
//{0x01c50001, "PMU1: DDR4 update Rd Pre Setting disable %d\n"},
//{0x01c60002, "PMU2: Setting BCW FxBC%Xx = 0x%02x\n"},
//{0x01c70002, "PMU2: Setting BCW BC%02X = 0x%02x\n"},
//{0x01c80002, "PMU2: Setting BCW PBA mode FxBC%Xx = 0x%02x\n"},
//{0x01c90002, "PMU2: Setting BCW PBA mode BC%02X = 0x%02x\n"},
{0x01ca0003, "PMU4: BCW value for dimm %d, fspace %d, addr 0x%04x\n"},
//{0x01cb0002, "PMU4: DB %d, value 0x%02x\n"},
//{0x01cc0000, "PMU6: WARNING MREP underflow, set to min value -2 coarse, 0 fine\n"},
//{0x01cd0004, "PMU6: LRDIMM Writing final data buffer fine delay value nib %2d, trainDly %3d, fineDly code %2d, new MREP fine %2d\n"},
//{0x01ce0003, "PMU6: LRDIMM Writing final data buffer fine delay value nib %2d, trainDly %3d, fineDly code %2d\n"},
//{0x01cf0003, "PMU6: LRDIMM Writing data buffer fine delay type %d nib %2d, code %2d\n"},
//{0x01d00002, "PMU6: Writing final data buffer coarse delay value dbyte %2d, coarse = 0x%02x\n"},
//{0x01d10003, "PMU4: data 0x%04x at MB addr 0x%016lx saved at CSR addr 0x%08x\n"},
//{0x01d20003, "PMU4: data 0x%04x at MB addr 0x%08x saved at CSR addr 0x%08x\n"},
//{0x01d30003, "PMU4: data 0x%04x at MB addr 0x%016lx restored from CSR addr 0x%08x\n"},
//{0x01d40003, "PMU4: data 0x%04x at MB addr 0x%08x restored from CSR addr 0x%08x\n"},
//{0x01d50003, "PMU4: data 0x%04x at MB addr 0x%016lx saved at CSR addr 0x%08x\n"},
//{0x01d60003, "PMU4: data 0x%04x at MB addr 0x%08x saved at CSR addr 0x%08x\n"},
//{0x01d70003, "PMU4: data 0x%04x at MB addr 0x%016lx restored from CSR addr 0x%08x\n"},
//{0x01d80003, "PMU4: data 0x%04x at MB addr 0x%08x restored from CSR addr 0x%08x\n"},
//{0x01d90001, "PMU3: Update BC00, BC01, BC02 for rank-dimm 0x%02x\n"},
//{0x01da0000, "PMU3: Writing D4 RDIMM RCD Control words F0RC00 -> F0RC0F\n"},
//{0x01db0000, "PMU3: Disable parity in F0RC0E\n"},
//{0x01dc0000, "PMU3: Writing D4 RDIMM RCD Control words F0RC1x -> F0RCBx\n"},
//{0x01dd0000, "PMU3: Writing D4 RDIMM RCD Control words F1RC00 -> F1RC05\n"},
//{0x01de0000, "PMU3: Writing D4 RDIMM RCD Control words F1RC1x -> F1RC9x\n"},
//{0x01df0000, "PMU3: Writing D4 RDIMM RCD Control words F2RC04\n"},
//{0x01e00000, "PMU3: Writing D4 RDIMM RCD Control words F2RC4x\n"},
//{0x01e10000, "PMU3: Writing D4 RDIMM RCD Control words F3RC08 -> F3RC0F\n"},
//{0x01e20000, "PMU3: Writing D4 RDIMM RCD Control words F3RC1x -> F3RCEx\n"},
//{0x01e30000, "PMU3: Writing D4 Data buffer Control words BC00 -> BC0E\n"},
//{0x01e40002, "PMU1: restoreAcsmFromAltCL Sending MR0 0x%x cl=%d\n"},
//{0x01e50001, "PMU1: PHY VREF @ (%d/1000)%% VDDQ\n"},
//{0x01e60002, "PMU1: initalizing phy vrefDacs to %d ExtVrefRange %x\n"},
//{0x01e70002, "PMU0: initalizing global vref to %d range %d\n"},
//{0x01e80000, "PMU: Error: start address of ACSM WR/RD activate sequence must be aligned on even acsm addr position\n"},
//{0x01e90000, "PMU1: loading 1D acsm sequence\n"},
//{0x01ea0000, "PMU: Error: start address of ACSM WR/RD program sequence must be aligned on even acsm addr position\n"},
//{0x01eb0002, "PMU3: %d memclocks @ %d to get half of 300ns\n"},
//{0x01ec0000, "PMU: Error: start address of ACSM DM sequence must be aligned on even acsm addr position\n"},
//{0x01ed0003, "PMU: Error: Firmware was not able to detect swizzle setting for TG%d Dbyte%d DQ%d\n"},
//{0x01ee0005, "PMU: Error: Wrong DqLnSelTg setting for TG%d Dbyte%d DQ%d: expected %d found %d\n"},
//{0x01ef0005, "PMU: Error: Wrong DqLnSelTg setting for TG%d Dbyte%d: DQ%d and DQ%d have the same value (%d)\n"},
//{0x01f00003, "PMU: Error: Firmware was not able to detect swizzle setting for TG%d Dbyte%d DQ%d\n"},
//{0x01f10001, "PMU5: DIMM%d <<KEY>> DIMM-DataBuffer nibble swapped\n"},
//{0x01f20000, "PMU5: -- db0  db1  db2  db3  db4  db5  db6  db7  db8  db9 --\n"},
//{0x01f3000a, "PMU5:    %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d\n"},
//{0x01f40001, "PMU5: DIMM%d <<KEY>> PHY-DataBuffer DqLnSelTg\n"},
//{0x01f50000, "PMU5:      -- db0  db1  db2  db3  db4  db5  db6  db7  db8  db9 --\n"},
//{0x01f6000b, "PMU5: [Dq%d]:   %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d\n"},
//{0x01f70001, "PMU5: TG%d <<KEY>> DataBuffer-DRAM DqLnSelTg\n"},
//{0x01f80000, "PMU5:      -- db0  db1  db2  db3  db4  db5  db6  db7  db8  db9 --\n"},
//{0x01f9000b, "PMU5: [Dq%d]:   %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d\n"},
//{0x01fa0000, "PMU: Error: internal error in d5_detect_dq_swizzle() cannot find unused mapping\n"},
{0x01fb0001, "PMU5: TG%d <<KEY>> PHY-DRAM DqLnSelTg\n"},
{0x01fc0000, "PMU5:      -- db0  db1  db2  db3  db4  db5  db6  db7  db8  db9 --\n"},
{0x01fd000b, "PMU5: [Dq%d]:   %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d   %2d\n"},
//{0x01fe0001, "PMU4: Skip setting initial device vrefDQ for NVDIMM CS%d\n"},
//{0x01ff0002, "PMU4: Setting initial device vrefDQ for CS%d to MR6 = 0x%04x\n"},
//{0x02000001, "PMU3: DDR5 infinite preamble enter/exit %d\n"},
//{0x02010000, "PMU: Error: start address of ACSM WL sequence must be aligned on even acsm addr position\n"},
{0x02020000, "PMU4: WL normalized pos   : ........................|........................\n"},
{0x02030007, "PMU4: WL margin for nib %2d: %08x%08x%08x%08x%08x%08x\n"},
{0x02040000, "PMU4: WL normalized pos   : ........................|........................\n"},
{0x02050000, "PMU3: Fine write leveling hardware search increasing TxDqsDly until full bursts are seen\n"},
{0x02060002, "PMU4: ext_WL delay for nib %d is %d\n"},
{0x02070000, "PMU4: Extracting external WL margins:\n"},
//{0x02080000, "PMU3: DWL software search increasing MDQS delay until full bursts are seen\n"},
//{0x02090001, "PMU4: Search DWL Coarse Delay = 0x%x\n"},
//{0x020a0001, "PMU3: Search DWL Fine Delay = %d\n"},
//{0x020b0003, "PMU3: Errcnt for DWL nib %2d delay = %2d is %d\n"},
//{0x020c0002, "PMU3: DWL nibble %d sampled a 1 at data buffer delay %d\n"},
//{0x020d0003, "PMU4: DWL nibble %d saw a 0 to 1 transition at data buffer delay coarse %d fine %d\n"},
//{0x020e0001, "PMU: Error: Failed DWL for nib %d\n"},
//{0x020f0001, "PMU4: external DWL nibble %d assume delay fine 0 coarse 0\n"},
//{0x02100001, "PMU4: Decrement ext_WL trained delays by WL_ADJ_START %d\n"},
//{0x02110002, "PMU: Error: nib %d external WL %d underflow\n"},
//{0x02120002, "PMU4: Adjusted ext_WL delay for nib %d is %d\n"},
//{0x02130000, "PMU: Error: internal DWL error ACSM sequences overlap\n"},
//{0x02140002, "PMU4: internal write leveling search for nib %d with MR3_ICA %d\n"},
//{0x02150002, "PMU3: DWL nibble %d sampled a 0 at data buffer delay %d\n"},
//{0x02160003, "PMU4: internal write leveling converge for nib %d with MR3_ICA %d and dly %d\n"},
//{0x02170000, "PMU: Error: Some nibble didn't converge during internal WL\n"},
//{0x02180001, "PMU4: Increment int_WL trained delays by WL_ADJ_END %d\n"},
//{0x02190002, "PMU: Error: nib %d internal WL %d overflow\n"},
//{0x021a0002, "PMU4: Adjusted int_WL delay for nib %d is %d\n"},
//{0x021b0001, "PMU4: Decrement ext_WL trained delays by WL_ADJ_START %d\n"},
//{0x021c0001, "PMU4: But to prevent potential underflow also increment by %d\n"},
//{0x021d0003, "PMU4: Fault Tolerance: rank %d nib %d external WL %d underflow, this nibble is now disable\n"},
//{0x021e0001, "PMU4: Fault Tolerance: for non x4, need to disable also nib %d\n"},
//{0x021f0002, "PMU: Error: nib %d external WL %d underflow\n"},
//{0x02200003, "PMU4: Fault Tolerance: rank %d nib %d external WL %d overflow, this nibble is now disable\n"},
//{0x02210001, "PMU4: Fault Tolerance: for non x4, need to disable also nib %d\n"},
//{0x02220002, "PMU: Error: nib %d external WL %d overflow\n"},
//{0x02230002, "PMU4: Adjusted ext_WL delay for nib %d is %d\n"},
//{0x02240002, "PMU3: internal write leveling search for nib %d with MR3_ICA %d\n"},
//{0x02250003, "PMU4: internal write leveling converge for nib %d with MR3_ICA %d and dly %d\n"},
//{0x02260002, "PMU4: Fault Tolerance: rank %d nib %d didn't converge during internal WL, this nibble is now disable\n"},
//{0x02270001, "PMU4: Fault Tolerance: for non x4, need to disable also nib %d\n"},
//{0x02280000, "PMU: Error: Some nibble didn't converge during internal WL\n"},
//{0x02290000, "PMU4: Extracting internal WL margins:\n"},
{0x022a0001, "PMU4: Increment int_WL trained delays by WL_ADJ_END %d\n"},
//{0x022b0003, "PMU4: Fault Tolerance: rank %d nib %d internal WL %d out-of-range, this nibble is now disable\n"},
//{0x022c0001, "PMU4: Fault Tolerance: for non x4, need to disable also nib %d\n"},
//{0x022d0002, "PMU: Error: nib %d internal WL %d overflow\n"},
//{0x022e0002, "PMU: Error: nib %d internal WL %d underflow\n"},
{0x022f0002, "PMU4: Adjusted int_WL delay for nib %d is %d\n"},
//{0x02300003, "PMU1: In d5_write_level() csn=%d dimm=%d pstate=%d\n"},
//{0x02310004, "PMU1: In d5_write_level() csn=%d dimm=%d pstate=%d\n"},
{0x02320001, "PMU4: Increment WL trained delays by WL_ADJ %d\n"},
//{0x02330002, "PMU: Error: nib %d external WL %d overflow\n"},
//{0x02340002, "PMU: Error: nib %d external WL %d underflow\n"},
//{0x02350003, "PMU4: Fault Tolerance: rank %d nib %d external WL %d underflow/overflow, this nibble is now disable\n"},
//{0x02360002, "PMU: Error: nib %d external WL %d overflow\n"},
//{0x02370002, "PMU: Error: nib %d external WL %d underflow\n"},
//{0x02380002, "PMU3: Adjusted WL delay for nib %d is %d\n"},
//{0x02390000, "PMU3: Exiting write leveling mode\n"},
//{0x023a0001, "PMU5: DWL CS%d RCWE1 RCWE8 RCWE9\n"},
//{0x023b0004, "PMU5: DB%d     0x%02x  0x%02x  0x%02x\n"},
//{0x023c0004, "PMU1: In write_level_fine() csn=%d dimm=%d pstate=%d\n"},
{0x023d0000, "PMU3: Fine write leveling hardware search increasing TxDqsDly until full bursts are seen\n"},
//{0x023e0000, "PMU4: WL normalized pos   : ........................|........................\n"},
//{0x023f0007, "PMU4: WL margin for nib %2d: %08x%08x%08x%08x%08x%08x\n"},
//{0x02400000, "PMU4: WL normalized pos   : ........................|........................\n"},
//{0x02410000, "PMU3: Exiting write leveling mode\n"},
//{0x02420001, "PMU3: got %d for cl in load_wrlvl_acsm\n"},
//{0x02430003, "PMU3: In write_level_coarse() csn=%d tg=%d pstate=%d\n"},
//{0x02440003, "PMU3: left eye edge search db:%d ln:%d dly:0x%x\n"},
//{0x02450003, "PMU3: right eye edge search db: %d ln: %d dly: 0x%x\n"},
//{0x02460004, "PMU3: eye center db: %d ln: %d dly: 0x%x (maxdq: 0x%x)\n"},
{0x02470003, "PMU3: Wrote to TxDqDly db: %d ln: %d dly: 0x%x\n"},
{0x02480003, "PMU3: Wrote to TxDqDly db: %d ln: %d dly: 0x%x\n"},
{0x02490002, "PMU3: Coarse write leveling nibble%2d is still failing for TxDqsDly=0x%04x\n"},
{0x024a0002, "PMU4: Fault Tolerance: rank %d nib %d TxDqsDly overflow, this nibble is now disable\n"},
//{0x024b0002, "PMU4: Coarse write leveling iteration %d saw %d data miscompares across the entire phy\n"},
//{0x024c0002, "PMU4: Fault Tolerance: rank %d nib %d did not converge, this nibble is now disable\n"},
//{0x024d0000, "PMU: Error: Failed write leveling coarse\n"},
//{0x024e0000, "PMU4: WL normalized pos   : ................................|................................\n"},
//{0x024f0009, "PMU4: WL margin for nib %2d: %08x%08x%08x%08x%08x%08x%08x%08x\n"},
//{0x02500000, "PMU4: WL normalized pos   : ................................|................................\n"},
//{0x02510001, "PMU8: Adjust margin after WL coarse to be larger than %d\n"},
//{0x02520001, "PMU: Error: All margin after write leveling coarse are smaller than minMargin %d\n"},
{0x02530002, "PMU8: Decrement nib %d TxDqsDly by %d fine step\n"},
//{0x02540001, "PMU3: DWL delay = %d\n"},
//{0x02550003, "PMU3: Errcnt for DWL nib %2d delay = %2d is %d\n"},
//{0x02560002, "PMU3: DWL nibble %d sampled a 1 at delay %d\n"},
//{0x02570003, "PMU3: DWL nibble %d passed at delay %d. Rising edge was at %d\n"},
//{0x02580000, "PMU2: DWL did nto find a rising edge of memclk for all nibbles. Failing nibbles assumed to have rising edge close to fine delay 63\n"},
//{0x02590002, "PMU2:  Rising edge found in alias window, setting wrlvlDly for nibble %d = %d\n"},
//{0x025a0002, "PMU: Error: Failed DWL for nib %d with %d one\n"},
//{0x025b0003, "PMU2:  Rising edge not found in alias window with %d one, leaving wrlvlDly for nibble %d = %d\n"},
{0x04000000, "PMU: ***** Assertion Error - terminating *****\n"},
//{0x04010003, "PMU3: get_cmd_dly max(%d ps, %d memclk) = %d\n"},
//{0x04020002, "PMU0: Write CSR 0x%06x 0x%04x\n"},
//{0x04030002, "PMU0: hwt_init_ppgc_prbs(): Polynomial: %x, Deg: %d\n"},
//{0x04040005, "PMU1: acsm_addr %02x, AcsmSeq0/1/2/3 %04x %04x %04x %04x\n"},
//{0x04050005, "PMU1: acsm_addr %02x, AcsmSeq0/1/2/3 %04x %04x %04x %04x\n"},
//{0x04060004, "PMU1: acsm_set_delay_cmd %02x, cmd_dly %d cmd_rcnt %d chan1Nmode %d\n"},
//{0x04070003, "PMU1: acsm_set_long_nop_cmd: %02x, ddr_cs 0x%02x cmd_rcnt %d\n"},
//{0x04080004, "PMU1: acsm_set_multicycle_cmd %02x, ddr_cmd %d ddr_addr 0x%04x ddr_cs 0x%02x\n"},
//{0x04090008, "PMU1: acsm_set_cmd %02x, acsm_flgs 0x%08x ddr_cmd %d cmd_dly %d ddr_addr 0x%04x ddr_bnk %d ddr_cs 0x%02x ddr_rcnt %d\n"},
//{0x040a0001, "PMU: Error: acsm_set_cmd to non existant instruction adddress %d\n"},
//{0x040b0001, "PMU: Error: acsm_set_cmd with unknown ddr cmd 0x%x\n"},
//{0x040c000c, "PMU1: acsm_addr %02x, acsm_flgs %04x, ddr_cmd %02x, cmd_dly %02x, ddr_addr %04x, ddr_bnk %02x, ddr_cs %02x, cmd_rcnt %02x, AcsmSeq0/1/2/3 %04x %04x %04x %04x\n"},
//{0x040d0000, "PMU: Error - acsm_set_lptr() invoked with wrong ptr value...\n"},
//{0x040e0000, "PMU: Error - acsm_set_eptr() invoked with wrong ptr value...\n"},
//{0x040f0000, "PMU: Error: Polling on ACSM done failed to complete in acsm_poll_done()...\n"},
//{0x04100000, "PMU1: acsm RUN\n"},
//{0x04110000, "PMU1: acsm STOPPED\n"},
//{0x04120000, "PMU1: acsm STOPPED\n"},
//{0x04130002, "PMU1: acsm_init: acsm_mode %04x mxrdlat %04x\n"},
//{0x04140004, "PMU: Error: setAcsmCLCWL: cl and cwl must be each >= %d, and %d, resp. CL=%d CWL=%d\n"},
//{0x04150002, "PMU: Error: setAcsmCLCWL: cl and cwl must be each >= 5. CL=%d CWL=%d\n"},
//{0x04160002, "PMU1: setAcsmCLCWL: CASL %04d WCASL %04d\n"},
//{0x04170001, "PMU: Error: Reserved value of register F0RC0F found in message block: 0x%04x\n"},
//{0x04180001, "PMU3: Written MRS to CS=0x%02x\n"},
//{0x04190001, "PMU3: Written MRS to CS=0x%02x\n"},
//{0x041a0002, "PMU2: Use PDA mode to set MR%d with value 0x%02x\n"},
//{0x041b0001, "PMU3: Written Vref with PDA to CS=0x%02x\n"},
//{0x041c0001, "PMU2: Use PDA mode to send MPC command 0x%02x\n"},
//{0x041d0001, "PMU2: Use PDA mode to send MPC command 0x%02x\n"},
//{0x041e0001, "PMU3: Complete PDA enumerate to CS=0x%02x\n"},
//{0x041f0005, "PMU3: Set PDA select ID %d on chan %d rank %d for MRW 0x%02x to MR%d\n"},
//{0x04200001, "PMU4: Complete PBA enumerate to dimm=%d\n"},
//{0x04210001, "PMU1: lock_pll_dll: DEBUG: pstate = %d\n"},
//{0x04220001, "PMU1: lock_pll_dll: DEBUG: dfifreqxlat_pstate = %d\n"},
//{0x04230001, "PMU1: lock_pll_dll: DEBUG: pllbypass = %d\n"},
//{0x04240001, "PMU3: SaveLcdlSeed: Saving seed %d\n"},
//{0x04250000, "PMU1: in phy_defaults()\n"},
//{0x04260003, "PMU3: ACXConf:%d MaxNumDbytes:%d NumDfi:%d\n"},
//{0x04270005, "PMU1: setAltAcsmCLCWL setting cl=%d cwl=%d\n"},
};

void dwc_decode_streaming_message(void)
{
	uint32_t str, msg, msg2, count, i;

	dwc_get_mailbox(1, &msg);

	if (msg != 0x1020001 && msg != 0xf90001)
		printf("\n%s 0x%x\n", __func__, msg);

	str = (msg & 0xffff0000) >> 16;
	count = msg & 0xffff;

	for (i = 0; i < ARRAY_SIZE(dwc_ddr5_msg); i++) {
		if (msg == dwc_ddr5_msg[i].id)
			break;
	}

	if (msg != 0x1020001 && msg != 0xf90001) {
		if (i < ARRAY_SIZE(dwc_ddr5_msg))
			printf("%s, ", dwc_ddr5_msg[i].desc);
	}

	for (i = 0; i < count; i++) {
		dwc_get_mailbox(1, &msg2);
		if (msg != 0x1020001 && msg != 0xf90001)
			printf(" 0x%x", msg2 & 0xffff);
		else
			printf("%x", msg2 & 0xffff);
	}

	if (msg != 0x1020001 && msg != 0xf90001)
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
	int type;
	int ret = 0;

	LOG_DBG("%s %d\n", __func__, train2D);

	type = is_ddr4();

//	if (is_recovery()) {
//		aspeed_spl_ddr_image_ymodem_load(dwc_train, type,
//						 1, train2D);
//		memcpy((void *)(DRAMC_PHY_BASE + 2 * imem_base),
//		       (void *)dwc_train[type][train2D].imem_base,
//		       dwc_train[type][train2D].imem_len);
//		return ret;
//	}

	soc_fmc_obj.stor_copy((uint32_t *)(DRAMC_PHY_BASE + 2 * imem_base),
		  dwc_train[type][train2D].imem_base,
		  dwc_train[type][train2D].imem_len);

	return ret;
}

int dwc_ddrphy_phyinit_userCustom_F_loadDMEM(const int pState, const int train2D)
{
	uint32_t dmem_base = DWC_PHY_DMEM_OFFSET;
	int type;
	int ret = 0;

	LOG_DBG("%s %d\n", __func__, train2D);

	type = is_ddr4();

//	if (is_recovery()) {
//		aspeed_spl_ddr_image_ymodem_load(dwc_train, type,
//						 0, train2D);
//		memcpy((void *)(DRAMC_PHY_BASE + 2 * dmem_base),
//		       (void *)dwc_train[type][train2D].dmem_base,
//		       dwc_train[type][train2D].dmem_len);
//		return ret;
//	}

	soc_fmc_obj.stor_copy((uint32_t *)(DRAMC_PHY_BASE + 2 * dmem_base),
		  dwc_train[type][train2D].dmem_base,
		  dwc_train[type][train2D].dmem_len);

	return ret;
}

void dwc_phy_init(struct sdramc *sdramc)
{
	uint32_t imem_start = 0, dmem_start = 0, imem_2d_start = 0, dmem_2d_start = 0;
	uint32_t imem_len = 0, dmem_len = 0, imem_2d_len = 0, dmem_2d_len = 0;
	uint32_t ddr5_imem = 0, ddr5_imem_len = 0, ddr5_dmem = 0, ddr5_dmem_len = 0;

	fmc_hdr_get_prebuilt(PBT_DDR4_PMU_TRAIN_IMEM, &imem_start, &imem_len, NULL);
	fmc_hdr_get_prebuilt(PBT_DDR4_PMU_TRAIN_DMEM, &dmem_start, &dmem_len, NULL);
	fmc_hdr_get_prebuilt(PBT_DDR4_2D_PMU_TRAIN_IMEM, &imem_2d_start, &imem_2d_len, NULL);
	fmc_hdr_get_prebuilt(PBT_DDR4_2D_PMU_TRAIN_DMEM, &dmem_2d_start, &dmem_2d_len, NULL);
	fmc_hdr_get_prebuilt(PBT_DDR5_PMU_TRAIN_IMEM, &ddr5_imem, &ddr5_imem_len, NULL);
	fmc_hdr_get_prebuilt(PBT_DDR5_PMU_TRAIN_DMEM, &ddr5_dmem, &ddr5_dmem_len, NULL);

	LOG_DBG("%s: imem_start=0x%x, imem_len=0x%x\n", __func__, imem_start, imem_len);
	LOG_DBG("%s: dmem_start=0x%x, dmem_len=0x%x\n", __func__, dmem_start, dmem_len);
	LOG_DBG("%s: imem_2d_start=0x%x, imem_2d_len=0x%x\n", __func__, imem_2d_start, imem_2d_len);
	LOG_DBG("%s: dmem_2d_start=0x%x, dmem_2d_len=0x%x\n", __func__, dmem_2d_start, dmem_2d_len);
	LOG_DBG("%s: ddr5_imem=0x%x, ddr5_imem_len=0x%x\n", __func__, ddr5_imem, ddr5_imem_len);
	LOG_DBG("%s: ddr5_dmem=0x%x, ddr5_dmem_len=0x%x\n", __func__, ddr5_dmem, ddr5_dmem_len);

	// ddr5
	dwc_train[0][0].imem_base = ddr5_imem;
	dwc_train[0][0].imem_len = ddr5_imem_len;
	dwc_train[0][0].dmem_base = ddr5_dmem;
	dwc_train[0][0].dmem_len = ddr5_dmem_len;

	// ddr4 1d
	dwc_train[1][0].imem_base = imem_start;
	dwc_train[1][0].imem_len = imem_len;
	dwc_train[1][0].dmem_base = dmem_start;
	dwc_train[1][0].dmem_len = dmem_len;

	// ddr4 2d
	dwc_train[1][1].imem_base = imem_2d_start;
	dwc_train[1][1].imem_len = imem_2d_len;
	dwc_train[1][1].dmem_base = dmem_2d_start;
	dwc_train[1][1].dmem_len = dmem_2d_len;

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
