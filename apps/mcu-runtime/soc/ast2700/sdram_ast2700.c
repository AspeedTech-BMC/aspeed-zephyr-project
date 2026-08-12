/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/sys/util.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>
#include <zephyr/dt-bindings/memory-controller/ast27xx-mpu.h>
#include <sdram_ast2700.h>

#define LOG_MODULE_NAME	sdram_ast2700
LOG_MODULE_REGISTER(LOG_MODULE_NAME, CONFIG_SOC_FMC_LOG_LEVEL);

#define SDRAMMC_NODE DT_NODELABEL(sdrammc)

#define SDRAMC_AES_ENABLED		DT_PROP(SDRAMMC_NODE, aes_enable)

#if SDRAMC_AES_ENABLED
#define TRNG_NODE DT_CHOSEN(zephyr_entropy)

BUILD_ASSERT(DT_NODE_HAS_COMPAT(TRNG_NODE, aspeed_hwrng),
	     "DRAM AES key source must be the ASPEED hardware TRNG");
#endif

#define DRAMC_UNLOCK_KEY		0x1688a8a8
#define DRAMC_HARD_LOCK_KEY		0xdeaddead
#define DRAMC_VIDEO_UNLOCK_KEY		0x00440003

#define SCU_IO_HWSTRAP1			(SCU1_REG + 0x010)
#define IO_HWSTRAP1_DRAM_TYPE		BIT(10)
#define SCU_IO_MCU0_CTRL		(SCU1_REG + 0x110)
#define SCU_MCU0_MAP1_MASK		GENMASK(22, 16)
#define SCU_MCU0_MAP1_SHIFT		(16)

#define WDT_BASE			0x14c37000
#define WDTn_BASE(idx)			(WDT_BASE + (idx) * 0x80)
#define WDT_FOR_DRAM_SW_RESET_BASE	(WDTn_BASE(7))
#define WDT_SW_RESET_CTRL_REG		(WDT_FOR_DRAM_SW_RESET_BASE + 0x30)
#define WDT_SW_RESET_MASK_REG		(WDT_FOR_DRAM_SW_RESET_BASE + 0x34)
#define WDT_SW_RESET_DRAM_MASK		0x2
#define WDT_SW_RESET_KICK		0xaeedf123

/*
 * Given a maximum RFC value for biggest capacity,
 * it will be updated after dram size is determined later
 */

#define RFC 880

struct sdramc sdramc[1];

struct sdramc_ac_timing ac_table[] = {
	/* DDR4 1600 */
	{
		DRAM_TYPE_4,
		"DDR4 1600",
		10, 9, 8,
	/*     rcd, rp, ras, rrd, rrd_l, faw, rtp */
		10, 10, 28,  5,   6,	 28,  6,
		2,	/* t_wtr */
		6,	/* t_wtr_l */
		0,	/* t_wtr_a */
		12,	/* t_wtp */
		0,	/* t_rtw */
	/*	ccd_l, dllk, cksre, pd, xp, rfc */
		5, 597,  8,	4,  5,	RFC,
		24,	/* t_mrd */
		0,	/* t_refsbrd */
		0,	/* t_rfcsb */
		0,	/* t_cshsr */
		80,	/* zq */
	},
	/* DDR4 2400 */
	{
		DRAM_TYPE_4,
		"DDR4 2400",
		15, 12, 8,
	/*     rcd, rp, ras, rrd, rrd_l, faw, rtp */
		16, 16, 39, 7, 8, 37, 10,
		4,	/* t_wtr */
		10,	/* t_wtr_l */
		0,	/* t_wtr_a */
		19,	/* t_wtp */
		0,
	/*	ccd_l, dllk, cksre, pd, xp, rfc */
		7, 768,  13,	7,  8,	RFC,
		24,	/* t_mrd */
		0,	/* t_refsbrd */
		0,	/* t_rfcsb */
		0,	/* t_cshsr */
		80,	/* zq */
	},
	/* DDR4 3200 */
	{
		DRAM_TYPE_4,
		"DDR4 3200",
		22, 16, 8,
	/*     rcd, rp, ras, rrd, rrd_l, faw, rtp */
		22, 22, 52, 9, 11, 48, 12,
		4,	/* t_wtr */
		12,	/* t_wtr_l */
		0,	/* t_wtr_a */
		24,	/* t_wtp */
		0,	/* t_rtw */
	/*	ccd_l, dllk, cksre, pd, xp, rfc */
		8, 1023, 16,	8,  10, RFC,
		24,	/* t_mrd */
		0,	/* t_refsbrd */
		0,	/* t_rfcsb */
		0,	/* t_cshsr */
		80,	/* zq */
	},
	/* DDR5 3200 */
	{
		DRAM_TYPE_5,
		"DDR5 3200",
		26, 24, 16,
	/*     rcd, rp, ras, rrd, rrd_l, faw, rtp */
		26, 26, 52,  8,   8,	 40,  12,
		4,	/* t_wtr */
		16,	/* t_wtr_l */
		36,	/* t_wtr_a */
		48,	/* t_wtp */
		0,
	/*	ccd_l, dllk, cksre, pd, xp, rfc */
		8, 1024, 9,	13, 13, RFC,
		23,	/* t_mrd */
		48,	/* t_refsbrd */
		208,	/* t_rfcsb */
		30,	/* t_cshsr */
		48,	/* zq */
	},
};

#define DRAMC_INIT_DONE		BIT(6)
static bool is_ddr_initialized(struct sdramc *sdramc)
{
	struct sdramc_regs *regs = sdramc->regs;

	if (sys_read32((uint32_t)&regs->mctl) & DRAMC_MCTL_PHY_POWER_ON) {
		//printf("DDR has been initialized\n");
		return 1;
	}

	return 0;
}

bool is_fpga(void)
{
#ifdef CONFIG_ASPEED_FPGA
	sdramc->fpga = 1;
#ifdef CONFIG_ASPEED_HAPS
	sdramc->fpga = 0;
#endif
#else
	sdramc->fpga = 0;
#endif
	return sdramc->fpga;
}

bool is_ddr4(void)
{
#ifdef CONFIG_ASPEED_HAPS
	return 1;
#endif
	if (is_fpga())
		/* made fpga strap reverse */
		return ((sys_read32(SCU_IO_HWSTRAP1) & IO_HWSTRAP1_DRAM_TYPE) ? 0 : 1);
	else
		/* asic strap default 0 is ddr5, 1 is ddr4 */
		return ((sys_read32(SCU_IO_HWSTRAP1) & IO_HWSTRAP1_DRAM_TYPE) ? 1 : 0);
}

#define ACTIME1(ccd, rrd_l, rrd, mrd)	\
	(((ccd) << 24) | (((rrd_l) >> 1) << 16) | (((rrd) >> 1) << 8) | ((mrd) >> 1))

#define ACTIME2(faw, rp, ras, rcd)	\
	((((faw) >> 1) << 24) | (((rp) >> 1) << 16) | (((ras) >> 1) << 8) | ((rcd) >> 1))

#define ACTIME3(wtr, rtw, wtp, rtp)	\
	((((wtr) >> 1) << 24) | \
	(((rtw) >> 1) << 16) | \
	(((wtp) >> 1) << 8) | \
	((rtp) >> 1))

#define ACTIME4(wtr_a, wtr_l)		\
	((((wtr_a) >> 1) << 8) | ((wtr_l) >> 1))

#define ACTIME5(refsbrd, rfcsb, rfc)	\
	((((refsbrd) >> 1) << 20) | (((rfcsb) >> 1) << 10) | ((rfc) >> 1))

#define ACTIME6(cshsr, pd, xp, cksre)	\
	((((cshsr) >> 1) << 24) | (((pd) >> 1) << 16) | (((xp) >> 1) << 8) | ((cksre) >> 1))

#define ACTIME7(zqcs, dllk)	\
	((((zqcs) >> 1) << 10) | ((dllk) >> 1))

static void sdramc_configure_ac_timing(struct sdramc *sdramc, struct sdramc_ac_timing *ac)
{
	struct sdramc_regs *regs = sdramc->regs;

	sys_write32(ACTIME1(ac->t_ccd_l, ac->t_rrd_l, ac->t_rrd, ac->t_mrd),
	       (uint32_t)&regs->actime1);
	sys_write32(ACTIME2(ac->t_faw, ac->t_rp, ac->t_ras, ac->t_rcd),
	       (uint32_t)&regs->actime2);
	sys_write32(ACTIME3(ac->t_cwl + ac->t_bl / 2 + ac->t_wtr,
		       ac->t_cl - ac->t_cwl + (ac->t_bl / 2) + 2,
		       ac->t_cwl + ac->t_bl / 2 + ac->t_wtp,
		       ac->t_rtp),
	       (uint32_t)&regs->actime3);
	sys_write32(ACTIME4(ac->t_cwl + ac->t_bl / 2 + ac->t_wtr_a,
		       ac->t_cwl + ac->t_bl / 2 + ac->t_wtr_l),
	       (uint32_t)&regs->actime4);
	sys_write32(ACTIME5(ac->t_refsbrd, ac->t_rfcsb, ac->t_rfc),
	       (uint32_t)&regs->actime5);
	sys_write32(ACTIME6(ac->t_cshsr, ac->t_pd, ac->t_xp, ac->t_cksre), (uint32_t)&regs->actime6);
	sys_write32(ACTIME7(ac->t_zq, ac->t_dllk), (uint32_t)&regs->actime7);
}

static void sdramc_configure_register(struct sdramc *sdramc, struct sdramc_ac_timing *ac)
{
	struct sdramc_regs *regs = sdramc->regs;

	uint32_t dram_size = 5;
	uint32_t t_phy_wrdata;
	uint32_t t_phy_wrlat;
	uint32_t t_phy_rddata_en;
	uint32_t t_phy_odtlat;
	uint32_t t_phy_odtext;

	if (sdramc->fpga) {
		t_phy_wrlat = ac->t_cwl - 6;
		t_phy_rddata_en = ac->t_cl - 5;
		t_phy_wrdata = 1;
		t_phy_odtlat = 1;
		t_phy_odtext = 0;
	} else {
		if (ac->type == DRAM_TYPE_4) {
			t_phy_wrlat = ac->t_cwl - 5 - 4;
			t_phy_rddata_en = ac->t_cl - 5 - 4;
			t_phy_wrdata = 2;
			t_phy_odtlat = ac->t_cwl - 5 - 4;
			t_phy_odtext = 0;
		} else {
			t_phy_wrlat = ac->t_cwl - 13 - 3;
			t_phy_rddata_en = ac->t_cl - 13 - 3;
			t_phy_wrdata = 6;
			t_phy_odtlat = 0;
			t_phy_odtext = 0;
		}
	}

	sys_write32(0x20 + (dram_size << 2) + ac->type, (uint32_t)&regs->mcfg);

	/*
	 * [5:0], t_phy_wrlat, for cycles from WR command to write data enable.
	 * [8:6], t_phy_wrdata, for cycles from write data enable to write data.
	 * [9], reserved
	 * [15:10] t_phy_rddata_en, for cycles from RD command to read data enable.
	 * [19:16], t_phy_odtlat, for cycles from WR command to ODT signal control.
	 * [21:20], ODT signal extension control
	 * [22], ODT signal enable
	 * [23], ODT signal auto mode
	 */
	sys_write32((t_phy_odtext << 20) + (t_phy_odtlat << 16) + (t_phy_rddata_en << 10) + (t_phy_wrdata << 6) + t_phy_wrlat, (uint32_t)&regs->dfi_timing);
	sys_write32(0, (uint32_t)&regs->dctl);

	/*
	 * [31:24]: refresh felxibility time period
	 * [23:16]: refresh time interfal
	 * [15]   : refresh function disable
	 * [14:10]: reserved
	 * [9:6]  : refresh threshold
	 * [5]	  : refresh option
	 * [4]	  : auto MR command sending for mode change
	 * [3]	  : same bank refresh operation
	 * [2]	  : refresh rate selection
	 * [1]	  : refresh mode selection
	 * [0]	  : refresh mode update trigger
	 */
	sys_write32(0x40b48200, (uint32_t)&regs->refctl);

	/*
	 * [31:16]: ZQ calibration period
	 * [15:8] : ZQ latch time period
	 * [7]	  : ZQ control status
	 * [6:3]  : reserved
	 * [2]	  : ZQCL command enable
	 * [1]	  : ZQ calibration auto mode
	 */
	sys_write32(0x42aa1800, (uint32_t)&regs->zqctl);

	/*
	 * [31:14]: reserved
	 * [13:12]: selection of limited request number for page-hit request
	 * [11]   : enable control of limitation for page-hit request counter
	 * [10]   : arbiter read threshold limitation disable control
	 * [9]	  : arbiter write threshold limitation disable control
	 * [8:5]  : read access limit threshold selection
	 * [4]	  : read request limit threshold enable
	 * [3:1]  : write request limit threshold selection
	 * [0]	  : write request limit enable
	 */
	sys_write32(0, (uint32_t)&regs->arbctl);

	if (ac->type)
		sys_write32(0, (uint32_t)&regs->refmng_ctl);

	sys_write32(0xffffffff, (uint32_t)&regs->intr_mask);
}

static void sdramc_mr_send(struct sdramc *sdramc, uint32_t ctrl, uint32_t op)
{
	struct sdramc_regs *regs = sdramc->regs;

	sys_write32(op, (uint32_t)&regs->mrwr);
	sys_write32(ctrl | DRAMC_MRCTL_CMD_START, (uint32_t)&regs->mrctl);

	while (!(sys_read32((uint32_t)&regs->intr_status) & DRAMC_IRQSTA_MR_DONE))
		;

	sys_write32(DRAMC_IRQSTA_MR_DONE, (uint32_t)&regs->intr_clear);
}

static void sdramc_unlock(struct sdramc *sdramc)
{
	struct sdramc_regs *regs = sdramc->regs;

	sys_write32(DRAMC_UNLOCK_KEY, (uint32_t)&regs->prot_key);

	while (!sys_read32((uint32_t)&regs->prot_key))
		;
}

static void __unused sdramc_hard_lock(struct sdramc *sdramc)
{
	struct sdramc_regs *regs = sdramc->regs;

	sdramc_unlock(sdramc);

	sys_write32(DRAMC_HARD_LOCK_KEY, (uint32_t)&regs->prot_key);
}

static void sdramc_set_flag(uint32_t flag)
{
	uint32_t val;

	val = sys_read32(SCU_CPU_VGA0_SCRATCH);
	val |= flag;
	sys_write32(val, SCU_CPU_VGA0_SCRATCH);

	val = sys_read32(SCU_CPU_VGA1_SCRATCH);
	val |= flag;
	sys_write32(val, SCU_CPU_VGA1_SCRATCH);
}

static int sdramc_init(struct sdramc *sdramc, struct sdramc_ac_timing **ac)
{
	struct sdramc_ac_timing *tbl = ac_table;
	int speed;

	/* Detect dram type by a hw strap at IO SCU010 */
	if (is_ddr4()) {
		/* DDR4 type */
		if (IS_ENABLED(CONFIG_ASPEED_DDR_1600)) {
			speed = DDR4_1600;
		} else if (IS_ENABLED(CONFIG_ASPEED_DDR_2400)) {
			speed = DDR4_2400;
		} else if (IS_ENABLED(CONFIG_ASPEED_DDR_3200)) {
			speed = DDR4_3200;
		} else {
			printf("Speed %d is not supported!!!\n", speed);
			return 1;
		}
	} else {
		/* DDR5 type */
		speed = DDR5_3200;
	}

	LOG_DBG("%s is selected\n", tbl[speed].desc);

	/* Configure ac timing */
	sdramc_configure_ac_timing(sdramc, &tbl[speed]);

	/* Configure register */
	sdramc_configure_register(sdramc, &tbl[speed]);

	*ac = &tbl[speed];

	return 0;
}

static int sdramc_phy_init(struct sdramc *sdramc, struct sdramc_ac_timing *ac)
{
	int err = -1;

	/* initialize phy */
	if (sdramc->fpga)
		err = fpga_phy_init(sdramc);
	else
		err = dwc_phy_init(sdramc);

	return err;
}

static int sdramc_exit_self_refresh(struct sdramc *sdramc)
{
	struct sdramc_regs *regs = sdramc->regs;

	/* exit self-refresh after phy init */
	//setbits(le32, (uint32_t)&regs->mctl, DRAMC_MCTL_SELF_REF_START);
	sys_write32(sys_read32((uint32_t)&regs->mctl) | DRAMC_MCTL_SELF_REF_START, (uint32_t)&regs->mctl);

	/* query if self-ref done */
	while (!(sys_read32((uint32_t)&regs->intr_status) & DRAMC_IRQSTA_REF_DONE))
		;

	/* clear status */
	sys_write32(DRAMC_IRQSTA_REF_DONE, (uint32_t)&regs->intr_clear);

	//udelay(1);

	return 0;
}

static void sdramc_enable_refresh(struct sdramc *sdramc)
{
	struct sdramc_regs *regs = sdramc->regs;
	uint32_t tREFI;

	/* update tREFI */
	tREFI = (is_ddr4() ? 0xb4 : 0x5a);
	sys_write32((sys_read32((uint32_t)&regs->refctl) & ~0xff0000) | (tREFI << 16), (uint32_t)&regs->refctl);

	/* refresh update */
	//clrbits(le32, (uint32_t)&regs->refctl, 0x8000);
	sys_write32(sys_read32((uint32_t)&regs->refctl) & ~0x8000, (uint32_t)&regs->refctl);
}

static void sdramc_configure_mrs(struct sdramc *sdramc, struct sdramc_ac_timing *ac)
{
	struct sdramc_regs *regs = sdramc->regs;
	uint32_t mr0_cas = 0, mr0_rtp = 0, mr2_cwl = 0, mr6_tccd_l = 0;
	uint32_t mr0_val, mr1_val, mr2_val, mr3_val, mr4_val, mr5_val, mr6_val;

	if (ac->type == DRAM_TYPE_5)
		return;

	//-------------------------------------------------------------------
	// CAS Latency (Table-15)
	//-------------------------------------------------------------------
	switch (ac->t_cl) {
	case 9:
		mr0_cas = 0x00; //5'b00000;
		break;
	case 10:
		mr0_cas = 0x01; //5'b00001;
		break;
	case 11:
		mr0_cas = 0x02; //5'b00010;
		break;
	case 12:
		mr0_cas = 0x03; //5'b00011;
		break;
	case 13:
		mr0_cas = 0x04; //5'b00100;
		break;
	case 14:
		mr0_cas = 0x05; //5'b00101;
		break;
	case 15:
		mr0_cas = 0x06; //5'b00110;
		break;
	case 16:
		mr0_cas = 0x07; //5'b00111;
		break;
	case 18:
		mr0_cas = 0x08; //5'b01000;
		break;
	case 20:
		mr0_cas = 0x09; //5'b01001;
		break;
	case 22:
		mr0_cas = 0x0a; //5'b01010;
		break;
	case 24:
		mr0_cas = 0x0b; //5'b01011;
		break;
	case 23:
		mr0_cas = 0x0c; //5'b01100;
		break;
	case 17:
		mr0_cas = 0x0d; //5'b01101;
		break;
	case 19:
		mr0_cas = 0x0e; //5'b01110;
		break;
	case 21:
		mr0_cas = 0x0f; //5'b01111;
		break;
	case 25:
		mr0_cas = 0x10; //5'b10000;
		break;
	case 26:
		mr0_cas = 0x11; //5'b10001;
		break;
	case 27:
		mr0_cas = 0x12; //5'b10010;
		break;
	case 28:
		mr0_cas = 0x13; //5'b10011;
		break;
	case 30:
		mr0_cas = 0x15; //5'b10101;
		break;
	case 32:
		mr0_cas = 0x17; //5'b10111;
		break;
	}

	//-------------------------------------------------------------------
	// WR and RTP (Table-14)
	//-------------------------------------------------------------------
	switch (ac->t_rtp) {
	case 5:
		mr0_rtp = 0x0; //4'b0000;
		break;
	case 6:
		mr0_rtp = 0x1; //4'b0001;
		break;
	case 7:
		mr0_rtp = 0x2; //4'b0010;
		break;
	case 8:
		mr0_rtp = 0x3; //4'b0011;
		break;
	case 9:
		mr0_rtp = 0x4; //4'b0100;
		break;
	case 10:
		mr0_rtp = 0x5; //4'b0101;
		break;
	case 12:
		mr0_rtp = 0x6; //4'b0110;
		break;
	case 11:
		mr0_rtp = 0x7; //4'b0111;
		break;
	case 13:
		mr0_rtp = 0x8; //4'b1000;
		break;
	}

	//-------------------------------------------------------------------
	// CAS Write Latency (Table-21)
	//-------------------------------------------------------------------
	switch (ac->t_cwl)  {
	case 9:
		mr2_cwl = 0x0; // 3'b000; // 1600
		break;
	case 10:
		mr2_cwl = 0x1; // 3'b001; // 1866
		break;
	case 11:
		mr2_cwl = 0x2; // 3'b010; // 2133
		break;
	case 12:
		mr2_cwl = 0x3; // 3'b011; // 2400
		break;
	case 14:
		mr2_cwl = 0x4; // 3'b100; // 2666
		break;
	case 16:
		mr2_cwl = 0x5; // 3'b101; // 2933/3200
		break;
	case 18:
		mr2_cwl = 0x6; // 3'b110;
		break;
	case 20:
		mr2_cwl = 0x7; // 3'b111;
		break;
	}

	//-------------------------------------------------------------------
	// tCCD_L and tDLLK
	//-------------------------------------------------------------------
	switch (ac->t_ccd_l) {
	case 4:
		mr6_tccd_l = 0x0; //3'b000;  // rate <= 1333
		break;
	case 5:
		mr6_tccd_l = 0x1; //3'b001;  // 1333 < rate <= 1866
		break;
	case 6:
		mr6_tccd_l = 0x2; //3'b010;  // 1866 < rate <= 2400
		break;
	case 7:
		mr6_tccd_l = 0x3; //3'b011;  // 2400 < rate <= 2666
		break;
	case 8:
		mr6_tccd_l = 0x4; //3'b100;  // 2666 < rate <= 3200
		break;
	}

	/*
	 * mr0_val = {
	 * mr0_rtp[3],		// 13
	 * mr0_cas[4],		// 12
	 * mr0_rtp[2:0],	// 13,11-9: WR and RTP
	 * 1'b0,		// 8: DLL reset
	 * 1'b0,		// 7: TM
	 * mr0_cas[3:1],	// 6-4,2: CAS latency
	 * 1'b0,		// 3: sequential
	 * mr0_cas[0],
	 * 2'b00		// 1-0: burst length
	 */
	mr0_val = ((mr0_cas & 0x1) << 2) | (((mr0_cas >> 1) & 0x7) << 4) | (((mr0_cas >> 4) & 0x1) << 12) |
		  ((mr0_rtp & 0x7) << 9) | (((mr0_rtp >> 3) & 0x1) << 13);

	/*
	 * 3'b2 //[10:8]: rtt_nom, 000:disable,001:rzq/4,010:rzq/2,011:rzq/6,100:rzq/1,101:rzq/5,110:rzq/3,111:rzq/7
	 * 1'b0 //[7]: write leveling enable
	 * 2'b0 //[6:5]: reserved
	 * 2'b0 //[4:3]: additive latency
	 * 2'b0 //[2:1]: output driver impedance
	 * 1'b1 //[0]: enable dll
	 */
	mr1_val = 0x201;

	/*
	 * [10:9]: rtt_wr, 00:dynamic odt off, 01:rzq/2, 10:rzq/1, 11: hi-z
	 * [8]: 0
	 */
	mr2_val = ((mr2_cwl & 0x7) << 3) | 0x200;

	mr3_val = 0;

	mr4_val = 0;

	/*
	 * mr5_val = {
	 * 1'b0,		// 13: RFU
	 * 1'b0,		// 12: read DBI
	 * 1'b0,		// 11: write DBI
	 * 1'b1,		// 10: Data mask
	 * 1'b0,		// 9: C/A parity persistent error
	 * 3'b000,		// 8-6: RTT_PARK (disable)
	 * 1'b1,		// 5: ODT input buffer during power down mode
	 * 1'b0,		// 4: C/A parity status
	 * 1'b0,		// 3: CRC error clear
	 * 3'b0			// 2-0: C/A parity latency mode
	 * };
	 */
	mr5_val = 0x420;

	/*
	 * mr6_val = {
	 * 1'b0,		// 13, 9-8: RFU
	 * mr6_tccd_l[2:0],	// 12-10: tCCD_L
	 * 2'b0,		// 13, 9-8: RFU
	 * 1'b0,		// 7: VrefDQ training enable
	 * 1'b0,		// 6: VrefDQ training range
	 * 6'b0			// 5-0: VrefDQ training value
	 * };
	 */
	mr6_val = ((mr6_tccd_l & 0x7) << 10);

	sys_write32((mr1_val << 16) + mr0_val, (uint32_t)&regs->mr01);
	sys_write32((mr3_val << 16) + mr2_val, (uint32_t)&regs->mr23);
	sys_write32((mr5_val << 16) + mr4_val, (uint32_t)&regs->mr45);
	sys_write32(mr6_val, (uint32_t)&regs->mr67);

	/* Power-up initialization sequence */
	sdramc_mr_send(sdramc, MR_ADDR(3), 0);
	sdramc_mr_send(sdramc, MR_ADDR(6), 0);
	sdramc_mr_send(sdramc, MR_ADDR(5), 0);
	sdramc_mr_send(sdramc, MR_ADDR(4), 0);
	sdramc_mr_send(sdramc, MR_ADDR(2), 0);
	sdramc_mr_send(sdramc, MR_ADDR(1), 0);
	sdramc_mr_send(sdramc, MR_ADDR(0), 0);
}

static int sdramc_bist(struct sdramc *sdramc, uint32_t addr, uint32_t size, uint32_t cfg, uint32_t timeout)
{
	struct sdramc_regs *regs = sdramc->regs;
	uint32_t val;

	sys_write32(0, (uint32_t)&regs->bistcfg);
	sys_write32(cfg, (uint32_t)&regs->bistcfg);
	sys_write32(addr >> 4, (uint32_t)&regs->bist_addr);
	sys_write32(size, (uint32_t)&regs->bist_size);
	sys_write32(0x89abcdef, (uint32_t)&regs->bist_patt);

	/* Start BIST */
	sys_write32(cfg | DRAMC_BISTCFG_START, (uint32_t)&regs->bistcfg);

	/* Wait for BIST done or timeout */
	while (!(sys_read32((uint32_t)&regs->intr_status) &
		 DRAMC_IRQSTA_BIST_DONE)) {
		if (!timeout--)
			return -ETIMEDOUT;

		k_busy_wait(1000); /* wait 1ms */
	}

	/* Clear BIST done interrupt */
	sys_write32(DRAMC_IRQSTA_BIST_DONE, (uint32_t)&regs->intr_clear);

	val = sys_read32((uint32_t)&regs->bist_res);

	/* Check BIST result */
	if (!(val & DRAMC_BISTRES_DONE))
		return -EIO;

	if (val & DRAMC_BISTRES_FAIL)
		return -EIO;

	return 0;
}

#define DRAMC_ENCCFG_REG_LOCK		BIT(31)
#define DRAMC_ENCCFG_EN			BIT(0)

#if SDRAMC_AES_ENABLED
static int sdramc_write_random(const struct device *trng, volatile uint32_t *dst, int cnt)
{
	uint32_t val;
	int err;

	for (int i = 0; i < cnt; i++) {
		err = entropy_get_entropy(trng, (uint8_t *)&val, sizeof(val));
		if (err)
			return err;

		sys_write32(val, (uint32_t)&dst[i]);
	}

	return 0;
}
#endif

static int sdramc_aes_enable(struct sdramc *sdramc)
{
#if SDRAMC_AES_ENABLED
	const struct device *trng = DEVICE_DT_GET(TRNG_NODE);
	struct sdramc_regs *regs = sdramc->regs;
	int err;

	if (!device_is_ready(trng)) {
		printf("aes: TRNG is not ready\n");
		return -ENODEV;
	}

	/*
	 * One-time random key and IV, generated by and kept in hardware only.
	 * DRAM content does not survive a reboot by design.
	 */
	err = sdramc_write_random(trng, regs->enc_key, ARRAY_SIZE(regs->enc_key));
	if (!err)
		err = sdramc_write_random(trng, regs->enc_iv, ARRAY_SIZE(regs->enc_iv));
	if (err) {
		printf("aes: failed to generate key/iv, err=%d\n", err);
		return err;
	}

	/* enc_min/max_addr are in 16-byte units */
	sys_write32(0, (uint32_t)&regs->enc_min_addr);
	sys_write32((uint32_t)sdramc->aes_size, (uint32_t)&regs->enc_max_addr);
	sys_write32(DRAMC_ENCCFG_EN, (uint32_t)&regs->enccfg);
#endif
	return 0;
}

static void __unused sdramc_aes_lock(struct sdramc *sdramc)
{
#if SDRAMC_AES_ENABLED
	struct sdramc_regs *regs = sdramc->regs;

	sys_write32(DRAMC_ENCCFG_REG_LOCK | DRAMC_ENCCFG_EN, (uint32_t)&regs->enccfg);
#endif
}

/* VRAM access for cursor & VGA */
static uint32_t ast_vga_get_gfm_ctrl(uint8_t node)
{
	if (node == 1)
		return (BIT(19) | BIT(28));
	return (BIT(10) | BIT(27));
}

static void sdramc_setup_vga_access(struct sdramc *sdramc)
{
	struct sdramc_regs *regs = sdramc->regs;

	regs->gfm0ctl = ast_vga_get_gfm_ctrl(0);
	regs->gfm1ctl = ast_vga_get_gfm_ctrl(1);
}

static int sdramc_get_vga_mem_size(struct sdramc *sdramc)
{
	struct ast_chip *chip = sdramc->chip;
	struct sdramc_regs *regs = sdramc->regs;
	uint8_t node0 = chip->pcie0_enable;
	uint8_t node1 = chip->pcie1_enable;
	uint32_t efuse;
	uint32_t vga_ram_size[] = {
	        0x2000000, // 32MB
		0x4000000, // 64MB
	};
	int vga_sz_sel;
	int vga_cnt;

	efuse = chip->efuse;
	vga_sz_sel = sys_read32((uint32_t)&regs->gfmcfg) & 0x1;

	/*
	 * Decide feature by efuse
	 *  0: 2750 has full function
	 *  1: 2700 has only 1 VGA
	 *  2: 2720 has no VGA
	 */
	switch (efuse) {

	case 0:
		vga_cnt = node0 + node1;
		break;
	case 1:
		vga_cnt = node0;
		break;
	case 2:
		vga_cnt =  0;
		break;
	default:
		printf("Unknown efuse setting %x\n", efuse);
		return -1;
	};

	return vga_ram_size[vga_sz_sel] * vga_cnt;
}

/* offset 0x10 */
#define DRAMC_MCFG_ECC_EN			BIT(6)
#define DRAMC_MCFG_PGM_EN			BIT(5)
#define DRAM_SIZE_DEF	3

static const uint32_t ram_size_ary[] = {
	0x1000000, // 256MB
	0x2000000, // 512MB
	0x4000000, // 1GB
	0x8000000, // 2GB
	0x10000000, // 4GB
	0x20000000, // 8GB
};

static int sdramc_ecc_enable(struct sdramc *sdramc)
{
	uint32_t ecc_sz, ram_size;
	struct sdramc_regs *regs = sdramc->regs;
	uint32_t bistcfg;
	uint32_t val;
	int err;

	if (!sdramc->ecc_enable) {
		LOG_DBG("ECC is not enabled\n");
		return 0;
	}

	/* ram_size_ary values are in 16-byte units, as the BIST engine takes */
	ram_size = ram_size_ary[sdramc->sz];

	/* Initialize the whole dram so the ECC check bytes are consistent */
	bistcfg = DRAMC_BISTCFG_INIT_MODE | DRAMC_BISTCFG_ENABLE;
	err = sdramc_bist(sdramc, 0, ram_size, bistcfg, 5000);
	if (err) {
		printf("ecc bist failed, err=%d\n", err);
		return err;
	}

	/* ecc_addr_range is in 16-byte units */
	ecc_sz = (uint32_t)sdramc->ecc_size;

	sys_write32(ecc_sz, (uint32_t)&regs->ecc_addr_range);

	/* enable ecc, page matching should be disabled */
	val = sys_read32((uint32_t)&regs->mcfg);
	val &= ~(DRAMC_MCFG_PGM_EN);
	val |= (DRAMC_MCFG_ECC_EN);
	sys_write32(val, (uint32_t)&regs->mcfg);

	return 0;
}

struct ddr_capacity {
	size_t size;
	int rfc[2];
};

static int sdramc_size_detect(struct sdramc *sdramc)
{
	struct sdramc_regs *regs = sdramc->regs;
	struct ddr_capacity ram_size[] = {
		{0x40,	{208, 256}}, // 256MB
		{0x40,	{208, 416}}, // 512MB
		{0x40,	{208, 560}}, // 1GB
		{0x44,	{472, 880}}, // 2GB
		{0x48,	{656, 880}}, // 4GB
		{0x50,	{880, 880}}, // 8GB
		};
	uint64_t max_ecc_size;
	uint64_t available_size;
	uint32_t val;
	int vga_size;
	int sz, ddr4;
	uint32_t pattern = 0xdeadbeef;
	void *test_addr = (void *)0xc0000000;
	void *start_addr = (void *)0x80000000;

	/* Assume the mimimum dram size is 1GB, hence test starts from 2GB */
	for (sz = SDRAM_SIZE_2GB; sz < SDRAM_SIZE_MAX; sz++) {
		/* change mapping address for mcu0 upper 1G space */
		sys_write32((sys_read32((uint32_t)SCU_IO_MCU0_CTRL) & ~SCU_MCU0_MAP1_MASK)
		       | (ram_size[sz].size << SCU_MCU0_MAP1_SHIFT),
		       (uint32_t)SCU_IO_MCU0_CTRL);

		sys_read32((uint32_t)SCU_IO_MCU0_CTRL);

		/* test if pattern wrapped around */
		sys_write32(pattern, (uint32_t)test_addr);

		/* prevent RAW hazzard */
		k_busy_wait(10);

		/* if it is wrapped around, the size should be smaller one */
		if (sys_read32((uint32_t)start_addr) == pattern)
			break;

		pattern = pattern >> 4;
	}

	sz--;
	sdramc->sz = sz;

	/* re-configure ram size to dramc. */
	val = sys_read32((uint32_t)&regs->mcfg);
	val &= ~(0x7 << 2);

	sys_write32(val | (sz << 2), (uint32_t)&regs->mcfg);

	ddr4 = is_ddr4();

	/* update rfc in ac_timing5 register. */
	val = sys_read32((uint32_t)&regs->actime5);
	val &= ~(0x3ff);
	val |= (ram_size[sz].rfc[ddr4] >> 1);
	sys_write32(val, (uint32_t)&regs->actime5);

	vga_size = sdramc_get_vga_mem_size(sdramc);
	if (vga_size < 0)
		vga_size = 0;

	/*
	 * Resolve the ECC/AES coverage in bytes now that the dram size is
	 * known. ram_size_ary values are in 16-byte units.
	 * The ECC check bytes take 1/9 of the protected range, so the
	 * protectable data size is at most (dram - vga) * 8 / 9.
	 */
	available_size = ((uint64_t)ram_size_ary[sz]) - (vga_size >> 4);
	max_ecc_size = available_size * 8 / 9;

	if (sdramc->ecc_size == 0 || sdramc->ecc_size > max_ecc_size)
		sdramc->ecc_size = max_ecc_size;

	/* AES covers the data region: the ECC-protected range if ECC is on */
	if (sdramc->aes_size == 0)
		sdramc->aes_size = sdramc->ecc_enable ? sdramc->ecc_size : available_size;

	return 0;
}

struct mpu_attr {
        uint32_t attr;
        const char *str;
};

struct mpu_id {
        int id;
        const char *str;
        uint8_t ofst;
        uint32_t mask;
};

static int sdramc_init_mpu(struct sdramc *sdramc)
{
	struct sdramc_regs *regs = sdramc->regs;
	uint32_t val;
	int id, attr;
	int i;
	char *name;
	struct mpu_attr attr_info[] = {
		{S_READWRITE, "_rw"},
		{S_READONLY, "_ro"},
		{S_WRITEONLY, "_wo"},
		{NS_READWRITE, "_nrw"},
		{NS_READONLY, "_nro"},
		{NS_WRITEONLY, "_nwo"},
	};

	struct mpu_id id_info[] = {
		{MPU_ID_CA35,   "ca35", 0x00, BIT(4)},
		{MPU_ID_VE_HI,  "ve_hi", 0x10, BIT(0)},
		{MPU_ID_VE_LO,  "ve_lo", 0x10, BIT(1)},
		{MPU_ID_USB_A1, "usb_a1", 0x10, BIT(2)},
		{MPU_ID_USB_A2, "usb_a2", 0x10, BIT(3)},
		{MPU_ID_E2M,    "e2m", 0x10, BIT(4)},
		{MPU_ID_MCTP,   "mctp", 0x10, BIT(5)},
		{MPU_ID_H2M,    "h2m", 0x10, BIT(6)},
		{MPU_ID_HMAC,   "hmac", 0x10, BIT(7)},
		{MPU_ID_USB_B1, "usb_b1", 0x10, BIT(16)},
		{MPU_ID_USB_B2, "usb_b2", 0x10, BIT(17)},
		{MPU_ID_VGA1_CR, "vga1_cr", 0x10, BIT(18)},
		{MPU_ID_VGA1_LE, "vga1_le", 0x10, BIT(19)},
		{MPU_ID_TSP_INST, "tsp_i", 0x10, BIT(20)},
		{MPU_ID_VE,     "ve", 0x10, BIT(21)},
		{MPU_ID_MCTP8,  "mctp8", 0x10, BIT(22)},
		{MPU_ID_UHCI,   "uhci", 0x10, BIT(23)},
		{MPU_ID_USB3_A1, "usb3_a1", 0x14, BIT(0)},
		{MPU_ID_USB3_A2, "usb3_a2", 0x14, BIT(1)},
		{MPU_ID_SHA3,   "sha3", 0x14, BIT(2)},
		{MPU_ID_VGA2_CR, "vga2_cr", 0x14, BIT(3)},
		{MPU_ID_VGA2_LE, "vga2_le", 0x14, BIT(4)},
		{MPU_ID_TSP_DATA, "tsp_d", 0x14, BIT(5)},
		{MPU_ID_E2M1,   "e2m1", 0x14, BIT(6)},
		{MPU_ID_GFX,    "gfx", 0x14, BIT(7)},
		{MPU_ID_RVAS1,  "rvas1", 0x14, BIT(8)},
		{MPU_ID_RVAS2,  "rvas2", 0x14, BIT(9)},
		{MPU_ID_MHMAC,  "mhmac", 0x14, BIT(10)},
		{MPU_ID_M2D,    "m2d", 0x14, BIT(11)},
		{MPU_ID_M2D2,   "m2d2", 0x14, BIT(12)},
		{MPU_ID_SSP_INST, "ssp_i", 0x14, BIT(13)},
		{MPU_ID_SSP_DATA, "ssp_d", 0x14, BIT(14)},
		{MPU_ID_XDMA8,  "xdma8", 0x14, BIT(15)},
		{MPU_ID_XDMA,   "xdma", 0x14, BIT(16)},
		{MPU_ID_EMMC,   "emmc", 0x14, BIT(17)},
		{MPU_ID_SLIM,   "slim", 0x14, BIT(19)},
		{MPU_ID_USBH_A, "usbh_a", 0x14, BIT(24)},
		{MPU_ID_USBH_B, "usbh_b", 0x14, BIT(25)},
		{MPU_ID_UFS,    "ufs", 0x14, BIT(26)},
	};

	for (i = 0; i < sdramc->mpu_cnt; i++) {
		/* define mpu range */
		sys_write32(sdramc->mpu[i].start >> 4, (uint32_t)&regs->region[i].start);
		sys_write32((sdramc->mpu[i].end - 1) >> 4, (uint32_t)&regs->region[i].end);

		/* protect from all master by default */
		sys_write32(0x00000030, (uint32_t)&regs->region[i].ctrl);
		sys_write32(0xffffffff, (uint32_t)&regs->region[i].wr_master_0);
		sys_write32(0xffffffff, (uint32_t)&regs->region[i].wr_master_1);
		sys_write32(0xffffffff, (uint32_t)&regs->region[i].rd_master_0);
		sys_write32(0xffffffff, (uint32_t)&regs->region[i].rd_master_1);
		sys_write32(0x00000000, (uint32_t)&regs->region[i].wr_secure_0);
		sys_write32(0x00000000, (uint32_t)&regs->region[i].wr_secure_1);
		sys_write32(0x00000000, (uint32_t)&regs->region[i].rd_secure_0);
		sys_write32(0x00000000, (uint32_t)&regs->region[i].rd_secure_1);

		name = malloc(128);
		if (!name)
			return -ENOMEM;

                memset(name, 0, 128);

                /* define mpu policy */
                for (int j = 0; j < sdramc->mpu[i].allow_cnt; j++) {
                        id = sdramc->mpu[i].allow[j].id;
                        attr = sdramc->mpu[i].allow[j].attr;

                        switch (attr) {
                        case S_READWRITE:
                                if (id == MPU_ID_CA35) {
                                        sys_write32(0xf0, (uint32_t)&regs->region[i].ctrl);
                                        break;
                                }
                                val = sys_read32((uint32_t)&regs->region[i].ctrl + id_info[id].ofst);
                                sys_write32(val & ~id_info[id].mask, (uint32_t)&regs->region[i].ctrl + id_info[id].ofst);
                                val = sys_read32((uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x8);
                                sys_write32(val & ~id_info[id].mask, (uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x8);
                                val = sys_read32((uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x10);
                                sys_write32(val & ~id_info[id].mask, (uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x10);
                                val = sys_read32((uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x18);
                                sys_write32(val & ~id_info[id].mask, (uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x18);
                                break;
                        case S_READONLY:
                                if (id == MPU_ID_CA35) {
                                        sys_write32(0xb0, (uint32_t)&regs->region[i].ctrl);
                                        break;
                                }
                                val = sys_read32((uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x8);
                                sys_write32(val & ~id_info[id].mask, (uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x8);
                                val = sys_read32((uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x18);
                                sys_write32(val & ~id_info[id].mask, (uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x18);
                                break;
                        case S_WRITEONLY:
                                if (id == MPU_ID_CA35) {
                                        sys_write32(0x70, (uint32_t)&regs->region[i].ctrl);
                                        break;
                                }
                                val = sys_read32((uint32_t)&regs->region[i].ctrl + id_info[id].ofst);
                                sys_write32(val & ~id_info[id].mask, (uint32_t)&regs->region[i].ctrl + id_info[id].ofst);
                                val = sys_read32((uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x10);
                                sys_write32(val & ~id_info[id].mask, (uint32_t)&regs->region[i].ctrl + id_info[id].ofst + 0x10);
                                break;
                        case NS_READWRITE:
                                if (id == MPU_ID_CA35) {
                                        sys_write32(0x00, (uint32_t)&regs->region[i].ctrl);
                                        break;
                                }
                                break;
                        case NS_READONLY:
                                if (id == MPU_ID_CA35) {
                                        sys_write32(0x10, (uint32_t)&regs->region[i].ctrl);
                                        break;
                                }
                                break;
                        case NS_WRITEONLY:
                                if (id == MPU_ID_CA35) {
                                        sys_write32(0x20, (uint32_t)&regs->region[i].ctrl);
                                        break;
                                }
                                break;
                        default:
                                break;
                        };

                        strcat(name, id_info[id].str);
                        strcat(name, attr_info[attr].str);
                        strcat(name, ",");
                }

                printf("[mpu-%d:%s:	0x%08x~0x%08x] %s\n", i, sdramc->mpu[i].name, sdramc->mpu[i].start, sdramc->mpu[i].end, name);
                free(name);
        }

        return 0;
}

void sdramc_mpu_enable(struct sdramc *sdramc)
{
        struct sdramc_regs *regs = sdramc->regs;
        int i;

        for (i = 0; i < sdramc->mpu_cnt; i++) {
		sys_set_bits((mm_reg_t)&regs->region[i].ctrl, DRAMC_MPU_EN);
                sys_write32(1 << i, (mm_reg_t)&regs->protect_lock_set);
        }
}

#define MPU_PHANDLE_BY_IDX(node_id, prop, idx) \
	do { \
		const uint32_t start = DT_PROP(DT_PHANDLE_BY_IDX(node_id, prop, idx), protect_start); \
		const uint32_t end = DT_PROP(DT_PHANDLE_BY_IDX(node_id, prop, idx), protect_end); \
		const char *name = DT_NODE_FULL_NAME(DT_PHANDLE_BY_IDX(node_id, prop, idx)); \
		const uint32_t attr[] = DT_PROP(DT_PHANDLE_BY_IDX(node_id, prop, idx), allow); \
		LOG_DBG("MPU-%d @ %s\n", (idx), DT_NODE_FULL_NAME(DT_PHANDLE_BY_IDX(node_id, prop, idx))); \
		sdramc->mpu[idx].start = start; \
		sdramc->mpu[idx].end = end; \
		sdramc->mpu[idx].name = name; \
		sdramc->mpu[idx].allow = malloc(sizeof(attr)); \
		for (int i = 0; i < DT_PROP_LEN(DT_PHANDLE_BY_IDX(node_id, prop, idx), allow); i += 2) { \
			const uint32_t id = attr[i]; \
			const uint32_t perm = attr[i + 1]; \
			sdramc->mpu[idx].allow[i / 2].id = id; \
			sdramc->mpu[idx].allow[i / 2].attr = perm; \
		} \
		sdramc->mpu[idx].allow_cnt = DT_PROP_LEN(DT_PHANDLE_BY_IDX(node_id, prop, idx), allow) / 2; \
		LOG_DBG("finalize region %s: [0x%08x, 0x%08x)", name, start, end); \
	} while (0);

static void sdramc_get_property(struct sdramc *sdramc)
{
#if DT_NODE_HAS_PROP(SDRAMMC_NODE, mpus)
	sdramc->mpu_cnt = DT_PROP_LEN(SDRAMMC_NODE, mpus);

	DT_FOREACH_PROP_ELEM(SDRAMMC_NODE, mpus, MPU_PHANDLE_BY_IDX);
#endif
#if DT_NODE_HAS_PROP(SDRAMMC_NODE, ecc_enable)
	sdramc->ecc_enable = DT_PROP(SDRAMMC_NODE, ecc_enable);
#if DT_NODE_HAS_PROP(SDRAMMC_NODE, ecc_size)
	sdramc->ecc_size = DT_PROP(SDRAMMC_NODE, ecc_size);
#else
	sdramc->ecc_size = 0;
#endif
#endif
#if DT_NODE_HAS_PROP(SDRAMMC_NODE, aes_enable)
	sdramc->aes_enable = DT_PROP(SDRAMMC_NODE, aes_enable);
#if DT_NODE_HAS_PROP(SDRAMMC_NODE, aes_size)
	sdramc->aes_size = DT_PROP(SDRAMMC_NODE, aes_size);
#else
	sdramc->aes_size = 0;
#endif
#endif
}

static void sdramc_qos_init(struct sdramc *sdramc)
{
        /* raise SLI write/read priority */
        sys_write32(QOS_SLI_LEVEL(10),
               (uint32_t)&sdramc->regs->port[4].write_qos);
        sys_write32(QOS_SLI_LEVEL(9),
               (uint32_t)&sdramc->regs->port[4].read_qos);
        sys_write32(DRAMC_PORT_CFG_RDQOS_EN | DRAMC_PORT_CFG_WRQOS_EN | DEFAULT_RDQOS_LEVEL,
               (uint32_t)&sdramc->regs->port[4].cfg);

        /* raise usb 2.0 B1/B2, vga1 priority */
        sys_write32(QOS_USB2_B1_LEVEL(9) | QOS_USB2_B2_LEVEL(9) | QOS_VGA1_CR_LEVEL(9),
               (uint32_t)&sdramc->regs->port[2].read_qos);
        sys_write32(DRAMC_PORT_CFG_RDQOS_EN | DRAMC_PORT_CFG_WRQOS_EN | DEFAULT_RDQOS_LEVEL,
               (uint32_t)&sdramc->regs->port[2].cfg);

        /* raise vga2 priority */
        sys_write32(QOS_VGA2_CR_LEVEL(9),
               (uint32_t)&sdramc->regs->port[3].read_qos);
        sys_write32(DRAMC_PORT_CFG_RDQOS_EN | DRAMC_PORT_CFG_WRQOS_EN | DEFAULT_RDQOS_LEVEL,
               (uint32_t)&sdramc->regs->port[3].cfg);

        /* raise u2 A1/A2 priority */
        sys_write32(QOS_USB2_A1_LEVEL(9) | QOS_USB2_A2_LEVEL(9),
               (uint32_t)&sdramc->regs->port[1].read_qos);
        sys_write32(DRAMC_PORT_CFG_RDQOS_EN | DRAMC_PORT_CFG_WRQOS_EN | DEFAULT_RDQOS_LEVEL,
               (uint32_t)&sdramc->regs->port[1].cfg);
}

/*
 * Disable the DARB master request recovery for the given masters on the
 * DARB instance at @darb_base. Setting a master's bit to 1 disables its
 * reset recovery request, which avoids the master being unable to access
 * DRAM after a reset (e.g. the SSP/TSP data masters after an SSP/TSP reset).
 * @master_mask is an OR of DARB_RECOVERY_* bits.
 */
static void sdramc_darb_recovery_disable(uint32_t darb_base, uint32_t master_mask)
{
	sys_set_bits(darb_base + DARB_REQ_RECOVERY_CTRL, master_mask);
}

void sdramc_reset(struct sdramc *sdramc)
{
	// enable phy clock.
	sys_write32(BIT(11), 0x12c02244);

	// wdt sw reset for dramc only
	sys_write32(WDT_SW_RESET_DRAM_MASK, WDT_SW_RESET_MASK_REG);
	sys_write32(0x0, WDT_SW_RESET_MASK_REG + 4);
	sys_write32(0x0, WDT_SW_RESET_MASK_REG + 8);
	sys_write32(0x0, WDT_SW_RESET_MASK_REG + 12);
	sys_write32(0x0, WDT_SW_RESET_MASK_REG + 16);

	// kick wdt sw reset
	sys_write32(WDT_SW_RESET_KICK, WDT_SW_RESET_CTRL_REG);
	k_busy_wait(1000);
}

#define MPLL_RESET_BIT		BIT(25)
#define MPLL_BYPASS_BIT		BIT(24)
#define MPLL_CLKOD_MASK		GENMASK(22, 19)
#define MPLL_CLKNR_MASK		GENMASK(18, 13)
#define MPLL_CLKNF_MASK		GENMASK(12, 0)

#define MPLL_1600_nf300_nrb_od0

#if defined(MPLL_1600)
#define MPLL_OD	1
#define MPLL_NR 1
#define MPLL_NF (549755813888ULL / 4 / 1024 / 1024 / 1024 / 2)
#elif defined(MPLL_1625)
#define MPLL_OD	1
#define MPLL_NR 1
#define MPLL_NF (558345748480ULL / 4 / 1024 / 1024 / 1024 / 2)
#elif defined(MPLL_1590)
#define MPLL_OD	1
#define MPLL_NR 5
#define MPLL_NF (2731599200256ULL / 4 / 1024 / 1024 / 1024 / 2)
#elif defined(MPLL_1586)
#define MPLL_OD	1
#define MPLL_NR 17
#define MPLL_NF (9264072658780ULL / 4 / 1024 / 1024 / 1024 / 2)
#elif defined(MPLL_1575)
#define MPLL_OD	1
#define MPLL_NR 1
#define MPLL_NF (541165879296ULL  / 4 / 1024 / 1024 / 1024 / 2)
#elif defined(MPLL_1560)
#define MPLL_OD	1
#define MPLL_NR 3
#define MPLL_NF (1608035755622ULL / 4 / 1024 / 1024 / 1024 / 2)
#elif defined(MPLL_1560_B)
#define MPLL_OD	1
#define MPLL_NR 5
#define MPLL_NF (2680059592704ULL / 4 / 1024 / 1024 / 1024 / 2)
#elif defined(MPLL_1550)
#define MPLL_OD	1
#define MPLL_NR 1
#define MPLL_NF (532575944704ULL  / 4 / 1024 / 1024 / 1024 / 2)
#elif defined(MPLL_1550_nf7c_nr1_od0)
#define MPLL_OD	1
#define MPLL_NR 2
#define MPLL_NF (0x7cULL)
#elif defined(MPLL_1550_nff8_nr1_od1)
#define MPLL_OD	2
#define MPLL_NR 2
#define MPLL_NF (0xf8ULL)
#elif defined(MPLL_1550_nfba_nr2_od0)
#define MPLL_OD	1
#define MPLL_NR 3
#define MPLL_NF (0xbaULL)
#elif defined(MPLL_1600_nfc0_nr2_od0)
#define MPLL_OD	1
#define MPLL_NR 3
#define MPLL_NF (0xc0ULL)
#elif defined(MPLL_1600_nf300_nrb_od0)
#define MPLL_OD	1
#define MPLL_NR 0xc
#define MPLL_NF (0x300ULL)
#elif defined(MPLL_1500)
#define MPLL_OD	1
#define MPLL_NR 1
#define MPLL_NF (515396075520ULL  / 4 / 1024 / 1024 / 1024 / 2)
#endif
#define DDR_CLK_STOP_REG      0x12c02240
#define DDR_CLK_START_REG     0x12c02244

#define MPLL_CTRL_REG         0x12c02310
#define MPLL_STATUS_REG       0x12c02314

#define DDR_CLK_GATE_VALUE    0x801
#define MPLL_LOCK_BIT         BIT(31)

#define MPLL_LOCK_TIMEOUT_US  100000

static int mpll_wait_lock(uint32_t timeout_us)
{
	while (!(sys_read32(MPLL_STATUS_REG) & MPLL_LOCK_BIT)) {
		if (timeout_us == 0)
			return -ETIMEDOUT;

		k_busy_wait(1);
		timeout_us--;
	}

	return 0;
}

static int mpll_reset_and_lock(uint32_t pll_para)
{
	sys_write32(pll_para | MPLL_RESET_BIT | MPLL_BYPASS_BIT,
		    MPLL_CTRL_REG);

	k_busy_wait(10);

	sys_write32(pll_para | MPLL_BYPASS_BIT,
		    MPLL_CTRL_REG);

	if (mpll_wait_lock(MPLL_LOCK_TIMEOUT_US))
		return -ETIMEDOUT;

	sys_write32(pll_para, MPLL_CTRL_REG);

	if (mpll_wait_lock(MPLL_LOCK_TIMEOUT_US))
		return -ETIMEDOUT;

	return 0;
}

void sdramc_pll_reset(struct sdramc *sdramc)
{
	uint32_t pll_para;
	int retry;

	ARG_UNUSED(sdramc);

	printf("MPLL NF=0x%llx NR=%d OD=%d\n",
		MPLL_NF, MPLL_NR, MPLL_OD);

	/* Stop DDR clocks */
	sys_write32(DDR_CLK_GATE_VALUE, DDR_CLK_STOP_REG);

	/* Prepare MPLL parameters once */
	pll_para = sys_read32(MPLL_CTRL_REG);
	pll_para &= ~(MPLL_CLKOD_MASK |
		      MPLL_CLKNR_MASK |
		      MPLL_CLKNF_MASK);

	pll_para |= MPLL_NF;
	pll_para |= (MPLL_NR - 1) << 13;
	pll_para |= (MPLL_OD - 1) << 19;

	for (retry = 0; retry < 3; retry++) {
		if (!mpll_reset_and_lock(pll_para))
			break;

		printk("MPLL retry %d failed\n", retry + 1);
	}

	if (retry == 3) {
		printk("MPLL failed to lock after 3 retries\n");
	}

	/* Restart DDR clocks */
	sys_write32(DDR_CLK_GATE_VALUE, DDR_CLK_START_REG);
}

void sdramc_preset(struct sdramc *sdramc)
{
	// save wdt sw reset mask
	for (int i = 0; i < 5; i++)
		sdramc->wdt_swrst[i] = sys_read32(WDT_SW_RESET_MASK_REG + i * 4);
	// save gfm cfg
	sdramc->gfmcfg_bak = sdramc->regs->gfmcfg;
}

void sdramc_full_reset(struct sdramc *sdramc)
{
	sdramc_pll_reset(sdramc);
	sdramc_reset(sdramc);
}

void sdramc_postset(struct sdramc *sdramc)
{
	// restore wdt reset mask
	for (int i = 0; i < 5; i++)
		sys_write32(sdramc->wdt_swrst[i], WDT_SW_RESET_MASK_REG + i * 4);
	// restore gfm cfg
	sdramc->regs->gfmcfg = sdramc->gfmcfg_bak;
}

int dram_init(struct ast_chip *chip)
{
	struct sdramc_ac_timing *ac = NULL;
	uint32_t bistcfg;
	int err = -1;
	int retry = 3;

	sdramc->chip = chip;
	sdramc->regs = (struct sdramc_regs *)DRAMC_BASE;
	sdramc->phy_regs = (uint32_t *)DRAMC_PHY_BASE;

	while (is_ddr_initialized(sdramc)) {
		dwc_ddrphy_apb_wr(0xd0000, 0);

		if (dwc_ddrphy_apb_rd(0x200d5) & BIT(1)) {
			printf("DDR PHY is already initialized, but PHY PllUnlocked!!!\n");
			break;
		} else {
			dwc_ddrphy_apb_wr(0xd0000, 1);
		}

		return 0;
	}

	sdramc_preset(sdramc);
	while (retry--) {

		sdramc_full_reset(sdramc);
		sdramc_unlock(sdramc);

		err = sdramc_init(sdramc, &ac);
		if (err)
			return err;

		err = sdramc_phy_init(sdramc, ac);
		if (err)
			continue;

		sys_write32(0, 0x131a0000);
		printf("DDRPHY unlock status=0x%08x\n", sys_read32(0x130401a8));
		sys_write32(0x1, 0x130401ac);
		printf("DDRPHY unlock clear set 1 status=0x%08x\n", sys_read32(0x130401a8));
		sys_write32(0x0, 0x130401ac);
		printf("DDRPHY unlock clear set 0 status=0x%08x\n", sys_read32(0x130401a8));
		sys_write32(1, 0x131a0000);
		sdramc_exit_self_refresh(sdramc);
		sdramc_configure_mrs(sdramc, ac);
		sdramc_enable_refresh(sdramc);
		sdramc_get_property(sdramc);

		bistcfg = FIELD_PREP(DRAMC_BISTCFG_PMODE, BIST_PMODE_CRC)
			| FIELD_PREP(DRAMC_BISTCFG_BMODE, BIST_BMODE_RW_SWITCH)
			| DRAMC_BISTCFG_ENABLE;

		err = sdramc_bist(sdramc, 0, 0x10000, bistcfg, 1000);
		if (!err)
			break;
	};

	if (err) {
		printf("%s init is failed, err=%d\n",
			ac ? ac->desc : "unknow", err);
		return err;
	}

	sdramc_postset(sdramc);
	sdramc_size_detect(sdramc);

	err = sdramc_ecc_enable(sdramc);
	if (err)
		return err;

	err = sdramc_aes_enable(sdramc);
	if (err)
		return err;

	sdramc_init_mpu(sdramc);
	sdramc_mpu_enable(sdramc);

	sdramc_qos_init(sdramc);
	sdramc_setup_vga_access(sdramc);

	/* SSP/TSP data masters are routed to DRAMC port served by DARB2 */
	sdramc_darb_recovery_disable(DARB2_BASE,
				     DARB2_RECOVERY_TSP_DATA | DARB2_RECOVERY_SSP_DATA);

	sdramc_aes_lock(sdramc);
	sdramc_hard_lock(sdramc);

	LOG_DBG("%s is successfully initialized\n", ac->desc);
	sdramc_set_flag(DRAMC_INIT_DONE);

	return 0;
}
