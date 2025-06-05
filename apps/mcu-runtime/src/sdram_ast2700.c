// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */
//#include <common.h>
//#include <dm.h>
//#include <asm/arch-aspeed/sdram_ast2700.h>
//#include <asm/arch-aspeed/pll.h>
#include <sdram_ast2700.h>
#include <zephyr/logging/log.h>

#define LOG_MODULE_NAME	sdram_ast2700
LOG_MODULE_REGISTER(LOG_MODULE_NAME, LOG_LEVEL_DBG);

#define DRAMC_UNLOCK_KEY		0x1688a8a8
#define DRAMC_VIDEO_UNLOCK_KEY		0x00440003

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
		20, 16, 8,
	/*     rcd, rp, ras, rrd, rrd_l, faw, rtp */
		20, 20, 52, 9, 11, 48, 12,
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
static bool is_ddr_initialized(void)
{
	if (sys_read32(SCU_CPU_VGA0_SCRATCH) & DRAMC_INIT_DONE) {
		//printf("DDR has been initialized\n");
		return 1;
	}

	return 0;
}

bool is_fpga(void)
{
#ifdef CONFIG_ASPEED_FPGA
	sdramc->fpga = 1;
#else
	sdramc->fpga = 0;
#endif
	return sdramc->fpga;
}

bool is_ddr4(void)
{
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

static void sdramc_phy_init(struct sdramc *sdramc, struct sdramc_ac_timing *ac)
{
	/* initialize phy */
	if (sdramc->fpga)
		fpga_phy_init(sdramc);
	else
		dwc_phy_init(sdramc);
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
	uint32_t err = 0;

	sys_write32(0, (uint32_t)&regs->bistcfg);
	sys_write32(cfg, (uint32_t)&regs->bistcfg);
	sys_write32(addr >> 4, (uint32_t)&regs->bist_addr);
	sys_write32(size >> 4, (uint32_t)&regs->bist_size);
	sys_write32(0x89abcdef, (uint32_t)&regs->bist_patt);
	sys_write32(cfg | DRAMC_BISTCFG_START, (uint32_t)&regs->bistcfg);

	while (!(sys_read32((uint32_t)&regs->intr_status) & DRAMC_IRQSTA_BIST_DONE))
		;

	sys_write32(DRAMC_IRQSTA_BIST_DONE, (uint32_t)&regs->intr_clear);

	val = sys_read32((uint32_t)&regs->bist_res);

	/* bist done */
	if (val & DRAMC_BISTRES_DONE) {
		/* bist pass [9]=0 */
		if (val & DRAMC_BISTRES_FAIL)
			err++;
	} else {
		err++;
	}

	return err;
}

static void sdramc_aes_enable(struct sdramc *sdramc, uint32_t addr_min, uint32_t addr_max)
{
	struct sdramc_regs *regs = sdramc->regs;

	sys_write32(addr_min >> 4, (uint32_t)&regs->enc_min_addr);
	sys_write32(addr_max >> 4, (uint32_t)&regs->enc_max_addr);
	sys_write32(1, (uint32_t)&regs->enccfg);
}

/* offset 0x10 */
#define DRAMC_MCFG_ECC_EN			BIT(6)
#define DRAMC_MCFG_PGM_EN			BIT(5)
#define DRAM_SIZE_DEF	3
static int sdramc_ecc_enable(struct sdramc *sdramc)
{
	size_t ram_size_ary[] = {
		0x10000000, // 256MB
		0x20000000, // 512MB
		0x40000000, // 1GB
		0x80000000, // 2GB
		};
	size_t ecc_sz, ram_size = ram_size_ary[DRAM_SIZE_DEF];
	struct sdramc_regs *regs = sdramc->regs;
	uint32_t bistcfg;
	uint32_t val;
	int err;

	bistcfg = 0x82;
	err = sdramc_bist(sdramc, 0, ram_size, bistcfg, 0x200000);
	if (err) {
		printf("bist is failed\n");
		return err;
	}

	/* config ecc range */
	//ecc_sz = (((ram_size / 9) * 8) >> 4);
	ecc_sz = ((0x30000000) >> 4);
	sys_write32(ecc_sz, (uint32_t)&regs->ecc_addr_range);

	/* enable ecc, page matching should be disabled */
	val = sys_read32((uint32_t)&regs->mcfg);
	val &= ~(DRAMC_MCFG_PGM_EN | 0x1c);
	val |= (DRAMC_MCFG_ECC_EN | (DRAM_SIZE_DEF << 2));
	sys_write32(val, (uint32_t)&regs->mcfg);

	return err;
}

int dram_init(void)
{
	struct sdramc_ac_timing *ac;
	uint32_t bistcfg;
	int err = 0;

	if (is_ddr_initialized())
		goto out;

	sdramc->regs = (struct sdramc_regs *)DRAMC_BASE;
	sdramc->phy_regs = (uint32_t *)DRAMC_PHY_BASE;

//	mpll_init();

	sdramc_unlock(sdramc);

	err = sdramc_init(sdramc, &ac);
	if (err)
		return err;

	sdramc_phy_init(sdramc, ac);

	sdramc_exit_self_refresh(sdramc);

	sdramc_configure_mrs(sdramc, ac);

	sdramc_enable_refresh(sdramc);

	if (IS_ENABLED(CONFIG_ASPEED_DRAM_ECC))
		sdramc_ecc_enable(sdramc);

	if (IS_ENABLED(CONFIG_ASPEED_DRAM_AES))
		sdramc_aes_enable(sdramc, 0, 0x30000000);

	bistcfg = FIELD_PREP(DRAMC_BISTCFG_PMODE, BIST_PMODE_CRC)
		| FIELD_PREP(DRAMC_BISTCFG_BMODE, BIST_BMODE_RW_SWITCH)
		| DRAMC_BISTCFG_ENABLE;

	err = sdramc_bist(sdramc, 0, 0x10000, bistcfg, 0x200000);
	if (err) {
		printf("%s bist is failed\n", ac->desc);
		return err;
	}

	LOG_DBG("%s is successfully initialized\n", ac->desc);
	sdramc_set_flag(DRAMC_INIT_DONE);

out:
//	sdramc->info.base = 0x80000000;
//	sdramc->info.size = 0x40000000;
//	gd->ram_size = sdramc->info.size;

	return 0;
}
