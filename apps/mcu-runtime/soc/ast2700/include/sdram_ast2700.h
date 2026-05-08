/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _SDRAM_AST2700_H
#define _SDRAM_AST2700_H

#include <errno.h>
#include <zephyr/types.h>
#include <zephyr/sys/sys_io.h>
#include <zephyr/sys/util.h>
#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <platform.h>
#include <chip.h>

#define MAX_MPU_COUNT                   16

#define SCU_CPU_VGA0_SCRATCH            (SCU0_REG + 0x900)
#define SCU_CPU_VGA1_SCRATCH            (SCU0_REG + 0x910)

#define SCU_IO_HWSTRAP1                 (SCU1_REG + 0x010)
#define IO_HWSTRAP1_DRAM_TYPE           BIT(10)

#define DRAMC_BASE			(0x12c00000)
#define DRAMC_PHY_BASE			(0x13000000)
#define dwc_ddrphy_apb_wr(addr, value)		(*(volatile unsigned short *)(DRAMC_PHY_BASE + 2 * (addr)) = (unsigned short)value)
#define dwc_ddrphy_apb_rd(addr)			(*(volatile unsigned short *)(DRAMC_PHY_BASE + 2 * (addr)))

#define dwc_ddrphy_apb_wr_32b(addr, value)	(*((volatile unsigned int *)(DRAMC_PHY_BASE + 2 * (addr))) = (unsigned int)value)
#define dwc_ddrphy_apb_rd_32b(addr)		(*(volatile unsigned int *)(DRAMC_PHY_BASE + 2 * (addr)))

/* offset 0x04 */
#define DRAMC_IRQSTA_PWRCTL_ERR			BIT(16)
#define DRAMC_IRQSTA_PHY_ERR			BIT(15)
#define DRAMC_IRQSTA_LOWPOWER_DONE		BIT(12)
#define DRAMC_IRQSTA_FREQ_CHG_DONE		BIT(11)
#define DRAMC_IRQSTA_REF_DONE			BIT(10)
#define DRAMC_IRQSTA_ZQ_DONE			BIT(9)
#define DRAMC_IRQSTA_BIST_DONE			BIT(8)
#define DRAMC_IRQSTA_ECC_RCVY_ERR		BIT(5)
#define DRAMC_IRQSTA_ECC_ERR			BIT(4)
#define DRAMC_IRQSTA_PROT_ERR			BIT(3)
#define DRAMC_IRQSTA_OVERSZ_ERR			BIT(2)
#define DRAMC_IRQSTA_MR_DONE			BIT(1)
#define DRAMC_IRQSTA_PHY_INIT_DONE		BIT(0)

/* offset 0x10 */
#define DRAMC_MCFG_ECC_EN			BIT(6)
#define DRAMC_MCFG_PGM_EN			BIT(5)

/* offset 0x14 */
#define DRAMC_MCTL_WB_SOFT_RESET		BIT(24)
#define DRAMC_MCTL_PHY_CLK_DIS			BIT(18)
#define DRAMC_MCTL_PHY_RESET			BIT(17)
#define DRAMC_MCTL_PHY_POWER_ON			BIT(16)
#define DRAMC_MCTL_FREQ_CHG_START		BIT(3)
#define DRAMC_MCTL_PHY_LOWPOWER_START		BIT(2)
#define DRAMC_MCTL_SELF_REF_START		BIT(1)
#define DRAMC_MCTL_PHY_INIT_START		BIT(0)

/* offset 0x40 */
#define DRAMC_DFICFG_WD_POL			BIT(18)
#define DRAMC_DFICFG_CKE_OUT			BIT(17)
#define DRAMC_DFICFG_RESET			BIT(16)

/* offset 0x48 */
#define DRAMC_MRCTL_ERR_STATUS			BIT(31)
#define DRAMC_MRCTL_READY_STATUS		BIT(30)
#define DRAMC_MRCTL_MR_ADDR			BIT(8)
#define DRAMC_MRCTL_CMD_DLL_RST			BIT(7)
#define DRAMC_MRCTL_CMD_DQ_SEL			BIT(6)
#define DRAMC_MRCTL_CMD_TYPE			BIT(2)
#define DRAMC_MRCTL_CMD_WR_CTL			BIT(1)
#define DRAMC_MRCTL_CMD_START			BIT(0)

/* DRAMC048 MR Control Register */
#define MR_TYPE_SHIFT				2
#define MR_RW					(0 << MR_TYPE_SHIFT)
#define MR_MPC					BIT(2)
#define MR_VREFCS				(2 << MR_TYPE_SHIFT)
#define MR_VREFCA				(3 << MR_TYPE_SHIFT)

#define MR_ADDRESS_SHIFT			8
#define MR_ADDR(n)				(((n) << MR_ADDRESS_SHIFT) | DRAMC_MRCTL_CMD_WR_CTL)

#define MR_NUM_SHIFT				4
#define MR_NUM(n)				((n) << MR_NUM_SHIFT)

#define MR_DLL_RESET				BIT(7)
#define MR_1T_MODE				BIT(16)

/* MPC command definition */
#define MPC_OP_EXIT_CS			0
#define MPC_OP_ENTER_CS			1
#define MPC_OP_DLL_RESET		2
#define MPC_OP_ENTER_CA			3
#define MPC_OP_ZQCAL_LATCH		4
#define MPC_OP_ZQCAL_START		5
#define MPC_OP_STOP_DQS			6
#define MPC_OP_START_DQS		7
#define MPC_OP_SET_2N_CMD		8
#define MPC_OP_SET_1N_CMD		9
#define MPC_OP_EXIT_PDA			10
#define MPC_OP_ENTER_PDA		11
#define MPC_OP_MANUAL_ECS		12
#define MPC_OP_APPLY			0x1f
#define MPC_OP_RTT_CK_A			0x20
#define MPC_OP_RTT_CK_B			0x28
#define MPC_OP_RTT_CS_A			0x30
#define MPC_OP_RTT_CS_B			0x38
#define MPC_OP_RTT_CA_A			0x40
#define MPC_OP_RTT_CA_B			0x48
#define MPC_OP_SET_DQS_RTT_PARK		0x50
#define MPC_OP_SET_RTT_PARK		0x58
#define MPC_OP_PDA_ENUM_ID		0x60
#define MPC_OP_PDA_SEL_ID		0x70
#define MPC_OP_CONFIG_DLLK_CCD		0x80

/* MR2 */
#define MR2_READ_PREAMBLE_TRAIN		BIT(0)
#define MR2_WRITE_LEVELING		BIT(1)
#define MR2_2N_MODE			BIT(2)
#define MR2_POWER_SAVING		BIT(3)
#define MR2_CS_ASSERTION		BIT(4)
#define MR2_DEVICE_15_PWR_SAVE		BIT(5)
#define MR2_INTERN_WR_TIMING		BIT(7)

/* MR8 */
#define MR8_READ_PREAMBLE_1TCK		0
#define MR8_READ_PREAMBLE_2TCK		1
#define MR8_READ_PREAMBLE_2TCK_DDR4	2
#define MR8_READ_PREAMBLE_3TCK		3
#define MR8_READ_PREAMBLE_4TCK		4
#define MR8_WRITE_PREAMBLE_2TCK		BIT(3)
#define MR8_WRITE_PREAMBLE_3TCK		(2 << 3)
#define MR8_WRITE_PREAMBLE_4TCK		(3 << 3)
#define MR8_READ_POST_0_5TCK		(0 << 6)
#define MR8_READ_POST_1_5TCK		BIT(6)
#define MR8_WRITE_POST_0_5TCK		(0 << 7)
#define MR8_WRITE_POST_1_5TCK		BIT(7)

/* MR10 */
#define MR10_VREFDQ_RANGE_90		(0x0f)
#define MR10_VREFDQ_RANGE_85		(0x19)
#define MR10_VREFDQ_RANGE_80		(0x23)
#define MR10_VREFDQ_RANGE_75		(0x2d)
#define MR10_VREFDQ_RANGE_70		(0x37)

/* MR11 */
#define MR11_VREFCA_RANGE_90		(0x0f)
#define MR11_VREFCA_RANGE_85		(0x19)
#define MR11_VREFCA_RANGE_80		(0x23)
#define MR11_VREFCA_RANGE_75		(0x2d)
#define MR11_VREFCA_RANGE_70		(0x37)

/* MR12 */
#define MR12_VREFCS_RANGE_90		(0x0f)
#define MR12_VREFCS_RANGE_85		(0x19)
#define MR12_VREFCS_RANGE_80		(0x23)
#define MR12_VREFCS_RANGE_75		(0x2d)
#define MR12_VREFCS_RANGE_70		(0x37)

/* MR32 */
#define MR32_CK_ODT_RTT_OFF		(0)
#define MR32_CK_ODT_480			(1)
#define MR32_CK_ODT_240			(2)
#define MR32_CK_ODT_120			(3)
#define MR32_CK_ODT_80			(4)
#define MR32_CK_ODT_60			(5)
#define MR32_CK_ODT_40			(7)

#define MR32_CS_ODT_RTT_OFF		(0)
#define MR32_CS_ODT_480			(1)
#define MR32_CS_ODT_240			(2)
#define MR32_CS_ODT_120			(3)
#define MR32_CS_ODT_80			(4)
#define MR32_CS_ODT_60			(5)
#define MR32_CS_ODT_40			(7)

#define MR32_CA_ODT_STRAP_BIT		BIT(6)

/* MR33 */
#define MR33_CA_ODT_RTT_OFF		(0)
#define MR33_CA_ODT_480			(1)
#define MR33_CA_ODT_240			(2)
#define MR33_CA_ODT_120			(3)
#define MR33_CA_ODT_80			(4)
#define MR33_CA_ODT_60			(5)
#define MR33_CA_ODT_40			(7)

#define MR33_DQS_RTT_PARK_OFF		(0)
#define MR33_DQS_RTT_PARK_240		(1)
#define MR33_DQS_RTT_PARK_120		(2)
#define MR33_DQS_RTT_PARK_80		(3)
#define MR33_DQS_RTT_PARK_60		(4)
#define MR33_DQS_RTT_PARK_40		(5)
#define MR33_DQS_RTT_PARK_34		(7)

/* MR34 */
#define MR34_RTT_PARK_OFF		(0)
#define MR34_RTT_PARK_240		(1)
#define MR34_RTT_PARK_120		(2)
#define MR34_RTT_PARK_80		(3)
#define MR34_RTT_PARK_60		(4)
#define MR34_RTT_PARK_40		(5)
#define MR34_RTT_PARK_34		(7)

/* offset 0xC0 */
#define DRAMC_BISTRES_RUNNING			BIT(10)
#define DRAMC_BISTRES_FAIL			BIT(9)
#define DRAMC_BISTRES_DONE			BIT(8)
#define DRAMC_BISTCFG_INIT_MODE			BIT(7)
#define DRAMC_BISTCFG_PMODE			GENMASK(6, 4)
#define DRAMC_BISTCFG_BMODE			GENMASK(3, 2)
#define DRAMC_BISTCFG_ENABLE			BIT(1)
#define DRAMC_BISTCFG_START			BIT(0)
#define BIST_PMODE_CRC				(3)
#define BIST_BMODE_RW_SWITCH			(3)

/* offset 0x288 */
#define DRAMC_PORT1_VE_HIGH_SHIFT		(0)
#define DRAMC_PORT1_VE_LOW_SHIFT		(1)
#define DRAMC_PORT1_USB2_A1_SHIFT		(2)
#define DRAMC_PORT1_USB2_A2_SHIFT		(3)
#define DRAMC_PORT1_E2M_SHIFT			(4)
#define DRAMC_PORT1_MCTP_SHIFT			(5)
#define DRAMC_PORT1_H2M_SHIFT			(6)
#define DRAMC_PORT1_HMAC_SHIFT			(7)

#define QOS_USB2_A1_LEVEL(x)			((x) << (DRAMC_PORT1_USB2_A1_SHIFT * 4))
#define QOS_USB2_A2_LEVEL(x)			((x) << (DRAMC_PORT1_USB2_A2_SHIFT * 4))

/* offset 0x310 */
#define DRAMC_PORT2_USB2_B1_SHIFT		(0)
#define DRAMC_PORT2_USB2_B2_SHIFT		(1)
#define DRAMC_PORT2_VGA1_CR_SHIFT		(2)
#define DRAMC_PORT2_VGA1_LE_SHIFT		(3)
#define DRAMC_PORT2_TSP_INST_SHIFT		(4)
#define DRAMC_PORT2_VIDEO_SHIFT			(5)
#define DRAMC_PORT2_MCTP8_SHIFT			(6)
#define DRAMC_PORT2_UHCI_SHIFT			(7)

#define QOS_USB2_B1_LEVEL(x)			((x) << (DRAMC_PORT2_USB2_B1_SHIFT * 4))
#define QOS_USB2_B2_LEVEL(x)			((x) << (DRAMC_PORT2_USB2_B2_SHIFT * 4))
#define QOS_VGA1_CR_LEVEL(x)			((x) << (DRAMC_PORT2_VGA1_CR_SHIFT * 4))

/* offset 0x380 */
#define DRAMC_PORT_CFG_RDQOS_EN			BIT(2)
#define DRAMC_PORT_CFG_WRQOS_EN			BIT(3)
#define DRAMC_PORT_CFG_RDQOS_LVL_MASK		GENMASK(7, 4)
#define DRAMC_PORT_CFG_RDQOS_LVL_SHIFT		(4)

/* offset 0x388 */
#define DRAMC_PORT3_USB3_A1_SHIFT		(0)
#define DRAMC_PORT3_USB3_B1_SHIFT		(1)
#define DRAMC_PORT3_SHA3_SHIFT			(2)
#define DRAMC_PORT3_VGA2_CR_SHIFT		(3)
#define DRAMC_PORT3_VGA2_LE_SHIFT		(4)
#define DRAMC_PORT3_TSP_SHIFT			(5)
#define DRAMC_PORT3_E2M1_SHIFT			(6)
#define DRAMC_PORT3_GFX_SHIFT			(7)

#define QOS_VGA2_CR_LEVEL(x)			((x) << (DRAMC_PORT3_VGA2_CR_SHIFT * 4))

/* offset 0x400 */
#define DRAMC_PORT4_XDMA_SHIFT			(0)
#define DRAMC_PORT4_SDIO_SHIFT			(1)
#define DRAMC_PORT4_SLI_SHIFT			(3)

/* offset 0x600 */
#define DRAMC_MPU_EN				BIT(0)
#define DRAMC_MPU_NS_WRITE			BIT(4)
#define DRAMC_MPU_NS_READ			BIT(5)
#define DRAMC_MPU_S_WRITE			BIT(6)
#define DRAMC_MPU_S_READ			BIT(7)

#define QOS_SLI_LEVEL(x)			((x) << (DRAMC_PORT4_SLI_SHIFT * 4))

#define DEFAULT_RDQOS_LEVEL			(8 << DRAMC_PORT_CFG_RDQOS_LVL_SHIFT)

struct mpu_allow {
	int id;
	int attr;
};

struct mpu_info {
	int id;
	const char *name;
	uint32_t start;
	uint32_t end;
	struct mpu_allow *allow;
	int allow_cnt;
};

struct sdramc {
	struct ast_chip *chip;
//	struct ram_info info;
	struct sdramc_regs *regs;
	uint32_t *phy_regs;
	bool fpga;
//	void __iomem *phy_setting;
//	void __iomem *phy_status;
	unsigned long clock_rate;

	int sz;

	bool ecc_enable;
	uint32_t ecc_size;
	bool aes_enable;
	uint32_t aes_size;

	struct mpu_info mpu[MAX_MPU_COUNT];
	int mpu_cnt;
	uint32_t wdt_swrst[5];
};

struct sdramc_port {
	uint32_t cfg;
	uint32_t timeout;
	uint32_t read_qos;
	uint32_t resvd0;
	uint32_t write_qos;
	uint32_t resvd1[3];
	uint32_t monitor_config;
	uint32_t monitor_limit;
	uint32_t monitor_timer;
	uint32_t resvd2;
	uint32_t monitor_status;
	uint32_t bandwidth_log;
	uint32_t resvd3[2];
	uint32_t intf_monitor[3];
	uint32_t resvd4[13];
};

struct sdramc_protect {
	uint32_t ctrl;
	uint32_t status;
	uint32_t start;
	uint32_t end;
	uint32_t wr_master_0;
	uint32_t wr_master_1;
	uint32_t rd_master_0;
	uint32_t rd_master_1;
	uint32_t wr_secure_0;
	uint32_t wr_secure_1;
	uint32_t rd_secure_0;
	uint32_t rd_secure_1;
	uint32_t resvd[4];
};

struct sdramc_regs {
	uint32_t prot_key;			/* offset 0x00 */
	uint32_t intr_status;		/* offset 0x04 */
	uint32_t intr_clear;			/* offset 0x08 */
	uint32_t intr_mask;			/* offset 0x0C */
	uint32_t mcfg;			/* offset 0x10 */
	uint32_t mctl;
	uint32_t msts;
	uint32_t error_status;
	uint32_t actime1;
	uint32_t actime2;
	uint32_t actime3;
	uint32_t actime4;
	uint32_t actime5;
	uint32_t actime6;
	uint32_t actime7;
	uint32_t dfi_timing;
	uint32_t dcfg;
	uint32_t dctl;
	uint32_t mrctl;
	uint32_t mrwr;
	uint32_t mrrd;
	uint32_t mr01;
	uint32_t mr23;
	uint32_t mr45;
	uint32_t mr67;
	uint32_t refctl;
	uint32_t refmng_ctl;
	uint32_t refsts;
	uint32_t zqctl;			/* offset 0x70 */
	uint32_t ecc_addr_range;		/* offset 0x74 */
	uint32_t ecc_failure_status;		/* offset 0x78 */
	uint32_t ecc_failure_addr;		/* offset 0x7C */
	uint32_t ecc_test_control;		/* offset 0x80 */
	uint32_t ecc_test_status;		/* offset 0x84 */
	uint32_t arbctl;			/* offset 0x88 */
	uint32_t enccfg;			/* offset 0x8c */
	uint32_t protect_lock_set;		/* offset 0x90 */
	uint32_t protect_lock_status;	/* offset 0x94 */
	uint32_t protect_lock_reset;		/* offset 0x98 */
	uint32_t enc_min_addr;		/* offset 0x9c */
	uint32_t enc_max_addr;		/* offset 0xa0 */
	uint32_t enc_key[4];			/* offset 0xa4~0xb0 */
	uint32_t enc_iv[3];			/* offset 0xb4~0xbc */
	uint32_t bistcfg;			/* offset 0xc0 */
	uint32_t bist_addr;
	uint32_t bist_size;
	uint32_t bist_patt;
	uint32_t bist_res;
	uint32_t bist_fail_addr;
	uint32_t bist_fail_data[4];
	uint32_t reserved2[2];
	uint32_t debug_control;		/* offset 0xf0 */
	uint32_t debug_status;
	uint32_t phy_intf_status;
	uint32_t testcfg;
	uint32_t gfmcfg;			/* 0x100 */
	uint32_t gfm0ctl;
	uint32_t gfm1ctl;
	uint32_t reserved3[0x3d];
	struct sdramc_port port[6];	/* 0x200 */
	uint32_t reserved4[64];
	struct sdramc_protect region[16];/* 0x600 */
};

enum {
	SDRAM_SIZE_256MB = 0,
	SDRAM_SIZE_512MB,
	SDRAM_SIZE_1GB,
	SDRAM_SIZE_2GB,
	SDRAM_SIZE_4GB,
	SDRAM_SIZE_8GB,
	SDRAM_SIZE_MAX,
};

enum {
	SDRAM_VGA_RSVD_32MB = 0,
	SDRAM_VGA_RSVD_64MB,
};

enum ddr_speed_bin {
	DDR4_1600,
	DDR4_2400,
	DDR4_3200,
	DDR5_3200,
};

enum ddr_type {
	DRAM_TYPE_4,
	DRAM_TYPE_5,
	DRAM_TYPE_MAX,
};

struct sdramc_ac_timing {
	uint32_t type;
	char desc[30];
	uint32_t t_cl;
	uint32_t t_cwl;
	uint32_t t_bl;
	uint32_t t_rcd;		/* ACT-to-read/write command delay */
	uint32_t t_rp;		/* PRE command period */
	uint32_t t_ras;		/* ACT-to-PRE command delay */
	uint32_t t_rrd;		/* ACT-to-ACT delay for different BG */
	uint32_t t_rrd_l;		/* ACT-to-ACT delay for same BG */
	uint32_t t_faw;		/* Four active window */
	uint32_t t_rtp;		/* Read-to-PRE command delay */
	uint32_t t_wtr;		/* Minimum write to read command for different BG */
	uint32_t t_wtr_l;		/* Minimum write to read command for same BG */
	uint32_t t_wtr_a;		/* Write to read command for same BG with auto precharge */
	uint32_t t_wtp;		/* Minimum write to precharge command delay */
	uint32_t t_rtw;		/* minimum read to write command */
	uint32_t t_ccd_l;		/* CAS-to-CAS delay for same BG */
	uint32_t t_dllk;		/* DLL locking time */
	uint32_t t_cksre;		/* valid clock before after self-refresh or power-down entry/exit process */
	uint32_t t_pd;		/* power-down entry to exit minimum width */
	uint32_t t_xp;		/* exit power-down to valid command delay */
	uint32_t t_rfc;		/* refresh time period */
	uint32_t t_mrd;
	uint32_t t_refsbrd;
	uint32_t t_rfcsb;
	uint32_t t_cshsr;
	uint32_t t_zq;
};

struct train_bin {
	uint32_t imem_base;
	uint32_t imem_len;
	uint32_t dmem_base;
	uint32_t dmem_len;
};

int fpga_phy_init(struct sdramc *sdramc);
int dwc_phy_init(struct sdramc *sdramc);
bool is_ddr4(void);
//void sdramc_mpu_enable(struct udevice *dev);
int dram_init(struct ast_chip *chip);
#endif
