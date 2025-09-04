// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#include <platform.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <scu_ast2700.h>
#include <ast_loader.h>
#include <aspeed_util.h>

#define readx_poll_timeout(op, addr, val, cond, sleep_us, timeout_ms)	    	    \
	({									    \
		uint32_t __timeout_tick = Z_TIMEOUT_MS(timeout_ms).ticks;	    \
		uint32_t __start = sys_clock_tick_get_32();			    \
		int __ret = 0;							    \
		for (;;) {							    \
			val = op(addr);						    \
			if (cond) {						    \
				break;						    \
			}							    \
			if ((sys_clock_tick_get_32() - __start) > __timeout_tick) { \
				__ret = -ETIMEDOUT;				    \
				break;						    \
			}							    \
			if (sleep_us) {						    \
				k_usleep(sleep_us);				    \
			}							    \
		}								    \
		__ret;								    \
	})

LOG_MODULE_REGISTER(ast_i3c, CONFIG_SOC_FMC_LOG_LEVEL);
struct i3c_hci g_hci;
#define DEV_DATA(dev)	((struct i3c_hci *)((dev)->data))

#define I3C_BCR_DEVICE_ROLE(bcr)	((bcr) & GENMASK(7, 6))
#define I3C_BCR_I3C_SLAVE		0
#define I3C_BCR_I3C_MASTER		BIT(6)
#define I3C_BCR_HDR_CAP			BIT(5)
#define I3C_BCR_BRIDGE			BIT(4)
#define I3C_BCR_OFFLINE_CAP		BIT(3)
#define I3C_BCR_IBI_PAYLOAD		BIT(2)
#define I3C_BCR_IBI_REQ_CAP		BIT(1)
#define I3C_BCR_MAX_DATA_SPEED_LIM BIT(0)

/**
 * enum i3c_hdr_mode - HDR mode ids
 * @I3C_HDR_DDR: DDR mode
 * @I3C_HDR_TSP: TSP mode
 * @I3C_HDR_TSL: TSL mode
 * @I3C_HDR_BT: BT mode
 */
enum i3c_hdr_mode {
	I3C_HDR_DDR,
	I3C_HDR_TSP,
	I3C_HDR_TSL,
	I3C_HDR_BT,
};

#define reg_read(r)		sys_read32(hci->base_regs + (r))
#define reg_write(r, v)		sys_write32(v, hci->base_regs + (r))
#define reg_set(r, v)		reg_write(r, reg_read(r) | (v))
#define reg_clear(r, v)		reg_write(r, reg_read(r) & ~(v))

#define HCI_VERSION			0x00	/* HCI Version (in BCD) */

#define HC_CONTROL			0x04
#define HC_CONTROL_BUS_ENABLE		BIT(31)
#define HC_CONTROL_RESUME		BIT(30)
#define HC_CONTROL_ABORT		BIT(29)
#define HC_CONTROL_HALT_ON_CMD_TIMEOUT	BIT(12)
#define HC_CONTROL_HOT_JOIN_CTRL	BIT(8)	/* Hot-Join ACK/NACK Control */
#define HC_CONTROL_I2C_TARGET_PRESENT	BIT(7)
#define HC_CONTROL_PIO_MODE		BIT(6)	/* DMA/PIO Mode Selector */
#define HC_CONTROL_DATA_BIG_ENDIAN	BIT(4)
#define HC_CONTROL_IBA_INCLUDE		BIT(0)	/* Include I3C Broadcast Address */

#define MASTER_DEVICE_ADDR		0x08	/* Master Device Address */
#define MASTER_DYNAMIC_ADDR_VALID	BIT(31)	/* Dynamic Address is Valid */
#define MASTER_DYNAMIC_ADDR(v)		FIELD_PREP(GENMASK(22, 16), v)

#define HC_CAPABILITIES			0x0c
#define HC_CAP_SG_DC_EN			BIT(30)
#define HC_CAP_SG_IBI_EN		BIT(29)
#define HC_CAP_SG_CR_EN			BIT(28)
#define HC_CAP_MAX_DATA_LENGTH		GENMASK(24, 22)
#define HC_CAP_CMD_SIZE			GENMASK(21, 20)
#define HC_CAP_DIRECT_COMMANDS_EN	BIT(18)
#define HC_CAP_MULTI_LANE_EN		BIT(15)
#define HC_CAP_CMD_CCC_DEFBYTE		BIT(10)
#define HC_CAP_HDR_BT_EN		BIT(8)
#define HC_CAP_HDR_TS_EN		BIT(7)
#define HC_CAP_HDR_DDR_EN		BIT(6)
#define HC_CAP_NON_CURRENT_MASTER_CAP	BIT(5)	/* master handoff capable */
#define HC_CAP_DATA_BYTE_CFG_EN		BIT(4)	/* endian selection possible */
#define HC_CAP_AUTO_COMMAND		BIT(3)
#define HC_CAP_COMBO_COMMAND		BIT(2)

#define RESET_CONTROL			0x10
#define BUS_RESET			BIT(31)
#define BUS_RESET_TYPE			GENMASK(30, 29)
#define IBI_QUEUE_RST			BIT(5)
#define RX_FIFO_RST			BIT(4)
#define TX_FIFO_RST			BIT(3)
#define RESP_QUEUE_RST			BIT(2)
#define CMD_QUEUE_RST			BIT(1)
#define SOFT_RST			BIT(0)	/* Core Reset */

#define PRESENT_STATE			0x14
#define STATE_CURRENT_MASTER		BIT(2)

#define INTR_STATUS			0x20
#define INTR_STATUS_ENABLE		0x24
#define INTR_SIGNAL_ENABLE		0x28
#define INTR_FORCE			0x2c
#define INTR_HC_CMD_SEQ_UFLOW_STAT	BIT(12)	/* Cmd Sequence Underflow */
#define INTR_HC_RESET_CANCEL		BIT(11)	/* HC Cancelled Reset */
#define INTR_HC_INTERNAL_ERR		BIT(10)	/* HC Internal Error */
#define INTR_HC_PIO			BIT(8)	/* cascaded PIO interrupt */
#define INTR_HC_RINGS			GENMASK(7, 0)

#define DAT_SECTION			0x30	/* Device Address Table */
#define DAT_ENTRY_SIZE			GENMASK(31, 28)
#define DAT_TABLE_SIZE			GENMASK(18, 12)
#define DAT_TABLE_OFFSET		GENMASK(11, 0)

#define DCT_SECTION			0x34	/* Device Characteristics Table */
#define DCT_ENTRY_SIZE			GENMASK(31, 28)
#define DCT_TABLE_INDEX			GENMASK(23, 19)
#define DCT_TABLE_SIZE			GENMASK(18, 12)
#define DCT_TABLE_OFFSET		GENMASK(11, 0)

#define RING_HEADERS_SECTION		0x38
#define RING_HEADERS_OFFSET		GENMASK(15, 0)

#define PIO_SECTION			0x3c
#define PIO_REGS_OFFSET			GENMASK(15, 0)	/* PIO Offset */

#define EXT_CAPS_SECTION		0x40
#define EXT_CAPS_OFFSET			GENMASK(15, 0)

#define IBI_NOTIFY_CTRL			0x58	/* IBI Notify Control */
#define IBI_NOTIFY_SIR_REJECTED		BIT(3)	/* Rejected Target Interrupt Request */
#define IBI_NOTIFY_MR_REJECTED		BIT(1)	/* Rejected Master Request Control */
#define IBI_NOTIFY_HJ_REJECTED		BIT(0)	/* Rejected Hot-Join Control */

#define DEV_CTX_BASE_LO			0x60
#define DEV_CTX_BASE_HI			0x64

/* Aspeed in-house register */
#define ast_inhouse_read(r)		sys_read32(hci->INHOUSE_regs + (r))
#define ast_inhouse_write(r, v)		sys_write32(v, hci->INHOUSE_regs + (r))

#define ASPEED_I3C_CTRL			0x0
#define ASPEED_I3C_CTRL_STOP_QUEUE_PT	BIT(31) //Stop the queue read pointer.
#define ASPEED_I3C_SLV_CCC_NOTIFY_DIS	BIT(22) //Only generate the response with SETMRL/SETMWL
#define ASPEED_I3C_CTRL_INIT		BIT(4)
#define ASPEED_I3C_CTRL_INIT_MODE	GENMASK(1, 0)
#define INIT_MST_MODE 0
#define INIT_SEC_MST_MODE 1
#define INIT_SLV_MODE 2

#define ASPEED_I3C_STS	0x4
#define ASPEED_I3C_STS_SLV_DYNAMIC_ADDRESS_VALID	BIT(23)
#define ASPEED_I3C_STS_SLV_DYNAMIC_ADDRESS		GENMASK(22, 16)
#define ASPEED_I3C_STS_MODE_PURE_SLV			BIT(8)
#define ASPEED_I3C_STS_MODE_SECONDARY_SLV_TO_MST	BIT(7)
#define ASPEED_I3C_STS_MODE_SECONDARY_MST_TO_SLV	BIT(6)
#define ASPEED_I3C_STS_MODE_SECONDARY_SLV		BIT(5)
#define ASPEED_I3C_STS_MODE_SECONDARY_MST		BIT(4)
#define ASPEED_I3C_STS_MODE_PRIMARY_SLV_TO_MST		BIT(3)
#define ASPEED_I3C_STS_MODE_PRIMARY_MST_TO_SLV		BIT(2)
#define ASPEED_I3C_STS_MODE_PRIMARY_SLV			BIT(1)
#define ASPEED_I3C_STS_MODE_PRIMARY_MST			BIT(0)

#define ASPEED_I3C_DAA_INDEX0	0x10
#define ASPEED_I3C_DAA_INDEX1	0x14
#define ASPEED_I3C_DAA_INDEX2	0x18
#define ASPEED_I3C_DAA_INDEX3	0x1C

#define ASPEED_I3C_AUTOCMD_0	0x20
#define ASPEED_I3C_AUTOCMD_1	0x24
#define ASPEED_I3C_AUTOCMD_2	0x28
#define ASPEED_I3C_AUTOCMD_3	0x2C
#define ASPEED_I3C_AUTOCMD_4	0x30
#define ASPEED_I3C_AUTOCMD_5	0x34
#define ASPEED_I3C_AUTOCMD_6	0x38
#define ASPEED_I3C_AUTOCMD_7	0x3C

#define ASPEED_I3C_AUTOCMD_SEL_0_7	0x40
#define ASPEED_I3C_AUTOCMD_SEL_8_15	0x44
#define ASPEED_I3C_AUTOCMD_SEL_16_23	0x48
#define ASPEED_I3C_AUTOCMD_SEL_24_31	0x4C
#define ASPEED_I3C_AUTOCMD_SEL_32_39	0x50
#define ASPEED_I3C_AUTOCMD_SEL_40_47	0x54
#define ASPEED_I3C_AUTOCMD_SEL_48_55	0x58
#define ASPEED_I3C_AUTOCMD_SEL_56_63	0x5C
#define ASPEED_I3C_AUTOCMD_SEL_64_71	0x60
#define ASPEED_I3C_AUTOCMD_SEL_72_79	0x64
#define ASPEED_I3C_AUTOCMD_SEL_80_87	0x68
#define ASPEED_I3C_AUTOCMD_SEL_88_95	0x6C
#define ASPEED_I3C_AUTOCMD_SEL_96_103	0x70
#define ASPEED_I3C_AUTOCMD_SEL_104_111	0x74
#define ASPEED_I3C_AUTOCMD_SEL_112_119	0x78
#define ASPEED_I3C_AUTOCMD_SEL_120_127	0x7C

#define ASPEED_I3C_SLV_CHAR_CTRL	0xA0
#define ASPEED_I3C_SLV_CHAR_CTRL_DCR	GENMASK(23, 16)
#define ASPEED_I3C_SLV_CHAR_CTRL_BCR	GENMASK(15, 8)
#define     SLV_BCR_DEVICE_ROLE		GENMASK(7, 6)
#define ASPEED_I3C_SLV_CHAR_CTRL_STATIC_ADDR_EN	BIT(7)
#define ASPEED_I3C_SLV_CHAR_CTRL_STATIC_ADDR	GENMASK(6, 0)
#define SLV_PID_HI(x)			(((x) >> 32) & GENMASK(15, 0))
#define SLV_PID_LO(x)			((x) & GENMASK(31, 0))
#define ASPEED_I3C_SLV_PID_LO	0xA4
#define ASPEED_I3C_SLV_PID_HI	0xA8
#define ASPEED_I3C_SLV_FSM	0xAC
#define ASPEED_I3C_SLV_FSM_MASK GENMASK(5, 0)
#define ASPEED_I3C_SLV_FSM_HALT 0x16
#define ASPEED_I3C_SLV_CAP_CTRL	0xB0
#define ASPEED_I3C_SLV_CAP_CTRL_PEC_EN		BIT(31)
#define ASPEED_I3C_SLV_CAP_CTRL_HAIT_IF_IBI_ERR	BIT(30)
#define ASPEED_I3C_SLV_CAP_CTRL_ACCEPT_CR	BIT(16)
#define ASPEED_I3C_SLV_CAP_CTRL_HJ_REQ		BIT(10)
#define ASPEED_I3C_SLV_CAP_CTRL_MR_REQ		BIT(9)
#define ASPEED_I3C_SLV_CAP_CTRL_IBI_REQ		BIT(8)
#define ASPEED_I3C_SLV_CAP_CTRL_HJ_WAIT		BIT(6)
#define ASPEED_I3C_SLV_CAP_CTRL_MR_WAIT		BIT(5)
#define ASPEED_I3C_SLV_CAP_CTRL_IBI_WAIT	BIT(4)
#define ASPEED_I3C_SLV_CAP_CTRL_NOTSUP_DEF_BYTE	BIT(1)
#define ASPEED_I3C_SLV_CAP_CTRL_I2C_DEV		BIT(0)
/* CCC related registers */
#define ASPEED_I3C_SLV_STS1			0xB4
#define ASPEED_I3C_SLV_STS1_IBI_PAYLOAD_SIZE	GENMASK(31, 24)
#define ASPEED_I3C_SLV_STS1_RSTACT		GENMASK(22, 16)
/* the parameters for the HDR-DDR Data Transfer Early Termination procedure*/
#define ASPEED_I3C_SLV_STS1_ETP_ACK_CAP		BIT(15)
#define ASPEED_I3C_SLV_STS1_ETP_W_REQ		BIT(14)
#define ASPEED_I3C_SLV_STS1_ETP_CRC		GENMASK(13, 12)
#define ASPEED_I3C_SLV_STS1_ENDXFER_CONFIRM	BIT(11)
#define ASPEED_I3C_SLV_STS1_ENTER_TEST_MDOE	BIT(8)
#define ASPEED_I3C_SLV_STS1_HJ_EN		BIT(6)
#define ASPEED_I3C_SLV_STS1_CR_EN		BIT(5)
#define ASPEED_I3C_SLV_STS1_IBI_EN		BIT(4)
#define ASPEED_I3C_SLV_STS1_HJ_DONE		BIT(2)
#define ASPEED_I3C_SLV_STS1_CR_DONE		BIT(1)
#define ASPEED_I3C_SLV_STS1_IBI_DONE		BIT(0)
#define ASPEED_I3C_SLV_STS2			0xB8
#define ASPEED_I3C_SLV_STS2_MWL			GENMASK(31, 16)
#define ASPEED_I3C_SLV_STS2_MRL			GENMASK(15, 0)
#define ASPEED_I3C_SLV_STS3_GROUP_ADDR		0xBC
#define ASPEED_I3C_SLV_STS3_GROUP3_VALID	BIT(31)
#define ASPEED_I3C_SLV_STS3_GROUP3_ADDR		GENMASK(30, 24)
#define ASPEED_I3C_SLV_STS3_GROUP2_VALID	BIT(23)
#define ASPEED_I3C_SLV_STS3_GROUP2_ADDR		GENMASK(22, 16)
#define ASPEED_I3C_SLV_STS3_GROUP1_VALID	BIT(15)
#define ASPEED_I3C_SLV_STS3_GROUP1_ADDR		GENMASK(14, 8)
#define ASPEED_I3C_SLV_STS3_GROUP0_VALID	BIT(7)
#define ASPEED_I3C_SLV_STS3_GROUP0_ADDR		GENMASK(6, 0)
#define ASPEED_I3C_SLV_STS4_RSTACT_TIME		0xC0
#define ASPEED_I3C_SLV_STS4_DBG_NET		GENMASK(23, 16)
#define ASPEED_I3C_SLV_STS4_WHOLE_CHIP		GENMASK(15, 8)
#define ASPEED_I3C_SLV_STS4_I3C			GENMASK(7, 0)
#define ASPEED_I3C_SLV_STS5_GETMXDS_RW		0xC4
#define ASPEED_I3C_SLV_STS5_MAXWR		GENMASK(15, 8)
#define ASPEED_I3C_SLV_STS5_MAXRD		GENMASK(7, 0)
#define ASPEED_I3C_SLV_STS6_GETMXDS		0xC8
#define ASPEED_I3C_SLV_STS6_FORMAT		BIT(24)
#define ASPEED_I3C_SLV_STS6_MAXRD_TURN_H	GENMASK(23, 16)
#define ASPEED_I3C_SLV_STS6_MAXRD_TURN_M	GENMASK(15, 8)
#define ASPEED_I3C_SLV_STS6_MAXRD_TURN_L	GENMASK(7, 0)
#define ASPEED_I3C_SLV_STS7_GETSTATUS		0xCC
#define ASPEED_I3C_SLV_STS7_PRECR		GENMASK(31, 16)
#define ASPEED_I3C_SLV_STS7_TGT			GENMASK(15, 0)
#define ASPEED_I3C_SLV_STS8_GETCAPS_TGT		0xD0
#define ASPEED_I3C_SLV_STS9_GETCAPS_VT_CR	0xD4
#define ASPEED_I3C_SLV_STS7_VT			GENMASK(31, 16)
#define ASPEED_I3C_SLV_STS7_CR			GENMASK(15, 0)

#define ASPEED_I3C_QUEUE_PTR0		0xD8
#define QUEUE_PTR0_TX_R(q)		FIELD_GET(GENMASK(24, 20), q)
#define QUEUE_PTR0_TX_W(q)		FIELD_GET(GENMASK(16, 12), q)
#define QUEUE_PTR0_IBI_R(q)		FIELD_GET(GENMASK(11, 10), q)
#define QUEUE_PTR0_IBI_W(q)		FIELD_GET(GENMASK(9, 8), q)
#define QUEUE_PTR0_RESP_R(q)		FIELD_GET(GENMASK(7, 6), q)
#define QUEUE_PTR0_RESP_W(q)		FIELD_GET(GENMASK(5, 4), q)
#define QUEUE_PTR0_CMD_R(q)		FIELD_GET(GENMASK(3, 2), q)
#define QUEUE_PTR0_CMD_W(q)		FIELD_GET(GENMASK(1, 0), q)

#define ASPEED_I3C_QUEUE_PTR1		0xDC
#define QUEUE_PTR1_IBI_DATA_R(q)	FIELD_GET(GENMASK(28, 24), q)
#define QUEUE_PTR1_IBI_DATA_W(q)	FIELD_GET(GENMASK(20, 16), q)
#define QUEUE_PTR1_RX_R(q)	        FIELD_GET(GENMASK(12, 8), q)
#define QUEUE_PTR1_RX_W(q)	        FIELD_GET(GENMASK(4, 0), q)

#define ASPEED_I3C_INTR_STATUS		0xE0
#define ASPEED_I3C_INTR_STATUS_ENABLE	0xE4
#define ASPEED_I3C_INTR_SIGNAL_ENABLE	0xE8
#define ASPEED_I3C_INTR_FORCE		0xEC
#define ASPEED_I3C_INTR_I2C_SDA_STUCK_LOW	BIT(14)
#define ASPEED_I3C_INTR_I3C_SDA_STUCK_HIGH	BIT(13)
#define ASPEED_I3C_INTR_I3C_SDA_STUCK_LOW	BIT(12)
#define ASPEED_I3C_INTR_MST_INTERNAL_DONE	BIT(10)
#define ASPEED_I3C_INTR_MST_DDR_READ_DONE	BIT(9)
#define ASPEED_I3C_INTR_MST_DDR_WRITE_DONE	BIT(8)
#define ASPEED_I3C_INTR_MST_IBI_DONE		BIT(7)
#define ASPEED_I3C_INTR_MST_READ_DONE		BIT(6)
#define ASPEED_I3C_INTR_MST_WRITE_DONE		BIT(5)
#define ASPEED_I3C_INTR_MST_DAA_DONE		BIT(4)
#define ASPEED_I3C_INTR_SLV_SCL_STUCK		BIT(1)
#define ASPEED_I3C_INTR_TGRST			BIT(0)

#define ASPEED_I3C_INTR_SUM_STATUS	0xF0
#define ASPEED_INTR_SUM_INHOUSE		BIT(3)
#define ASPEED_INTR_SUM_RHS		BIT(2)
#define ASPEED_INTR_SUM_PIO		BIT(1)
#define ASPEED_INTR_SUM_CAP		BIT(0)

#define ASPEED_I3C_INTR_RENEW		0xF4

/* Aspeed Phy register */
#define ast_phy_read(r)			sys_read32(hci->PHY_regs + (r))
#define ast_phy_write(r, v)		sys_write32(v, hci->PHY_regs + (r))

/* I2C FM */
#define PHY_I2C_FM_CTRL0		0x8
#define PHY_I2C_FM_CTRL0_CAS		GENMASK(25, 16)
#define PHY_I2C_FM_CTRL0_SU_STO		GENMASK(9, 0)
#define PHY_I2C_FM_CTRL1		0xC
#define PHY_I2C_FM_CTRL1_SCL_H		GENMASK(25, 16)
#define PHY_I2C_FM_CTRL1_SCL_L		GENMASK(9, 0)
#define PHY_I2C_FM_CTRL2		0x10
#define PHY_I2C_FM_CTRL2_ACK_H		GENMASK(25, 16)
#define PHY_I2C_FM_CTRL2_ACK_L		GENMASK(9, 0)
#define PHY_I2C_FM_CTRL3		0x14
#define PHY_I2C_FM_CTRL3_HD_DAT		GENMASK(25, 16)
#define PHY_I2C_FM_CTRL3_AHD_DAT	GENMASK(9, 0)

#define PHY_I2C_FM_DEFAULT_CAS_NS	1130
#define PHY_I2C_FM_DEFAULT_SU_STO_NS	1370
#define PHY_I2C_FM_DEFAULT_SCL_H_NS	1130
#define PHY_I2C_FM_DEFAULT_SCL_L_NS	1370
#define PHY_I2C_FM_DEFAULT_HD_DAT	10
#define PHY_I2C_FM_DEFAULT_AHD_DAT	10

/* I2C FMP */
#define PHY_I2C_FMP_CTRL0		0x18
#define PHY_I2C_FMP_CTRL0_CAS		GENMASK(25, 16)
#define PHY_I2C_FMP_CTRL0_SU_STO	GENMASK(9, 0)
#define PHY_I2C_FMP_CTRL1		0x1C
#define PHY_I2C_FMP_CTRL1_SCL_H		GENMASK(25, 16)
#define PHY_I2C_FMP_CTRL1_SCL_L		GENMASK(9, 0)
#define PHY_I2C_FMP_CTRL2		0x20
#define PHY_I2C_FMP_CTRL2_ACK_H		GENMASK(25, 16)
#define PHY_I2C_FMP_CTRL2_ACK_L		GENMASK(9, 0)
#define PHY_I2C_FMP_CTRL3		0x24
#define PHY_I2C_FMP_CTRL3_HD_DAT	GENMASK(25, 16)
#define PHY_I2C_FMP_CTRL3_AHD_DAT	GENMASK(9, 0)

#define PHY_I2C_FMP_DEFAULT_CAS_NS	380
#define PHY_I2C_FMP_DEFAULT_SU_STO_NS	620
#define PHY_I2C_FMP_DEFAULT_SCL_H_NS	380
#define PHY_I2C_FMP_DEFAULT_SCL_L_NS	620
#define PHY_I2C_FMP_DEFAULT_HD_DAT	10
#define PHY_I2C_FMP_DEFAULT_AHD_DAT	10

/* I3C OD */
#define PHY_I3C_OD_CTRL0		0x28
#define PHY_I3C_OD_CTRL0_CAS		GENMASK(25, 16)
#define PHY_I3C_OD_CTRL0_SU_STO		GENMASK(9, 0)
#define PHY_I3C_OD_CTRL1		0x2C
#define PHY_I3C_OD_CTRL1_SCL_H		GENMASK(25, 16)
#define PHY_I3C_OD_CTRL1_SCL_L		GENMASK(9, 0)
#define PHY_I3C_OD_CTRL2		0x30
#define PHY_I3C_OD_CTRL2_ACK_H		GENMASK(25, 16)
#define PHY_I3C_OD_CTRL2_ACK_L		GENMASK(9, 0)
#define PHY_I3C_OD_CTRL3		0x34
#define PHY_I3C_OD_CTRL3_HD_DAT		GENMASK(25, 16)
#define PHY_I3C_OD_CTRL3_AHD_DAT	GENMASK(9, 0)

#define PHY_I3C_OD_DEFAULT_CAS_NS	40
#define PHY_I3C_OD_DEFAULT_SU_STO_NS	40
#define PHY_I3C_OD_DEFAULT_SCL_H_NS	380
#define PHY_I3C_OD_DEFAULT_SCL_L_NS	620
#define PHY_I3C_OD_DEFAULT_HD_DAT	10
#define PHY_I3C_OD_DEFAULT_AHD_DAT	10

/* I3C PP SDR0 */
#define PHY_I3C_SDR0_CTRL0			0x38
#define PHY_I3C_SDR0_CTRL0_SCL_H		GENMASK(25, 16)
#define PHY_I3C_SDR0_CTRL0_SCL_L		GENMASK(9, 0)
#define PHY_I3C_SDR0_CTRL1			0x3C
#define PHY_I3C_SDR0_CTRL1_TBIT_H		GENMASK(25, 16)
#define PHY_I3C_SDR0_CTRL1_TBIT_L		GENMASK(9, 0)
#define PHY_I3C_SDR0_CTRL2			0x40
#define PHY_I3C_SDR0_CTRL2_HD_PP		GENMASK(25, 16)
#define PHY_I3C_SDR0_CTRL2_TBIT_HD_PP		GENMASK(9, 0)

/* 1MHz */
#define PHY_I3C_SDR0_DEFAULT_SCL_H_NS		380
#define PHY_I3C_SDR0_DEFAULT_SCL_L_NS		620
#define PHY_I3C_SDR0_DEFAULT_TBIT_H_NS		380
#define PHY_I3C_SDR0_DEFAULT_TBIT_L_NS		620
#define PHY_I3C_SDR0_DEFAULT_HD_PP_NS		10
#define PHY_I3C_SDR0_DEFAULT_TBIT_HD_PP_NS	10

/* I3C PP SDR1 */
#define PHY_I3C_SDR1_CTRL0			0x44
#define PHY_I3C_SDR1_CTRL0_SCL_H		GENMASK(25, 16)
#define PHY_I3C_SDR1_CTRL0_SCL_L		GENMASK(9, 0)
#define PHY_I3C_SDR1_CTRL1			0x48
#define PHY_I3C_SDR1_CTRL1_TBIT_H		GENMASK(25, 16)
#define PHY_I3C_SDR1_CTRL1_TBIT_L		GENMASK(9, 0)
#define PHY_I3C_SDR1_CTRL2			0x4C
#define PHY_I3C_SDR1_CTRL2_HD_PP		GENMASK(25, 16)
#define PHY_I3C_SDR1_CTRL2_TBIT_HD_PP		GENMASK(9, 0)
/* I3C PP SDR2 */
#define PHY_I3C_SDR2_CTRL0			0x50
#define PHY_I3C_SDR2_CTRL0_SCL_H		GENMASK(25, 16)
#define PHY_I3C_SDR2_CTRL0_SCL_L		GENMASK(9, 0)
#define PHY_I3C_SDR2_CTRL1			0x54
#define PHY_I3C_SDR2_CTRL1_TBIT_H		GENMASK(25, 16)
#define PHY_I3C_SDR2_CTRL1_TBIT_L		GENMASK(9, 0)
#define PHY_I3C_SDR2_CTRL2			0x58
#define PHY_I3C_SDR2_CTRL2_HD_PP		GENMASK(25, 16)
#define PHY_I3C_SDR2_CTRL2_TBIT_HD_PP		GENMASK(9, 0)
/* I3C PP SDR3 */
#define PHY_I3C_SDR3_CTRL0			0x5C
#define PHY_I3C_SDR3_CTRL0_SCL_H		GENMASK(25, 16)
#define PHY_I3C_SDR3_CTRL0_SCL_L		GENMASK(9, 0)
#define PHY_I3C_SDR3_CTRL1			0x60
#define PHY_I3C_SDR3_CTRL1_TBIT_H		GENMASK(25, 16)
#define PHY_I3C_SDR3_CTRL1_TBIT_L		GENMASK(9, 0)
#define PHY_I3C_SDR3_CTRL2			0x64
#define PHY_I3C_SDR3_CTRL2_HD_PP		GENMASK(25, 16)
#define PHY_I3C_SDR3_CTRL2_TBIT_HD_PP		GENMASK(9, 0)
/* I3C PP SDR4 */
#define PHY_I3C_SDR5_CTRL0			0x68
#define PHY_I3C_SDR5_CTRL0_SCL_H		GENMASK(25, 16)
#define PHY_I3C_SDR5_CTRL0_SCL_L		GENMASK(9, 0)
#define PHY_I3C_SDR5_CTRL1			0x6C
#define PHY_I3C_SDR5_CTRL1_TBIT_H		GENMASK(25, 16)
#define PHY_I3C_SDR5_CTRL1_TBIT_L		GENMASK(9, 0)
#define PHY_I3C_SDR5_CTRL2			0x70
#define PHY_I3C_SDR5_CTRL2_HD_PP		GENMASK(25, 16)
#define PHY_I3C_SDR5_CTRL2_TBIT_HD_PP		GENMASK(9, 0)
/* I3C PP DDR */
#define PHY_I3C_DDR_CTRL0			0x74
#define PHY_I3C_DDR_CTRL0_SCL_H			GENMASK(25, 16)
#define PHY_I3C_DDR_CTRL0_SCL_L			GENMASK(9, 0)
#define PHY_I3C_DDR_CTRL1			0x78
#define PHY_I3C_DDR_CTRL1_TBIT_H		GENMASK(25, 16)
#define PHY_I3C_DDR_CTRL1_TBIT_L		GENMASK(9, 0)
#define PHY_I3C_DDR_CTRL2			0x7C
#define PHY_I3C_DDR_CTRL2_HD_PP			GENMASK(25, 16)
#define PHY_I3C_DDR_CTRL2_TBIT_HD_PP		GENMASK(9, 0)

/* 1MHz */
#define PHY_I3C_DDR_DEFAULT_SCL_H_NS		380
#define PHY_I3C_DDR_DEFAULT_SCL_L_NS		620
#define PHY_I3C_DDR_DEFAULT_TBIT_H_NS		380
#define PHY_I3C_DDR_DEFAULT_TBIT_L_NS		620
#define PHY_I3C_DDR_DEFAULT_HD_PP_NS		10
#define PHY_I3C_DDR_DEFAULT_TBIT_HD_PP_NS	10

#define PHY_I3C_SR_P_PREPARE_CTRL		0x80
#define PHY_I3C_SR_P_PREPARE_CTRL_HD		GENMASK(25, 16)
#define PHY_I3C_SR_P_PREPARE_CTRL_SCL_L		GENMASK(9, 0)
#define PHY_I3C_SR_P_DEFAULT_HD_NS	10
#define PHY_I3C_SR_P_DEFAULT_SCL_L_NS	40

#define PHY_PULLUP_EN		0x98
#define PHY_PULLUP_EN_SCL	GENMASK(14, 12)
#define PHY_PULLUP_EN_SDA	GENMASK(10, 8)
#define PHY_PULLUP_EN_DDR_SCL	GENMASK(6, 4)
#define PHY_PULLUP_EN_DDR_SDA	GENMASK(2, 0)

/*
 * PIO Access Area
 */

#define pio_reg_read(r)		sys_read32((uintptr_t)hci->PIO_regs + (PIO_##r))
#define pio_reg_write(r, v)	sys_write32(v, (uintptr_t)hci->PIO_regs + (PIO_##r))

#define PIO_COMMAND_QUEUE_PORT		0x00
#define PIO_RESPONSE_QUEUE_PORT		0x04
#define PIO_XFER_DATA_PORT		0x08
#define PIO_IBI_PORT			0x0c

#define PIO_QUEUE_THLD_CTRL		0x10
#define QUEUE_IBI_STATUS_THLD		GENMASK(31, 24)
#define QUEUE_IBI_DATA_THLD		GENMASK(23, 16)
#define QUEUE_RESP_BUF_THLD		GENMASK(15, 8)
#define QUEUE_CMD_EMPTY_BUF_THLD	GENMASK(7, 0)

#define PIO_DATA_BUFFER_THLD_CTRL	0x14
#define DATA_RX_START_THLD		GENMASK(26, 24)
#define DATA_TX_START_THLD		GENMASK(18, 16)
#define DATA_RX_BUF_THLD		GENMASK(10, 8)
#define DATA_TX_BUF_THLD		GENMASK(2, 0)

#define PIO_QUEUE_SIZE			0x18
#define TX_DATA_BUFFER_SIZE		GENMASK(31, 24)
#define RX_DATA_BUFFER_SIZE		GENMASK(23, 16)
#define IBI_STATUS_SIZE			GENMASK(15, 8)
#define CR_QUEUE_SIZE			GENMASK(7, 0)

#define PIO_INTR_STATUS			0x20
#define PIO_INTR_STATUS_ENABLE		0x24
#define PIO_INTR_SIGNAL_ENABLE		0x28
#define PIO_INTR_FORCE			0x2c
#define STAT_TRANSFER_ERR		BIT(9)
#define STAT_TRANSFER_ABORT		BIT(5)
#define STAT_RESP_READY			BIT(4)
#define STAT_CMD_QUEUE_READY		BIT(3)
#define STAT_IBI_STATUS_THLD		BIT(2)
#define STAT_RX_THLD			BIT(1)
#define STAT_TX_THLD			BIT(0)

#define PIO_QUEUE_CUR_STATUS		0x38
#define CUR_IBI_Q_LEVEL			GENMASK(28, 20)
#define CUR_RESP_Q_LEVEL		GENMASK(18, 10)
#define CUR_CMD_Q_EMPTY_LEVEL		GENMASK(8, 0)

#define PIO_DATA_BUFFER_CUR_STATUS	0x3c
#define CUR_RX_BUF_LVL			GENMASK(26, 16)
#define CUR_TX_BUF_LVL			GENMASK(10, 0)

/*
 * Handy status bit combinations
 */
#define STAT_ALL_ERRORS			(STAT_TRANSFER_ABORT | \
					 STAT_TRANSFER_ERR)

/*
 * Target mode Response Descriptor Structure
 */
#define TARGET_RESP_STATUS(resp)	FIELD_GET(GENMASK(31, 28), resp)
#define TARGET_RESP_XFER_TYPE(resp)	FIELD_GET(BIT(27), resp)
#define TARGET_RESP_XFER_TYPE_W		0
#define TARGET_RESP_XFER_TYPE_R		1
#define TARGET_RESP_CCC_INDICATE(resp)	FIELD_GET(BIT(26), resp)
#define TARGET_RESP_TID(resp)		FIELD_GET(GENMASK(25, 24), resp)
#define TARGET_RESP_CCC_HDR(resp)	FIELD_GET(GENMASK(23, 16), resp)
#define TARGET_RESP_SDR_PRIV_XFER	0
#define TARGET_RESP_DATA_LENGTH(resp) FIELD_GET(GENMASK(15, 0), resp)

#define SCU1_REG	0x14c02000
#define SCU1_OTPCFG	(SCU1_REG + 0x880)
#define SCU1_OTPCFG_15_14		(SCU1_OTPCFG + 0x1c)
#define   SCU1_OTPCFG14_SIZE_SEC0	GENMASK(15, 0)
#define   SCU1_OTPCFG15_I3C_I2C_CH	GENMASK(19, 16)
#define   SCU1_OTPCFG15_I3C_HJ_REQ	BIT(20)
#define   SCU1_OTPCFG15_I3C_DCR		GENMASK(31, 24)
#define   SCU1_OTPCFG15_I2C_SLAVE_ADDR	GENMASK(31, 24)

#define SCU1_PINMUX_GRP_I	(SCU1_REG + 0x420)
#define SCU1_PINMUX_GRP_J	(SCU1_REG + 0x424)
#define SCU1_PINMUX_GRP_K	(SCU1_REG + 0x428)
#define SCU1_PINMUX_GRP_L	(SCU1_REG + 0x42c)

#define SCU1_RSTCTL1			(SCU1_REG + 0x200)
#define   SCU1_RSTCTL1_I3C(x)		(BIT(16) << (x))
#define SCU1_RSTCTL1_CLR		(SCU1_REG + 0x204)
#define   SCU1_RSTCTL1_CLR_I3C(x)	(BIT(16) << (x))

#define SCU1_CLKGATE1		(SCU1_REG + 0x240)
#define   SCU1_CLKGATE1_I3C(x)	(BIT(16) << (x))
#define   SCU1_CLKGATE1_I2C	BIT(15)

#define SCU1_CLKGATE1_CLR		(SCU1_REG + 0x244)
#define   SCU1_CLKGATE1_CLR_I3C(x)	(BIT(16) << (x))
#define   SCU1_CLKGATE1_CLR_I2C		BIT(15)

#define I3C_REG(x) (0x14c20000 + 0x1000 * (x))

#define MIPI_VENDOR_ASPEED 0x3f6
/* Aspeed part id: G6 A1 */
#define PART_ID_ASPEED 0x0601
/* Extended Capability Header */
#define CAP_HEADER_LENGTH GENMASK(23, 8)
#define CAP_HEADER_ID GENMASK(7, 0)

#define DBG(...)

#define I3C_PID(manuf_id, pid_type, part_id, instance_id, extra_info) \
	((((u_int64_t)(manuf_id) & GENMASK(14, 0)) << 33) |                   \
	 ((u_int64_t)!!(pid_type) << 32) |                                 \
	 (((u_int64_t)(part_id) & GENMASK(14, 0)) << 16) |                    \
	 (((u_int64_t)(instance_id) & GENMASK(3, 0)) << 12) |                 \
	 ((u_int64_t)(extra_info) & GENMASK(11, 0)))

/* Bootrom only supoort this two command*/
enum ocp_recovery_command {
	OCP_REC_CTRL = 0x26,
	OCP_INDIRECT_DATA = 0x2B,
};

#define OCP_REC_CTRL_BYTES 3
#define OCP_REC_CTRL_CMS_BYTE 0
#define OCP_REC_CTRL_IMG_SEL_BYTE 1
#define OCP_REC_CTRL_IMG_SEL_CMS 0x1
#define OCP_REC_CTRL_IMG_SEL_CIMAGE 0x2
#define OCP_REC_CTRL_ACTIVATE_BYTE 2
#define OCP_REC_CTRL_ACTIVATE_REC_IMG 0xF

struct i3c_recovey_packet {
	uint8_t command;
	uint8_t len_hi;
	uint8_t len_lo;
	uint8_t payload[125];
};

struct i3c_hci {
	uint32_t index;
	uint32_t caps;
	mem_addr_t base_regs;
	mem_addr_t PIO_regs;
	mem_addr_t EXTCAPS_regs;
	mem_addr_t INHOUSE_regs;
	mem_addr_t PHY_regs;
	/* Temp buffer to store the data from PIO fifo*/
	uint8_t data[128];
};

static void clrsetbits_le32(mm_reg_t addr, uint32_t clr, uint32_t set)
{
	sys_write32((sys_read32(addr) & (~clr)) | set, addr);
}

static int hci_extcap_vendor_ASPEED(struct i3c_hci *hci, mem_addr_t base)
{
	uint32_t regs_offset;

	regs_offset = sys_read32(base + 1 * 4);
	hci->INHOUSE_regs = hci->base_regs + regs_offset;
	DBG("INHOUSE control at offset %x\n", regs_offset);
	regs_offset = sys_read32(base + 2 * 4);
	hci->PHY_regs = hci->base_regs + regs_offset;
	DBG("PHY_regs control at offset %x\n", regs_offset);
	return 0;
}

static int i3c_hci_parse_ext_caps(struct i3c_hci *hci)
{
	mem_addr_t curr_cap = hci->EXTCAPS_regs;
	mem_addr_t end = curr_cap + 0x1000; /* some arbitrary limit */
	uint32_t cap_header, cap_id, cap_length;
	int err = 0;

	if (!curr_cap)
		return 0;

	for (; !err && curr_cap < end; curr_cap += cap_length * 4) {
		cap_header = sys_read32(curr_cap);
		cap_id = FIELD_GET(CAP_HEADER_ID, cap_header);
		cap_length = FIELD_GET(CAP_HEADER_LENGTH, cap_header);
		DBG("id=0x%02x length=%d\n", cap_id, cap_length);
		if (!cap_length)
			break;
		if (curr_cap + cap_length * 4 >= end)
			break;

		if (cap_id >= 0xc0 && cap_id <= 0xcf) {
			err = hci_extcap_vendor_ASPEED(hci, curr_cap);
			continue;
		}
	}
	return 0;
}

static void i3c_pio_init(struct i3c_hci *hci)
{
	uint32_t val;

	val = FIELD_PREP(QUEUE_RESP_BUF_THLD, 1) | FIELD_PREP(QUEUE_CMD_EMPTY_BUF_THLD, 1);
	pio_reg_write(QUEUE_THLD_CTRL, val);

	/* Disable all IRQs but allow all status bits */
	pio_reg_write(INTR_SIGNAL_ENABLE, 0x0);
	pio_reg_write(INTR_STATUS_ENABLE, 0xffffffff);
}

static void i3c_target_read_rx_fifo(struct i3c_hci *hci, unsigned int count, void *buf)
{
	uint32_t *p = buf;

	if (count >= 4) {
		unsigned int nr_words = count / 4;

		while (nr_words--)
			*p++ = pio_reg_read(XFER_DATA_PORT);
	}
	count &= 3;
	if (count) {
		uint8_t *p_byte = (uint8_t *)p;
		uint32_t data = pio_reg_read(XFER_DATA_PORT);

		data = (uint32_t)sys_cpu_to_le32(data);
		while (count--) {
			*p_byte++ = data;
			data >>= 8;
		}
	}
}

static int i3c_pio_process_resp(struct i3c_hci *hci, uint8_t *data)
{
	uint32_t resp = pio_reg_read(RESPONSE_QUEUE_PORT);
	size_t nbytes = TARGET_RESP_DATA_LENGTH(resp);

	DBG("resp status:%lx, xfer type:%lx, CCC_INDI:%lx tid:%lx, CCC_HDR: %lx, data legth: %lx\n",
	    TARGET_RESP_STATUS(resp), TARGET_RESP_XFER_TYPE(resp), TARGET_RESP_CCC_INDICATE(resp),
	    TARGET_RESP_TID(resp), TARGET_RESP_CCC_HDR(resp), TARGET_RESP_DATA_LENGTH(resp));

	if (TARGET_RESP_STATUS(resp))
		return -TARGET_RESP_STATUS(resp);

	if (TARGET_RESP_CCC_INDICATE(resp)) {
		if (TARGET_RESP_XFER_TYPE(resp)) {
			i3c_target_read_rx_fifo(hci, nbytes, data);
			/* TODO: Handle the SET CCC */
			return -ENOTSUP;
		}
	} else if (TARGET_RESP_XFER_TYPE(resp)) {
		i3c_target_read_rx_fifo(hci, nbytes, data);
		return nbytes;
	}
	return 0;
}

/*
 * HV I3C: index 0~3(GRP_L), 12~15(GRP_I)
 * LV I3C: index 4~11(GRP_J and GRP_K)
 */
#define field_prep(_mask, _val) (((_val) << (ffs(_mask) - 1)) & (_mask))
static void i3c_pinctrl_setting(uint8_t index)
{
	uint32_t mask, value, bit_shift, gpio_group;

	bit_shift = (index & 0x3) << 3;
	mask = GENMASK(7 + bit_shift, 0 + bit_shift);
	value = field_prep(mask, 0x11);
	gpio_group = index >> 2;

	switch (gpio_group) {
	case 0:
		clrsetbits_le32(SCU1_PINMUX_GRP_L, mask, value);
		break;
	case 1:
		clrsetbits_le32(SCU1_PINMUX_GRP_J, mask, value);
		break;
	case 2:
		clrsetbits_le32(SCU1_PINMUX_GRP_K, mask, value);
		break;
	case 3:
		clrsetbits_le32(SCU1_PINMUX_GRP_I, mask, value);
		break;
	default:
		break;
	}
}

static int i3c_target_bus_init(struct i3c_hci *hci)
{
	u_int64_t pid;
	uint8_t bcr;
	uint8_t dcr;
	uint8_t hdr_cap = 0;
	uint32_t reg;

	pid = I3C_PID(MIPI_VENDOR_ASPEED, 0, PART_ID_ASPEED, hci->index, 0);
	ast_inhouse_write(ASPEED_I3C_SLV_PID_LO, SLV_PID_LO(pid));
	ast_inhouse_write(ASPEED_I3C_SLV_PID_HI, SLV_PID_HI(pid));
	bcr = I3C_BCR_DEVICE_ROLE(I3C_BCR_I3C_SLAVE) | I3C_BCR_HDR_CAP | I3C_BCR_IBI_PAYLOAD |
	      I3C_BCR_IBI_REQ_CAP;
	/* Generic device */
	dcr = FIELD_GET(SCU1_OTPCFG15_I3C_DCR, sys_read32(SCU1_OTPCFG_15_14));
	DBG("dcr = %x\n", dcr);
	ast_inhouse_write(ASPEED_I3C_SLV_CHAR_CTRL,
			  FIELD_PREP(ASPEED_I3C_SLV_CHAR_CTRL_DCR, dcr) |
				  FIELD_PREP(ASPEED_I3C_SLV_CHAR_CTRL_BCR, bcr));
	/* Make slave will send the ibi when bus idle */
	reg = ast_inhouse_read(ASPEED_I3C_SLV_CAP_CTRL);
	ast_inhouse_write(ASPEED_I3C_SLV_CAP_CTRL,
			  reg | ASPEED_I3C_SLV_CAP_CTRL_IBI_WAIT | ASPEED_I3C_SLV_CAP_CTRL_HJ_WAIT);
	if (hci->caps & HC_CAP_HDR_DDR_EN)
		hdr_cap |= BIT(I3C_HDR_DDR);
	if (hci->caps & HC_CAP_HDR_TS_EN) {
		if (reg_read(HC_CONTROL) & HC_CONTROL_I2C_TARGET_PRESENT)
			hdr_cap |= BIT(I3C_HDR_TSL);
		else
			hdr_cap |= BIT(I3C_HDR_TSP);
	}
	if (hci->caps & HC_CAP_HDR_BT_EN)
		hdr_cap |= BIT(I3C_HDR_BT);

	ast_inhouse_write(ASPEED_I3C_SLV_STS8_GETCAPS_TGT, hdr_cap);

	ast_inhouse_write(ASPEED_I3C_CTRL,
			  ASPEED_I3C_CTRL_INIT | ASPEED_I3C_SLV_CCC_NOTIFY_DIS |
				  FIELD_PREP(ASPEED_I3C_CTRL_INIT_MODE, INIT_SEC_MST_MODE));

	i3c_pio_init(hci);

	reg_set(HC_CONTROL, HC_CONTROL_BUS_ENABLE);

	return 0;
}

static void i3c_wait_address_assign(struct i3c_hci *hci)
{
	uint32_t reg;
	bool hj_req_en;

	reg = sys_read32(SCU1_OTPCFG_15_14);
	hj_req_en = FIELD_GET(SCU1_OTPCFG15_I3C_HJ_REQ, reg);
	while (!(ast_inhouse_read(ASPEED_I3C_STS) & ASPEED_I3C_STS_SLV_DYNAMIC_ADDRESS_VALID)) {
		if (hj_req_en) {
			if (ast_inhouse_read(ASPEED_I3C_SLV_STS1) & ASPEED_I3C_SLV_STS1_HJ_EN) {
				reg = ast_inhouse_read(ASPEED_I3C_SLV_CAP_CTRL);
				ast_inhouse_write(ASPEED_I3C_SLV_CAP_CTRL,
						  reg | ASPEED_I3C_SLV_CAP_CTRL_HJ_REQ);
				k_busy_wait(10);
			}
		}
	}
	DBG("Dynamic address assigned 0x%lx\n",
	    FIELD_GET(ASPEED_I3C_STS_SLV_DYNAMIC_ADDRESS, ast_inhouse_read(ASPEED_I3C_STS)));
}

static int i3c_init(struct device *dev)
{
	struct i3c_hci *hci = DEV_DATA(dev);
	uint32_t regval, offset;
	int ret;

	regval = sys_read32(SCU1_OTPCFG_15_14);
	hci->index = FIELD_GET(SCU1_OTPCFG15_I3C_I2C_CH, regval);
	hci->base_regs = (mem_addr_t)I3C_REG(hci->index);

	DBG("Choice I3C%d for recovery\n", hci->index);

	i3c_pinctrl_setting(hci->index);

	/* assert reset */
	sys_write32(SCU1_RSTCTL1_I3C(hci->index), SCU1_RSTCTL1);
	/* clk gate */
	sys_write32(SCU1_CLKGATE1_I3C(hci->index), SCU1_CLKGATE1);
	k_busy_wait(1);
	/* de-assert reset and delay */
	/* clk ungate */
	sys_write32(SCU1_CLKGATE1_CLR_I3C(hci->index), SCU1_CLKGATE1_CLR);
	sys_write32(SCU1_RSTCTL1_CLR_I3C(hci->index), SCU1_RSTCTL1_CLR);
	k_busy_wait(1000);

	hci->caps = reg_read(HC_CAPABILITIES);
	DBG("caps = %x\n", hci->caps);

	regval = reg_read(PIO_SECTION);
	offset = FIELD_GET(PIO_REGS_OFFSET, regval);
	hci->PIO_regs = offset ? hci->base_regs + offset : (mem_addr_t)NULL;
	DBG("PIO section at offset %x\n", offset);

	regval = reg_read(EXT_CAPS_SECTION);
	offset = FIELD_GET(EXT_CAPS_OFFSET, regval);
	hci->EXTCAPS_regs = offset ? hci->base_regs + offset : (mem_addr_t)NULL;
	DBG("Extended Caps at offset %x\n", offset);

	i3c_hci_parse_ext_caps(hci);

        ret = readx_poll_timeout(reg_read, RESET_CONTROL, regval,
                                 !(regval & SOFT_RST), 0, 10000);
        if (ret)
          return -EINVAL;
        reg_write(RESET_CONTROL, SOFT_RST);
        ret = readx_poll_timeout(reg_read, RESET_CONTROL, regval,
                                 !(regval & SOFT_RST), 0, 10000);

        if (ret)
		return -EINVAL;

	/* Disable all interrupts and allow all signal updates */
	reg_write(INTR_SIGNAL_ENABLE, 0x0);
	reg_write(INTR_STATUS_ENABLE, 0xffffffff);
	ast_inhouse_write(ASPEED_I3C_INTR_SIGNAL_ENABLE, 0);
	ast_inhouse_write(ASPEED_I3C_INTR_STATUS_ENABLE, 0xffffffff);

	/* Make sure our data ordering fits the host's (little endian) */
	regval = reg_read(HC_CONTROL);
	if (regval & HC_CONTROL_DATA_BIG_ENDIAN) {
		regval &= ~HC_CONTROL_DATA_BIG_ENDIAN;
		reg_write(HC_CONTROL, regval);
		regval = reg_read(HC_CONTROL);
		if (regval & HC_CONTROL_DATA_BIG_ENDIAN) {
			DBG("cannot clear BE mode\n");
			return -EINVAL;
		}
	}

	/* Activating PIO mode */
	reg_set(HC_CONTROL, HC_CONTROL_PIO_MODE);
	if (!(reg_read(HC_CONTROL) & HC_CONTROL_PIO_MODE)) {
		DBG("DMA mode is stuck\n");
		return -EINVAL;
	}

	i3c_target_bus_init(hci);
	i3c_wait_address_assign(hci);

	return 0;
}

void i3c_deinit(struct device *dev)
{
	struct i3c_hci *hci = DEV_DATA(dev);

	/* assert reset */
	sys_write32(SCU1_RSTCTL1_I3C(hci->index), SCU1_RSTCTL1);
	/* clk gate */
	sys_write32(SCU1_CLKGATE1_I3C(hci->index), SCU1_CLKGATE1);
}

void mipi_i3c_hci_resume(struct i3c_hci *hci)
{
	reg_set(HC_CONTROL, HC_CONTROL_RESUME);
}

int i3c_poll_in_forever(struct i3c_hci *hci, uint8_t *data, uint32_t *size)
{
	uint32_t status;
	int ret;

	while (true) {
		status = pio_reg_read(INTR_STATUS);
		if (status & STAT_RESP_READY) {
			ret = i3c_pio_process_resp(hci, data);
			if (ret <= 0) {
				if (!ret || ret == -ENOTSUP)
					continue;
				else
					return -ret;
			}
			*size = ret;
			break;
		}
		if (FIELD_GET(ASPEED_I3C_SLV_FSM_MASK, ast_inhouse_read(ASPEED_I3C_SLV_FSM)) ==
		    ASPEED_I3C_SLV_FSM_HALT) {
			DBG("Detect i3c enter halt, resum it\n");
			mipi_i3c_hci_resume(hci);
		}
	}
	return 0;
}

/*
 * from: don't care.
 * *dst: destination address to move to
 * len: required length, if not equal, return failre
 */
static int i3c_recovery(struct device *dev, uint32_t *dst, uint32_t *len)
{
	struct i3c_hci *hci = DEV_DATA(dev);
	uint32_t size, packet_size, received_size = 0;
	uint8_t *io_sram_ptr;
	struct i3c_recovey_packet const *hdr;
	int resp_sts = 0;

	io_sram_ptr = (uint8_t *)dst;
	while (1) {
		resp_sts = i3c_poll_in_forever(hci, hci->data, &size);
		if (resp_sts)
			return resp_sts;
		hdr = (struct i3c_recovey_packet *)hci->data;
		packet_size = (hdr->len_hi << 8) | hdr->len_lo;
		DBG("command: 0x%x, length: %x, hw received size: %x\n", hdr->command, packet_size,
		    size);
		/*
		 * Packet size should same as hardware received size.
		 * Header size = 3 bytes, PEC size = 1 byte, DDR padding data = 1bytes
		 * Without PEC, the packet size should equal to hw received size - Header size
		 * With PEC, it should be minus an additional 1 byte.
		 * With DDR mode, the packet size is even with PEC then need to minus padding data
		 */
		if (packet_size != size - 3 && packet_size != size - 4 && packet_size != size - 5)
			return -EINVAL;
		if (hdr->command == OCP_REC_CTRL) {
			if (packet_size != OCP_REC_CTRL_BYTES)
				continue;
			if (hdr->payload[OCP_REC_CTRL_CMS_BYTE] == 0 &&
			    hdr->payload[OCP_REC_CTRL_IMG_SEL_BYTE] == OCP_REC_CTRL_IMG_SEL_CMS &&
			    hdr->payload[OCP_REC_CTRL_ACTIVATE_BYTE] ==
				    OCP_REC_CTRL_ACTIVATE_REC_IMG)
				break;
		} else if (hdr->command == OCP_INDIRECT_DATA) {
			received_size += packet_size;
			memcpy(io_sram_ptr, hdr->payload, packet_size);
			io_sram_ptr += packet_size;
		}
	}

	DBG("received_size = %x\n", received_size);
	*len = received_size;

	return 0;
}

static struct ast_loader_ops booti3c_ops = {
	.init = i3c_init,
	.load = i3c_recovery,
};

int i3c_register(struct ast_loader *loader)
{
	struct device *dev;

	dev = (struct device *)device_get_binding("i3c@recovery");
	if (!dev) {
		LOG_ERR("No device named i3c");
		return -1;
	}

	loader->ops = &booti3c_ops;
	loader->dev = dev;

	LOG_DBG("I3C loader registered");

	return 0;
}

DEVICE_DEFINE(i3c, "i3c@recovery", NULL, NULL,
		&g_hci, NULL,
		POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
		NULL);