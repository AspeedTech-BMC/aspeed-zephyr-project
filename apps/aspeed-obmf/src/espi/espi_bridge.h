/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ESPI_BRIDGE_H
#define ESPI_BRIDGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <zephyr/device.h>
#include <zephyr/sys/util.h>

#include "lstp/lstp_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

struct k_work_q;

/* The bridged controllers come from the topology; lstp_backend.h checks them. */
#define ESPI_NODE  DT_PHANDLE(LSTP_BACKEND_NODE, espi_controller)
#define SNOOP_NODE DT_PHANDLE(LSTP_BACKEND_NODE, snoop_controller)

/* SoC blocks the bridge programs directly; there is one of each. */
#define ASPEED_ESPI_BASE DT_REG_ADDR(ESPI_NODE)
#define ASPEED_LPC_BASE  DT_REG_ADDR(DT_NODELABEL(lsc))
#define ASPEED_SCU_BASE  DT_REG_ADDR(DT_NODELABEL(syscon))
#define ASPEED_GPIO_BASE DT_REG_ADDR(DT_NODELABEL(gpio0))

#define ESPI_CTRL_REG       (ASPEED_ESPI_BASE + 0x000)
#define ESPI_STS_REG        (ASPEED_ESPI_BASE + 0x004)
#define ESPI_INT_STS_REG    (ASPEED_ESPI_BASE + 0x008)
#define ESPI_INT_EN_REG     (ASPEED_ESPI_BASE + 0x00c)
#define ESPI_GEN_CAP_REG    (ASPEED_ESPI_BASE + 0x014)
#define ESPI_CH0_CAP_REG    (ASPEED_ESPI_BASE + 0x018)
#define ESPI_CH1_CAP_REG    (ASPEED_ESPI_BASE + 0x01c)
#define ESPI_CH2_CAP_REG    (ASPEED_ESPI_BASE + 0x020)
#define ESPI_CH3_CAP_REG    (ASPEED_ESPI_BASE + 0x024)
#define ESPI_CH3_CAP2_REG   (ASPEED_ESPI_BASE + 0x028)
#define ESPI_DEV_STS_REG    (ASPEED_ESPI_BASE + 0x030)
#define ESPI_CH0_CTRL_REG   (ASPEED_ESPI_BASE + 0x100)
#define ESPI_CH0_STS_REG    (ASPEED_ESPI_BASE + 0x104)
#define ESPI_CH0_INT_STS_REG (ASPEED_ESPI_BASE + 0x108)
#define ESPI_CH0_INT_EN_REG  (ASPEED_ESPI_BASE + 0x10c)
#define ESPI_CH0_MCYC1_SADDRL_REG (ASPEED_ESPI_BASE + 0x158)
#define ESPI_CH0_MCYC1_SADDRH_REG (ASPEED_ESPI_BASE + 0x15c)
#define ESPI_CH0_MCYC1_TADDRL_REG (ASPEED_ESPI_BASE + 0x160)
#define ESPI_CH0_MCYC1_TADDRH_REG (ASPEED_ESPI_BASE + 0x164)
#define ESPI_CH0_MCYC1_MASKL_REG  (ASPEED_ESPI_BASE + 0x168)
#define ESPI_CH0_MCYC1_MASKH_REG  (ASPEED_ESPI_BASE + 0x16c)
#define ESPI_CH0_MCYC1_MASKL_FW   BIT(1) /* cycles go to FW via PC/NP FIFO */
#define ESPI_CH0_MCYC1_MASKL_EN   BIT(0)
#define ESPI_CH0_CTRL_MCYC_RD_DIS BIT(6)
#define ESPI_CH0_CTRL_MCYC_WR_DIS BIT(4)
#define ESPI_CH0_CTRL_SW_RDY      BIT(1)
#define ESPI_CH0_INT_EN_NP_RX_VALID BIT(2)
#define ESPI_CH0_INT_EN_PC_RX_CMPLT BIT(0)
#define ESPI_CH1_CTRL_REG   (ASPEED_ESPI_BASE + 0x200)
#define ESPI_CH1_CTRL_AUTO_ACK_BOOT_DONE BIT(8)
#define ESPI_CH1_CTRL_AUTO_ACK_BOOT_STS  BIT(7)
#define ESPI_CH1_STS_REG    (ASPEED_ESPI_BASE + 0x204)
#define ESPI_EVT0_REG       (ASPEED_ESPI_BASE + 0x210)
#define ESPI_EVT1_REG       (ASPEED_ESPI_BASE + 0x230)
#define ESPI_VW_GPIO_VAL0   (ASPEED_ESPI_BASE + 0x250)
#define ESPI_VW_GPIO_VAL1   (ASPEED_ESPI_BASE + 0x254)
#define ESPI_VW_GPIO_DIR0   (ASPEED_ESPI_BASE + 0x258)
#define ESPI_VW_GPIO_DIR1   (ASPEED_ESPI_BASE + 0x25c)
#define ESPI_VW_GPIO_GRP    (ASPEED_ESPI_BASE + 0x268)
#define ESPI_VW_GP50_DIR0   (ASPEED_ESPI_BASE + 0x270)
#define ESPI_VW_GP50_DIR1   (ASPEED_ESPI_BASE + 0x274)
#define ESPI_VW_GP50_VAL0   (ASPEED_ESPI_BASE + 0x278)
#define ESPI_VW_GP50_VAL1   (ASPEED_ESPI_BASE + 0x27c)
#define ESPI_CH2_CTRL_REG   (ASPEED_ESPI_BASE + 0x300)
#define ESPI_CH2_STS_REG    (ASPEED_ESPI_BASE + 0x304)
#define ESPI_CH3_CTRL_REG   (ASPEED_ESPI_BASE + 0x400)
#define ESPI_CH3_STS_REG    (ASPEED_ESPI_BASE + 0x404)

#define ESPI_ASPEED_VW_GPIO_INDEX_MIN 0x80
#define ESPI_ASPEED_VW_GPIO_INDEX_MAX 0x8f
#define ESPI_ASPEED_VW_GPIO_SRC_COUNT 4

enum espi_aspeed_vw_gpio_direction {
	ESPI_ASPEED_VW_GPIO_CONTROLLER_TO_TARGET = 0,
	ESPI_ASPEED_VW_GPIO_TARGET_TO_CONTROLLER = 1,
};

#define GPIO_PIN0_CTRL_REG (ASPEED_GPIO_BASE + 0x180)
#define GPIO_PIN1_CTRL_REG (ASPEED_GPIO_BASE + 0x184)
#define GPIO_PIN2_CTRL_REG (ASPEED_GPIO_BASE + 0x188)
#define GPIO_PIN3_CTRL_REG (ASPEED_GPIO_BASE + 0x18c)
#define GPIO_DATA_ABCD_REG (ASPEED_GPIO_BASE + 0x000)

int espi_perif_mem_read(uint32_t offset, void *buf, size_t len);
int espi_perif_mem_write(uint32_t offset, const void *buf, size_t len);
size_t espi_perif_mem_get_size(void);
uint32_t espi_perif_mem_get_base_addr(void);

struct k_work_q *espi_bridge_work_queue(void);

enum espi_memtrace_mode {
	ESPI_MEMTRACE_OFF = 0,
	ESPI_MEMTRACE_WR,  /* host writes only */
	ESPI_MEMTRACE_RW,  /* host writes and reads */
};

void espi_bridge_set_memtrace(enum espi_memtrace_mode mode);
enum espi_memtrace_mode espi_bridge_get_memtrace(void);

int espi_portio_read(uint16_t port, uint8_t *val);
int espi_portio_write(uint16_t port, uint8_t val);

/* Keep OBMF mirrors above ESPI_MIRROR_BASE; the lower window belongs to MMBI. */
#define ESPI_MIRROR_BASE            0x8000U

#define ESPI_PORT80_OFFSET          (ESPI_MIRROR_BASE + 0x0000U) /* 1 byte: POST code, port 0x80 */
#define ESPI_PORT81_OFFSET          (ESPI_MIRROR_BASE + 0x0001U) /* 1 byte: POST code, port 0x81 */

#define ESPI_VWIRE_IN_OFFSET        (ESPI_MIRROR_BASE + 0x0002U) /* 4 bytes: Host -> AST2700 Virtual Wires (Read-only) */
#define ESPI_VWIRE_OUT_OFFSET       (ESPI_MIRROR_BASE + 0x0006U) /* 4 bytes: AST2700 -> Host Virtual Wires (Read/Write) */

#define ESPI_VW_HW_EVT0_OFFSET      (ESPI_MIRROR_BASE + 0x0010U) /* 4 bytes: EVT0 (0x210) System Events 0..4 */
#define ESPI_VW_HW_EVT1_OFFSET      (ESPI_MIRROR_BASE + 0x0014U) /* 4 bytes: EVT1 (0x230) System Events 5+ */
#define ESPI_VW_HW_GPIO0_OFFSET     (ESPI_MIRROR_BASE + 0x0018U) /* 4 bytes: GPIO_VAL0 (0x250) VGPIO 0x80..0x87 */
#define ESPI_VW_HW_GPIO1_OFFSET     (ESPI_MIRROR_BASE + 0x001CU) /* 4 bytes: GPIO_VAL1 (0x254) VGPIO 0x88..0x8F */
#define ESPI_VW_HW_GP50_0_OFFSET    (ESPI_MIRROR_BASE + 0x0020U) /* 4 bytes: GP50_VAL0 (0x278) GP50 0x50..0x57 */
#define ESPI_VW_HW_GP50_1_OFFSET    (ESPI_MIRROR_BASE + 0x0024U) /* 4 bytes: GP50_VAL1 (0x27C) GP50 0x58..0x5F */

#define ESPI_VW_GROUP_TABLE_OFFSET  (ESPI_MIRROR_BASE + 0x0030U)
#define ESPI_VW_GROUP_MAX           208U

#define ESPI_VWIRE_IN_PLTRST        BIT(0)
#define ESPI_VWIRE_IN_SLP_S3        BIT(1)
#define ESPI_VWIRE_IN_SLP_S4        BIT(2)
#define ESPI_VWIRE_IN_SLP_S5        BIT(3)
#define ESPI_VWIRE_IN_HOST_RST_WARN BIT(4)
#define ESPI_VWIRE_IN_OOB_RST_WARN  BIT(5)
#define ESPI_VWIRE_IN_SUS_STAT      BIT(6)
#define ESPI_VWIRE_IN_SUS_PWRDN_ACK BIT(7)
#define ESPI_VWIRE_IN_SLP_A         BIT(8)
#define ESPI_VWIRE_IN_SUS_WARN      BIT(9)
#define ESPI_VWIRE_IN_SLP_LAN       BIT(10)
#define ESPI_VWIRE_IN_SLP_WLAN      BIT(11)
#define ESPI_VWIRE_IN_HOST_C10      BIT(12)

#define ESPI_VWIRE_OUT_SMI          BIT(0)
#define ESPI_VWIRE_OUT_SCI          BIT(1)
#define ESPI_VWIRE_OUT_HOST_RST_ACK BIT(2)
#define ESPI_VWIRE_OUT_OOB_RST_ACK  BIT(3)
#define ESPI_VWIRE_OUT_RST_CPU_INIT BIT(4)
#define ESPI_VWIRE_OUT_TARGET_BOOT_DONE BIT(5)
#define ESPI_VWIRE_OUT_TARGET_BOOT_STS  BIT(6)
#define ESPI_VWIRE_OUT_PME          BIT(7)
#define ESPI_VWIRE_OUT_WAKE         BIT(8)
#define ESPI_VWIRE_OUT_RCIN         BIT(9)
#define ESPI_VWIRE_OUT_SUS_ACK      BIT(10)
#define ESPI_VWIRE_OUT_ERR_FATAL    BIT(11)
#define ESPI_VWIRE_OUT_ERR_NONFATAL BIT(12)

/* ESPI210: SMI/SCI/PME/WAKE are read-only; ACK/boot wires use hardware auto-ack.
 * RST_CPU_INIT and RCIN# alias bit 26. ERR_FATAL/NONFATAL are software-writable. */

void espi_vwire_bridge_init(void);
void espi_vwire_sync_all_to_mmio(void);
void espi_vwire_set_output_reg(uint32_t val);
/* Write perif memory that overlaps the VWIRE_OUT mirror and apply the result. */
int espi_vwire_write_output_mirror(uint32_t offset, const uint8_t *data, size_t len);
void espi_vwire_on_rx_event(void);

int espi_bridge_aspeed_vw_gpio_get_direction(const struct device *dev, uint8_t index,
					     uint8_t source,
					     enum espi_aspeed_vw_gpio_direction *direction);
int espi_bridge_aspeed_vw_gpio_get(const struct device *dev, uint8_t index, uint8_t source,
				   uint8_t *level);

/* Read-only reliability diagnostics (LE32) */
#define ESPI_DIAG_UART_RX_DROP_OFFSET  (ESPI_MIRROR_BASE + 0x03C0U)
#define ESPI_DIAG_UART_TX_DROP_OFFSET  (ESPI_MIRROR_BASE + 0x03C4U)
#define ESPI_DIAG_USB_RESP_DROP_OFFSET (ESPI_MIRROR_BASE + 0x03C8U)
#define ESPI_DIAG_USB_EVT_DROP_OFFSET  (ESPI_MIRROR_BASE + 0x03CCU)
#define ESPI_DIAG_USB_RX_DROP_OFFSET   (ESPI_MIRROR_BASE + 0x03D0U)
#define ESPI_DIAG_USB_ERROR_OFFSET     (ESPI_MIRROR_BASE + 0x03D4U)
#define ESPI_DIAG_USB_HIGH_WATER_OFF   (ESPI_MIRROR_BASE + 0x03D8U)
/* Reserved: unsolicited channels are best-effort, nothing retries. Always 0. */
#define ESPI_DIAG_UART_RETRY_OFFSET    (ESPI_MIRROR_BASE + 0x03DCU)
#define ESPI_DIAG_UART_DROP_OFFSET     (ESPI_MIRROR_BASE + 0x03E0U)
/* Reserved: see ESPI_DIAG_UART_RETRY_OFFSET. Always 0. */
#define ESPI_DIAG_GPIO_RETRY_OFFSET    (ESPI_MIRROR_BASE + 0x03E4U)
#define ESPI_DIAG_GPIO_DROP_OFFSET     (ESPI_MIRROR_BASE + 0x03E8U)
#define ESPI_DIAG_GPIO_QUEUE_DROP_OFF  (ESPI_MIRROR_BASE + 0x03ECU)

const struct device *espi_bridge_get_dev(void);

/*
 * One system-event virtual wire: where it sits in ESPI EVT0/EVT1 and which
 * ESPI_VWIRE_IN_* / ESPI_VWIRE_OUT_* mirror bits it drives (0 when it is only
 * shown, never mirrored).
 */
struct espi_vw_bit_info {
	const char *name;
	uint8_t evt; /* 0 = EVT0, 1 = EVT1 */
	uint8_t bit;
	uint32_t in_mask;
	uint32_t out_mask;
};

extern const struct espi_vw_bit_info espi_vw_bit_map[];
extern const size_t espi_vw_bit_count;
bool espi_bridge_monitor_is_active(void);
int espi_bridge_set_monitor(bool enable);

struct espi_bridge_snoop_stats {
	uint32_t elapsed_ms;
	uint32_t port80_count;
	uint32_t ch1_count;
	uint32_t dropped;
	uint32_t lstp_errors;
	uint64_t rate;
};

void espi_bridge_get_snoop_stats(struct espi_bridge_snoop_stats *stats);
void espi_bridge_reset_snoop_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* ESPI_BRIDGE_H */
