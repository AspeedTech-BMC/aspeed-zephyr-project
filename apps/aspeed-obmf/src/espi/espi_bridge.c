/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/espi.h>
#include <zephyr/drivers/espi_aspeed.h>
#include <zephyr/drivers/misc/aspeed/snoop_aspeed.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/sys_io.h>
#include <zephyr/sys/util.h>

#include "espi_bridge.h"
#include "espi_oob_bridge.h"
#include "gpio/lstp_gpio.h"
#include "espi_mmbi.h"

#include "safs_handler.h"

LOG_MODULE_REGISTER(espi_bridge, CONFIG_LOG_DEFAULT_LEVEL);

static K_THREAD_STACK_DEFINE(espi_bridge_work_stack, 2048);
static struct k_work_q espi_bridge_workq;

struct k_work_q *espi_bridge_work_queue(void)
{
	return &espi_bridge_workq;
}

#define ESPI_MONITOR_PERIOD K_MSEC(50)
#define ESPI_SERVICE_PERIOD K_MSEC(1)
#define PERIF_TX_TIMEOUT_MS 100

#define ESPI_TEST_REGION_BASE DT_PROP_BY_IDX(ESPI_NODE, perif_mcyc_src_addr, 1)
#define ESPI_TEST_REGION_SIZE DT_PROP_BY_IDX(ESPI_NODE, perif_mcyc_size, 1)

BUILD_ASSERT(DT_PROP_BY_IDX(ESPI_NODE, perif_mcyc_src_addr, 0) == 0,
	     "OBMF eSPI test service supports only 32-bit host addresses");
BUILD_ASSERT(DT_PROP_BY_IDX(ESPI_NODE, perif_mcyc_size, 0) == 0,
	     "OBMF eSPI test service supports a region smaller than 4 GiB");

static const struct device *const espi_dev = DEVICE_DT_GET(ESPI_NODE);
static const struct device *snoop_dev = DEVICE_DT_GET(SNOOP_NODE);

const struct device *espi_bridge_get_dev(void)
{
	if (!device_is_ready(espi_dev)) {
		return NULL;
	}
	return espi_dev;
}

static atomic_t espi_monitor_active = ATOMIC_INIT(0); /* debug printk monitor, off by default */
static struct espi_callback espi_vwire_cb;
static struct k_work espi_vwire_work;
static struct k_work_delayable espi_monitor_work;
static struct k_work_delayable espi_service_work;
static struct k_work_sync espi_monitor_sync;

static uint32_t last_evt0;
static uint32_t last_evt1;
static uint32_t last_vw_gpio0;
static uint32_t last_vw_gp50;
static uint32_t last_pin0_ctrl;
static uint32_t last_pin1_ctrl;
static uint32_t last_pin2_ctrl;
static uint32_t last_pin3_ctrl;
static uint32_t last_data_abcd;

static uint8_t perif_mem[ESPI_TEST_REGION_SIZE];

/*
 * Host MEMWR may not touch what the firmware owns: the MMBI descriptor, HROP
 * and B2H ring (the low half of the MMBI instance) and the OBMF mirror up to
 * the end of the OOB mailboxes (VWIRE_OUT, OOB status/control/TX). Otherwise
 * a host write could set OOB TX TRIGGER or an SMI bit in the VWIRE_OUT
 * mirror. The reliability diagnostics above the mailboxes are read-only too.
 */
static bool perif_host_write_allowed(uint32_t off, uint32_t len)
{
	const uint32_t end = off + len;

	if (off < MMBI_HALF_SIZE) {
		return false;
	}
	if (off < ESPI_DIAG_GPIO_QUEUE_DROP_OFF + sizeof(uint32_t) &&
	    end > ESPI_DIAG_UART_RX_DROP_OFFSET) {
		return false;
	}
	return end <= ESPI_MIRROR_BASE || off >= ESPI_OOB_MAILBOX_END;
}
static K_MUTEX_DEFINE(perif_mem_lock);

BUILD_ASSERT(MMBI_INSTANCE_OFFSET + MMBI_INSTANCE_SIZE <= ESPI_MIRROR_BASE,
	     "MMBI instance overlaps the obmf MMIO mirrors");
BUILD_ASSERT(ESPI_MIRROR_BASE + 0x400U <= ESPI_TEST_REGION_SIZE,
	     "obmf MMIO mirrors do not fit in the peripheral memory window");

int espi_perif_mem_read(uint32_t offset, void *buf, size_t len)
{
	if (!buf) {
		return -EINVAL;
	}
	if (offset >= sizeof(perif_mem) || len > sizeof(perif_mem) - offset) {
		return -EINVAL;
	}

	k_mutex_lock(&perif_mem_lock, K_FOREVER);
	memcpy(buf, perif_mem + offset, len);
	k_mutex_unlock(&perif_mem_lock);

	return 0;
}

int espi_perif_mem_write(uint32_t offset, const void *buf, size_t len)
{
	if (!buf && len > 0) {
		return -EINVAL;
	}
	if (offset >= sizeof(perif_mem) || len > sizeof(perif_mem) - offset) {
		return -EINVAL;
	}

	k_mutex_lock(&perif_mem_lock, K_FOREVER);
	if (len > 0) {
		memcpy(perif_mem + offset, buf, len);
	}
	k_mutex_unlock(&perif_mem_lock);

	return 0;
}

size_t espi_perif_mem_get_size(void)
{
	return sizeof(perif_mem);
}

uint32_t espi_perif_mem_get_base_addr(void)
{
	return ESPI_TEST_REGION_BASE;
}

bool espi_bridge_monitor_is_active(void)
{
	return atomic_get(&espi_monitor_active) != 0;
}

static void espi_snapshot_state(void);

int espi_bridge_set_monitor(bool enable)
{
	if (enable) {
		if (atomic_cas(&espi_monitor_active, 0, 1)) {
			espi_snapshot_state();
			k_work_reschedule_for_queue(&espi_bridge_workq, &espi_monitor_work,
						    ESPI_MONITOR_PERIOD);
		}
	} else {
		atomic_set(&espi_monitor_active, 0);
		(void)k_work_cancel_delayable_sync(&espi_monitor_work, &espi_monitor_sync);
	}
	return 0;
}

/*
 * The driver stores a 64-bit cycle as header + 8-byte address + data, but
 * struct espi_perif_mem64 declares a 32-bit address; size from the wire format.
 */
#define PERIF_RX_HDR_MAX (sizeof(struct espi_comm_hdr) + sizeof(uint64_t))

static uint8_t perif_pc_rx_buf[PERIF_RX_HDR_MAX + ESPI_PLD_LEN_MAX];
static uint8_t perif_np_rx_buf[PERIF_RX_HDR_MAX + sizeof(uint32_t)];
static uint8_t perif_pc_tx_buf[sizeof(struct espi_perif_cmplt) + ESPI_PLD_LEN_MAX];

static bool perif_tx_pending;
static int64_t perif_tx_started;
static uint32_t perif_tx_dropped;
static struct espi_aspeed_ioc perif_tx_ioc = { .pkt = perif_pc_tx_buf };

static uint16_t espi_packet_len(const struct espi_comm_hdr *hdr)
{
	uint16_t len = ((uint16_t)hdr->len_h << 8) | hdr->len_l;

	return len ? len : ESPI_PLD_LEN_MAX;
}

static bool range_is_valid(uint32_t addr, uint32_t base, size_t size, size_t len)
{
	return addr >= base && len <= size && (addr - base) <= (size - len);
}

static atomic_t espi_memtrace_mode = ATOMIC_INIT(ESPI_MEMTRACE_OFF);

void espi_bridge_set_memtrace(enum espi_memtrace_mode mode)
{
	atomic_set(&espi_memtrace_mode, (atomic_val_t)mode);
}

enum espi_memtrace_mode espi_bridge_get_memtrace(void)
{
	return (enum espi_memtrace_mode)atomic_get(&espi_memtrace_mode);
}

/* Name the MMBI structure an in-window offset lands in, for readable traces. */
static const char *espi_memtrace_region(uint32_t off, uint32_t *rel)
{
	static const struct {
		uint32_t base;
		uint32_t size;
		const char *name;
	} map[] = {
		{ MMBI_DESCRIPTOR_OFFSET, MMBI_DESCRIPTOR_SIZE, "DESC" },
		{ MMBI_HROP_OFFSET,       MMBI_HROP_SIZE,       "HROP" },
		{ MMBI_B2H_CB_OFFSET,     MMBI_B2H_CB_SIZE,     "B2H" },
		{ MMBI_HRWP_OFFSET,       MMBI_HRWP_SIZE,       "HRWP" },
		{ MMBI_H2B_CB_OFFSET,     MMBI_H2B_CB_SIZE,     "H2B" },
	};

	for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
		if (off >= map[i].base && off < map[i].base + map[i].size) {
			*rel = off - map[i].base;
			return map[i].name;
		}
	}

	*rel = off;
	return "?";
}

static void espi_memtrace_pkt(const char *fifo, const struct espi_comm_hdr *hdr,
			      uint16_t len, size_t pkt_len)
{
	if (espi_bridge_get_memtrace() == ESPI_MEMTRACE_OFF) {
		return;
	}

	printk("[CH0 %s] cyc=0x%02x tag=0x%x len=%u pkt_len=%zu\n",
	       fifo, hdr->cyc, hdr->tag, len, pkt_len);
}

static void espi_memtrace(bool is_wr, uint32_t addr, const uint8_t *data, uint16_t len)
{
	enum espi_memtrace_mode mode = espi_bridge_get_memtrace();

	if (mode == ESPI_MEMTRACE_OFF || (mode == ESPI_MEMTRACE_WR && !is_wr)) {
		return;
	}

	if (!range_is_valid(addr, ESPI_TEST_REGION_BASE, sizeof(perif_mem), len)) {
		printk("[CH0 MEM] %s addr=0x%08x len=%u OUT-OF-WINDOW (window 0x%08x+0x%zx)\n",
		       is_wr ? "WR" : "RD", addr, len,
		       (uint32_t)ESPI_TEST_REGION_BASE, sizeof(perif_mem));
		return;
	}

	uint32_t off = addr - ESPI_TEST_REGION_BASE;
	uint32_t rel;
	const char *region = espi_memtrace_region(off, &rel);

	printk("[CH0 MEM] %s addr=0x%08x off=0x%05x %s+0x%x len=%u",
	       is_wr ? "WR" : "RD", addr, off, region, rel, len);

	if (data != NULL) {
		uint16_t show = MIN(len, 32U);

		printk(" |");
		for (uint16_t i = 0; i < show; i++) {
			printk(" %02x", data[i]);
		}
		if (show < len) {
			printk(" ...");
		}
	}
	printk("\n");
}

static void espi_config_pinmux(void)
{
	uint32_t val;

	val = sys_read32(ASPEED_SCU_BASE + 0x43c);
	val = (val & ~0x77000000U) | 0x11000000U;
	sys_write32(val, ASPEED_SCU_BASE + 0x43c);

	val = sys_read32(ASPEED_SCU_BASE + 0x440);
	val = (val & ~0x00777777U) | 0x00111111U;
	sys_write32(val, ASPEED_SCU_BASE + 0x440);
}

#define VW_IN(name, evt, bit, mask)  { name, evt, bit, mask, 0 }
#define VW_OUT(name, evt, bit, mask) { name, evt, bit, 0, mask }
#define VW_SHOW(name, evt, bit)      { name, evt, bit, 0, 0 }

/* The single place that knows the ESPI210/ESPI230 bit of each wire. */
const struct espi_vw_bit_info espi_vw_bit_map[] = {
	VW_IN("SLP_S3#", 0, 0, ESPI_VWIRE_IN_SLP_S3),
	VW_IN("SLP_S4#", 0, 1, ESPI_VWIRE_IN_SLP_S4),
	VW_IN("SLP_S5#", 0, 2, ESPI_VWIRE_IN_SLP_S5),
	VW_IN("SUS_STAT#", 0, 4, ESPI_VWIRE_IN_SUS_STAT),
	VW_IN("PLTRST#", 0, 5, ESPI_VWIRE_IN_PLTRST),
	VW_IN("OOB_RST_WARN", 0, 6, ESPI_VWIRE_IN_OOB_RST_WARN),
	VW_IN("HOST_RST_WARN", 0, 8, ESPI_VWIRE_IN_HOST_RST_WARN),
	VW_SHOW("SMIOUT#", 0, 9),
	VW_SHOW("NMIOUT#", 0, 10),
	VW_OUT("OOB_RST_ACK", 0, 16, ESPI_VWIRE_OUT_OOB_RST_ACK),
	VW_OUT("WAKE#", 0, 18, ESPI_VWIRE_OUT_WAKE),
	VW_OUT("PME#", 0, 19, ESPI_VWIRE_OUT_PME),
	VW_OUT("TARGET_BOOT_DONE", 0, 20, ESPI_VWIRE_OUT_TARGET_BOOT_DONE),
	VW_OUT("ERR_FATAL", 0, 21, ESPI_VWIRE_OUT_ERR_FATAL),
	VW_OUT("ERR_NON_FATAL", 0, 22, ESPI_VWIRE_OUT_ERR_NONFATAL),
	VW_OUT("TARGET_BOOT_STS", 0, 23, ESPI_VWIRE_OUT_TARGET_BOOT_STS),
	VW_OUT("SCI#", 0, 24, ESPI_VWIRE_OUT_SCI),
	VW_OUT("SMI#", 0, 25, ESPI_VWIRE_OUT_SMI),
	/* RST_CPU_INIT and RCIN# share bit 26. */
	VW_OUT("RCIN#", 0, 26, ESPI_VWIRE_OUT_RST_CPU_INIT | ESPI_VWIRE_OUT_RCIN),
	VW_OUT("HOST_RST_ACK", 0, 27, ESPI_VWIRE_OUT_HOST_RST_ACK),
	VW_IN("SUS_WARN#", 1, 0, ESPI_VWIRE_IN_SUS_WARN),
	VW_IN("SUS_PWRDN_ACK", 1, 1, ESPI_VWIRE_IN_SUS_PWRDN_ACK),
	VW_IN("SLP_A#", 1, 3, ESPI_VWIRE_IN_SLP_A),
	VW_IN("SLP_LAN#", 1, 4, ESPI_VWIRE_IN_SLP_LAN),
	VW_IN("SLP_WLAN#", 1, 5, ESPI_VWIRE_IN_SLP_WLAN),
	VW_IN("HOST_C10", 1, 16, ESPI_VWIRE_IN_HOST_C10),
	VW_OUT("SUS_ACK#", 1, 20, ESPI_VWIRE_OUT_SUS_ACK),
};

const size_t espi_vw_bit_count = ARRAY_SIZE(espi_vw_bit_map);

static void print_vwire_changes(uint32_t prev0, uint32_t prev1, uint32_t cur0, uint32_t cur1)
{
	const uint32_t prev[2] = { prev0, prev1 };
	const uint32_t cur[2] = { cur0, cur1 };

	for (size_t i = 0; i < espi_vw_bit_count; i++) {
		const struct espi_vw_bit_info *sig = &espi_vw_bit_map[i];

		if (((prev[sig->evt] ^ cur[sig->evt]) & BIT(sig->bit)) == 0U) {
			continue;
		}

		printk("  - %-17s: %u -> %u\n", sig->name,
		       !!(prev[sig->evt] & BIT(sig->bit)), !!(cur[sig->evt] & BIT(sig->bit)));
	}
}

static uint8_t virtual_port_io[65536];
static uint8_t virtual_sio_idx;
static K_MUTEX_DEFINE(portio_lock);

struct espi_snoop_event {
	uint8_t channel;
	uint8_t data;
};

#define ESPI_SNOOP_QUEUE_DEPTH 64
K_MSGQ_DEFINE(espi_snoop_queue, sizeof(struct espi_snoop_event),
	      ESPI_SNOOP_QUEUE_DEPTH, 4);
static struct k_work espi_snoop_work;
static atomic_t espi_snoop_dropped;
static atomic_t espi_snoop_port80_count;
static atomic_t espi_snoop_ch1_count;
static atomic_t espi_snoop_stats_start_ms;

int espi_portio_read(uint16_t port, uint8_t *val)
{
	if (!val) {
		return -EINVAL;
	}
	k_mutex_lock(&portio_lock, K_FOREVER);
	*val = virtual_port_io[port];
	k_mutex_unlock(&portio_lock);
	return 0;
}

int espi_portio_write(uint16_t port, uint8_t val)
{
	k_mutex_lock(&portio_lock, K_FOREVER);
	virtual_port_io[port] = val;
	k_mutex_unlock(&portio_lock);
	return 0;
}

void espi_bridge_get_snoop_stats(struct espi_bridge_snoop_stats *stats)
{
	uint32_t now = k_uptime_get_32();
	uint32_t elapsed_ms = now - (uint32_t)atomic_get(&espi_snoop_stats_start_ms);
	uint32_t ch1_count = (uint32_t)atomic_get(&espi_snoop_ch1_count);

	stats->elapsed_ms = elapsed_ms;
	stats->port80_count = (uint32_t)atomic_get(&espi_snoop_port80_count);
	stats->ch1_count = ch1_count;
	stats->dropped = (uint32_t)atomic_get(&espi_snoop_dropped);
	stats->lstp_errors = 0U; /* Retain the shared stats layout. */
	stats->rate = (elapsed_ms == 0U) ? 0U : ((uint64_t)ch1_count * 1000U) / elapsed_ms;
}

void espi_bridge_reset_snoop_stats(void)
{
	atomic_set(&espi_snoop_port80_count, 0);
	atomic_set(&espi_snoop_ch1_count, 0);
	atomic_set(&espi_snoop_dropped, 0);
	atomic_set(&espi_snoop_stats_start_ms, (atomic_val_t)k_uptime_get_32());
}

static void espi_snoop_queue_byte(uint8_t channel, uint8_t data)
{
	struct espi_snoop_event event = {
		.channel = channel,
		.data = data,
	};

	if (k_msgq_put(&espi_snoop_queue, &event, K_NO_WAIT) != 0) {
		atomic_inc(&espi_snoop_dropped);
		return;
	}

	k_work_submit_to_queue(&espi_bridge_workq, &espi_snoop_work);
}

static void espi_snoop_rx_callback(const uint8_t *snoop0, const uint8_t *snoop1)
{
	if (snoop0 != NULL) {
		atomic_inc(&espi_snoop_port80_count);
		espi_snoop_queue_byte(0, *snoop0);
	}

	if (snoop1 != NULL) {
		atomic_inc(&espi_snoop_ch1_count);
		espi_snoop_queue_byte(1, *snoop1);
	}
}

static void espi_snoop_work_handler(struct k_work *work)
{
	struct espi_snoop_event event;

	ARG_UNUSED(work);

	/* Snoop only mirrors POST codes; the UART bridge is VUART0's job. */
	while (k_msgq_get(&espi_snoop_queue, &event, K_NO_WAIT) == 0) {
		if (event.channel == 0U) {
			espi_portio_write(0x80U, event.data);
			espi_perif_mem_write(ESPI_PORT80_OFFSET, &event.data, 1);
		} else {
			espi_portio_write(0x81U, event.data);
			espi_perif_mem_write(ESPI_PORT81_OFFSET, &event.data, 1);
		}
	}
}

static void espi_monitor_work_handler(struct k_work *work)
{
	uint32_t cur_evt0, cur_evt1, cur_vw_gpio0, cur_vw_gp50;
	uint32_t cur_pin0, cur_pin1, cur_pin2, cur_pin3, cur_data_abcd;

	ARG_UNUSED(work);
	if (!atomic_get(&espi_monitor_active)) {
		return;
	}

	cur_evt0 = sys_read32(ESPI_EVT0_REG);
	cur_evt1 = sys_read32(ESPI_EVT1_REG);
	cur_vw_gpio0 = sys_read32(ESPI_VW_GPIO_VAL0);
	cur_vw_gp50 = sys_read32(ESPI_VW_GP50_VAL0);
	cur_pin0 = sys_read32(GPIO_PIN0_CTRL_REG);
	cur_pin1 = sys_read32(GPIO_PIN1_CTRL_REG);
	cur_pin2 = sys_read32(GPIO_PIN2_CTRL_REG);
	cur_pin3 = sys_read32(GPIO_PIN3_CTRL_REG);
	cur_data_abcd = sys_read32(GPIO_DATA_ABCD_REG);

	if (cur_pin0 != last_pin0_ctrl || cur_pin1 != last_pin1_ctrl ||
	    cur_pin2 != last_pin2_ctrl || cur_pin3 != last_pin3_ctrl ||
	    cur_data_abcd != last_data_abcd) {
		printk("\n>>> [AST1040 GPIO change] <<<\n");
		printk("  GPIOA0: %08x (out:%u dir:%u in:%u)\n", cur_pin0,
		       cur_pin0 & 1, (cur_pin0 >> 1) & 1, (cur_pin0 >> 13) & 1);
		printk("  GPIOA1: %08x (out:%u dir:%u in:%u)\n", cur_pin1,
		       cur_pin1 & 1, (cur_pin1 >> 1) & 1, (cur_pin1 >> 13) & 1);
		printk("  GPIOA2: %08x (out:%u dir:%u in:%u)\n", cur_pin2,
		       cur_pin2 & 1, (cur_pin2 >> 1) & 1, (cur_pin2 >> 13) & 1);
		printk("  GPIOA3: %08x (out:%u dir:%u in:%u)\n", cur_pin3,
		       cur_pin3 & 1, (cur_pin3 >> 1) & 1, (cur_pin3 >> 13) & 1);
		printk("  GPIO A-D data: %08x\n", cur_data_abcd);
		last_pin0_ctrl = cur_pin0;
		last_pin1_ctrl = cur_pin1;
		last_pin2_ctrl = cur_pin2;
		last_pin3_ctrl = cur_pin3;
		last_data_abcd = cur_data_abcd;
	}

	if (cur_evt0 != last_evt0 || cur_evt1 != last_evt1 ||
	    cur_vw_gpio0 != last_vw_gpio0 || cur_vw_gp50 != last_vw_gp50) {
		printk("\n>>> [eSPI Virtual Wire update] (Forwarded to AST2700) <<<\n");
		printk("  EVT0: %08x EVT1: %08x\n", cur_evt0, cur_evt1);
		printk("  VW GPIO ESPI250: %08x\n", cur_vw_gpio0);
		printk("  VW GP50 ESPI278: %08x\n", cur_vw_gp50);
		print_vwire_changes(last_evt0, last_evt1, cur_evt0, cur_evt1);

		espi_vwire_on_rx_event();

		last_evt0 = cur_evt0;
		last_evt1 = cur_evt1;
		last_vw_gpio0 = cur_vw_gpio0;
		last_vw_gp50 = cur_vw_gp50;
	}

	static uint8_t last_mbx_data[16];
	for (int i = 0; i < 16; i++) {
		uint8_t mbx_val = sys_read32(ASPEED_LPC_BASE + 0x200 + (i << 2)) & 0xff;
		if (mbx_val != last_mbx_data[i]) {
			uint16_t mbox_port = 0x300 + i;
			printk("\n>>> [eSPI Mailbox Port 0x%04x] Data: 0x%02x (Forwarded to AST2700) <<<\n",
			       mbox_port, mbx_val);
			k_mutex_lock(&portio_lock, K_FOREVER);
			virtual_port_io[mbox_port] = mbx_val;
			k_mutex_unlock(&portio_lock);
			last_mbx_data[i] = mbx_val;
		}
	}

	if (atomic_get(&espi_monitor_active)) {
		k_work_reschedule_for_queue(&espi_bridge_workq, &espi_monitor_work,
					    ESPI_MONITOR_PERIOD);
	}
}

static void espi_configure_lpc_bridge(void)
{
	uint32_t lpc = ASPEED_LPC_BASE;

	/* Enable LPC channels 0..2. HICR0[0] is read-only on AST1040. */
	uint32_t hicr0 = sys_read32(lpc + 0x00);
	hicr0 |= (BIT(7) | BIT(6) | BIT(5));
	sys_write32(hicr0, lpc + 0x00);

	/* HICRB[18] disables physical UART0 so VUART0 exclusively owns port 0x3F8. */
	uint32_t hicrb = sys_read32(lpc + 0x100);
	WRITE_BIT(hicrb, 18, IS_ENABLED(CONFIG_OBMF_ESPI_UART_VUART));
	sys_write32(hicrb, lpc + 0x100);
}

/*
 * vwire_lock serialises the LSTP task (MMIO reads, vwire SetValue) against the
 * bridge work queue (edge detection) on the caches and the EVT0/EVT1 RMW.
 * s_vwire_in_reported is owned by the edge detector, so a sync from another
 * thread cannot swallow an edge before it is reported.
 */
static K_MUTEX_DEFINE(vwire_lock);
static uint32_t s_vwire_in_cached;
static uint32_t s_vwire_out_cached;
static uint32_t s_vwire_in_reported;

/* Translate EVT0/EVT1 into the ESPI_VWIRE_IN_* and ESPI_VWIRE_OUT_* mirrors. */
static void espi_vwire_decode(uint32_t evt0, uint32_t evt1, uint32_t *in, uint32_t *out)
{
	const uint32_t evt[2] = { evt0, evt1 };

	*in = 0U;
	*out = 0U;
	for (size_t i = 0; i < ARRAY_SIZE(espi_vw_bit_map); i++) {
		const struct espi_vw_bit_info *sig = &espi_vw_bit_map[i];

		if ((evt[sig->evt] & BIT(sig->bit)) != 0U) {
			*in |= sig->in_mask;
			*out |= sig->out_mask;
		}
	}
}

static void espi_vwire_sync_locked(void)
{
	uint32_t evt0 = sys_read32(ESPI_EVT0_REG);
	uint32_t evt1 = sys_read32(ESPI_EVT1_REG);
	uint32_t gpio0 = sys_read32(ESPI_VW_GPIO_VAL0);
	uint32_t gpio1 = sys_read32(ESPI_VW_GPIO_VAL1);
	uint32_t gp50_0 = sys_read32(ESPI_VW_GP50_VAL0);
	uint32_t gp50_1 = sys_read32(ESPI_VW_GP50_VAL1);

	espi_vwire_decode(evt0, evt1, &s_vwire_in_cached, &s_vwire_out_cached);

	uint32_t le_in = sys_cpu_to_le32(s_vwire_in_cached);
	espi_perif_mem_write(ESPI_VWIRE_IN_OFFSET, &le_in, sizeof(le_in));

	uint32_t le_out = sys_cpu_to_le32(s_vwire_out_cached);
	espi_perif_mem_write(ESPI_VWIRE_OUT_OFFSET, &le_out, sizeof(le_out));

	uint32_t le_evt0 = sys_cpu_to_le32(evt0);
	uint32_t le_evt1 = sys_cpu_to_le32(evt1);
	uint32_t le_gpio0 = sys_cpu_to_le32(gpio0);
	uint32_t le_gpio1 = sys_cpu_to_le32(gpio1);
	uint32_t le_gp50_0 = sys_cpu_to_le32(gp50_0);
	uint32_t le_gp50_1 = sys_cpu_to_le32(gp50_1);

	espi_perif_mem_write(ESPI_VW_HW_EVT0_OFFSET, &le_evt0, 4);
	espi_perif_mem_write(ESPI_VW_HW_EVT1_OFFSET, &le_evt1, 4);
	espi_perif_mem_write(ESPI_VW_HW_GPIO0_OFFSET, &le_gpio0, 4);
	espi_perif_mem_write(ESPI_VW_HW_GPIO1_OFFSET, &le_gpio1, 4);
	espi_perif_mem_write(ESPI_VW_HW_GP50_0_OFFSET, &le_gp50_0, 4);
	espi_perif_mem_write(ESPI_VW_HW_GP50_1_OFFSET, &le_gp50_1, 4);

	uint8_t grp[ESPI_VW_GROUP_MAX];
	memset(grp, 0, sizeof(grp));

	grp[2] = (uint8_t)(evt0 & 0x7); /* SLP_S3, SLP_S4, SLP_S5 */
	grp[3] = (uint8_t)((evt0 >> 4) & 0x7); /* SUS_STAT, PLTRST, OOB_RST_WARN */
	grp[4] = (uint8_t)((evt0 >> 16) & 0xf); /* OOB_RST_ACK, WAKE, PME */
	grp[5] = (uint8_t)((evt0 >> 20) & 0xf); /* TARGET_BOOT_DONE, ERR_FATAL, ERR_NON_FATAL, TARGET_BOOT_STS */
	grp[6] = (uint8_t)((evt0 >> 24) & 0xf); /* SCI, SMI, RCIN, HOST_RST_ACK */
	grp[7] = (uint8_t)((evt0 >> 8) & 0x7); /* HOST_RST_WARN, SMIOUT, NMIOUT */
	/* Indexes 0x40-0x47 follow the eSPI system-event layout, not EVT1's. */
	grp[0x40] = (uint8_t)((evt1 >> 20) & 0x1); /* SUS_ACK */
	grp[0x41] = (uint8_t)(evt1 & 0xb); /* SUS_WARN, SUS_PWRDN_ACK, -, SLP_A */
	grp[0x42] = (uint8_t)((evt1 >> 4) & 0x3); /* SLP_LAN, SLP_WLAN */
	grp[0x47] = (uint8_t)((evt1 >> 16) & 0x1); /* HOST_C10 */

	for (int i = 0; i < 8; i++) {
		grp[0x50 + i] = (uint8_t)((gp50_0 >> (i * 4)) & 0xf);
		grp[0x58 + i] = (uint8_t)((gp50_1 >> (i * 4)) & 0xf);
	}

	for (int i = 0; i < 8; i++) {
		grp[0x80 + i] = (uint8_t)((gpio0 >> (i * 4)) & 0xf);
		grp[0x88 + i] = (uint8_t)((gpio1 >> (i * 4)) & 0xf);
	}

	espi_perif_mem_write(ESPI_VW_GROUP_TABLE_OFFSET, grp, sizeof(grp));
}

void espi_vwire_sync_all_to_mmio(void)
{
	k_mutex_lock(&vwire_lock, K_FOREVER);
	espi_vwire_sync_locked();
	k_mutex_unlock(&vwire_lock);
}

void espi_vwire_on_rx_event(void)
{
	uint32_t in;
	uint32_t diff;

	k_mutex_lock(&vwire_lock, K_FOREVER);
	espi_vwire_sync_locked();
	in = s_vwire_in_cached;
	diff = in ^ s_vwire_in_reported;
	s_vwire_in_reported = in;
	k_mutex_unlock(&vwire_lock);

	if (!IS_ENABLED(CONFIG_OBMF_LSTP_GPIO_CHANNEL)) {
		return;
	}

	for (uint16_t pin = 0; pin <= 5; pin++) {
		if (diff & BIT(pin)) {
			lstp_gpio_vwire_event(pin, (in & BIT(pin)) ? 1 : 0);
		}
	}
}

/* ESPI210 SMI/SCI/PME/WAKE are read-only, so those wires cannot be driven. */
#define VWIRE_OUT_READ_ONLY (ESPI_VWIRE_OUT_SMI | ESPI_VWIRE_OUT_SCI | \
			     ESPI_VWIRE_OUT_PME | ESPI_VWIRE_OUT_WAKE)

/* RST_CPU_INIT and RCIN# are one wire (bit 26): a change to either moves both. */
#define VWIRE_OUT_RCIN_ALIAS (ESPI_VWIRE_OUT_RST_CPU_INIT | ESPI_VWIRE_OUT_RCIN)

static void espi_vwire_set_output_locked(uint32_t val)
{
	uint32_t evt[2] = { sys_read32(ESPI_EVT0_REG), sys_read32(ESPI_EVT1_REG) };
	uint32_t old_alias = s_vwire_out_cached & VWIRE_OUT_RCIN_ALIAS;
	uint32_t new_alias = val & VWIRE_OUT_RCIN_ALIAS;

	if (new_alias != old_alias && new_alias != 0U && new_alias != VWIRE_OUT_RCIN_ALIAS) {
		/* Only one alias bit moved: it decides the wire. */
		bool set = ((new_alias ^ old_alias) & new_alias) != 0U;

		val = set ? (val | VWIRE_OUT_RCIN_ALIAS) : (val & ~VWIRE_OUT_RCIN_ALIAS);
	}

	for (size_t i = 0; i < ARRAY_SIZE(espi_vw_bit_map); i++) {
		const struct espi_vw_bit_info *sig = &espi_vw_bit_map[i];

		/* Preserve live auto-ack wires unless the caller changed them. */
		if (((val ^ s_vwire_out_cached) & sig->out_mask) == 0U) {
			continue;
		}
		WRITE_BIT(evt[sig->evt], sig->bit, (val & sig->out_mask) != 0U);
	}

	/* Preserve the existing clearing of undocumented ESPI210 bit 28. */
	evt[0] &= ~BIT(28);

	/* Write both together so the boot wires go out in one virtual-wire packet. */
	sys_write32(evt[0], ESPI_EVT0_REG);
	sys_write32(evt[1], ESPI_EVT1_REG);

	espi_vwire_sync_locked();
}

void espi_vwire_set_output_reg(uint32_t val)
{
	k_mutex_lock(&vwire_lock, K_FOREVER);
	espi_vwire_set_output_locked(val);
	k_mutex_unlock(&vwire_lock);
}

int espi_vwire_write_output_mirror(uint32_t offset, const uint8_t *data, size_t len)
{
	uint32_t value = 0;
	int rc;

	k_mutex_lock(&vwire_lock, K_FOREVER);
	rc = espi_perif_mem_write(offset, data, len);
	if (rc == 0) {
		(void)espi_perif_mem_read(ESPI_VWIRE_OUT_OFFSET, &value, sizeof(value));
		value = sys_le32_to_cpu(value);
		/* Same rule as the GPIO path: a write that drives a read-only wire
		 * is rejected whole, and the mirror goes back to the hardware state.
		 */
		if (((value ^ s_vwire_out_cached) & VWIRE_OUT_READ_ONLY) != 0U) {
			rc = -ENOTSUP;
			espi_vwire_sync_locked();
		} else {
			espi_vwire_set_output_locked(value);
		}
	}
	k_mutex_unlock(&vwire_lock);
	return rc;
}

static int espi_vwire_gpio_get_pin(uint16_t pin)
{
	uint32_t in;
	uint32_t out;

	k_mutex_lock(&vwire_lock, K_FOREVER);
	in = s_vwire_in_cached;
	out = s_vwire_out_cached;
	k_mutex_unlock(&vwire_lock);

	if (pin <= 5) {
		return (in & BIT(pin)) ? 1 : 0;
	} else if (pin >= 6 && pin <= 15) {
		return (out & BIT(pin - 6)) ? 1 : 0;
	}
	return 0;
}

static int espi_vwire_gpio_set_pin(uint16_t pin, uint8_t value)
{
	/*
	 * GPIO pins 6..15 map to VWIRE_OUT bits 0..9 (SMI#..RCIN#), matching the
	 * 16 named lines of the GPIO channel. SUS_ACK and ERR_* are not exposed.
	 */
	if (pin < 6 || pin > 15) {
		return -EINVAL;
	}
	if ((BIT(pin - 6) & VWIRE_OUT_READ_ONLY) != 0U) {
		return -ENOTSUP;
	}

	k_mutex_lock(&vwire_lock, K_FOREVER);
	uint32_t val = s_vwire_out_cached;

	WRITE_BIT(val, pin - 6, value != 0U);
	espi_vwire_set_output_locked(val);
	k_mutex_unlock(&vwire_lock);
	return 0;
}

static const struct lstp_gpio_vwire_ops espi_vwire_gpio_ops = {
	.get_pin = espi_vwire_gpio_get_pin,
	.set_pin = espi_vwire_gpio_set_pin,
};

void espi_vwire_bridge_init(void)
{
	k_mutex_lock(&vwire_lock, K_FOREVER);
	espi_vwire_sync_locked();
	s_vwire_in_reported = s_vwire_in_cached;
	k_mutex_unlock(&vwire_lock);
}

static void espi_vwire_work_handler(struct k_work *work);

static void espi_vwire_event_handler(const struct device *dev, struct espi_callback *cb,
				     struct espi_event event)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(cb);
	ARG_UNUSED(event);

	/* eSPI callbacks run in interrupt context. Defer MMIO locking and USB work. */
	k_work_submit_to_queue(&espi_bridge_workq, &espi_vwire_work);
}

static void espi_vwire_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	espi_vwire_on_rx_event();
}

/* Answer a malformed non-posted request so the host does not wait for it. */
static void perif_np_queue_unsuc(struct espi_perif_cmplt *cmplt)
{
	cmplt->cyc = ESPI_PERIF_UNSUC_CMPLT;
	cmplt->len_h = 0;
	cmplt->len_l = 0;
	perif_tx_ioc.pkt_len = sizeof(*cmplt);
	perif_tx_started = k_uptime_get();
	perif_tx_pending = true;
}

static void espi_service_peripheral(void)
{
	struct espi_aspeed_ioc rx_ioc;
	struct espi_comm_hdr *hdr;
	struct espi_perif_cmplt *cmplt;
	uint32_t addr;
	uint16_t len;
	size_t header_len;
	int rc;

	if (perif_tx_pending) {
		if (k_uptime_get() - perif_tx_started < PERIF_TX_TIMEOUT_MS) {
			rc = espi_aspeed_perif_pc_put_tx(espi_dev, &perif_tx_ioc);
			if (rc != 0) {
				return;
			}
		} else {
			perif_tx_dropped++;
			LOG_WRN("Peripheral completion timed out, dropped=%u", perif_tx_dropped);
		}
		perif_tx_pending = false;
	}

	rx_ioc.pkt = perif_pc_rx_buf;
	rx_ioc.pkt_len = sizeof(perif_pc_rx_buf);
	rc = espi_aspeed_perif_pc_get_rx(espi_dev, &rx_ioc, false);
	if (rc == 0) {
		if (rx_ioc.pkt_len < sizeof(*hdr)) {
			goto np_rx;
		}
		hdr = (struct espi_comm_hdr *)rx_ioc.pkt;
		len = espi_packet_len(hdr);
		if (hdr->cyc == ESPI_PERIF_MEMWR32) {
			header_len = sizeof(*hdr) + sizeof(uint32_t);
			if (rx_ioc.pkt_len < header_len) {
				goto np_rx;
			}
			addr = sys_get_be32(rx_ioc.pkt + sizeof(*hdr));
		} else if (hdr->cyc == ESPI_PERIF_MEMWR64) {
			uint64_t addr64;

			header_len = sizeof(*hdr) + sizeof(uint64_t);
			if (rx_ioc.pkt_len < header_len) {
				goto np_rx;
			}
			addr64 = sys_get_be64(rx_ioc.pkt + sizeof(*hdr));
			addr = (uint32_t)addr64;
			if (addr64 > UINT32_MAX) {
				/* Drop this packet without delaying non-posted RX. */
				goto np_rx;
			}
		} else {
			espi_memtrace_pkt("PC", hdr, len, rx_ioc.pkt_len);
			goto np_rx;
		}

		if (rx_ioc.pkt_len < header_len + len) {
			goto np_rx;
		}

		espi_memtrace(true, addr, rx_ioc.pkt + header_len, len);

		if (range_is_valid(addr, ESPI_TEST_REGION_BASE, sizeof(perif_mem), len) &&
		    perif_host_write_allowed(addr - ESPI_TEST_REGION_BASE, len)) {
			k_mutex_lock(&perif_mem_lock, K_FOREVER);
			memcpy(perif_mem + addr - ESPI_TEST_REGION_BASE,
			       rx_ioc.pkt + header_len, len);
			k_mutex_unlock(&perif_mem_lock);
		}
	}

np_rx:
	rx_ioc.pkt = perif_np_rx_buf;
	rx_ioc.pkt_len = sizeof(perif_np_rx_buf);
	rc = espi_aspeed_perif_np_get_rx(espi_dev, &rx_ioc, false);
	if (rc != 0 || rx_ioc.pkt_len < sizeof(*hdr)) {
		return;
	}

	hdr = (struct espi_comm_hdr *)rx_ioc.pkt;
	len = espi_packet_len(hdr);
	cmplt = (struct espi_perif_cmplt *)perif_pc_tx_buf;
	cmplt->tag = hdr->tag;

	if (hdr->cyc == ESPI_PERIF_MEMRD32 || hdr->cyc == ESPI_PERIF_MEMRD64) {
		header_len = sizeof(*hdr) + ((hdr->cyc == ESPI_PERIF_MEMRD32) ?
					     sizeof(uint32_t) : sizeof(uint64_t));
		if (rx_ioc.pkt_len < header_len) {
			perif_np_queue_unsuc(cmplt);
			return;
		}
		if (hdr->cyc == ESPI_PERIF_MEMRD32) {
			addr = sys_get_be32(rx_ioc.pkt + sizeof(*hdr));
		} else {
			uint64_t addr64 = sys_get_be64(rx_ioc.pkt + sizeof(*hdr));
			addr = (addr64 > UINT32_MAX) ? 0 : (uint32_t)addr64;
		}

		if (range_is_valid(addr, ESPI_TEST_REGION_BASE, sizeof(perif_mem), len)) {
			cmplt->cyc = ESPI_PERIF_SUC_CMPLT_D_ONLY;
			cmplt->len_h = (len >> 8) & 0xf;
			cmplt->len_l = len & 0xff;
			k_mutex_lock(&perif_mem_lock, K_FOREVER);
			memcpy(cmplt->data, perif_mem + addr - ESPI_TEST_REGION_BASE, len);
			k_mutex_unlock(&perif_mem_lock);
			perif_tx_ioc.pkt_len = sizeof(*cmplt) + len;
			espi_memtrace(false, addr, cmplt->data, len);
		} else {
			espi_memtrace(false, addr, NULL, len);
			cmplt->cyc = ESPI_PERIF_UNSUC_CMPLT;
			cmplt->len_h = 0;
			cmplt->len_l = 0;
			perif_tx_ioc.pkt_len = sizeof(*cmplt);
		}
	} else if (hdr->cyc == ESPI_PERIF_IOWR) {
		struct espi_perif_io *io = (struct espi_perif_io *)rx_ioc.pkt;
		uint16_t port;

		if (rx_ioc.pkt_len < sizeof(*io)) {
			perif_np_queue_unsuc(cmplt);
			return;
		}
		port = sys_be16_to_cpu(io->addr_be);

		/* Validate against received bytes, not just the host-provided payload length. */
		size_t avail = (rx_ioc.pkt_len > sizeof(*io))
				     ? rx_ioc.pkt_len - sizeof(*io) : 0U;

		if (len > avail) {
			static bool iowr_trunc_reported;

			if (!iowr_trunc_reported) {
				iowr_trunc_reported = true;
				LOG_WRN("IOWR payload unavailable: header len=%u, driver "
					"delivered %zu byte(s); data dropped",
					len, avail);
			}
			len = (uint16_t)avail;
		}

		k_mutex_lock(&portio_lock, K_FOREVER);
		for (uint16_t i = 0; i < len; i++) {
			virtual_port_io[(port + i) & 0xffff] = io->data[i];
		}
		k_mutex_unlock(&portio_lock);

		if (port == 0x2e && len >= 1) {
			virtual_sio_idx = io->data[0];
		}
		/*
		 * The current NP RX driver never delivers IOWR data, so a short
		 * write is the normal case; an UNSUC completion would fail every
		 * host port write (and may surface as an eSPI error in BIOS).
		 * Complete it; the drop is logged once above.
		 */
		cmplt->cyc = ESPI_PERIF_SUC_CMPLT;
		cmplt->len_h = 0;
		cmplt->len_l = 0;
		perif_tx_ioc.pkt_len = sizeof(*cmplt);
		if (atomic_get(&espi_monitor_active) && port != 0x3f8 && port != 0x2f8) {
			printk("[eSPI Port IO] Host WRITE: port=0x%04x (len=%u) data=", port, len);
			for (uint16_t i = 0; i < len; i++) {
				printk("%02x ", io->data[i]);
			}
			printk("(Forwarded to AST2700)\n");
		}
	} else if (hdr->cyc == ESPI_PERIF_IORD) {
		struct espi_perif_io *io = (struct espi_perif_io *)rx_ioc.pkt;
		uint16_t port;
		uint8_t read_buf[4] = {0};

		if (rx_ioc.pkt_len < sizeof(*io)) {
			perif_np_queue_unsuc(cmplt);
			return;
		}
		port = sys_be16_to_cpu(io->addr_be);

		k_mutex_lock(&portio_lock, K_FOREVER);
		for (uint16_t i = 0; i < len && i < 4; i++) {
			uint16_t cur_port = (port + i) & 0xffff;
			if (cur_port == 0x2f) {
				if (virtual_sio_idx == 0x20) {
					read_buf[i] = 0x10; /* AST1040 chip ID */
				} else {
					read_buf[i] = virtual_port_io[cur_port];
				}
			} else if (cur_port == 0x3fd || cur_port == 0x2fd) {
				read_buf[i] = virtual_port_io[cur_port] ? virtual_port_io[cur_port] : 0x60;
			} else if (cur_port == 0x3fa || cur_port == 0x2fa) {
				read_buf[i] = virtual_port_io[cur_port] ? virtual_port_io[cur_port] : 0x01;
			} else if (cur_port == 0x3fe || cur_port == 0x2fe) {
				read_buf[i] = virtual_port_io[cur_port] ? virtual_port_io[cur_port] : 0xb0;
			} else {
				read_buf[i] = virtual_port_io[cur_port];
			}
		}
		k_mutex_unlock(&portio_lock);
		if (len > sizeof(read_buf)) {
			/* Reject host lengths exceeding read_buf to avoid transmitting stack contents. */
			LOG_WRN("IORD len=%u exceeds %zu-byte read buffer, rejecting",
				len, sizeof(read_buf));
			cmplt->cyc = ESPI_PERIF_UNSUC_CMPLT;
			cmplt->len_h = 0;
			cmplt->len_l = 0;
			perif_tx_ioc.pkt_len = sizeof(*cmplt);
			goto iord_done;
		}

		cmplt->cyc = ESPI_PERIF_SUC_CMPLT_D_ONLY;
		cmplt->len_h = (len >> 8) & 0xf;
		cmplt->len_l = len & 0xff;
		memcpy(cmplt->data, read_buf, len);
		perif_tx_ioc.pkt_len = sizeof(*cmplt) + len;
		if (atomic_get(&espi_monitor_active) && port != 0x3f8 && port != 0x2f8) {
			printk("[eSPI Port IO] Host READ : port=0x%04x (len=%u) resp=", port, len);
			for (uint16_t i = 0; i < len; i++) {
				printk("%02x ", read_buf[i]);
			}
			printk("(Forwarded to AST2700)\n");
		}
iord_done:
		;
	} else {
		perif_np_queue_unsuc(cmplt);
		return;
	}
	perif_tx_started = k_uptime_get();
	perif_tx_pending = true;
}

static void espi_service_oob(void)
{
	espi_oob_bridge_service();
}

static void espi_service_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	if (!device_is_ready(espi_dev)) {
		k_work_reschedule_for_queue(&espi_bridge_workq, &espi_service_work,
					    K_MSEC(100));
		return;
	}

	espi_service_peripheral();
#if IS_ENABLED(CONFIG_OBMF_ESPI_IPMI)
	espi_mmbi_poll();
#endif
	espi_service_oob();
	k_work_reschedule_for_queue(&espi_bridge_workq, &espi_service_work,
				    ESPI_SERVICE_PERIOD);
}

static void espi_snapshot_state(void)
{
	last_evt0 = sys_read32(ESPI_EVT0_REG);
	last_evt1 = sys_read32(ESPI_EVT1_REG);
	last_vw_gpio0 = sys_read32(ESPI_VW_GPIO_VAL0);
	last_vw_gp50 = sys_read32(ESPI_VW_GP50_VAL0);
	last_pin0_ctrl = sys_read32(GPIO_PIN0_CTRL_REG);
	last_pin1_ctrl = sys_read32(GPIO_PIN1_CTRL_REG);
	last_pin2_ctrl = sys_read32(GPIO_PIN2_CTRL_REG);
	last_pin3_ctrl = sys_read32(GPIO_PIN3_CTRL_REG);
	last_data_abcd = sys_read32(GPIO_DATA_ABCD_REG);
}

static int vw_gpio_locate(uint8_t index, uint8_t source, uint32_t *reg_hi, uint32_t *bit)
{
	uint32_t pos;

	if (index < ESPI_ASPEED_VW_GPIO_INDEX_MIN || index > ESPI_ASPEED_VW_GPIO_INDEX_MAX ||
	    source >= ESPI_ASPEED_VW_GPIO_SRC_COUNT) {
		return -EINVAL;
	}

	pos = (uint32_t)(index - ESPI_ASPEED_VW_GPIO_INDEX_MIN) * ESPI_ASPEED_VW_GPIO_SRC_COUNT +
	      source;
	*reg_hi = pos / 32;
	*bit = pos % 32;
	return 0;
}

int espi_bridge_aspeed_vw_gpio_get_direction(const struct device *dev, uint8_t index,
					     uint8_t source,
					     enum espi_aspeed_vw_gpio_direction *direction)
{
	uint32_t reg_hi, bit, dir;
	int rc;

	ARG_UNUSED(dev);
	rc = vw_gpio_locate(index, source, &reg_hi, &bit);
	if (rc) {
		return rc;
	}

	dir = sys_read32(reg_hi ? ESPI_VW_GPIO_DIR1 : ESPI_VW_GPIO_DIR0);
	*direction = (dir & BIT(bit)) ? ESPI_ASPEED_VW_GPIO_TARGET_TO_CONTROLLER
				       : ESPI_ASPEED_VW_GPIO_CONTROLLER_TO_TARGET;
	return 0;
}

int espi_bridge_aspeed_vw_gpio_get(const struct device *dev, uint8_t index, uint8_t source,
				   uint8_t *level)
{
	uint32_t reg_hi, bit, val;
	int rc;

	ARG_UNUSED(dev);
	rc = vw_gpio_locate(index, source, &reg_hi, &bit);
	if (rc) {
		return rc;
	}

	val = sys_read32(reg_hi ? ESPI_VW_GPIO_VAL1 : ESPI_VW_GPIO_VAL0);
	*level = (val & BIT(bit)) ? 1 : 0;
	return 0;
}

static int espi_bridge_init(void)
{
	int rc;
	int init_rc = 0; /* last failure, reported after every part has started */
	struct k_work_queue_config workq_config = { .name = "espi_bridge" };

	k_work_queue_start(&espi_bridge_workq, espi_bridge_work_stack,
			   K_THREAD_STACK_SIZEOF(espi_bridge_work_stack),
			   K_PRIO_PREEMPT(4), &workq_config);

	espi_config_pinmux();
	espi_configure_lpc_bridge();
	espi_vwire_bridge_init();
	if (IS_ENABLED(CONFIG_OBMF_LSTP_GPIO_CHANNEL)) {
		lstp_gpio_set_vwire_ops(&espi_vwire_gpio_ops);
	}
	espi_snapshot_state();
	k_work_init(&espi_snoop_work, espi_snoop_work_handler);
	k_work_init(&espi_vwire_work, espi_vwire_work_handler);
	atomic_set(&espi_snoop_stats_start_ms, (atomic_val_t)k_uptime_get_32());
	k_work_init_delayable(&espi_monitor_work, espi_monitor_work_handler);
	k_work_init_delayable(&espi_service_work, espi_service_work_handler);
	/* Port 80 snooping is optional: the rest of the bridge still starts. */
	if (!device_is_ready(snoop_dev)) {
		LOG_ERR("Snoop device not ready");
		init_rc = -ENODEV;
	} else {
		rc = snoop_aspeed_register_rx_callback(snoop_dev, espi_snoop_rx_callback);
		if (rc != 0) {
			LOG_ERR("Failed to register Snoop callback: %d", rc);
			init_rc = rc;
		}
	}
	espi_init_callback(&espi_vwire_cb, espi_vwire_event_handler,
			   ESPI_BUS_EVENT_VWIRE_RECEIVED);
	if (device_is_ready(espi_dev)) {
		/* A failed OOB or vwire hook must not take the peripheral channel down too. */
		rc = espi_oob_bridge_init(espi_dev);
		if (rc != 0) {
			LOG_ERR("Failed to initialize OOB bridge: %d", rc);
			init_rc = rc;
		}
		rc = espi_add_callback(espi_dev, &espi_vwire_cb);
		if (rc != 0) {
			LOG_ERR("Failed to register the vwire callback: %d", rc);
			init_rc = rc;
		}
		/* Without TAF the MMIO channel stops advertising the SAFS window. */
		rc = safs_init();
		if (rc != 0) {
			init_rc = rc;
		}
#if IS_ENABLED(CONFIG_OBMF_ESPI_IPMI)
		rc = espi_mmbi_init();
		if (rc != 0 && rc != -ENOTSUP) {
			LOG_ERR("MMBI init failed: %d", rc);
		}
#endif
	}
	k_work_reschedule_for_queue(&espi_bridge_workq, &espi_monitor_work, K_MSEC(100));
	k_work_reschedule_for_queue(&espi_bridge_workq, &espi_service_work, K_MSEC(100));

	if (!device_is_ready(espi_dev)) {
		return -ENODEV;
	}
	return init_rc;
}

SYS_INIT(espi_bridge_init, APPLICATION, 50);
