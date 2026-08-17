/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdbool.h>
#include <stdint.h>
#include <zephyr/logging/log.h>
#include <zephyr/cache.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/sys_io.h>
#include <zephyr/sys/util.h>
#include <platform.h>
#include <mac_ast2700.h>
#include <scu.h>

#define readl_poll_timeout(addr, val, cond, timeout_us) \
({ \
	uint32_t start__ = k_cycle_get_32(); \
	uint32_t timeout__ = k_us_to_cyc_ceil32(timeout_us); \
	int ret__ = 0; \
	for (;;) { \
		(val) = sys_read32(addr); \
		if (cond) \
			break; \
		if ((timeout_us) && ((k_cycle_get_32() - start__) > timeout__)) { \
			(val) = sys_read32(addr); \
			ret__ = (cond) ? 0 : -ETIMEDOUT; \
			break; \
		} \
	} \
	ret__; \
})

struct mac_des_s {
	uint32_t des0;
	uint32_t des1;
	uint32_t des2;
	uint32_t des3;
};

#define MAC_CPU_BUF_BASE	0x80000000U
#define MAC_DMA_ADDR_HI		0x4
#define MAC_TX_DESC_OFFSET	0x000
#define MAC_RX_DESC_OFFSET	0x100
#define MAC_TX_PKT_OFFSET	0x200
#define MAC_RX_PKT_OFFSET	0x800

#define MAC_CPU_PTR(offset)	((void *)(uintptr_t)(MAC_CPU_BUF_BASE + (offset)))
#define txdes			((volatile struct mac_des_s *)MAC_CPU_PTR(MAC_TX_DESC_OFFSET))
#define rxdes			((volatile struct mac_des_s *)MAC_CPU_PTR(MAC_RX_DESC_OFFSET))
#define tx_pkt_buf		((uint8_t *)MAC_CPU_PTR(MAC_TX_PKT_OFFSET))

static uintptr_t mac_base(uint32_t index)
{
	return index ? ASPEED_IO_MAC1_BASE : ASPEED_IO_MAC0_BASE;
}

static uint32_t counter_to_delay_ps(uint32_t value)
{
	return 2560000U / (value + 1);
}

static uint32_t cal_delay32_ring(struct ast2700_scu1 *scu, uint8_t rgmii_chain)
{
	uintptr_t base = (uintptr_t)&scu->freq_counter_ctrl;
	uint32_t reg, dbgsel;
	int ret;

	sys_write32(0x1c, base);
	ret = readl_poll_timeout(base, reg, ((reg & SCU_FREQ_COUNTER_MASK) == 0), 50);
	if (ret < 0) {
		return 0;
	}

	reg = SCU_FREQ_RING_ENABLE | SCU_FREQ_RING_STG(31);
	if (rgmii_chain) {
		reg |= SCU_FREQ_SELECT_RGMII;
		dbgsel = SCU_DBGSEL_RING_SEL(rgmii_chain);
		sys_write32((sys_read32((uintptr_t)&scu->rsv_0xC4) &
			     ~SCU_DBGSEL_RING_SEL_MASK) | dbgsel,
			    (uintptr_t)&scu->rsv_0xC4);
	} else {
		reg |= SCU_FREQ_SELECT_DLY32;
	}

	sys_write32(reg, base);
	k_busy_wait(1000);

	reg |= SCU_FREQ_OSC_ENABLE;
	sys_write32(reg, base);
	ret = readl_poll_timeout(base, reg, (reg & SCU_FREQ_DONE), 1000);
	if (ret < 0)
		return 0;

	sys_write32(0, base);
	sys_write32(sys_read32((uintptr_t)&scu->rsv_0xC4) &
		    ~SCU_DBGSEL_RING_SEL_MASK,
		    (uintptr_t)&scu->rsv_0xC4);

	return counter_to_delay_ps(SCU_FREQ_COUNTER(reg));
}

static void mac_reset_assert(struct ast2700_scu1 *scu, uint32_t index)
{
	sys_write32(BIT(5 + index), (uintptr_t)&scu->modrst1_ctrl);
}

static void mac_reset_deassert(struct ast2700_scu1 *scu, uint32_t index)
{
	sys_write32(BIT(5 + index), (uintptr_t)&scu->modrst1_clr);
}

static void mac_clk_enable(struct ast2700_scu1 *scu, uint32_t index)
{
	sys_write32(BIT(8 + index), (uintptr_t)&scu->clkgate_clr1);
}

static void mac_set_freq(struct ast2700_scu1 *scu)
{
	uint32_t data = sys_read32((uintptr_t)&scu->clk_sel1);

	data &= ~(SCU_CLK_SEL1_RGMIICLK_MASK | SCU_CLK_SEL1_MHCLK_MASK);
	data |= SCU_CLK_SEL1_RGMIICLK | SCU_CLK_SEL1_RMHCLK;
	sys_write32(data, (uintptr_t)&scu->clk_sel1);
}

static void mac_clk_disable(struct ast2700_scu1 *scu, uint32_t index)
{
	sys_write32(BIT(9 + index), (uintptr_t)&scu->clkgate_ctrl1);
}

static void mac_init_rx_desc_only_desc0(void)
{
	rxdes->des0 = MAC_RXDES0_EDORR;
}

static void mac_init_tx_desc(void)
{
	txdes->des3 = 0;
	txdes->des1 = 0;
	txdes->des0 = 0;
	txdes->des0 = MAC_TXDES0_EDOTR;
}

static void mac_init_rx_desc(void)
{
	rxdes->des2 = FIELD_PREP(MAC_RXDES2_RXBUF_BADR_HI, MAC_DMA_ADDR_HI);
	rxdes->des3 = MAC_RX_PKT_OFFSET;
	rxdes->des0 = MAC_RXDES0_EDORR;
	rxdes->des1 = 0;
}

static void mac_set_loopback(uint32_t index, bool enable)
{
	uintptr_t base = mac_base(index);
	uint32_t fear = sys_read32(base + FEAR);

	if (enable)
		fear |= BIT(30);
	else
		fear &= ~BIT(30);

	sys_write32(fear, base + FEAR);
}

static void mac_rgmii_pin(uint32_t index)
{
	uintptr_t reg = SCU1_REG + (index ? SCU_MULTI_CTRL20 : SCU_MULTI_CTRL18);

	sys_write32(0, reg);
	sys_write32(sys_read32(reg + 4) & ~GENMASK(14, 0), reg + 4);
}

static void mac_controller_init(struct ast2700_scu1 *scu, uint32_t index)
{
	uintptr_t base = mac_base(index);
	uint32_t reg, dblac;

	mac_rgmii_pin(index);
	mac_reset_deassert(scu, index);
	mac_clk_enable(scu, index);
	mac_set_freq(scu);

	sys_write32(0, base + IER);

	sys_write32(MAC_TX_DESC_OFFSET, base + TXR_BADR);
	sys_write32(MAC_DMA_ADDR_HI, base + TXR_BADR_HI);

	sys_write32(MAC_RX_DESC_OFFSET, base + RXR_BADR);
	sys_write32(MAC_DMA_ADDR_HI, base + RXR_BADR_HI);

	mac_init_tx_desc();
	mac_init_rx_desc();

	sys_write32(FIELD_PREP(APTC_RPOLL_CNT, 0x1), base + APTC);
	sys_write32(0x600, base + RBSR);

	dblac = sys_read32(base + DBLAC) & ~GENMASK(19, 12);
	dblac |= DBLAC_RDES_SIZE(MAC_DESC_ALIGN / DBLAC_DESC_UINT) |
		 DBLAC_TDES_SIZE(MAC_DESC_ALIGN / DBLAC_DESC_UINT);
	sys_write32(dblac, base + DBLAC);

	reg = MACCR_RXDMA_EN | MACCR_RXMAC_EN | MACCR_TXDMA_EN |
	      MACCR_TXMAC_EN | MACCR_CRC_APD | MACCR_FULLDUP |
	      MACCR_RX_RUNT | MACCR_RX_BROADPKT_EN | MACCR_GMAC_MODE;
	sys_write32(reg, base + MACCR);
}

static void prepare_tx_packet(uint8_t *pkt)
{
	uint8_t *ptr = pkt;
	int j;

	for (j = 0; j < 6; j++)
		*ptr++ = 0xff;

	ptr += 6;

	*ptr++ = 0x55;
	*ptr++ = 0xaa;
}

static void mac_txpkt_add(uint32_t packet)
{
	txdes->des2 = FIELD_PREP(MAC_TXDES2_TXBUF_BADR_HI, MAC_DMA_ADDR_HI);
	txdes->des3 = packet;
	txdes->des0 |= MAC_TXDES0_FTS | MAC_TXDES0_LTS |
		      MAC_TXDES0_TXBUF_SIZE(60) | MAC_TXDES0_TXDMA_OWN;
	txdes->des1 = 0;
}

static void mac_init_tx_desc_only_desc0(void)
{
	txdes->des0 |= MAC_TXDES0_TXDMA_OWN;
}

static void set_rgmii_delay(struct ast2700_scu1 *scu, uint32_t tx, uint32_t rx,
			    uint32_t index, uintptr_t target)
{
	uint32_t reg = sys_read32(target);
	uint32_t shift = index ? 6 : 0;
	uint32_t mask = (TX_DELAY_1 | RX_DELAY_1) << shift;

	reg &= ~mask;
	reg |= FIELD_PREP(TX_DELAY_1, tx) << shift;
	reg |= FIELD_PREP(RX_DELAY_1, rx) << shift;

	sys_write32(reg, target);
}

static void set_rgmii_1g_delay(struct ast2700_scu1 *scu, uint32_t tx, uint32_t rx,
			       uint32_t index, bool freq_set)
{
	uintptr_t target = freq_set ? (uintptr_t)&scu->mac_10m_delay :
				      (uintptr_t)&scu->mac_delay;

	set_rgmii_delay(scu, tx, rx, index, target);
}

static void record_rgmii_delay(struct ast2700_scu1 *scu, uint32_t index,
			       uint8_t tx_dis, uint8_t tx_en, uint8_t rx_dis,
			       uint8_t rx_en, uint32_t tx_average_delay,
			       uint32_t rx_average_delay)
{
	uint32_t scratch = index ? 6 : 4;
	uint32_t scu0 = SCU1_SCRATCH_TX_DELAY_STEP(tx_average_delay) |
			SCU1_SCRATCH_RX_DELAY_STEP(rx_average_delay);
	uint32_t scu1 = FIELD_PREP(GENMASK(7, 0), tx_dis) |
			FIELD_PREP(GENMASK(15, 8), tx_en) |
			FIELD_PREP(GENMASK(23, 16), rx_dis) |
			FIELD_PREP(GENMASK(31, 24), rx_en);

	sys_write32(scu0, (uintptr_t)&scu->scratch[scratch]);
	sys_write32(scu1, (uintptr_t)&scu->scratch[scratch + 1]);
}

static int mac_xmit(uint32_t index)
{
	uintptr_t base = mac_base(index);
	uint32_t des0;
	int ret;

	sys_write32(1, base + TXPD);
	ret = readl_poll_timeout((uintptr_t)&txdes->des0, des0,
				 !(des0 & MAC_TXDES0_TXDMA_OWN), MAC_TX_TIMEOUT_US);

	return ret;
}

static int mac_recv_no_data(void)
{
	int i = 50;

	do {
		if (i-- < 0)
			return -1;
	} while (!(rxdes->des0 & MAC_RXDES0_RXPKT_RDY));

	if (rxdes->des0 & MAC_RXDES0_ANY_ERROR)
		return -1;

	return 0;
}

static int packet_check(uint32_t index)
{
	int ret;

	mac_init_rx_desc_only_desc0();
	mac_init_tx_desc_only_desc0();

	ret = mac_xmit(index);
	if (ret)
		return -1;

	return mac_recv_no_data();
}

static uint32_t find_rx_center(uint8_t *data)
{
	uint32_t best_start = 0;
	uint32_t best_len = 0;
	uint32_t current_start = 0;
	uint32_t current_len = 0;

	for (uint32_t i = 0; i < 32; i++) {
		if (data[i] == 0) {
			if (!current_len)
				current_start = i;
			if (++current_len > best_len) {
				best_len = current_len;
				best_start = current_start;
			}
		} else {
			current_len = 0;
		}
	}

	if (!best_len)
		return UINT32_MAX;

	return best_start + (best_len - 1) / 2;
}

static bool check_calibration_delay(struct ast2700_scu1 *scu, uint32_t index)
{
	uint32_t scratch = index ? 6 : 4;

	return sys_read32((uintptr_t)&scu->scratch[scratch]) &
	       SCU1_SCRATCH_TX_DELAY_STEP(0xffff);
}

static void find_rgmii_delay(struct ast_chip *chip, uint32_t index)
{
	struct ast2700_scu1 *scu = (struct ast2700_scu1 *)chip->scu1;
	uint32_t rx, tx_en, tx_dis, rx_en, rx_dis;
	uint32_t tx_average_delay, rx_average_delay;
	uint32_t mac_loopback_delay = 0, dly32_average_delay = 0;
	uint8_t revision = FIELD_GET(SCU_HW_REVISION_ID, sys_read32((uintptr_t)&scu->chip_id1));
	uint8_t rgmii_chain;
	uint8_t result[32];

	if (check_calibration_delay(scu, index))
		return;

	if (revision == 1) {
		tx_average_delay = cal_delay32_ring(scu, 0);
		tx_average_delay /= 32;
		if (tx_average_delay == 0)
			return;
		tx_average_delay = tx_average_delay * 10 / 7;
		rx_average_delay = tx_average_delay;
	} else {
		uint32_t tx_start, tx_end;
#ifdef RX_DELAY_CHAIN
		uint32_t rx_start, rx_end;
#endif

		dly32_average_delay = cal_delay32_ring(scu, 0);
		dly32_average_delay /= 32;
		if (dly32_average_delay == 0)
			return;

		rgmii_chain = index ? SCU_DBGSEL_RING_SEL_RGMII1_TX :
				      SCU_DBGSEL_RING_SEL_RGMII0_TX;
		set_rgmii_1g_delay(scu, 0, 0, index, true);
		tx_start = cal_delay32_ring(scu, rgmii_chain);
		set_rgmii_1g_delay(scu, 31, 0, index, true);
		tx_end = cal_delay32_ring(scu, rgmii_chain);

		tx_average_delay = (tx_end - tx_start) / 62;
		if (tx_average_delay == 0)
			return;

#ifdef RX_DELAY_CHAIN
		rgmii_chain = index ? SCU_DBGSEL_RING_SEL_RGMII1_RX :
				      SCU_DBGSEL_RING_SEL_RGMII0_RX;
		set_rgmii_1g_delay(scu, 0, 0, index, true);
		rx_start = cal_delay32_ring(scu, rgmii_chain);
		set_rgmii_1g_delay(scu, 0, 31, index, true);
		rx_end = cal_delay32_ring(scu, rgmii_chain);
		rx_average_delay = (rx_end - rx_start) / 62;
#endif

		if (index)
			rx_average_delay = (dly32_average_delay * 1778460) / 1000000;
		else
			rx_average_delay = (dly32_average_delay * 1926404) / 1000000;

		mac_loopback_delay = index ? 400 : 700;
	}

	mac_controller_init(scu, index);
	mac_set_loopback(index, true);
	prepare_tx_packet(tx_pkt_buf);
	mac_txpkt_add(MAC_TX_PKT_OFFSET);

	if (revision == 2)
		tx_en = (10000 - mac_loopback_delay) / tx_average_delay;
	else
		tx_en = 2000 / tx_average_delay;

	for (rx = 0; rx < 32; rx++) {
		set_rgmii_1g_delay(scu, tx_en, rx, index, false);
		result[rx] = packet_check(index);
	}

	if (revision == 2 && index == 0) {
		tx_en = 10000 / tx_average_delay;
		tx_dis = 8000 / tx_average_delay;
	} else {
		tx_dis = 0;
	}

	rx_dis = find_rx_center(result) + 1;
	rx_en = rx_dis + 2000 / rx_average_delay;

	mac_set_loopback(index, false);
	mac_clk_disable(scu, index);
	mac_reset_assert(scu, index);

	set_rgmii_delay(scu, 0, 0, index, (uintptr_t)&scu->mac_delay);
	set_rgmii_delay(scu, tx_en, rx_en, index, (uintptr_t)&scu->mac_100m_delay);
	set_rgmii_delay(scu, tx_en, rx_en, index, (uintptr_t)&scu->mac_10m_delay);
	record_rgmii_delay(scu, index, tx_dis, tx_en, rx_dis, rx_en,
			   tx_average_delay, rx_average_delay);
}

int mac_init(struct ast_chip *chip)
{
	find_rgmii_delay(chip, 0);
	find_rgmii_delay(chip, 1);

	return 0;
}
