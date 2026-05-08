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

static volatile struct mac_des_s *txdes = (volatile struct mac_des_s *) 0x80000000ULL;
static volatile struct mac_des_s *txdes_mac = (volatile struct mac_des_s *) 0x400000000ULL;
static volatile struct mac_des_s *rxdes = (volatile struct mac_des_s *) 0x80000100ULL;
static volatile struct mac_des_s *rxdes_mac = (volatile struct mac_des_s *) 0x400000100ULL;
static uint8_t *tx_pkt_buf = (uint8_t *)(0x80000200ULL);
static uint8_t *tx_pkt_buf_mac = (uint8_t *)(0x400000200ULL);
static uint8_t *rx_pkt_buf_mac = (uint8_t *)(0x400000800ULL);

static uint64_t mac_dma_addr(const volatile void *ptr)
{
	return (uint64_t)(uintptr_t)ptr;
}

static uintptr_t mac_base(uint32_t index)
{
	return index ? ASPEED_IO_MAC1_BASE : ASPEED_IO_MAC0_BASE;
}

static uint32_t calculate_freq(uint32_t value)
{
	uint64_t freq = (uint64_t)25000000 * (value + 1) * 8;

	freq /= 512;

	return (uint32_t)freq;
}

static uint32_t cal_delay32_ring(struct ast2700_scu1 *scu, uint8_t revision,
				 uint8_t rgmii_chain)
{
	uintptr_t base = (uintptr_t)&scu->freq_counter_ctrl;
	uint64_t time_ps;
	uint32_t reg, dbgsel;
	int ret;

	sys_write32(0x1c, base);
	ret = readl_poll_timeout(base, reg, ((reg & SCU_FREQ_COUNTER_MASK) == 0), 50);
	if (ret < 0) {
		return 0;
	}

	reg = SCU_FREQ_RING_ENABLE | SCU_FREQ_RING_STG(31);
	if (revision == 1) {
		reg |= SCU_FREQ_SELECT_DLY32;
	} else {
		reg |= SCU_FREQ_SELECT_RGMII;
		dbgsel = SCU_DBGSEL_RING_SEL(rgmii_chain);
		sys_write32((sys_read32((uintptr_t)&scu->rsv_0xC4) &
			     ~SCU_DBGSEL_RING_SEL_MASK) | dbgsel,
			    (uintptr_t)&scu->rsv_0xC4);
	}

	sys_write32(reg, base);
	k_busy_wait(1000);

	reg |= SCU_FREQ_OSC_ENABLE;
	sys_write32(reg, base);
	ret = readl_poll_timeout(base, reg, (reg & SCU_FREQ_DONE), 1000);
	if (ret < 0)
		return 0;

	reg = SCU_FREQ_COUNTER(sys_read32(base));
	reg = calculate_freq(reg);
	time_ps = 1000000000000ULL / reg;

	sys_write32(0, base);
	sys_write32(sys_read32((uintptr_t)&scu->rsv_0xC4) &
		    ~SCU_DBGSEL_RING_SEL_MASK,
		    (uintptr_t)&scu->rsv_0xC4);

	return (uint32_t)time_ps;
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
	uint64_t addr = mac_dma_addr(rx_pkt_buf_mac);

	rxdes->des2 = FIELD_PREP(MAC_RXDES2_RXBUF_BADR_HI, 0x4);
	rxdes->des3 = (uint32_t)addr;
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
	if (index) {
		sys_write32(0, SCU1_REG + SCU_MULTI_CTRL20);
		sys_write32(sys_read32(SCU1_REG + SCU_MULTI_CTRL21) & ~GENMASK(14, 0),
			    SCU1_REG + SCU_MULTI_CTRL21);
	} else {
		sys_write32(0, SCU1_REG + SCU_MULTI_CTRL18);
		sys_write32(sys_read32(SCU1_REG + SCU_MULTI_CTRL19) & ~GENMASK(14, 0),
			    SCU1_REG + SCU_MULTI_CTRL19);
	}
}

static void mac_controller_init(struct ast2700_scu1 *scu, uint32_t index)
{
	uintptr_t base = mac_base(index);
	uint32_t reg, dblac, desc_size;
	uint64_t addr;

	mac_rgmii_pin(index);
	mac_reset_deassert(scu, index);
	mac_clk_enable(scu, index);
	mac_set_freq(scu);

	sys_write32(0, base + IER);

	addr = mac_dma_addr(txdes_mac);
	sys_write32((uint32_t)addr, base + TXR_BADR);
	sys_write32(0x4, base + TXR_BADR_HI);

	addr = mac_dma_addr(rxdes_mac);
	sys_write32((uint32_t)addr, base + RXR_BADR);
	sys_write32(0x4, base + RXR_BADR_HI);

	mac_init_tx_desc();
	mac_init_rx_desc();

	sys_write32(FIELD_PREP(APTC_RPOLL_CNT, 0x1), base + APTC);
	sys_write32(0x600, base + RBSR);

	desc_size = MAC_DESC_ALIGN / DBLAC_DESC_UINT;
	if (desc_size < 2)
		desc_size = 2;

	dblac = sys_read32(base + DBLAC) & ~GENMASK(19, 12);
	dblac |= DBLAC_RDES_SIZE(desc_size) | DBLAC_TDES_SIZE(desc_size);
	sys_write32(dblac, base + DBLAC);

	reg = FIELD_PREP(MACCR_RXDMA_EN, 1) |
	      FIELD_PREP(MACCR_RXMAC_EN, 1) |
	      FIELD_PREP(MACCR_TXDMA_EN, 1) |
	      FIELD_PREP(MACCR_TXMAC_EN, 1) |
	      FIELD_PREP(MACCR_CRC_APD, 1) |
	      FIELD_PREP(MACCR_FULLDUP, 1) |
	      FIELD_PREP(MACCR_RX_RUNT, 1) |
	      FIELD_PREP(MACCR_RX_BROADPKT_EN, 1) |
	      FIELD_PREP(MACCR_GMAC_MODE, 1);
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

static void mac_txpkt_add(void *packet)
{
	uint64_t addr;

	addr = mac_dma_addr(packet);
	txdes->des2 = FIELD_PREP(MAC_TXDES2_TXBUF_BADR_HI, 0x4);
	txdes->des3 = (uint32_t)addr;
	txdes->des0 |= MAC_TXDES0_FTS | MAC_TXDES0_LTS |
		      MAC_TXDES0_TXBUF_SIZE(60) | MAC_TXDES0_TXDMA_OWN;
	txdes->des1 = 0;
}

static void mac_init_tx_desc_only_desc0(void)
{
	txdes->des0 |= MAC_TXDES0_TXDMA_OWN;
}

static void set_rgmii_delay(struct ast2700_scu1 *scu, uint32_t tx, uint32_t rx,
			    uint32_t index, bool freq_set)
{
	uintptr_t target = freq_set ? (uintptr_t)&scu->mac_10m_delay :
				     (uintptr_t)&scu->mac_delay;
	uint32_t reg = sys_read32(target);

	if (index) {
		reg &= ~(TX_DELAY_2 | RX_DELAY_2);
		reg |= FIELD_PREP(TX_DELAY_2, tx) | FIELD_PREP(RX_DELAY_2, rx);
	} else {
		reg &= ~(TX_DELAY_1 | RX_DELAY_1);
		reg |= FIELD_PREP(TX_DELAY_1, tx) | FIELD_PREP(RX_DELAY_1, rx);
	}

	sys_write32(reg, target);
}

static void record_rgmii_delay(struct ast2700_scu1 *scu, uint32_t index,
			       uint8_t tx_dis, uint8_t tx_en, uint8_t rx_dis,
			       uint8_t rx_en, uint32_t tx_average_delay,
			       uint32_t rx_average_delay)
{
	uint32_t scu0 = SCU1_SCRATCH_TX_DELAY_STEP(tx_average_delay) |
			SCU1_SCRATCH_RX_DELAY_STEP(rx_average_delay);
	uint32_t scu1 = FIELD_PREP(GENMASK(7, 0), tx_dis) |
			FIELD_PREP(GENMASK(15, 8), tx_en) |
			FIELD_PREP(GENMASK(23, 16), rx_dis) |
			FIELD_PREP(GENMASK(31, 24), rx_en);

	if (index) {
		sys_write32(scu0, (uintptr_t)&scu->scratch[6]);
		sys_write32(scu1, (uintptr_t)&scu->scratch[7]);
	} else {
		sys_write32(scu0, (uintptr_t)&scu->scratch[4]);
		sys_write32(scu1, (uintptr_t)&scu->scratch[5]);
	}
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
	int max_len = 0;
	int max_start = -1;
	int max_end = -1;
	int current_start = -1;
	int i;

	for (i = 0; i < 32; i++) {
		if (data[i] == 0) {
			if (current_start == -1)
				current_start = i;
		} else if (current_start != -1) {
			int current_len = i - current_start;

			if (current_len > max_len) {
				max_len = current_len;
				max_start = current_start;
				max_end = i - 1;
			}
			current_start = -1;
		}
	}

	if (current_start != -1) {
		int current_len = i - current_start;

		if (current_len > max_len) {
			max_len = current_len;
			max_start = current_start;
			max_end = i - 1;
		}
	}

	ARG_UNUSED(max_end);

	return max_start + (max_len - 1) / 2;
}

static bool check_calibration_delay(struct ast2700_scu1 *scu, uint32_t index)
{
	if (index) {
		if ((sys_read32((uintptr_t)&scu->scratch[6]) &
		     SCU1_SCRATCH_TX_DELAY_STEP(0xffff)) == 0)
			return false;
	} else {
		if ((sys_read32((uintptr_t)&scu->scratch[4]) &
		     SCU1_SCRATCH_TX_DELAY_STEP(0xffff)) == 0)
			return false;
	}

	return true;
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
		tx_average_delay = cal_delay32_ring(scu, revision, 0);
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

		dly32_average_delay = cal_delay32_ring(scu, 1, 0);
		dly32_average_delay /= 32;
		if (dly32_average_delay == 0)
			return;

		rgmii_chain = index ? SCU_DBGSEL_RING_SEL_RGMII1_TX :
				      SCU_DBGSEL_RING_SEL_RGMII0_TX;
		set_rgmii_delay(scu, 0, 0, index, true);
		tx_start = cal_delay32_ring(scu, revision, rgmii_chain);
		set_rgmii_delay(scu, 31, 0, index, true);
		tx_end = cal_delay32_ring(scu, revision, rgmii_chain);

		tx_average_delay = (tx_end - tx_start) / 31;
		tx_average_delay /= 2;
		if (tx_average_delay == 0)
			return;

#ifdef RX_DELAY_CHAIN
		rgmii_chain = index ? SCU_DBGSEL_RING_SEL_RGMII1_RX :
				      SCU_DBGSEL_RING_SEL_RGMII0_RX;
		set_rgmii_delay(scu, 0, 0, index, true);
		rx_start = cal_delay32_ring(scu, revision, rgmii_chain);
		set_rgmii_delay(scu, 0, 31, index, true);
		rx_end = cal_delay32_ring(scu, revision, rgmii_chain);
		rx_average_delay = (rx_end - rx_start) / 31;
		rx_average_delay /= 2;
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
	mac_txpkt_add(tx_pkt_buf_mac);

	if (revision == 2)
		tx_en = (10000 - mac_loopback_delay) / tx_average_delay;
	else
		tx_en = 2000 / tx_average_delay;

	for (rx = 0; rx < 32; rx++) {
		set_rgmii_delay(scu, tx_en, rx, index, false);
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

	record_rgmii_delay(scu, index, tx_dis, tx_en, rx_dis, rx_en,
			   tx_average_delay, rx_average_delay);
}

int mac_init(struct ast_chip *chip)
{
	find_rgmii_delay(chip, 0);
	find_rgmii_delay(chip, 1);

	return 0;
}
