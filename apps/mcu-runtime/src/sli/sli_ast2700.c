#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <platform.h>
#include <scu_ast2700.h>
#include "zephyr/arch/common/sys_io.h"
#include "zephyr/logging/log.h"
#include "zephyr/sys/sys_io.h"

#include <zephyr/logging/log.h>
#define LOG_MODULE_NAME			sli_ast2700
LOG_MODULE_REGISTER(LOG_MODULE_NAME, LOG_LEVEL_DBG);

#define SLIM_REG_OFFSET			0x000
#define SLIH_REG_OFFSET			0x200
#define SLIV_REG_OFFSET			0x400

#define SLI_CTRL_I			0x00
#define   SLI_ALL_IN_SUSPEND            BIT(28)
#define   SLI_AUTO_CLR_OFF_DAT          BIT(23) /* No auto-clear when changing data pad delay */
#define   SLI_AUTO_CLR_OFF_CLK          BIT(22) /* No auto-clear when changing clock pad delay */
#define   SLI_SP_DOWN_PERIOD            GENMASK(21, 20)
#define   SLI_NO_RST_TXCLK_CHG          BIT(17) /* No reset when changing TX clock */
#define   SLIV_RAW_MODE			BIT(15)
#define   SLI_TX_MODE			BIT(14)
#define   SLI_RX_PHY_LAH_SEL_REV	BIT(13)
#define   SLI_RX_PHY_LAH_SEL_NEG	BIT(12)
#define   SLI_AUTO_SEND_TRN_OFF		BIT(8)
#define   SLI_CLEAR_BUS			BIT(6)
#define   SLI_TRANS_EN			BIT(5)
#define   SLI_CLEAR_RX			BIT(2)
#define   SLI_CLEAR_TX			BIT(1)
#define   SLI_RESET_TRIGGER		BIT(0)
#define SLI_CTRL_II			0x04
#define SLI_CTRL_III			0x08
#define   SLI_CLK_SEL			GENMASK(31, 28)
#define     SLI_CLK_25M			0x0
#define     SLI_CLK_800M		0x1
#define     SLI_CLK_400M		0x2
#define     SLI_CLK_200M		0x3
#define     SLI_CLK_500M		0x6
#define     SLI_CLK_250M		0x7
#define   SLI_PHYCLK_SEL		GENMASK(27, 24)
#define     SLI_PHYCLK_25M		0x0
#define     SLI_PHYCLK_800M		0x1
#define     SLI_PHYCLK_400M		0x2
#define     SLI_PHYCLK_200M		0x3
#define     SLI_PHYCLK_1G		0x5
#define     SLI_PHYCLK_500M		0x6
#define     SLI_PHYCLK_250M		0x7
#define   SLIH_PAD_DLY_TX1		GENMASK(23, 18)
#define   SLIH_PAD_DLY_TX0		GENMASK(17, 12)
#define   SLIH_PAD_DLY_RX1		GENMASK(11, 6)
#define   SLIH_PAD_DLY_RX0		GENMASK(5, 0)
#define   SLIM_PAD_DLY_RX3		GENMASK(23, 18)
#define   SLIM_PAD_DLY_RX2		GENMASK(17, 12)
#define   SLIM_PAD_DLY_RX1		GENMASK(11, 6)
#define   SLIM_PAD_DLY_RX0		GENMASK(5, 0)
#define SLI_CTRL_IV			0x0c
#define   SLIM_PAD_DLY_TX3		GENMASK(23, 18)
#define   SLIM_PAD_DLY_TX2		GENMASK(17, 12)
#define   SLIM_PAD_DLY_TX1		GENMASK(11, 6)
#define   SLIM_PAD_DLY_TX0		GENMASK(5, 0)
#define SLI_INTR_EN			0x10
#define SLI_INTR_STATUS			0x14
#define   SLI_INTR_RX_SYNC		BIT(15)
#define   SLI_INTR_RX_ERR		BIT(13)
#define   SLI_INTR_RX_NACK		BIT(12)
#define   SLI_INTR_RX_TRAIN_PKT		BIT(10)
#define   SLI_INTR_RX_DISCONN		BIT(6)
#define   SLI_INTR_TX_SUSPEND		BIT(4)
#define   SLI_INTR_TX_TRAIN		BIT(3)
#define   SLI_INTR_TX_IDLE		BIT(2)
#define   SLI_INTR_RX_SUSPEND		BIT(1)
#define   SLI_INTR_RX_IDLE		BIT(0)
#define   SLI_INTR_RX_ERRORS                                                     \
	  (SLI_INTR_RX_ERR | SLI_INTR_RX_NACK | SLI_INTR_RX_DISCONN)

#define SLIM_MARB_FUNC_I		0x60
#define   SLIM_SLI_MARB_CLR		BIT(4)
#define   SLIM_SLI_MARB_RR		BIT(0)

#if defined(CONFIG_SLI_TARGET_PHYCLK_1GHZ)
#define SLI_TARGET_PHYCLK		SLI_PHYCLK_1G
#elif defined(CONFIG_SLI_TARGET_PHYCLK_800MHZ)
#define SLI_TARGET_PHYCLK		SLI_PHYCLK_800M
#elif defined(CONFIG_SLI_TARGET_PHYCLK_500MHZ)
#define SLI_TARGET_PHYCLK		SLI_PHYCLK_500M
#elif defined(CONFIG_SLI_TARGET_PHYCLK_400MHZ)
#define SLI_TARGET_PHYCLK		SLI_PHYCLK_400M
#else
#define SLI_TARGET_PHYCLK		SLI_PHYCLK_25M
#endif

#define SLI_TARGET_ENGCLK		SLI_CLK_500M

#define SLIH_DEFAULT_DELAY		11
#if (SLI_TARGET_PHYCLK == SLI_PHYCLK_800M) || (SLI_TARGET_PHYCLK == SLI_PHYCLK_788M)
#define SLIM_DEFAULT_DELAY		5
#define SLIM_LAH_CONFIG			1
#else
#define SLIM_DEFAULT_DELAY		12
#define SLIM_LAH_CONFIG			0
#endif

#define SLI_MAX_POLL_CNT_CLEAR		10
#define SLI_MAX_POLL_CNT_SUSPEND	10

struct sli_config {
	mm_reg_t slim; /* SLI MBUS */
	mm_reg_t slih; /* SLI AHB */
	mm_reg_t sliv; /* SLI VIDEO */
	int eng_clk_freq;
	int phy_clk_freq;
};

struct sli_data {
	struct sli_config die0;	/* CPU die */
	struct sli_config die1;	/* IO die */
	struct ast2700_scu1 *scu1;

#define SLI_FLAG_AST2700A0		BIT(0)
#define SLI_FLAG_RX_LAH_NEG_IO_SLIH	BIT(1)
#define SLI_FLAG_RX_LAH_NEG_IO_SLIM	BIT(2)
	uint32_t flags;
};

#define SLIH_COARSE_D_BEGIN		6
#define SLIH_COARSE_D_END		24

#define SLIM_COARSE_D_BEGIN		0
#define SLIM_COARSE_D_END		24
#define SLIM_FINE_MARGIN		5

#define SCU1_SCRATCH31_SLI0_READY	BIT(0)
#define SCU1_SCRATCH31_SLI_SKIP_CALI	BIT(1)	/* skip calibration */
#define SCU0_SCRATCH31_SLI1_READY	BIT(0)
#define AHBC_MAX_TIMEOUT		0x1ff

static void setbits_le32(mm_reg_t addr, uint32_t set)
{
	sys_write32(sys_read32(addr) | set, addr);
}

static void clrbits_le32(mm_reg_t addr, uint32_t clr)
{
	sys_write32(sys_read32(addr) & (~clr), addr);
}

static void clrsetbits_le32(mm_reg_t addr, uint32_t clr, uint32_t set)
{
	sys_write32((sys_read32(addr) & (~clr)) | set, addr);
}

static bool is_sli_calibrated(struct sli_data *data)
{
	uint32_t reg_val;

	/* Check whethter the IO-die SLI engine clock has been sped up */
	reg_val = sys_read32(data->die1.slih + SLI_CTRL_III);
	if (FIELD_GET(SLI_CLK_SEL, reg_val)) {
		return true;
	}

	return false;
}

static void sli_clear_interrupt_status(mm_reg_t base)
{
	sys_write32(0xfffff, base + SLI_INTR_STATUS);
}

static int sli_wait_suspend(mm_reg_t base)
{
	uint32_t value, target;
	int count = 0;

	sli_clear_interrupt_status(base);

	/*
         * The target is for both RX and TX to enter the suspend state, meaning
         * that both the RX and TX hardware blocks are not in the training
         * state, and are therefore ready for software use.
         */
	target = SLI_INTR_RX_SUSPEND | SLI_INTR_TX_SUSPEND;

	for (;;) {
		value = sys_read32(base + SLI_INTR_STATUS);
		if (value & SLI_INTR_RX_ERRORS) {
			return -2;
		}

		if ((value & target) == target) {
			break;
		}

		if (++count > SLI_MAX_POLL_CNT_SUSPEND) {
			return -1;
		}

		k_busy_wait(1);
	}

	return 0;
}

static int is_sli_suspend(mm_reg_t base)
{
	uint32_t value;
	uint32_t suspend = SLI_INTR_TX_SUSPEND | SLI_INTR_RX_SUSPEND;

	value = sys_read32(base + SLI_INTR_STATUS);
	if (value & SLI_INTR_RX_ERRORS)
		return -1;
	else if ((value & suspend) == suspend)
		return 1;
	else
		return 0;
}

static int sli_wait_clear_done(mm_reg_t base, uint32_t target)
{
	uint32_t value;
	int count = 0;

	for (;;) {
		value = sys_read32(base + SLI_CTRL_I);
		if ((value & target) == 0) {
			break;
		}

		if (++count > SLI_MAX_POLL_CNT_CLEAR) {
			return -1;
		}

		k_busy_wait(1);
	}

	return 0;
}

static int sli_clear(mm_reg_t base, uint32_t clr)
{
	setbits_le32(base + SLI_CTRL_I, clr);

	return sli_wait_clear_done(base, clr & ~SLI_CLEAR_BUS);
}

static void sli_set_ahb_rx_delay(mm_reg_t base, int d0, int d1)
{
	uint32_t value;

	value = FIELD_PREP(SLIH_PAD_DLY_RX1, d1) | FIELD_PREP(SLIH_PAD_DLY_RX0, d0);
	clrsetbits_le32(base + SLI_CTRL_III, SLIH_PAD_DLY_RX1 | SLIH_PAD_DLY_RX0, value);
	sys_read32(base + SLI_CTRL_III);
	k_busy_wait(8);
}

static int sli_log_ahb_pad_delay(struct sli_data *data, int first, int last)
{
	clrsetbits_le32((mem_addr_t)&data->scu1->scratch[30], 0xffff,
			((last & 0xff) << 8) | (first & 0xff));

	return 0;
}

static int sli_get_ahb_pad_delay(struct sli_data *data, int *first, int *last)
{
	uint32_t value;

	value = sys_read32((mem_addr_t)&data->scu1->scratch[30]);
	*first = (value & 0xff);
	*last = (value >> 8) & 0xff;

	return 0;
}

static void sli_calibrate_ahb_delay(struct sli_data *data)
{
	int dc;
	int d_first_pass = -1;
	int d_last_pass = -1;
	int win_size = 0;

	if (data->flags & SLI_FLAG_RX_LAH_NEG_IO_SLIH)
		setbits_le32(data->die1.slih + SLI_CTRL_I, SLI_RX_PHY_LAH_SEL_NEG);
	else
		clrbits_le32(data->die1.slih + SLI_CTRL_I, SLI_RX_PHY_LAH_SEL_NEG);

	for (dc = SLIH_COARSE_D_BEGIN; dc < SLIH_COARSE_D_END; dc++) {
		sli_set_ahb_rx_delay(data->die1.slih, dc, dc);
		sli_clear(data->die1.slih, SLI_CLEAR_RX | SLI_CLEAR_BUS);

		/* Check result */
		sli_clear_interrupt_status(data->die1.slih);
		k_busy_wait(200);
		if (is_sli_suspend(data->die1.slih) > 0) {
			if (d_first_pass == -1)
				d_first_pass = dc;

			d_last_pass = dc;
		} else if (d_last_pass != -1) {
			if ((d_last_pass - d_first_pass) > win_size) {
				win_size = d_last_pass - d_first_pass;
				sli_log_ahb_pad_delay(data, d_first_pass, d_last_pass);
				LOG_DBG("IOD SLIH DS coarse win: {%d, %d}\n", d_first_pass, d_last_pass);
			}
			d_first_pass = -1;
			d_last_pass = -1;
		}
	}

	sli_get_ahb_pad_delay(data, &d_first_pass, &d_last_pass);
	dc = (d_first_pass + d_last_pass) >> 1;
	LOG_DBG("IOD SLIH DS coarse win: {%d, %d} -> select %d", d_first_pass, d_last_pass, dc);

	sli_set_ahb_rx_delay(data->die1.slih, dc, dc);

	/* Reset IOD SLIH Bus (to reset the counters) and RX */
	sli_clear(data->die1.slih, SLI_CLEAR_RX | SLI_CLEAR_BUS);

	/* Turn on the hardware training and wait suspend state */
	clrbits_le32(data->die1.slih + SLI_CTRL_I, SLI_AUTO_SEND_TRN_OFF);
	sli_wait_suspend(data->die1.slih);

	/* SLI-H is available now */
}

static void sli_set_mbus_rx_delay_single(mm_reg_t base, int index, int d)
{
	uint32_t offset = index * 6;
	uint32_t mask = SLIM_PAD_DLY_RX0 << offset;

	clrsetbits_le32(base + SLI_CTRL_III, mask, d << offset);
	sys_read32(base + SLI_CTRL_III);
	k_busy_wait(8);
}

static void sli_set_mbus_rx_delay(mm_reg_t base, int d0, int d1, int d2, int d3)
{
	uint32_t clr, set;

	clr = SLIM_PAD_DLY_RX3 | SLIM_PAD_DLY_RX2 | SLIM_PAD_DLY_RX1 | SLIM_PAD_DLY_RX0;
	set = FIELD_PREP(SLIM_PAD_DLY_RX3, d3) | FIELD_PREP(SLIM_PAD_DLY_RX2, d2) |
	      FIELD_PREP(SLIM_PAD_DLY_RX1, d1) | FIELD_PREP(SLIM_PAD_DLY_RX0, d0);
	clrsetbits_le32(base + SLI_CTRL_III, clr, set);
	sys_read32(base + SLI_CTRL_III);
	k_busy_wait(8);
}

static int sli_log_mbus_pad_delay(struct sli_data *data, int index, int first, int last)
{
	mem_addr_t addr;
	uint32_t bit_offset;

	if (index > 1)
		addr = (mem_addr_t)&data->scu1->scratch[29];
	else
		addr = (mem_addr_t)&data->scu1->scratch[28];

	if (index & 1)
		bit_offset = 16;
	else
		bit_offset = 0;

	clrsetbits_le32(addr, 0xffff << bit_offset,
			(last << (bit_offset + 8)) | (first << bit_offset));

	return 0;
}

static int sli_get_mbus_pad_delay(struct sli_data *data, int index, int *first, int *last)
{
	mem_addr_t addr;
	uint32_t value;
	uint32_t bit_offset;

	if (index > 1)
		addr = (mem_addr_t)&data->scu1->scratch[29];
	else
		addr = (mem_addr_t)&data->scu1->scratch[28];

	if (index & 1)
		bit_offset = 16;
	else
		bit_offset = 0;

	value = sys_read32(addr);
	*first = (value >> bit_offset) & 0xff;
	*last = (value >> (bit_offset + 8)) & 0xff;

	return 0;
}

static int sli_calibrate_mbus_pad_delay(struct sli_data *data, int index, int begin, int end)
{
	int d;
	int d_first_pass = -1;
	int d_last_pass = -1;
	int count;

	for (count = 0; count < 99; count++) {
		for (d = begin; d < end; d++) {
			sli_set_mbus_rx_delay_single(data->die1.slim, index, d);

			/* Reset CPU-die TX and IO-die RX */
			sli_clear(data->die0.slim, SLI_RESET_TRIGGER);
			sli_clear(data->die1.slim, SLI_RESET_TRIGGER);

			/* Check result */
			sli_clear_interrupt_status(data->die1.slim);
			k_busy_wait(200);
			if (is_sli_suspend(data->die1.slim) > 0) {
				if (d_first_pass == -1)
					d_first_pass = d;

				d_last_pass = d;
			} else if (d_last_pass != -1) {
				break;
			}
		}

		if ((d_last_pass - d_first_pass) > 3)
			break;
	}

	if (d_first_pass == -1)
		d = SLIM_DEFAULT_DELAY;
	else
		d = (d_first_pass + d_last_pass) >> 1;

	LOG_DBG("IOD SLIM[%d] DS win: {%d, %d} -> select %d", index, d_first_pass, d_last_pass, d);
	sli_log_mbus_pad_delay(data, index, d_first_pass, d_last_pass);

	return d;
}

static void sli_calibrate_mbus_delay(struct sli_data *data)
{
	int dc, d0, d1, d2, d3;
	int begin, end;
	int d_first_pass = -1;
	int d_last_pass = -1;
	int win_size = 0;

	if (data->flags & SLI_FLAG_RX_LAH_NEG_IO_SLIM)
		setbits_le32(data->die1.slim + SLI_CTRL_I, SLI_RX_PHY_LAH_SEL_NEG);
	else
		clrbits_le32(data->die1.slim + SLI_CTRL_I, SLI_RX_PHY_LAH_SEL_NEG);

	/* Find coarse delay */
	for (dc = SLIM_COARSE_D_BEGIN; dc < SLIM_COARSE_D_END; dc++) {
		sli_set_mbus_rx_delay(data->die1.slim, dc, dc, dc, dc);

		/* Reset CPU-die TX and IO-die RX */
		sli_clear(data->die0.slim, SLI_RESET_TRIGGER);
		sli_clear(data->die1.slim, SLI_RESET_TRIGGER);

		/* Check result */
		sli_clear_interrupt_status(data->die1.slim);
		k_busy_wait(200);
		if (is_sli_suspend(data->die1.slim) > 0) {
			if (d_first_pass == -1)
				d_first_pass = dc;

			d_last_pass = dc;
		} else if (d_last_pass != -1) {
			if ((d_last_pass - d_first_pass) > win_size) {
				win_size = d_last_pass - d_first_pass;
				sli_log_mbus_pad_delay(data, 0, d_first_pass, d_last_pass);
				LOG_DBG("IOD SLIM DS coarse win: {%d, %d}\n", d_first_pass, d_last_pass);
			}
			d_first_pass = -1;
			d_last_pass = -1;
		}
	}

	sli_get_mbus_pad_delay(data, 0, &d_first_pass, &d_last_pass);
	dc = (d_first_pass + d_last_pass) >> 1;
	if (dc == 0)
		dc = SLIM_DEFAULT_DELAY;

	LOG_DBG("IOD SLIM DS coarse win: {%d, %d} -> select %d", d_first_pass, d_last_pass, dc);

	sli_set_mbus_rx_delay(data->die1.slim, dc, dc, dc, dc);

	begin = MAX(dc - SLIM_FINE_MARGIN, 0);
	end = MIN(dc + SLIM_FINE_MARGIN, 31);

	/* Fine-tune per-PAD delay */
	d0 = sli_calibrate_mbus_pad_delay(data, 0, begin, end);
	sli_set_mbus_rx_delay_single(data->die1.slim, 0, d0);

	d1 = sli_calibrate_mbus_pad_delay(data, 1, begin, end);
	sli_set_mbus_rx_delay_single(data->die1.slim, 1, d1);

	d2 = sli_calibrate_mbus_pad_delay(data, 2, begin, end);
	sli_set_mbus_rx_delay_single(data->die1.slim, 2, d2);

	d3 = sli_calibrate_mbus_pad_delay(data, 3, begin, end);
	sli_set_mbus_rx_delay_single(data->die1.slim, 3, d3);

	/* Reset CPU-die TX and IO-die RX */
	sli_clear(data->die0.slim, SLI_RESET_TRIGGER);
	sli_clear(data->die1.slim, SLI_RESET_TRIGGER);

	/* Turn on the hardware training and wait suspend state */
	clrbits_le32(data->die1.slim + SLI_CTRL_I, SLI_AUTO_SEND_TRN_OFF);
	sli_wait_suspend(data->die1.slim);

	/* Enable the MARB RR mode for AST2700A0 */
	setbits_le32(data->die1.slim + SLIM_MARB_FUNC_I, SLIM_SLI_MARB_RR);
}

int sli_init_f(void)
{
	struct sli_data ast2700_sli_data[1];
	struct sli_data *data = ast2700_sli_data;
	uint32_t reg_val;

	/* CPU die */
	data->die0.slim = SLI0_REG + SLIM_REG_OFFSET;
	data->die0.slih = SLI0_REG + SLIH_REG_OFFSET;
	data->die0.sliv = SLI0_REG + SLIV_REG_OFFSET;
	data->die0.eng_clk_freq = SLI_CLK_500M;
	data->die0.phy_clk_freq = SLI_TARGET_PHYCLK;

	/* IO die */
	data->die1.slim = SLI1_REG + SLIM_REG_OFFSET;
	data->die1.slih = SLI1_REG + SLIH_REG_OFFSET;
	data->die1.sliv = SLI1_REG + SLIV_REG_OFFSET;
	data->die1.eng_clk_freq = SLI_CLK_500M;
	data->die1.phy_clk_freq = SLI_TARGET_PHYCLK;

	data->flags = 0;
	data->scu1 = (struct ast2700_scu1 *)DT_REG_ADDR(DT_NODELABEL(syscon1));

	if (FIELD_GET(SCU0_REVISION_ID_HW, data->scu1->chip_id1) == 0)
		data->flags |= SLI_FLAG_AST2700A0;

	/* Return if SLI had been calibrated */
	if (is_sli_calibrated(data)) {
		return 0;
	}

	/* AST2700A0 workaround for 25MHz */
	if (data->flags & SLI_FLAG_AST2700A0) {
		reg_val = SLI_RX_PHY_LAH_SEL_NEG | SLI_TRANS_EN | SLI_CLEAR_BUS;
		sys_write32(reg_val, data->die1.slih + SLI_CTRL_I);
		sys_write32(reg_val, data->die1.slim + SLI_CTRL_I);
		sys_write32(reg_val | SLIV_RAW_MODE, data->die1.sliv + SLI_CTRL_I);
		sli_wait_suspend(data->die1.slih);
		sli_wait_suspend(data->die0.slih);
		LOG_DBG("AST2700A0 SLI ready, 25MHz");

		if (IS_ENABLED(CONFIG_SLI_TARGET_PHYCLK_1GHZ) ||
		    IS_ENABLED(CONFIG_SLI_TARGET_PHYCLK_800MHZ)) {
			data->flags |= SLI_FLAG_RX_LAH_NEG_IO_SLIM;
		}
	} else {
		/* Return if SLI had been calibrated */
		reg_val = sys_read32((mem_addr_t)&data->scu1->scratch[31]);
		if (reg_val & SCU1_SCRATCH31_SLI_SKIP_CALI) {
			LOG_DBG("SLI1 has been initialized\n");
			return 0;
		}
	}

	if (IS_ENABLED(CONFIG_SLI_TARGET_PHYCLK_25MHZ)) {
		LOG_DBG("AST2700 SLI1 ready, 25MHz");
		return 0;
	}

	if (!(data->flags & SLI_FLAG_AST2700A0)) {
		/* Disable AHBC timeout before calibration */
		sys_write32(0, (mem_addr_t)ASPEED_AHBC1_BASE + 0x034);
		sys_write32(0, (mem_addr_t)ASPEED_AHBC1_BASE + 0x074);
		sys_write32(0, (mem_addr_t)ASPEED_AHBC1_BASE + 0x0b4);
		sys_write32(0, (mem_addr_t)ASPEED_AHBC1_BASE + 0x0f4);
		sys_write32(0, (mem_addr_t)ASPEED_AHBC1_BASE + 0x134);
		sys_write32(0, (mem_addr_t)ASPEED_AHBC1_BASE + 0x174);
		sys_write32(0, (mem_addr_t)ASPEED_AHBC1_BASE + 0x1b4);
		sys_write32(0, (mem_addr_t)ASPEED_AHBC1_BASE + 0x1f4);
		sys_write32(0, (mem_addr_t)ASPEED_AHBC0_BASE + 0x034);
		sys_write32(0, (mem_addr_t)ASPEED_AHBC0_BASE + 0x074);
		sys_write32(0, (mem_addr_t)ASPEED_AHBC0_BASE + 0x0b4);
		sys_write32(0, (mem_addr_t)ASPEED_AHBC0_BASE + 0x0f4);
	}

	/* Speed up engine clock before adjusting PHY TX clock and delay */
	reg_val = FIELD_PREP(SLI_CLK_SEL, data->die1.eng_clk_freq);
	clrsetbits_le32(data->die1.slih + SLI_CTRL_III, SLI_CLK_SEL, reg_val);
	reg_val = FIELD_PREP(SLI_CLK_SEL, data->die0.eng_clk_freq);
	clrsetbits_le32(data->die0.slih + SLI_CTRL_III, SLI_CLK_SEL, reg_val);

	/* Turn off auto-clear for AST2700A1 */
	if (!(data->flags & SLI_FLAG_AST2700A0)) {
		setbits_le32(data->die1.slih + SLI_CTRL_I,
			     SLI_AUTO_CLR_OFF_DAT | SLI_AUTO_CLR_OFF_CLK | SLI_NO_RST_TXCLK_CHG);
		setbits_le32(data->die0.slih + SLI_CTRL_I,
			     SLI_AUTO_CLR_OFF_DAT | SLI_AUTO_CLR_OFF_CLK | SLI_NO_RST_TXCLK_CHG);
	}

	/* Speed up CPU die PHY TX clock and clear TX PAD delay */
	reg_val = FIELD_PREP(SLI_PHYCLK_SEL, data->die0.phy_clk_freq);
	clrsetbits_le32(data->die0.slih + SLI_CTRL_III,
			SLI_PHYCLK_SEL | SLIH_PAD_DLY_TX1 | SLIH_PAD_DLY_TX0,
			reg_val);

	/* Turn off auto-training */
	setbits_le32(data->die1.slih + SLI_CTRL_I, SLI_AUTO_SEND_TRN_OFF);
	setbits_le32(data->die1.slim + SLI_CTRL_I, SLI_AUTO_SEND_TRN_OFF);
	setbits_le32(data->die1.sliv + SLI_CTRL_I, SLI_AUTO_SEND_TRN_OFF);

	sli_calibrate_ahb_delay(data);
	sli_calibrate_mbus_delay(data);

	LOG_INF("SLI1 calibration completed");

	/* Clear remote SLI controller */
	sli_clear(data->die0.slih, SLI_CLEAR_BUS);
	sli_wait_suspend(data->die0.slih);

	return 0;
}

int sli_init_r(void)
{
	struct ast2700_scu0 *scu0;
	struct ast2700_scu1 *scu1;
	uint32_t reg_val;
	int retry = 10;
	bool sli0_ready = false;

	if (IS_ENABLED(CONFIG_SLI_TARGET_PHYCLK_25MHZ)) {
		LOG_DBG("AST2700 SLI0 ready, 25MHz");
		return 0;
	}

	scu0 = (struct ast2700_scu0 *)DT_REG_ADDR(DT_NODELABEL(syscon0));
	scu1 = (struct ast2700_scu1 *)DT_REG_ADDR(DT_NODELABEL(syscon1));

	if (scu1->scratch[31] & SCU1_SCRATCH31_SLI_SKIP_CALI) {
		printf("SLI0 has been initialized\n");
		return 0;
	}
	while (--retry > 0) {
		if (scu1->scratch[31] & SCU1_SCRATCH31_SLI0_READY) {
			sli0_ready = true;
			break;
		}

		k_msleep(100);
	}

	if (sli0_ready) {
		sli_clear(SLI1_REG + SLIH_REG_OFFSET,
			  SLI_CLEAR_RX | SLI_CLEAR_BUS);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC1_BASE + 0x034);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC1_BASE + 0x074);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC1_BASE + 0x0b4);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC1_BASE + 0x0f4);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC1_BASE + 0x134);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC1_BASE + 0x174);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC1_BASE + 0x1b4);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC1_BASE + 0x1f4);
		k_busy_wait(200);
		setbits_le32((mem_addr_t)&scu0->cpu_scratch[31],
			     SCU0_SCRATCH31_SLI1_READY);
		k_busy_wait(100);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC0_BASE + 0x034);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC0_BASE + 0x074);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC0_BASE + 0x0b4);
		sys_write32(AHBC_MAX_TIMEOUT, (mem_addr_t)ASPEED_AHBC0_BASE + 0x0f4);
		LOG_INF("SLI0 calibration completed");

		setbits_le32((mem_addr_t)&scu1->scratch[31],
			     SCU1_SCRATCH31_SLI_SKIP_CALI);

		/* Reset SLIM MARB before using the SLIM */
		setbits_le32(SLI1_REG + SLIM_REG_OFFSET + SLIM_MARB_FUNC_I, SLIM_SLI_MARB_CLR);

		/* Clear the INTC reset interrupt status. */
		reg_val = sys_read32((mem_addr_t)ASPEED_IO_INTC_BASE + 0x14);
		sys_write32(reg_val, (mem_addr_t)ASPEED_IO_INTC_BASE + 0x14);

		return 0;
	}

	LOG_ERR("Timeout to wait SLI0 calibration");
	return -1;
}
