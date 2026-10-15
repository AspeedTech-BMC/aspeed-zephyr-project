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
#include <sdram_ast2700.h>
#include <tamper.h>

LOG_MODULE_REGISTER(tamper, CONFIG_SOC_FMC_LOG_LEVEL);

#define PLL_ALL_BAND_SWEEP_UPDOWN 1
//#define PLL_ALL_BAND_SCAN_DOWNUP 1
//#define ENABLE_TAMPER 1

#define FREQ_COUNTER_CTRL_REG	0x12c023a0
#define FREQ_COUNTER_STEP_REG	0x12c023a4
#define FREQ_COUNTER_DIFF_REG	0x12c023a8
#define FREQ_COUNTER_READBACK	0x12c023b0
#define UNLOCK_ALERT		BIT(17)
#define TAMPER_INIT_DIFF	0x0
#define TAMPER_INIT_STEP	0x1
#define TAMPER_RUNTIME_DIFF	0x0
#define TAMPER_RUNTIME_STEP	0x2
#define TAMPER_CLEAR_TIMEOUT_US	100000

/* DDRPHY registers for unlock detection */
#define DDRPHY_UNLOCK_STATUS_REG	0x130401a8
#define DDRPHY_UNLOCK_CLEAR_REG		0x130401ac

/* MBUS hang-check: write/read-back test addresses at top of 32-bit space */
#define MBUS_TEST_ADDR_A		0xfffffff0
#define MBUS_TEST_ADDR_B		0xfffffff4
#define MBUS_TEST_ADDR_C		0xfffffff8
#define MBUS_TEST_PAT_A			0x87654321U
#define MBUS_TEST_PAT_B			0x12345678U
#define MBUS_TEST_PAT_C			0x89abcdefU

/* The SCU scratch register is used to store the tamper retry count, tamper count, and unlock count.
 * The register is located at address 0x14c021a0. The tamper retry count is stored in bits [7:0],
 * the tamper count is stored in bits [15:8], and the unlock count is stored in bits [23:16].
 * The masks and shifts for each field are defined below.
 */
#define SCU_SCRATCH_REG		0x14c021a0
#define TAMPER_RETRY_CNT_SHIFT	0
#define TAMPER_RETRY_CNT_MASK	(0xffU << TAMPER_RETRY_CNT_SHIFT)
#define TAMPER_CNT_SHIFT	8
#define TAMPER_CNT_MASK		(0xffU << TAMPER_CNT_SHIFT)
#define UNLOCK_CNT_SHIFT	16
#define UNLOCK_CNT_MASK		(0xffU << UNLOCK_CNT_SHIFT)

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

#define SCU_FREQ_COUNTER_MASK 	GENMASK(17, 0)
#define SCU_FREQ_RING_ENABLE 	BIT(0)
#define SCU_FREQ_RING_STG(x)	FIELD_PREP(GENMASK(14, 9), (x))
#define SCU_FREQ_MAX_RING_STG	31U
#define SCU_FREQ_OSC_ENABLE	BIT(1)
#define SCU_FREQ_DONE		BIT(6)
#define SCU_FREQ_COUNTER(x)	FIELD_GET(SCU_FREQ_COUNTER_MASK, (x))

/* FREQ_COUNTER_CTRL source-select (pre-shifted to bits[4:2]) and combined control words */
#define FREQ_SRC_DLY32			(0x3U << 2)	/* dly32 ring oscillator */
#define FREQ_SRC_MPLL_DIV4		(0x5U << 2)	/* MPLL / 4 */
#define FREQ_CTRL_TAMPER_DISABLE	(0x180000U | FREQ_SRC_MPLL_DIV4)
#define FREQ_CTRL_TAMPER_ENABLE		(0x190000U | FREQ_SRC_MPLL_DIV4)

#ifdef ENABLE_TAMPER_TIMER
static uint32_t counter_to_delay_ps(uint32_t value)
{
	return (25000000U / 512) * (value + 1);
}

static uint32_t cal_src(int src)
{
	uintptr_t base = (uintptr_t) FREQ_COUNTER_CTRL_REG;
	uint32_t reg;
	uint32_t sel;
	int ret;

	sys_write32(0, FREQ_COUNTER_CTRL_REG);

	if (src == 0)
		sel = FREQ_SRC_DLY32;
	else if (src == 1)
		sel = FREQ_SRC_MPLL_DIV4;
	else
		return 0;

	reg = sel | SCU_FREQ_RING_ENABLE | SCU_FREQ_RING_STG(SCU_FREQ_MAX_RING_STG);

	sys_write32(reg, base);
	k_busy_wait(2000);

	reg |= SCU_FREQ_OSC_ENABLE;
	sys_write32(reg, base);
	ret = readl_poll_timeout(base, reg, (reg & SCU_FREQ_DONE), 1000000);
	if (ret < 0)
		return 0;

	reg = sys_read32(FREQ_COUNTER_READBACK);

	return 4 * counter_to_delay_ps(SCU_FREQ_COUNTER(reg));
}

static void tamper_timer_cb(struct k_timer *timer)
{
	uint32_t tamper, phyunlock;

	ARG_UNUSED(timer);

	tamper = sys_read32(TAMPER_STATUS_REG);
	phyunlock = sys_read32(DDRPHY_UNLOCK_STATUS_REG);

	LOG_INF("***** Tamper=%ld C, DDRPHY unlock status=0x%x *****", tamper & TAMPER_ALERT, phyunlock);

	if (tamper & TAMPER_ALERT) {
		LOG_WRN("Tamper Alert!!!");

		// clear tamper interrupt.
		sys_write32(TAMPER_ALERT, TAMPER_STATUS_REG);
		LOG_INF("SCU_3b0=0x%x", sys_read32(FREQ_COUNTER_READBACK));
		LOG_INF("MPLL=%d Hz, dly32=%d Hz", cal_src(1), cal_src(0));

		// restart tamper detection.
		tamper_init(TAMPER_RUNTIME_STEP, TAMPER_RUNTIME_DIFF);

		sys_write32(MBUS_TEST_PAT_A, MBUS_TEST_ADDR_A);
		k_busy_wait(1000);

		// check if mbus hang.
		if (sys_read32(MBUS_TEST_ADDR_A) != MBUS_TEST_PAT_A)
			LOG_INF("DDRPHY unlock cannot write to DRAM!!!");
	}

	// check if DDRPHY is unlocked
	if (phyunlock & UNLOCK_ALERT) {
		LOG_WRN("Unlock Alert!!!");

		sys_write32(MBUS_TEST_PAT_B, MBUS_TEST_ADDR_B);
		k_busy_wait(1000);

		// check if mbus hang.
		if (sys_read32(MBUS_TEST_ADDR_B) != MBUS_TEST_PAT_B) {
			// keep alert message but not clear status until wdt recovery.
			LOG_INF("DDRPHY unlock cannot write to DRAM!!!");
		} else {
			// clear ddrphy unlock status.
			sys_write32(BIT(0), DDRPHY_UNLOCK_CLEAR_REG);
			sys_write32(0, DDRPHY_UNLOCK_CLEAR_REG);
		}
	}
}

K_TIMER_DEFINE(tamper_progress_timer, tamper_timer_cb, NULL);
static int tamper_kick(void)
{
	sys_write32(TAMPER_RUNTIME_STEP, FREQ_COUNTER_STEP_REG);
	sys_write32(TAMPER_RUNTIME_DIFF, FREQ_COUNTER_DIFF_REG);

	// kick a timer to print tamper every 1 second.
	k_timer_start(&tamper_progress_timer, K_SECONDS(1), K_SECONDS(1));

	return 0;
}
#endif

int tamper_check(void)
{
	uint32_t tamper, phyunlock;

	tamper = sys_read32(TAMPER_STATUS_REG);
	phyunlock = sys_read32(DDRPHY_UNLOCK_STATUS_REG);

	if (tamper & TAMPER_ALERT) {
		uint32_t scratch = sys_read32(SCU_SCRATCH_REG);
		uint32_t cnt = (scratch & TAMPER_CNT_MASK) >> TAMPER_CNT_SHIFT;

		LOG_WRN("Tamper Attention!!!");
		LOG_INF("SCU_3b0=0x%x", sys_read32(FREQ_COUNTER_READBACK));

		if (cnt < 0xff)
			cnt++;
		scratch = (scratch & ~TAMPER_CNT_MASK) | (cnt << TAMPER_CNT_SHIFT);
		sys_write32(scratch, SCU_SCRATCH_REG);
	}

	if (phyunlock & UNLOCK_ALERT) {
		uint32_t scratch = sys_read32(SCU_SCRATCH_REG);
		uint32_t cnt = (scratch & UNLOCK_CNT_MASK) >> UNLOCK_CNT_SHIFT;

		LOG_WRN("DDRPHY Unlock Attention!!!");
		LOG_INF("SOC MPLL setting=0x%x, status=0x%08x", sys_read32(MPLL_CTRL_REG), sys_read32(MPLL_STATUS_REG));

		if (cnt < 0xff)
			cnt++;
		scratch = (scratch & ~UNLOCK_CNT_MASK) | (cnt << UNLOCK_CNT_SHIFT);
		sys_write32(scratch, SCU_SCRATCH_REG);

		// clear ddrphy unlock status.
		sys_write32(BIT(0), DDRPHY_UNLOCK_CLEAR_REG);
		sys_write32(0, DDRPHY_UNLOCK_CLEAR_REG);

		sys_write32(MBUS_TEST_PAT_C, MBUS_TEST_ADDR_C);
		k_busy_wait(1000);

		// check if mbus hang.
		if (sys_read32(MBUS_TEST_ADDR_C) != MBUS_TEST_PAT_C)
			LOG_ERR("DDRPHY unlock cannot write to DRAM!!!");
	}

	/* Change tamper detection to runtime setting */
	sys_write32(TAMPER_RUNTIME_STEP, FREQ_COUNTER_STEP_REG);
	sys_write32(TAMPER_RUNTIME_DIFF, FREQ_COUNTER_DIFF_REG);

#ifdef ENABLE_TAMPER_TIMER
	tamper_kick();
#endif
	return 0;
}

int tamper_init(int step, int diff)
{
	uint32_t reg;

	sys_write32(0, FREQ_COUNTER_STEP_REG);
	sys_write32(0, FREQ_COUNTER_DIFF_REG);
	sys_write32(FREQ_CTRL_TAMPER_DISABLE, FREQ_COUNTER_CTRL_REG);
	// wait for tamper settle.
	k_busy_wait(10);

	sys_write32(FREQ_SRC_MPLL_DIV4, FREQ_COUNTER_CTRL_REG);
	sys_write32(step, FREQ_COUNTER_STEP_REG);
	sys_write32(diff, FREQ_COUNTER_DIFF_REG);

	k_busy_wait(100);
	sys_write32(TAMPER_ALERT, TAMPER_STATUS_REG);

	// 16 refclk cycles: 25MHz / 16 = 1.5MHz x 4 = 6MHz -> 1.6GHz +- 6MHz => alert
	sys_write32(FREQ_CTRL_TAMPER_ENABLE, FREQ_COUNTER_CTRL_REG);

	// wait 100 us for tamper settle.
	k_busy_wait(100);

	reg = sys_read32(TAMPER_STATUS_REG);
	if (reg & TAMPER_ALERT) {
		LOG_WRN("Tamper alert!! FREQ_COUNTER_CTRL_REG=0x%08x, FREQ_COUNTER_READBACK=0x%08x",
				sys_read32(FREQ_COUNTER_CTRL_REG),
				sys_read32(FREQ_COUNTER_READBACK));
		sys_write32(TAMPER_ALERT, TAMPER_STATUS_REG);

		uint32_t scratch = sys_read32(SCU_SCRATCH_REG);
		uint32_t cnt = (scratch & TAMPER_RETRY_CNT_MASK) >> TAMPER_RETRY_CNT_SHIFT;

		if (cnt < 0xff)
			cnt++;
		scratch = (scratch & ~TAMPER_RETRY_CNT_MASK) | (cnt << TAMPER_RETRY_CNT_SHIFT);
		sys_write32(scratch, SCU_SCRATCH_REG);
	}

	return reg & TAMPER_ALERT;
}

/*
 * MPLL (SCU0+0x310): Fout = Fref(25MHz) * M / NR / OD, fields packed as
 * M=bits[12:0], NR-1=bits[18:13], OD-1=bits[22:19] (see the same layout in
 * sdram_ast2700.c). The default 1600MHz operating point here uses NR=1,
 * OD=1; NR/OD are held fixed for the whole scan and only M is stepped, so
 * each 1-count change of M is Fref/NR = 25MHz - a deliberately coarse,
 * full-band shmoo (+-MPLL_SHMOO_STEPS*25MHz), not a fine band-edge search.
 * MPLL_CTRL_REG/MPLL_STATUS_REG and the field masks/bits are declared in
 * tamper.h, shared with sdram_ast2700.c's sdramc_pll_reset().
 */
#define MPLL_REFCLK_HZ		25000000U
#define MPLL_DEFAULT_M		0x40U
#define MPLL_DEFAULT_NR		1U
#define MPLL_DEFAULT_OD		1U
#define MPLL_STEP_HZ		(MPLL_REFCLK_HZ / MPLL_DEFAULT_NR)	/* Hz per M count */
#define MPLL_DEFAULT_FREQ_HZ	(MPLL_STEP_HZ * MPLL_DEFAULT_M)	/* 1600MHz */
#define MPLL_DEFAULT_REG_VAL	(MPLL_DEFAULT_M | \
				 FIELD_PREP(MPLL_CLKNR_MASK, MPLL_DEFAULT_NR - 1) | \
				 FIELD_PREP(MPLL_CLKOD_MASK, MPLL_DEFAULT_OD - 1))

/* upper bound on how many 1-count M steps a single band-edge search leg may
 * take before giving up (no trip found).
 */
#define MPLL_SHMOO_STEPS	10
#define MPLL_SETTLE_US		500000

#define MPLL_M_TO_MHZ(m)	((MPLL_STEP_HZ * (uint32_t)(m)) / 1000000U)
#define MPLL_M_TO_KHZ_FRAC(m)	(((MPLL_STEP_HZ * (uint32_t)(m)) / 1000U) % 1000U)

static uint32_t mpll_reg_for_m(int m)
{
	return (MPLL_DEFAULT_REG_VAL & ~MPLL_CLKNF_MASK) | ((uint32_t)m & MPLL_CLKNF_MASK);
}

/* Programs the full MPLL control word (M/NR/OD all preserved from the
 * caller), clearing only reset/bypass, and waits for re-lock.
 */
static int mpll_program_nf(uint32_t reg_val)
{
	uint32_t reg;

	sys_write32(reg_val, MPLL_CTRL_REG);

	/* wait for the setting to propagate through the PLL and for the lock detector to see it */
	k_busy_wait(2000);

	return readl_poll_timeout(MPLL_STATUS_REG, reg, (reg & MPLL_LOCK_BIT),
				   MPLL_LOCK_TIMEOUT_US);
}

/*
 * Reconfigures the full MPLL control word (new NF/NR/OD) via reset+bypass,
 * settling MPLL_SETTLE_US between each step, then confirms lock. Used both
 * to bring the PLL to its default operating point here and by
 * sdram_ast2700.c's sdramc_pll_reset() for a full table-driven reconfigure.
 */
static int mpll_reconfigure(uint32_t pll_para)
{
	sys_write32(pll_para | MPLL_RESET_BIT | MPLL_BYPASS_BIT, MPLL_CTRL_REG);
	k_busy_wait(MPLL_SETTLE_US);
	sys_write32(pll_para | MPLL_BYPASS_BIT, MPLL_CTRL_REG);
	k_busy_wait(MPLL_SETTLE_US);
	sys_write32(pll_para, MPLL_CTRL_REG);
	k_busy_wait(MPLL_SETTLE_US);

	return (sys_read32(MPLL_STATUS_REG) & MPLL_LOCK_BIT) ? 0 : -1;
}

/*
 * Program M=m, wait for the glitch detector to observe the new frequency,
 * and report/clear a trip. Returns 0 if the step passed cleanly, -1 if the
 * PLL dropped lock or the tamper glitch detector tripped.
 */
static int mpll_try_m(int m, const char *phase)
{
	uint32_t reg = mpll_reg_for_m(m);

#ifdef ENABLE_TAMPER
	tamper_init(0, 8);

	if (mpll_program_nf(reg)) {
		LOG_INF("PLL shmoo (%s): lock lost at M=%d (%u.%03uMHz)",
		       phase, m, MPLL_M_TO_MHZ(m), MPLL_M_TO_KHZ_FRAC(m));
		return -1;
	}

	if (sys_read32(TAMPER_STATUS_REG) & TAMPER_ALERT) {
		LOG_INF("PLL shmoo (%s): tamper trip at M=%d (%u.%03uMHz)",
		       phase, m, MPLL_M_TO_MHZ(m), MPLL_M_TO_KHZ_FRAC(m));
		sys_write32(TAMPER_ALERT, TAMPER_STATUS_REG);
		if (readl_poll_timeout(TAMPER_STATUS_REG, reg, !(reg & TAMPER_ALERT),
				       TAMPER_CLEAR_TIMEOUT_US))
			LOG_INF("PLL shmoo (%s): tamper alert stuck at M=%d", phase, m);
		return -1;
	}

	LOG_INF("PLL shmoo (%s): M=%d (%u.%03uMHz) OK",
	       phase, m, MPLL_M_TO_MHZ(m), MPLL_M_TO_KHZ_FRAC(m));
#else
	if (mpll_program_nf(reg)) {
		LOG_INF("PLL shmoo (%s): lock lost at M=%d (%u.%03uMHz)",
		       phase, m, MPLL_M_TO_MHZ(m), MPLL_M_TO_KHZ_FRAC(m));
		return -1;
	}

#endif
	return 0;
}

/*
 * Steps M by 1 count per iteration from start_m to target_m (inclusive),
 * settling and checking lock at each step via mpll_try_m() (trips crossed
 * along the way are expected re-entering band 1 and are only logged, not
 * fatal). Used to bring the PLL back to its default operating frequency
 * gradually - one count at a time - instead of jumping the control word
 * directly, which would otherwise re-glitch through any band edge in
 * between. Returns 0 if still locked at target_m, -1 otherwise.
 */
static int mpll_step_to(int start_m, int target_m, const char *leg)
{
	int direction = (target_m >= start_m) ? 1 : -1;
	int m = start_m;

	while (m != target_m) {
		m += direction;
		mpll_try_m(m, leg);
	}

	return (sys_read32(MPLL_STATUS_REG) & MPLL_LOCK_BIT) ? 0 : -1;
}

int pll_calibration(int step, int diff)
{
	int ret = 0;

	LOG_INF("PLL calibration start");

	if (!(sys_read32(MPLL_STATUS_REG) & MPLL_LOCK_BIT)) {
		LOG_WRN("Power on pll is not locked");
		return -1;
	}

	// init pll to the default 1600MHz operating point via reset+bypass.
	if (mpll_reconfigure(MPLL_DEFAULT_REG_VAL)) {
		LOG_ERR("pll is not locking");
		return -1;
	}

	/*
	 * Fixed-width up/down shmoo around the default 1600MHz operating
	 * point: for i = MPLL_SHMOO_STEPS down to 0, step up to M+i and back
	 * (up1/down1), then down to M-i and back (down2/up2), one M count at
	 * a time via mpll_step_to(). This exercises both VCO band edges near
	 * the default point and logs any step that trips or loses lock
	 * (mpll_try_m()); it does not search for the edges dynamically.
	 */
#ifdef PLL_ALL_BAND_SWEEP_UPDOWN
	for (int i = MPLL_SHMOO_STEPS; i >= 0; i--) {
		if (mpll_step_to((int)MPLL_DEFAULT_M, (int)MPLL_DEFAULT_M + i, "up1")) {
			LOG_WRN("pll failed to i=%d:up1 upper frequency", i);
			LOG_INF("pll lock status=0x%x", sys_read32(MPLL_STATUS_REG));
			ret = -1;
		}
		if (mpll_step_to((int)MPLL_DEFAULT_M + i, (int)MPLL_DEFAULT_M, "down1")) {
			LOG_WRN("pll failed to i=%d:down1 default frequency", i);
			LOG_INF("pll lock status=0x%x", sys_read32(MPLL_STATUS_REG));
			ret = -1;
		}
		if (mpll_step_to((int)MPLL_DEFAULT_M, (int)MPLL_DEFAULT_M - i, "down2")) {
			LOG_WRN("pll failed to i=%d:down2 lower frequency", i);
			LOG_INF("pll lock status=0x%x", sys_read32(MPLL_STATUS_REG));
			ret = -1;
		}
		if (mpll_step_to((int)MPLL_DEFAULT_M - i, (int)MPLL_DEFAULT_M, "up2")) {
			LOG_WRN("pll failed to i=%d:up2 default frequency", i);
			LOG_INF("pll lock status=0x%x", sys_read32(MPLL_STATUS_REG));
			ret = -1;
		}
	}

#elif defined(PLL_ALL_BAND_SCAN_DOWNUP)
	if (mpll_step_to((int)MPLL_DEFAULT_M, (int)MPLL_DEFAULT_M - MPLL_SHMOO_STEPS, "down2")) {
		LOG_WRN("pll failed to down2 lower frequency");
		ret = -1;
	}
	if (mpll_step_to((int)MPLL_DEFAULT_M - MPLL_SHMOO_STEPS, (int)MPLL_DEFAULT_M, "up2")) {
		LOG_WRN("pll failed to up2 default frequency");
		ret = -1;
	}
	if (mpll_step_to((int)MPLL_DEFAULT_M, (int)MPLL_DEFAULT_M + MPLL_SHMOO_STEPS, "up1")) {
		LOG_WRN("pll failed to up1 upper frequency");
		ret = -1;
	}
	if (mpll_step_to((int)MPLL_DEFAULT_M + MPLL_SHMOO_STEPS, (int)MPLL_DEFAULT_M, "down1")) {
		LOG_WRN("pll failed to down1 default frequency");
		ret = -1;
	}
#endif

	LOG_INF("PLL calibration done");

	if (sys_read32(MPLL_STATUS_REG) & MPLL_LOCK_BIT)
		LOG_INF("PLL lock OK");
	else {
		LOG_ERR("PLL lock failed");
		ret = -1;
	}

	tamper_init(step, diff);
	if (sys_read32(TAMPER_STATUS_REG) & TAMPER_ALERT) {
		LOG_WRN("Tamper alert after pll_calibration!! FREQ_COUNTER_CTRL_REG=0x%08x, FREQ_COUNTER_READBACK=0x%08x",
				sys_read32(FREQ_COUNTER_CTRL_REG),
				sys_read32(FREQ_COUNTER_READBACK));
		sys_write32(TAMPER_ALERT, TAMPER_STATUS_REG);
		ret = -1;
	}

	return ret;
}
