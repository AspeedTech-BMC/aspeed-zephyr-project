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

#define PLL_ALL_BAND_SWEEP_UPDOWN 1
//#define PLL_ALL_BAND_SCAN_DOWNUP 1
//#define ENABLE_TAMPER 1

#define MPLL_CTRL_REG		0x12c02310
#define MPLL_STATUS_REG		0x12c02314

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

/* SCU scratch reg 0x12c029B8: upper 16 bits hold sticky event counters
 * that survive the WDT reset below, so they can be inspected post-mortem.
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

static uint32_t counter_to_delay_ps(uint32_t value)
{
	return (25000000U / 512) * (value + 1);
}

#define SCU_FREQ_COUNTER_MASK 	GENMASK(17, 0)
#define SCU_FREQ_RING_ENABLE 	BIT(0)
#define SCU_FREQ_RING_STG(x)	FIELD_PREP(GENMASK(14, 9), (x))
#define SCU_FREQ_OSC_ENABLE	BIT(1)
#define SCU_FREQ_DONE		BIT(6)
//#define SCU_FREQ_COUNTER_MASK	GENMASK(29, 16)
#define SCU_FREQ_COUNTER(x)	FIELD_GET(SCU_FREQ_COUNTER_MASK, (x))

static uint32_t cal_src(int src)
{
	uintptr_t base = (uintptr_t) FREQ_COUNTER_CTRL_REG;
	uint32_t reg;
	uint32_t sel;
	int ret;

	sys_write32(0, FREQ_COUNTER_CTRL_REG);

	if (src == 0)
		sel = 0x3; //dly32
	else if (src == 1)
		sel = 0x5; //mpll/4
	else
		return 0;

	sel = sel << 2;

	reg = sel | SCU_FREQ_RING_ENABLE | SCU_FREQ_RING_STG(31);

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
	phyunlock = sys_read32(0x130401a8);

	printf("***** Tamper=%d C, DDRPHY unlock status=0x%x *****\n", tamper & 8, phyunlock);

	if (tamper & TAMPER_ALERT) {
		printf("Tamper Alert!!!\n");

		// clear tamper interrupt.
		sys_write32(TAMPER_ALERT, TAMPER_STATUS_REG);
		printf("SCU_3b0=0x%x\n", sys_read32(FREQ_COUNTER_READBACK));
		printf("MPLL=%d Hz, dly32=%d Hz\n", cal_src(1), cal_src(0));

		// restart tamper detection.
		tamper_init(TAMPER_RUNTIME_STEP, TAMPER_RUNTIME_DIFF);

		sys_write32(0x87654321, 0xfffffff0);
		k_busy_wait(1000);

		// check if mbus hang.
		if (sys_read32(0xfffffff0) != 0x87654321)
			printf("DDRPHY unlock cannot write to DRAM!!!\n");
	}

	// check if DDRPHY is unlocked
	if (phyunlock & UNLOCK_ALERT) {
		printf("Unlock Alert!!!\n");

		sys_write32(0x12345678, 0xfffffff4);
		k_busy_wait(1000);

		// check if mbus hang.
		if (sys_read32(0xfffffff4) != 0x12345678) {
			// keep alert message but not clear status until wdt recovery.
			printf("DDRPHY unlock cannot write to DRAM!!!\n");
		} else {
			// clear ddrphy unlock status.
			sys_write32(0x1, 0x130401ac);
			sys_write32(0x0, 0x130401ac);
		}
	}
}

K_TIMER_DEFINE(tamper_progress_timer, tamper_timer_cb, NULL);
int tamper_kick(void)
{
	sys_write32(TAMPER_RUNTIME_STEP, FREQ_COUNTER_STEP_REG);
	sys_write32(TAMPER_RUNTIME_DIFF, FREQ_COUNTER_DIFF_REG);

	// kick a timer to print tamper every 1 second.
	k_timer_start(&tamper_progress_timer, K_SECONDS(1), K_SECONDS(1));

	return 0;
}

int tamper_check(void)
{
	uint32_t tamper, phyunlock;

	tamper = sys_read32(TAMPER_STATUS_REG);
	phyunlock = sys_read32(0x130401a8);

	if (tamper & TAMPER_ALERT) {
		uint32_t scratch = sys_read32(SCU_SCRATCH_REG);
		uint32_t cnt = (scratch & TAMPER_CNT_MASK) >> TAMPER_CNT_SHIFT;

		printf("Tamper Attention!!!\n");
		printf("SCU_3b0=0x%x\n", sys_read32(FREQ_COUNTER_READBACK));

		if (cnt < 0xff)
			cnt++;
		scratch = (scratch & ~TAMPER_CNT_MASK) | (cnt << TAMPER_CNT_SHIFT);
		sys_write32(scratch, SCU_SCRATCH_REG);
	}

	if (phyunlock & UNLOCK_ALERT) {
		uint32_t scratch = sys_read32(SCU_SCRATCH_REG);
		uint32_t cnt = (scratch & UNLOCK_CNT_MASK) >> UNLOCK_CNT_SHIFT;

		printf("DDRPHY Unlock Attention!!!\n");
		printf("SOC MPLL setting=0x%x, status=0x%08x\n", sys_read32(MPLL_CTRL_REG), sys_read32(MPLL_STATUS_REG));

		if (cnt < 0xff)
			cnt++;
		scratch = (scratch & ~UNLOCK_CNT_MASK) | (cnt << UNLOCK_CNT_SHIFT);
		sys_write32(scratch, SCU_SCRATCH_REG);

		// clear ddrphy unlock status.
		sys_write32(0x1, 0x130401ac);
		sys_write32(0x0, 0x130401ac);

		sys_write32(0x89abcdef, 0xfffffff8);
		k_busy_wait(1000);

		// check if mbus hang.
		if (sys_read32(0xfffffff8) != 0x89abcdef)
			printf("DDRPHY unlock cannot write to DRAM!!!\n");
	}

	/* Change tamper detection to runtime setting */
	sys_write32(TAMPER_RUNTIME_STEP, FREQ_COUNTER_STEP_REG);
	sys_write32(TAMPER_RUNTIME_DIFF, FREQ_COUNTER_DIFF_REG);

	return 0;
}

int tamper_stop(void)
{
	k_timer_stop(&tamper_progress_timer);

	printf("Tamper stop\n");
	return 0;
}

int tamper_init(int step, int diff)
{
	uint32_t reg;

	//printf("Tamper detection start\n");

	sys_write32(0, FREQ_COUNTER_STEP_REG); //Maximum Stepping error
	sys_write32(0, FREQ_COUNTER_DIFF_REG); //Maximum Difference error
	sys_write32(0x180014, FREQ_COUNTER_CTRL_REG); //Disable tamper and keep mpll source
	// wait for tamper settle.
	k_busy_wait(10);

	sys_write32(0x14, FREQ_COUNTER_CTRL_REG);
	sys_write32(step, FREQ_COUNTER_STEP_REG); //Maximum Stepping error
	sys_write32(diff, FREQ_COUNTER_DIFF_REG); //Maximum Difference error

	k_busy_wait(100);
	sys_write32(TAMPER_ALERT, TAMPER_STATUS_REG);

	// 0x15:64 refclk cycles. 25MHz / 64 = 390.625kHz, ~400KHz x 4 = 1.6MHz. 1.6GHz +- 1.6MHz => assert alert.
	// 0x19:16 refclk cycles. 25MHz / 16 = 1.562Mhz, 1.5MHz x 4 = 6MHz. 1.6GHz +- 6MHz => assert alert.
	// 0xb: 16384 refclk cycles. 25MHz / 16384 = 1.525kHz, 1.5kHz x 4 = 6kHz. 1.6GHz +- 6kHz => assert alert.
	sys_write32(0x190014, FREQ_COUNTER_CTRL_REG);

	// wait 100 us for tamper settle.
	k_busy_wait(100);

	reg = sys_read32(TAMPER_STATUS_REG);
	if (reg & TAMPER_ALERT) {
		printf("Tamper alert!! FREQ_COUNTER_CTRL_REG=0x%08x, FREQ_COUNTER_READBACK=0x%08x\n",
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
 */
#define MPLL_RESET_BIT		BIT(25)
#define MPLL_BYPASS_BIT		BIT(24)
#define MPLL_CLKNF_MASK		GENMASK(12, 0)	/* M */
#define MPLL_CLKNR_MASK		GENMASK(18, 13)	/* NR - 1 */
#define MPLL_CLKOD_MASK		GENMASK(22, 19)	/* OD - 1 */
#define MPLL_LOCK_BIT		BIT(31)
#define MPLL_LOCK_TIMEOUT_US	100000

#define MPLL_REFCLK_HZ		25000000U
#define MPLL_DEFAULT_M		0x40U//1024U
#define MPLL_DEFAULT_NR		1U//16U
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
		printf("PLL shmoo (%s): lock lost at M=%d (%u.%03uMHz)\n",
		       phase, m, MPLL_M_TO_MHZ(m), MPLL_M_TO_KHZ_FRAC(m));
		return -1;
	}

	if (sys_read32(TAMPER_STATUS_REG) & TAMPER_ALERT) {
		printf("PLL shmoo (%s): tamper trip at M=%d (%u.%03uMHz)\n",
		       phase, m, MPLL_M_TO_MHZ(m), MPLL_M_TO_KHZ_FRAC(m));
		sys_write32(TAMPER_ALERT, TAMPER_STATUS_REG);
		if (readl_poll_timeout(TAMPER_STATUS_REG, reg, !(reg & TAMPER_ALERT),
				       TAMPER_CLEAR_TIMEOUT_US))
			printf("PLL shmoo (%s): tamper alert stuck at M=%d\n", phase, m);
		return -1;
	}

	printf("PLL shmoo (%s): M=%d (%u.%03uMHz) OK\n",
	       phase, m, MPLL_M_TO_MHZ(m), MPLL_M_TO_KHZ_FRAC(m));
#else
	if (mpll_program_nf(reg)) {
		printf("PLL shmoo (%s): lock lost at M=%d (%u.%03uMHz)\n",
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

	printf("PLL calibration start\n");

	if (!(sys_read32(MPLL_STATUS_REG) & MPLL_LOCK_BIT)) {
		printf("Power on pll is not locked\n");
		return -1;
	}

	// init pll to the default 1600MHz operating point via reset+bypass.
	sys_write32(MPLL_DEFAULT_REG_VAL | MPLL_RESET_BIT | MPLL_BYPASS_BIT, MPLL_CTRL_REG);
	k_busy_wait(MPLL_SETTLE_US);
	sys_write32(MPLL_DEFAULT_REG_VAL | MPLL_BYPASS_BIT, MPLL_CTRL_REG);
	k_busy_wait(MPLL_SETTLE_US);
	sys_write32(MPLL_DEFAULT_REG_VAL, MPLL_CTRL_REG);
	k_busy_wait(MPLL_SETTLE_US);

	if (!(sys_read32(MPLL_STATUS_REG) & MPLL_LOCK_BIT)) {
		printf("pll is not locking\n");
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
			printf("pll failed to i=%d:up1 upper frequency\n", i);
			printf("pll lock status=0x%x\n", sys_read32(MPLL_STATUS_REG));
			ret = -1;
		}
		if (mpll_step_to((int)MPLL_DEFAULT_M + i, (int)MPLL_DEFAULT_M, "down1")) {
			printf("pll failed to i=%d:down1 default frequency\n", i);
			printf("pll lock status=0x%x\n", sys_read32(MPLL_STATUS_REG));
			ret = -1;
		}
		if (mpll_step_to((int)MPLL_DEFAULT_M, (int)MPLL_DEFAULT_M - i, "down2")) {
			printf("pll failed to i=%d:down2 lower frequency\n", i);
			printf("pll lock status=0x%x\n", sys_read32(MPLL_STATUS_REG));
			ret = -1;
		}
		if (mpll_step_to((int)MPLL_DEFAULT_M - i, (int)MPLL_DEFAULT_M, "up2")) {
			printf("pll failed to i=%d:up2 default frequency\n", i);
			printf("pll lock status=0x%x\n", sys_read32(MPLL_STATUS_REG));
			ret = -1;
		}
	}

#elif defined(PLL_ALL_BAND_SCAN_DOWNUP)
	if (mpll_step_to((int)MPLL_DEFAULT_M, (int)MPLL_DEFAULT_M - MPLL_SHMOO_STEPS, "down2")) {
		printf("pll failed to down2 lower frequency\n");
		ret = -1;
	}
	if (mpll_step_to((int)MPLL_DEFAULT_M - MPLL_SHMOO_STEPS, (int)MPLL_DEFAULT_M, "up2")) {
		printf("pll failed to up2 default frequency\n");
		ret = -1;
	}
	if (mpll_step_to((int)MPLL_DEFAULT_M, (int)MPLL_DEFAULT_M + MPLL_SHMOO_STEPS, "up1")) {
		printf("pll failed to up1 upper frequency\n");
		ret = -1;
	}
	if (mpll_step_to((int)MPLL_DEFAULT_M + MPLL_SHMOO_STEPS, (int)MPLL_DEFAULT_M, "down1")) {
		printf("pll failed to down1 default frequency\n");
		ret = -1;
	}
#endif

	printf("PLL calibration done\n");

	if (sys_read32(MPLL_STATUS_REG) & MPLL_LOCK_BIT)
		printf("PLL lock OK\n");
	else {
		printf("PLL lock failed\n");
		ret = -1;
	}

	tamper_init(step, diff);
	if (sys_read32(TAMPER_STATUS_REG) & TAMPER_ALERT) {
		printf("Tamper alert after pll_calibration!! FREQ_COUNTER_CTRL_REG=0x%08x, FREQ_COUNTER_READBACK=0x%08x\n",
				sys_read32(FREQ_COUNTER_CTRL_REG),
				sys_read32(FREQ_COUNTER_READBACK));
		sys_write32(TAMPER_ALERT, TAMPER_STATUS_REG);
		ret = -1;
	}

	return ret;
}
