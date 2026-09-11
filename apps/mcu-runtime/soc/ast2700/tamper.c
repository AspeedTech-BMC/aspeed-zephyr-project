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

#define TAMPER_ALERT		BIT(3)
#define UNLOCK_ALERT		BIT(17)
#define TAMPER_INIT_DIFF	0x0
#define TAMPER_INIT_STEP	0x1
#define TAMPER_RUNTIME_DIFF	0x0
#define TAMPER_RUNTIME_STEP	0x2

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
	uintptr_t base = (uintptr_t) 0x12c023a0;
	uint32_t reg;
	uint32_t sel;
	int ret;

	sys_write32(0, 0x12c023a0);

	if (src == 0)
		sel = 0x3; //dly32
	else if (src == 1)
		sel = 0x5; //mpll/4

	sel = sel << 2;

	reg = sel | SCU_FREQ_RING_ENABLE | SCU_FREQ_RING_STG(31);

	sys_write32(reg, base);
	k_busy_wait(2000);

	reg |= SCU_FREQ_OSC_ENABLE;
	sys_write32(reg, base);
	ret = readl_poll_timeout(base, reg, (reg & SCU_FREQ_DONE), 1000000);
	if (ret < 0)
		return 0;

	reg = sys_read32(0x12c023b0);

	return 4 * counter_to_delay_ps(SCU_FREQ_COUNTER(reg));
}

static void tamper_timer_cb(struct k_timer *timer)
{
	uint32_t tamper, phyunlock;

        ARG_UNUSED(timer);

	tamper = sys_read32(0x12c021c4);
	phyunlock = sys_read32(0x130401a8);

	printf("***** Tamper=%d C, DDRPHY unlock status=0x%x *****\n", tamper & 8, phyunlock);

	if (tamper & TAMPER_ALERT) {
		printf("Tamper Alert!!!\n");

		// clear tamper interrupt.
		sys_write32(TAMPER_ALERT, 0x12c021c4);
		printf("SCU_3b0=0x%x\n", sys_read32(0x12c023b0));
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
	sys_write32(TAMPER_RUNTIME_STEP, 0x12c023a4);
	sys_write32(TAMPER_RUNTIME_DIFF, 0x12c023a8);

	// kick a timer to print tamper every 1 second.
	k_timer_start(&tamper_progress_timer, K_SECONDS(1), K_SECONDS(1));

	return 0;
}

int tamper_check(void)
{
	uint32_t tamper, phyunlock;
	int reset = 0;

	tamper = sys_read32(0x12c021c4);
	phyunlock = sys_read32(0x130401a8);

	// reconfigure mcu0 remap for upper 1GB.
	sys_write32((0x44 << 16) | (sys_read32(0x14c02110) & 0xff00ffff), 0x14c02110);
	printf("SCU1_110=0x%x\n", sys_read32(0x14c02110));

	if (tamper & TAMPER_ALERT) {
		printf("Tamper Attention!!!\n");
		printf("SCU_3b0=0x%x\n", sys_read32(0x12c023b0));
		reset++;
	}

	if (phyunlock & UNLOCK_ALERT) {
		printf("DDRPHY Unlock Attention!!!\n");
		printf("SOC MPLL setting=0x%x, status=0x%08x\n", sys_read32(0x12c02310), sys_read32(0x12c02314));

		// clear ddrphy unlock status.
		sys_write32(0x1, 0x130401ac);
		sys_write32(0x0, 0x130401ac);

		sys_write32(0x89abcdef, 0xfffffff8);
		k_busy_wait(1000);

		// check if mbus hang.
		if (sys_read32(0xfffffff8) != 0x89abcdef)
			printf("DDRPHY unlock cannot write to DRAM!!!\n");

		reset++;
	}

	if (reset) {
		printf("Performing wdt reset...\n");

		// wdt dramc reset
		sys_write32(0x8207ff7b, 0x14c3701c);
		sys_write32(0x400, 0x14c37004);
		sys_write32(0x4755, 0x14c37008);
		sys_write32(0x13, 0x14c3700c);

		// shouldn't be here.
		while (1) {
			k_busy_wait(1000);
		};
	}

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

	printf("Tamper detection start\n");

	sys_write32(TAMPER_ALERT, 0x12c021c4);

	sys_write32(0x0, 0x12c023a0);
	sys_write32(step, 0x12c023a4); //Maximum Stepping error
	sys_write32(diff, 0x12c023a8); //Maximum Difference error

	// 64 refclk cycles.
	sys_write32(0x150014, 0x12c023a0);

	// wait 1 second for osc settle.
	k_busy_wait(1000000);

	reg = sys_read32(0x12c021c4);
	printf("Initial Tamper=%d \n", reg & 8);
	printf("0x12c023a0=0x%08x, 0x12c023b0=0x%08x\n", sys_read32(0x12c023a0), sys_read32(0x12c023b0));

	return reg & 8;
}

int pll_calibration(int step, int diff)
{
	uint32_t pllcfg[] = {0x41, 0x40, 0x3f, 0x40};
	int i = 0;//ARRAY_SIZE(pllcfg);

	printf("pll calibration start\n");

	// clear tamper interrupt
	sys_write32(0x8, 0x12c021c4);

	sys_write32(0x0, 0x12c023a0);
	sys_write32(step, 0x12c023a4); //Maximum Stepping error
	sys_write32(diff, 0x12c023a8); //Maximum Difference error
	sys_write32(0x130014, 0x12c023a0);

	// wait 1 second for osc settle.
	k_busy_wait(1000000);

	if (sys_read32(0x12c021c4) & 0x8) {
		printf("Initial Tamper detection failed\n");
		sys_write32(0x8, 0x12c021c4);
		return -1;
	}

	while (i < ARRAY_SIZE(pllcfg)) {
		sys_write32(pllcfg[i], 0x12c02310);

		// wait 100ms.
		k_busy_wait(100000);
		i++;
	};

	if (sys_read32(0x12c021c4) & 0x8) {
		printf("Runtime Tamper detection failed, 0x3b0=0x%x\n", sys_read32(0x12c023b0));
		sys_write32(0x8, 0x12c021c4);
		return -1;
	}

	return 0;
}
