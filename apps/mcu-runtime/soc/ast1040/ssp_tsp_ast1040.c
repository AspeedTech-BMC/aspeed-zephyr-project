/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/arch/common/sys_io.h>
#include <zephyr/arch/common/sys_bitops.h>
#include <zephyr/sys/sys_io.h>
#include <zephyr/logging/log.h>
#include <platform.h>
#include <scu_ast1040.h>

LOG_MODULE_REGISTER(ssp_tsp, CONFIG_SOC_FMC_LOG_LEVEL);

#define MAX_I_D_ADDRESS		MB(512)
#define TCM_SIZE		KB(8)

int ssp_init(mem_addr_t load_addr)
{
	sys_write32(0x100000, 0x14c02908);
	sys_write32(0x100000, 0x14c02934);

#if 0
	struct ast2700_scu0 *scu;
	uint32_t reg_val;
	uint64_t phy_addr;

	if (load_addr != (mem_addr_t)DT_REG_ADDR(DT_NODELABEL(ssp_memory))) {
		LOG_ERR("FIT load address %08lx doesn't match SSP reserved memory %08lx", load_addr,
			(mem_addr_t)DT_REG_ADDR(DT_NODELABEL(ssp_memory)));
		return -1;
	}

	scu = (struct ast2700_scu0 *)DT_REG_ADDR(DT_NODELABEL(syscon));

	reg_val = sys_read32((mm_reg_t)&scu->ssp_ctrl_0);
	if (!(reg_val & SCU0_SSP_TSP_RESET_STS)) {
		return 0;
	}

	sys_write32(SCU0_RST_SSP, (mm_reg_t)&scu->modrst1_ctrl);
	sys_write32(SCU0_RST_SSP, (mm_reg_t)&scu->modrst1_clr);

	reg_val = SCU0_SSP_TSP_NIDEN | SCU0_SSP_TSP_DBGEN |
		  SCU0_SSP_TSP_DBG_ENABLE | SCU0_SSP_TSP_RESET;
	sys_write32(reg_val, (mm_reg_t)&scu->ssp_ctrl_0);

	/*
	 * SSP Memory Map:
	 * - 0x0000_0000 - 0x0587_FFFF: ssp_remap2 -> DRAM[load_addr]
	 * - 0x0588_0000 - 0x1FFF_DFFF: ssp_remap1 -> AHB -> DRAM[0]
	 * - 0x1FFF_E000 - 0x2000_0000: ssp_remap0 -> TCM (SSP stack)
	 *
	 * The SSP serves as the secure loader for TSP, ATF, OP-TEE, and U-Boot.
	 * Therefore, their load buffers must be visible to the SSP.
	 *
	 * - SSP remap entry #2 (ssp_memory_base/size) maps the load buffers
	 *   for SSP, TSP, ATF, and OP-TEE. Ensure these buffers are contiguous.
	 * - SSP remap entry #1 (ssp_ahb_base/size) maps the load buffer
	 *   for U-Boot at DRAM offset 0x0.
	 * - SSP remap entry #0 (ssp_remap0_base/size) maps TCM, which is used for stack.
	 */
	sys_write32(0, (mm_reg_t)&scu->ssp_memory_base);
	reg_val = DT_REG_SIZE(DT_NODELABEL(ssp_memory)) + DT_REG_SIZE(DT_NODELABEL(tsp_memory)) +
		  DT_REG_SIZE(DT_NODELABEL(atf)) + DT_REG_SIZE(DT_NODELABEL(optee_core)) +
		  DT_REG_SIZE(DT_NODELABEL(ipc_ssp_share));
	sys_write32(reg_val, (mm_reg_t)&scu->ssp_memory_size);

	sys_write32(reg_val, (mm_reg_t)&scu->ssp_ahb_base);
	sys_write32(MAX_I_D_ADDRESS - reg_val - TCM_SIZE, (mm_reg_t)&scu->ssp_ahb_size);

	sys_write32(MAX_I_D_ADDRESS - TCM_SIZE, (mm_reg_t)&scu->ssp_tcm_base);
	sys_write32(TCM_SIZE, (mm_reg_t)&scu->ssp_tcm_size);

	/* Configure physical AHB remap: through H2M, mapped to SYS_DRAM_BASE */
	sys_write32((uint32_t)(SYS_DRAM_BASE >> 4), (mm_reg_t)&scu->ssp_ctrl_1);

	/* Configure physical DRAM remap */
	phy_addr = ((uint64_t)load_addr - ASPEED_DRAM_BASE) | SYS_DRAM_BASE;
	reg_val = (uint32_t)(phy_addr >> 4);
	sys_write32(reg_val, (mm_reg_t)&scu->ssp_ctrl_2);

        /*
         * For A1, the Cache region can only be enabled entirely;
         * partial enabling is not supported.
         */
        sys_write32(GENMASK(31, 0), (mm_reg_t)&scu->ssp_ctrl_3);
        sys_write32(GENMASK(31, 0), (mm_reg_t)&scu->ssp_ctrl_4);

        /* Disable i & d cache by default */
        sys_write32(SCU0_SSP_TSP_CTRL_ICACHE_EN | SCU0_SSP_TSP_CTRL_DCACHE_EN,
                    (mm_reg_t)&scu->ssp_ctrl_6);

#endif
	return 0;
}

int ssp_enable(void)
{
	sys_write32(sys_read32(0x14c02900) | 0x3, 0x14c02900);
#if 0
	struct ast2700_scu0 *scu;

	scu = (struct ast2700_scu0 *)DT_REG_ADDR(DT_NODELABEL(syscon));

        sys_set_bits((mem_addr_t)&scu->ssp_ctrl_0,
                     SCU0_SSP_TSP_ENABLE | SCU0_SSP_TSP_RESET);
#endif

	return 0;
}
