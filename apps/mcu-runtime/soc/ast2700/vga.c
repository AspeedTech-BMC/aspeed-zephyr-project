/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <zephyr/types.h>
#include <zephyr/sys/sys_io.h>
#include <zephyr/sys/util.h>
#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <platform.h>
#include <e2m_ast2700.h>
#include <sdram_ast2700.h>
#include <vga_ast2700.h>
#include <ast_loader.h>

#define VBIOS0_RESERVED_MEM_BASE DT_REG_ADDR(DT_NODELABEL(vbios_base0))
#define VBIOS1_RESERVED_MEM_BASE DT_REG_ADDR(DT_NODELABEL(vbios_base1))

#define BIOS_HEADER_TAG 0xaa55

LOG_MODULE_REGISTER(vga, CONFIG_SOC_FMC_LOG_LEVEL);

static uint32_t _ast_get_e2m_addr(struct sdramc_regs *ram, uint8_t node)
{
	uint32_t val;

	// get GM's base address
	val = (ram->reserved3[0] >> (node * 16)) & 0xffff;
	// e2m memory accessing address[36:24] will be replaced as
	// map_addr[31:20]
	val = (val << 20) | 0x40000000;

	return val;
}

static int vbios_init(struct ast2700_scu0 *scu, uint8_t node)
{
	uint32_t vbios_mem_base;
	void *vbios_base;
	uint32_t vbios_e2m_value;
	uint32_t arm_dram_base = ASPEED_DRAM_BASE >> 1;

	if (node == 0)
		vbios_base = (void *)VBIOS0_RESERVED_MEM_BASE;
	else
		vbios_base = (void *)VBIOS1_RESERVED_MEM_BASE;

	LOG_DBG("vbios%d mem : 0x%p", node, vbios_base);

	/* Get the controller base address */
	vbios_mem_base = (uintptr_t)(vbios_base);
	LOG_DBG("vbios_mem_base : 0x%x", vbios_mem_base);

	/* Initial memory region and copy vbios into it */
	/* If the memory region would not be loaded before */
	if (*(uint16_t *)vbios_mem_base != BIOS_HEADER_TAG) {
		memset((uint32_t *)vbios_base, 0x0, 0x10000);
		ast_loader_load_image(CPTRA_UEFI_FW_ID, (uint32_t *)vbios_base, 0);
	}

	/* Remove riscv Dram base */
	vbios_mem_base &= ~(ASPEED_DRAM_BASE);

	/* Set VBIOS 64KB into reserved buffer */
	vbios_e2m_value = (vbios_mem_base >> 4) | 0x05 | arm_dram_base;

	LOG_DBG("vbios_e2m_value : 0x%x", vbios_e2m_value);

	/* Set VBIOS setting into e2m */
	if (node == 0) {
		sys_write32(vbios_e2m_value, E2M0_VBIOS_RAM);
		sys_write32(vbios_e2m_value, (uintptr_t)&scu->pci0_misc[11]);
	} else {
		sys_write32(vbios_e2m_value, E2M1_VBIOS_RAM);
		sys_write32(vbios_e2m_value, (uintptr_t)&scu->pci1_misc[11]);
	}

	return 0;
}

static uint32_t ast_vga_get_gfm_ctrl(uint8_t node)
{
	if (node == 1)
		return (BIT(19) | BIT(28));
	return (BIT(10) | BIT(27));
}

static void _ast_update_e2m(struct ast2700_scu0 *scu, struct sdramc_regs *ram, bool is_64vram,
			    const uint8_t nodes[2])
{
	uint32_t val, addr, vram_size;
	uint8_t vram_size_cfg;
	const uint32_t offsets[2] = { E2M0_VGA_RAM, E2M1_VGA_RAM };
	const uint32_t misc[2] = { (uintptr_t)&scu->pci0_misc[3], (uintptr_t)&scu->pci1_misc[3] };
	int node;

	vram_size_cfg = is_64vram ? 0xf : 0xe;
	vram_size = 2 << (vram_size_cfg + 10);
	LOG_DBG("%s: VRAM size(%x) cfg(%x)\n", __func__, vram_size, vram_size_cfg);

	for (node = 0; node < 2; node++) {
		if (!nodes[node])
			continue;

		addr = _ast_get_e2m_addr(ram, node);
		val = addr | FIELD_PREP(SCU0_PCI_MISC0C_FB_SIZE, vram_size_cfg);
		LOG_DBG("pcie%d e2m addr(%x) val(%x)", node, addr, val);
		sys_write32(val, offsets[node]);
		sys_write32(val, misc[node]);
	}
}

int vga_init(struct ast_chip *chip, bool open_codec)
{
	struct sdramc_regs *ram = (struct sdramc_regs *)DRAMC_BASE;
	uint32_t val;
	struct ast2700_scu0 *scu = chip->scu0;
	bool is_pcie0_enable = chip->pcie0_enable;
	bool is_pcie1_enable = chip->pcie1_enable;
	uint8_t nodes[2];
	bool is_64vram = ram->gfmcfg & BIT(0);
	uint8_t dac_src = scu->hwstrap1 & BIT(28);
	uint8_t dp_src = scu->hwstrap1 & BIT(29);
	int node;
	volatile uint32_t *const scratch_regs[2] = {
		&scu->vga0_scratch1[0],
		&scu->vga1_scratch1[0],
	};
	volatile uint32_t *const gfm_regs[2] = {
		&ram->gfm0ctl,
		&ram->gfm1ctl,
	};
	const uint32_t clk_gates[2] = { SCU0_CLKGATE1_VGA0, SCU0_CLKGATE1_VGA1 };

	/* Decide feature by efuse
	 *  0: 2750 has full function
	 *  1: 2700 has only 1 VGA
	 *  2: 2720 has no VGA
	 */
	if (chip->efuse == 1) {
		is_pcie1_enable = false;
		dac_src = 0;
		dp_src = 0;
	} else if (chip->efuse == 2) {
		LOG_DBG("%s: 2720 has no VGA", __func__);
		return 0;
	}

	nodes[0] = is_pcie0_enable;
	nodes[1] = is_pcie1_enable;

	LOG_DBG("%s: ENABLE 0(%d) 1(%d)", __func__, is_pcie0_enable, is_pcie1_enable);

	if (scu->hwstrap1 & BIT(11)) {
		LOG_DBG("%s: Skip probe since it has been done.\n", __func__);
		return 0;
	}

	_ast_update_e2m(scu, ram, is_64vram, nodes);

	/* scratch for VGA CRAA[1:0] : 10b: 32Mbytes, 11b: 64Mbytes */
	setbits_le32(&scu->hwstrap1, BIT(11));
	if (is_64vram)
		setbits_le32(&scu->hwstrap1, BIT(10));
	else
		setbits_le32(&scu->hwstrap1_clr, BIT(10));

	for (node = 0; node < 2; node++) {
		if (!nodes[node])
			continue;

		// enable clk
		setbits_le32(&scu->clkgate_clr, clk_gates[node]);

		/* load node vbios */
		vbios_init(scu, node);

		// scratch for VGA CRD0[12]: Disable P2A
		setbits_le32(scratch_regs[node], BIT(7) | BIT(12));

		// Enable VRAM address offset: cursor, 2d
		sys_write32(ast_vga_get_gfm_ctrl(node), (uintptr_t)gfm_regs[node]);
	}

	if (nodes[0] || nodes[1]) {
		struct ast2700_vga_link *packer_cpu, *retimer_cpu, *packer_io,
					*retimer_io;

		// enable dac clk
		setbits_le32(&scu->clkgate_clr, SCU0_CLKGATE1_DAC);
		// release vga reset
		setbits_le32(&scu->modrst2_clr, SCU0_RST2_VGA);

		val = scu->vga_func_ctrl;
		val &= ~(SCU0_VGA_FUNC_DAC_OUTPUT |
			 SCU0_VGA_FUNC_DP_OUTPUT |
			 SCU0_VGA_FUNC_DAC_DISABLE);
		val |= FIELD_PREP(SCU0_VGA_FUNC_DAC_OUTPUT, dac_src) |
		       FIELD_PREP(SCU0_VGA_FUNC_DP_OUTPUT, dp_src) |
		       FIELD_PREP(SCU0_VGA_FUNC_DAC_DISABLE, 0);
		sys_write32(val, (uintptr_t)&scu->vga_func_ctrl);

		// vga link init
		packer_cpu = (struct ast2700_vga_link *)VGA_PACKER_CPU_BASE;
		retimer_cpu = (struct ast2700_vga_link *)VGA_RETIMER_CPU_BASE;
		packer_io = (struct ast2700_vga_link *)VGA_PACKER_IO_BASE;
		retimer_io = (struct ast2700_vga_link *)VGA_RETIMER_IO_BASE;

		/* codec setting for vlink */
		if (open_codec) {
			packer_cpu->REG10.value  = 0x00020009;
			packer_cpu->REG1C.value  = 0x80F0F002;
		} else {
			packer_cpu->REG10.value  = 0x00030009;
		}
		val = 0x10000000 | dac_src;
		packer_cpu->REG50.value  = val;
		packer_cpu->REG44.value  = 0x00100010;
		retimer_cpu->REG10.value = 0x00030009;
		packer_io->REG10.value   = 0x00030009;
		packer_io->REG44.value   = 0x00010002;
		retimer_io->REG10.value  = 0x00230009;
		retimer_io->REG44.value  = 0x00100010;
	}

	return 0;
}
