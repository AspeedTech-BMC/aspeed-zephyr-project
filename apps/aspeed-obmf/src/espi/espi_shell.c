/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/device.h>
#include <zephyr/drivers/espi.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/sys_io.h>
#include <zephyr/sys/util.h>

#include "espi_bridge.h"
#include "lstp/lstp_backend.h"

LOG_MODULE_REGISTER(espi_shell, CONFIG_LOG_DEFAULT_LEVEL);

/* Register data ports must not be touched by a diagnostic dump. */
#define ESPI_CH0_PC_RX_DATA 0x11cU
#define ESPI_CH0_PC_TX_DATA 0x12cU
#define ESPI_CH0_NP_TX_DATA 0x13cU
#define ESPI_CH2_RX_DATA    0x31cU
#define ESPI_CH2_TX_DATA    0x32cU
#define ESPI_CH3_RX_DATA    0x41cU
#define ESPI_CH3_TX_DATA    0x42cU

static const struct device *get_espi_dev(const struct shell *sh)
{
	const struct device *dev = espi_bridge_get_dev();

	if (dev == NULL) {
		if (sh != NULL) {
			shell_error(sh, "eSPI device (espi0) is not ready");
		}
		return NULL;
	}
	return dev;
}

static int parse_u32(const char *text, uint32_t *value)
{
	char *end;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 0);
	if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX) {
		return -EINVAL;
	}

	*value = (uint32_t)parsed;
	return 0;
}

static void print_vwire_decode_shell(const struct shell *sh, uint32_t evt0, uint32_t evt1)
{
	const uint32_t evt[2] = { evt0, evt1 };

	for (size_t i = 0; i < espi_vw_bit_count; i++) {
		const struct espi_vw_bit_info *sig = &espi_vw_bit_map[i];

		shell_print(sh, "  - %-17s: %u", sig->name, !!(evt[sig->evt] & BIT(sig->bit)));
	}
}

static int parse_vw_gpio(const struct shell *sh, const char *index_text,
			 const char *source_text, uint8_t *index, uint8_t *source)
{
	uint32_t parsed_index, parsed_source;

	if (parse_u32(index_text, &parsed_index) || parse_u32(source_text, &parsed_source) ||
	    parsed_index < ESPI_ASPEED_VW_GPIO_INDEX_MIN ||
	    parsed_index > ESPI_ASPEED_VW_GPIO_INDEX_MAX ||
	    parsed_source >= ESPI_ASPEED_VW_GPIO_SRC_COUNT) {
		shell_error(sh, "VW GPIO must be <index 0x80..0x8f> <source 0..3>");
		return -EINVAL;
	}

	*index = parsed_index;
	*source = parsed_source;
	return 0;
}

static const char *vw_gpio_direction_name(enum espi_aspeed_vw_gpio_direction direction)
{
	return direction == ESPI_ASPEED_VW_GPIO_TARGET_TO_CONTROLLER ? "target->controller"
								     : "controller->target";
}

static int cmd_espi_status(const struct shell *sh, size_t argc, char **argv)
{
	const struct device *dev = get_espi_dev(sh);

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	if (dev == NULL) {
		return -ENODEV;
	}
	shell_print(sh, "================ eSPI controller status ================");
	shell_print(sh, "Device            : %s", dev->name);
	shell_print(sh, "Event monitor     : %s", espi_bridge_monitor_is_active() ? "ON" : "OFF");
	shell_print(sh, "AST1040 services  : CH0 peripheral window, CH2 OOB, CH3 SAFS/TAF");
	shell_print(sh, "Peripheral SW_RDY : %s", espi_get_channel_status(dev, ESPI_CHANNEL_PERIPHERAL) ? "YES" : "NO");
	shell_print(sh, "Virtual Wire RDY  : %s", espi_get_channel_status(dev, ESPI_CHANNEL_VWIRE) ? "YES" : "NO");
	shell_print(sh, "OOB SW_RDY        : %s", espi_get_channel_status(dev, ESPI_CHANNEL_OOB) ? "YES" : "NO");
	shell_print(sh, "Note: SW_RDY is local target state, not host negotiation state.");
	shell_print(sh, "CTRL/STS/INT      : %08x / %08x / %08x (enable %08x)",
		    sys_read32(ESPI_CTRL_REG), sys_read32(ESPI_STS_REG),
		    sys_read32(ESPI_INT_STS_REG), sys_read32(ESPI_INT_EN_REG));
	shell_print(sh, "CH0/1/2 CTRL      : %08x / %08x / %08x",
		    sys_read32(ESPI_CH0_CTRL_REG), sys_read32(ESPI_CH1_CTRL_REG),
		    sys_read32(ESPI_CH2_CTRL_REG));
	shell_print(sh, "SCU pinmux        : %08x / %08x",
		    sys_read32(ASPEED_SCU_BASE + 0x43c), sys_read32(ASPEED_SCU_BASE + 0x440));
	return 0;
}

static int cmd_espi_vwire(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t evt0, evt1;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	if (get_espi_dev(sh) == NULL) {
		return -ENODEV;
	}

	evt0 = sys_read32(ESPI_EVT0_REG);
	evt1 = sys_read32(ESPI_EVT1_REG);
	shell_print(sh, "EVT0: 0x%08x, EVT1: 0x%08x", evt0, evt1);
	print_vwire_decode_shell(sh, evt0, evt1);
	shell_print(sh, "VW GPIO ESPI250/254: %08x / %08x", sys_read32(ESPI_VW_GPIO_VAL0),
		    sys_read32(ESPI_VW_GPIO_VAL1));
	shell_print(sh, "VW GP50 ESPI278/27c: %08x / %08x", sys_read32(ESPI_VW_GP50_VAL0),
		    sys_read32(ESPI_VW_GP50_VAL1));
	return 0;
}

static int cmd_espi_gpio_status(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	if (get_espi_dev(sh) == NULL) {
		return -ENODEV;
	}

	shell_print(sh, "Mode                 : %s",
		    sys_read32(ESPI_CH1_CTRL_REG) & BIT(9) ? "HW" : "SW");
	shell_print(sh, "VW group             : %08x", sys_read32(ESPI_VW_GPIO_GRP));
	shell_print(sh, "ESPI250/254 value    : %08x %08x", sys_read32(ESPI_VW_GPIO_VAL0),
		    sys_read32(ESPI_VW_GPIO_VAL1));
	shell_print(sh, "ESPI258/25c direction: %08x %08x", sys_read32(ESPI_VW_GPIO_DIR0),
		    sys_read32(ESPI_VW_GPIO_DIR1));
	shell_print(sh, "ESPI278/27c GP50     : %08x %08x", sys_read32(ESPI_VW_GP50_VAL0),
		    sys_read32(ESPI_VW_GP50_VAL1));
	shell_print(sh, "ESPI270/274 direction: %08x %08x", sys_read32(ESPI_VW_GP50_DIR0),
		    sys_read32(ESPI_VW_GP50_DIR1));
	shell_print(sh, "GPIOA0/A1 control    : %08x %08x", sys_read32(GPIO_PIN0_CTRL_REG), sys_read32(GPIO_PIN1_CTRL_REG));
	shell_print(sh, "GPIOA2/A3 control    : %08x %08x", sys_read32(GPIO_PIN2_CTRL_REG), sys_read32(GPIO_PIN3_CTRL_REG));
	return 0;
}

static int cmd_espi_gpio_get(const struct shell *sh, size_t argc, char **argv)
{
	enum espi_aspeed_vw_gpio_direction direction;
	const struct device *dev = get_espi_dev(sh);
	uint8_t index, source, level;
	int rc;

	ARG_UNUSED(argc);
	if (dev == NULL) {
		return -ENODEV;
	}
	rc = parse_vw_gpio(sh, argv[1], argv[2], &index, &source);
	if (rc) {
		return rc;
	}
	rc = espi_bridge_aspeed_vw_gpio_get_direction(dev, index, source, &direction);
	if (rc == 0) {
		rc = espi_bridge_aspeed_vw_gpio_get(dev, index, source, &level);
	}
	if (rc) {
		shell_error(sh, "Failed to read VW GPIO: %d", rc);
		return rc;
	}

	shell_print(sh, "VW[0x%02x].SRC%u = %u (%s)", index, source, level,
		    vw_gpio_direction_name(direction));
	return 0;
}

static int cmd_espi_monitor(const struct shell *sh, size_t argc, char **argv)
{
	if (get_espi_dev(sh) == NULL) {
		return -ENODEV;
	}
	if (argc != 2) {
		return -EINVAL;
	}
	if (strcmp(argv[1], "on") == 0) {
		espi_bridge_set_monitor(true);
		shell_print(sh, "eSPI event monitor enabled");
		return 0;
	}
	if (strcmp(argv[1], "off") == 0) {
		espi_bridge_set_monitor(false);
		shell_print(sh, "eSPI event monitor disabled");
		return 0;
	}
	shell_error(sh, "Invalid argument '%s'", argv[1]);
	return -EINVAL;
}

static int cmd_espi_memtrace(const struct shell *sh, size_t argc, char **argv)
{
	static const char *const name[] = {
		[ESPI_MEMTRACE_OFF] = "off",
		[ESPI_MEMTRACE_WR] = "wr",
		[ESPI_MEMTRACE_RW] = "rw",
	};

	if (argc == 1) {
		shell_print(sh, "CH0 memory-cycle trace: %s", name[espi_bridge_get_memtrace()]);
		return 0;
	}

	for (size_t i = 0; i < ARRAY_SIZE(name); i++) {
		if (strcmp(argv[1], name[i]) == 0) {
			espi_bridge_set_memtrace((enum espi_memtrace_mode)i);
			shell_print(sh, "CH0 memory-cycle trace: %s", name[i]);
			return 0;
		}
	}

	shell_error(sh, "Usage: obmf espi memtrace <off|wr|rw>");
	return -EINVAL;
}

static int cmd_espi_mcyc(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (get_espi_dev(sh) == NULL) {
		return -ENODEV;
	}

	uint32_t ctrl = sys_read32(ESPI_CH0_CTRL_REG);
	uint32_t int_en = sys_read32(ESPI_CH0_INT_EN_REG);
	uint32_t int_sts = sys_read32(ESPI_CH0_INT_STS_REG);
	uint32_t maskl = sys_read32(ESPI_CH0_MCYC1_MASKL_REG);
	uint32_t maskh = sys_read32(ESPI_CH0_MCYC1_MASKH_REG);
	uint32_t saddrl = sys_read32(ESPI_CH0_MCYC1_SADDRL_REG);
	uint32_t saddrh = sys_read32(ESPI_CH0_MCYC1_SADDRH_REG);
	uint32_t taddrl = sys_read32(ESPI_CH0_MCYC1_TADDRL_REG);
	uint32_t taddrh = sys_read32(ESPI_CH0_MCYC1_TADDRH_REG);

	shell_print(sh, "CH0 CTRL      : 0x%08x  SW_RDY=%d MCYC_RD=%s MCYC_WR=%s", ctrl,
		    (ctrl & ESPI_CH0_CTRL_SW_RDY) ? 1 : 0,
		    (ctrl & ESPI_CH0_CTRL_MCYC_RD_DIS) ? "DIS" : "en",
		    (ctrl & ESPI_CH0_CTRL_MCYC_WR_DIS) ? "DIS" : "en");
	shell_print(sh, "CH0 INT_EN    : 0x%08x  PC_RX_CMPLT=%d NP_RX_VALID=%d", int_en,
		    (int_en & ESPI_CH0_INT_EN_PC_RX_CMPLT) ? 1 : 0,
		    (int_en & ESPI_CH0_INT_EN_NP_RX_VALID) ? 1 : 0);
	shell_print(sh, "CH0 INT_STS   : 0x%08x", int_sts);
	shell_print(sh, "MCYC1 MASK    : 0x%08x_%08x  EN=%d FW=%d", maskh, maskl,
		    (maskl & ESPI_CH0_MCYC1_MASKL_EN) ? 1 : 0,
		    (maskl & ESPI_CH0_MCYC1_MASKL_FW) ? 1 : 0);
	shell_print(sh, "MCYC1 host    : 0x%08x_%08x (host-side decode address)",
		    saddrh, saddrl);
	shell_print(sh, "MCYC1 target  : 0x%08x_%08x (AST1040-side buffer)", taddrh, taddrl);

	uint32_t win_lo = saddrl & (maskl & ~0x3U);
	uint32_t win_sz = ~(maskl & ~0x3U) + 1U;

	shell_print(sh, "");
	shell_print(sh, "Decoded window: 0x%08x .. 0x%08x (0x%x bytes)", win_lo,
		    win_lo + win_sz - 1U, win_sz);
	shell_print(sh, "App perif_mem : 0x%08x .. 0x%08x (0x%zx bytes)",
		    espi_perif_mem_get_base_addr(),
		    espi_perif_mem_get_base_addr() + (uint32_t)espi_perif_mem_get_size() - 1U,
		    espi_perif_mem_get_size());

	if ((maskl & ESPI_CH0_MCYC1_MASKL_EN) == 0U) {
		shell_warn(sh, "Memory cycle decode is DISABLED: no host cycle can arrive.");
	} else if ((maskl & ESPI_CH0_MCYC1_MASKL_FW) == 0U) {
		shell_warn(sh, "FW mode off: hardware handles cycles, firmware sees no packet.");
	}
	shell_print(sh,
		    "Host must target the decoded window above; anything else is "
		    "never claimed and produces no packet at all.");

	return 0;
}

static bool espi_dump_offset_is_safe(uint32_t off)
{
	switch (off) {
	case ESPI_CH0_PC_RX_DATA:
	case ESPI_CH0_PC_TX_DATA:
	case ESPI_CH0_NP_TX_DATA:
	case ESPI_CH2_RX_DATA:
	case ESPI_CH2_TX_DATA:
	case ESPI_CH3_RX_DATA:
	case ESPI_CH3_TX_DATA:
		return false;
	default:
		return true;
	}
}

static int cmd_espi_dump(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	if (get_espi_dev(sh) == NULL) {
		return -ENODEV;
	}

	shell_print(sh, "eSPI register dump ('--------' = skipped FIFO data port)");
	for (uint32_t off = 0; off <= 0x450; off += 4) {
		if ((off & 0xf) == 0) {
			shell_fprintf(sh, SHELL_NORMAL, "0x%04x:", off);
		}
		if (espi_dump_offset_is_safe(off)) {
			shell_fprintf(sh, SHELL_NORMAL, " %08x", sys_read32(ASPEED_ESPI_BASE + off));
		} else {
			shell_fprintf(sh, SHELL_NORMAL, " --------");
		}
		if ((off & 0xf) == 0xc) {
			shell_fprintf(sh, SHELL_NORMAL, "\n");
		}
	}
	shell_fprintf(sh, SHELL_NORMAL, "\n");
	return 0;
}

static void print_espi_dev_sts(const struct shell *sh, const char *label, uint16_t sts)
{
	shell_print(sh, "%s: 0x%04x", label, sts);
	shell_print(sh, "  [0]  PC_FREE       : %u", (sts >> 0)  & 1);
	shell_print(sh, "  [1]  NP_FREE       : %u", (sts >> 1)  & 1);
	shell_print(sh, "  [2]  VWIRE_FREE    : %u", (sts >> 2)  & 1);
	shell_print(sh, "  [3]  OOB_FREE      : %u", (sts >> 3)  & 1);
	shell_print(sh, "  [4]  PC_AVAIL      : %u", (sts >> 4)  & 1);
	shell_print(sh, "  [5]  NP_AVAIL      : %u", (sts >> 5)  & 1);
	shell_print(sh, "  [6]  VWIRE_AVAIL   : %u", (sts >> 6)  & 1);
	shell_print(sh, "  [7]  OOB_AVAIL     : %u", (sts >> 7)  & 1);
	shell_print(sh, "  [8]  FLASH_C_FREE  : %u", (sts >> 8)  & 1);
	shell_print(sh, "  [10] FLASH_NP_FREE : %u", (sts >> 10) & 1);
	shell_print(sh, "  [12] FLASH_C_AVAIL : %u", (sts >> 12) & 1);
	shell_print(sh, "  [14] FLASH_NP_AVAIL: %u", (sts >> 14) & 1);
}

static int cmd_espi_dev_status(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	uint32_t val = sys_read32(ESPI_DEV_STS_REG);

	shell_print(sh, "ESPI030(ESPI_DEV_STS): 0x%08x", val);
	shell_print(sh, "");
	print_espi_dev_sts(sh, "Previous status [15:0] ", (uint16_t)(val & 0xffff));
	shell_print(sh, "");
	print_espi_dev_sts(sh, "Current  status [31:16]", (uint16_t)(val >> 16));

	return 0;
}

static int cmd_espi_ch_cap(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	uint32_t v;

	v = sys_read32(ESPI_GEN_CAP_REG);
	shell_print(sh, "GEN_CAP (0x014): 0x%08x", v);
	shell_print(sh, "  [2:0]  OP freq supported : %u (0=20M 1=25M 2=33M 3=50M 4=66M)", v & 0x7);
	shell_print(sh, "  [4:3]  OP freq selected  : %u", (v >> 3) & 0x3);
	shell_print(sh, "  [6:5]  IO mode supported : %u (0=x1 1=x1/x2 2=x1/x4 3=x1/x2/x4)",
		    (v >> 5) & 0x3);
	shell_print(sh, "  [8:7]  IO mode selected  : %u (0=x1 1=x2 2=x4)", (v >> 7) & 0x3);
	shell_print(sh, "  [9]    Alert mode        : %u (0=IO1 1=pin)", (v >> 9) & 0x1);
	shell_print(sh, "  [10]   Alert pin mode    : %u (0=OD 1=PP)", (v >> 10) & 0x1);
	shell_print(sh, "  [12]   CRC checking      : %u", (v >> 12) & 0x1);
	shell_print(sh, "  [20]   eSPI Reset        : %u", (v >> 20) & 0x1);
	shell_print(sh, "");

	v = sys_read32(ESPI_CH0_CAP_REG);
	shell_print(sh, "CH0_CAP (0x018): 0x%08x  [Peripheral]", v);
	shell_print(sh, "  [0]    CH supported      : %u", v & 0x1);
	shell_print(sh, "  [1]    CH enabled        : %u", (v >> 1) & 0x1);
	shell_print(sh, "  [2]    CH ready          : %u", (v >> 2) & 0x1);
	shell_print(sh, "  [11:8] Max payload (supp): %u (0=64 1=128 2=256)", (v >> 8) & 0xf);
	shell_print(sh, "  [15:12]Max payload (sel) : %u", (v >> 12) & 0xf);
	shell_print(sh, "  [19:16]Max rd req size   : %u", (v >> 16) & 0xf);
	shell_print(sh, "");

	v = sys_read32(ESPI_CH1_CAP_REG);
	shell_print(sh, "CH1_CAP (0x01c): 0x%08x  [Virtual Wire]", v);
	shell_print(sh, "  [0]    CH supported      : %u", v & 0x1);
	shell_print(sh, "  [1]    CH enabled        : %u", (v >> 1) & 1);
	shell_print(sh, "  [2]    CH ready          : %u", (v >> 2) & 1);
	shell_print(sh, "  [13:8] Max VW cnt (supp) : %u", (v >> 8) & 0x3f);
	shell_print(sh, "  [21:16]Max VW cnt (sel)  : %u", (v >> 16) & 0x3f);
	shell_print(sh, "");

	v = sys_read32(ESPI_CH2_CAP_REG);
	shell_print(sh, "CH2_CAP (0x020): 0x%08x  [OOB]", v);
	shell_print(sh, "  [0]    CH supported      : %u", v & 0x1);
	shell_print(sh, "  [1]    CH enabled        : %u", (v >> 1) & 1);
	shell_print(sh, "  [2]    CH ready          : %u", (v >> 2) & 1);
	shell_print(sh, "  [11:8] Max payload (supp): %u (0=64 1=128 2=256)", (v >> 8) & 0xf);
	shell_print(sh, "  [15:12]Max payload (sel) : %u", (v >> 12) & 0xf);
	shell_print(sh, "");

	v = sys_read32(ESPI_CH3_CAP_REG);
	shell_print(sh, "CH3_CAP (0x024): 0x%08x  [Flash]", v);
	shell_print(sh, "  [0]    CH enable         : %u", (v >> 0) & 1);
	shell_print(sh, "  [1]    CH ready          : %u", (v >> 1) & 1);
	shell_print(sh, "  [4:2]  Erase size        : %u (1=4K 2=64K 3=4K+64K 4=128K 5=256K)",
		    (v >> 2) & 0x7);
	shell_print(sh, "  [7:5]  Max payload (supp): %u (1=64 2=128 3=256)", (v >> 5) & 0x7);
	shell_print(sh, "  [10:8] Max payload (sel) : %u (1=64 2=128 3=256)", (v >> 8) & 0x7);
	shell_print(sh, "  [11]   Flash share mode  : %u (0=ctrl-attached 1=tgt-attached)",
		    (v >> 11) & 1);
	shell_print(sh, "  [14:12]Max rd req (sel)  : %u (1=64 2=128 3=256 4=512 5=1024 6=2048 7=4096)",
		    (v >> 12) & 0x7);
	shell_print(sh, "  [17:16]Flash share cap   : %u (0=ctrl-only 1=tgt-only 2=ctrl-only 3=both)",
		    (v >> 16) & 0x3);
	shell_print(sh, "  [23:20]RPMC counter (1st): %u (0-based)", (v >> 20) & 0xf);
	shell_print(sh, "  [31:24]RPMC OP1 opcode   : 0x%02x", (v >> 24) & 0xff);
	shell_print(sh, "");

	return 0;
}

static int cmd_espi_portio_dump(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t port = 0x80;
	uint32_t count = 16;

	if ((argc >= 2 && parse_u32(argv[1], &port)) || port > 0xffffU) {
		shell_error(sh, "Port must be 0..0xffff (use 0x prefix for hexadecimal)");
		return -EINVAL;
	}
	if ((argc >= 3 && parse_u32(argv[2], &count)) || count == 0U || count > 256U) {
		shell_error(sh, "Count must be 1..256");
		return -EINVAL;
	}

	shell_print(sh, "Virtual Port I/O Dump (port 0x%04x, count %u):", port, count);
	for (uint32_t i = 0; i < count; i++) {
		uint8_t val = 0;
		if (i % 16 == 0) {
			shell_fprintf(sh, SHELL_NORMAL, "\n0x%04x: ", port + i);
		}
		(void)espi_portio_read((port + i) & 0xffffU, &val);
		shell_fprintf(sh, SHELL_NORMAL, "%02x ", val);
	}
	shell_fprintf(sh, SHELL_NORMAL, "\n");
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_espi_portio,
	SHELL_CMD_ARG(dump, NULL, "Dump virtual Port I/O: [port=0x80] [count=16]", cmd_espi_portio_dump, 1, 2),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_espi_gpio,
	SHELL_CMD_ARG(status, NULL, "Show vGPIO registers and mode", cmd_espi_gpio_status, 1, 0),
	SHELL_CMD_ARG(get, NULL, "Get: <index 0x80..0x8f> <source 0..3>",
		      cmd_espi_gpio_get, 3, 0),
	SHELL_SUBCMD_SET_END
);

/* vuart0 itself, not the uart-controller phandle, which may name a plain UART. */
static int cmd_lstp_vuart(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t base = DT_REG_ADDR(DT_NODELABEL(vuart0));

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!IS_ENABLED(CONFIG_OBMF_ESPI_UART_VUART)) {
		return -ENOTSUP;
	}

	uint32_t gcra = sys_read32(base + 0x20);
	uint32_t gcrb = sys_read32(base + 0x24);
	uint32_t addrl = sys_read32(base + 0x28);
	uint32_t addrh = sys_read32(base + 0x2c);
	uint32_t lsr = sys_read32(base + 0x14);

	shell_print(sh, "=== VUART Registers (0x%08x) ===", base);
	shell_print(sh, "  LSR   (0x14): 0x%08x (THRE:%u TEMT:%u DR:%u)",
		    lsr, !!(lsr & BIT(5)), !!(lsr & BIT(6)), !!(lsr & BIT(0)));
	shell_print(sh, "  GCRA  (0x20): 0x%08x (VUART_EN:%u NO_HOST_TX_DISCARD:%u SIRQ_POL:%u)",
		    gcra, !!(gcra & BIT(0)), !!(gcra & BIT(5)), !!(gcra & BIT(1)));
	shell_print(sh, "  GCRB  (0x24): 0x%08x (HOST_SIRQ:%u)", gcrb, (gcrb >> 4) & 0xf);
	shell_print(sh, "  ADDRL (0x28): 0x%08x", addrl);
	shell_print(sh, "  ADDRH (0x2c): 0x%08x", addrh);
	/* V0UART28 address bits are [7:3]; [2:0] hold DMA controls and version ID. */
	shell_print(sh, "  Host I/O port: 0x%04x  (ADDRL: HaltTxDMA:%u HaltRxDMA:%u VerID:%u)",
		    ((addrh & 0xff) << 8) | (addrl & 0xf8),
		    !!(addrl & BIT(2)), !!(addrl & BIT(1)), !!(addrl & BIT(0)));
	shell_print(sh, "");
	shell_print(sh, "  THRE:0 means the previous byte has not been read by the host yet.");

	return 0;
}

static int cmd_espi_lpc_dump(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	uint32_t lpc = ASPEED_LPC_BASE;

	shell_print(sh, "LPC Controller Registers (0x%08x):", lpc);
	shell_print(sh, "  HICR0 (0x00): 0x%08x", sys_read32(lpc + 0x00));
	shell_print(sh, "  HICR1 (0x04): 0x%08x", sys_read32(lpc + 0x04));
	shell_print(sh, "  HICR2 (0x08): 0x%08x", sys_read32(lpc + 0x08));
	shell_print(sh, "  HICR3 (0x0c): 0x%08x", sys_read32(lpc + 0x0c));
	shell_print(sh, "  HICR4 (0x10): 0x%08x", sys_read32(lpc + 0x10));
	shell_print(sh, "  HICR5 (0x80): 0x%08x (Snoop Control)", sys_read32(lpc + 0x80));
	shell_print(sh, "  HICR6 (0x84): 0x%08x (Snoop Status)", sys_read32(lpc + 0x84));
	shell_print(sh, "  HICR7 (0x88): 0x%08x (Generic IO Dec 2/3)", sys_read32(lpc + 0x88));
	shell_print(sh, "  HICR8 (0x8c): 0x%08x (Generic IO Dec 4/5)", sys_read32(lpc + 0x8c));
	shell_print(sh, "  SNPWADR(0x90): 0x%08x (Snoop 0/1 Addr)", sys_read32(lpc + 0x90));
	shell_print(sh, "  SNPWDR (0x94): 0x%08x (Snoop 0/1 Data)", sys_read32(lpc + 0x94));
	shell_print(sh, "  HICRA (0x9c): 0x%08x (UART Routing)", sys_read32(lpc + 0x9c));
	shell_print(sh, "  HICRB (0x100): 0x%08x", sys_read32(lpc + 0x100));

	return 0;
}

static int cmd_espi_snoop_stats(const struct shell *sh, size_t argc, char **argv)
{
	struct espi_bridge_snoop_stats stats;

	if (argc == 2) {
		if (strcmp(argv[1], "reset") != 0) {
			shell_error(sh, "Usage: obmf espi snoop_stats [reset]");
			return -EINVAL;
		}
		espi_bridge_reset_snoop_stats();
		shell_print(sh, "Snoop statistics reset");
		return 0;
	}

	espi_bridge_get_snoop_stats(&stats);

	shell_print(sh, "UART bridge mode : %s",
		    IS_ENABLED(CONFIG_OBMF_ESPI_UART_VUART) ? "VUART (" LSTP_UART_CHANNEL_NAME ")"
							   : "plain UART (" LSTP_UART_CHANNEL_NAME ")");
	shell_print(sh, "Snoop mode       : ch0=0x80 ch1=0x081 (POST codes only)");
	shell_print(sh, "Elapsed          : %u ms", stats.elapsed_ms);
	shell_print(sh, "Port 0x80 writes : %u", stats.port80_count);
	shell_print(sh, "Snoop ch1 writes : %u", stats.ch1_count);
	shell_print(sh, "Queue drops      : %u", stats.dropped);

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_espi,
	SHELL_CMD_ARG(status, NULL, "Show read-only controller status", cmd_espi_status, 1, 0),
	SHELL_CMD_ARG(dev_sts, NULL, "Read ESPI030 (ESPI_DEV_STS)", cmd_espi_dev_status, 1, 0),
	SHELL_CMD_ARG(ch_cap, NULL, "Print eSPI channel capabilities", cmd_espi_ch_cap, 1, 0),
	SHELL_CMD_ARG(vwire, NULL, "Show decoded Virtual Wire state", cmd_espi_vwire, 1, 0),
	SHELL_CMD(gpio, &sub_espi_gpio, "Inspect eSPI platform-specific virtual GPIO", NULL),
	SHELL_CMD(portio, &sub_espi_portio, "Inspect virtual Port I/O table", NULL),
	SHELL_CMD_ARG(lpc, NULL, "Dump LPC/SIO/Snoop hardware registers", cmd_espi_lpc_dump, 1, 0),
	SHELL_CMD_ARG(snoop_stats, NULL, "Show/reset Snoop performance counters: [reset]",
		      cmd_espi_snoop_stats, 1, 1),
	SHELL_CMD_ARG(monitor, NULL, "Enable/disable event monitor", cmd_espi_monitor, 2, 0),
	SHELL_CMD_ARG(memtrace, NULL,
		      "Trace raw CH0 host memory cycles (MMBI transport): <off|wr|rw>",
		      cmd_espi_memtrace, 1, 1),
	SHELL_CMD_ARG(mcyc, NULL, "Show the CH0 memory-cycle decode window", cmd_espi_mcyc, 1, 0),
	SHELL_CMD_ARG(dump, NULL, "Safely dump eSPI registers", cmd_espi_dump, 1, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_SUBCMD_ADD((obmf), espi, &sub_espi, "ASPEED eSPI diagnostics", NULL, 1, 0);

/* Only the VUART backend uses vuart0; otherwise the registers mean nothing here. */
SHELL_SUBCMD_COND_ADD(IS_ENABLED(CONFIG_OBMF_ESPI_UART_VUART), (obmf), vuart, NULL,
		      "Show LSTP VUART registers",
		      cmd_lstp_vuart, 1, 0);
