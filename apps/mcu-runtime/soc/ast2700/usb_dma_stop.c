/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <platform.h>
#include <chip.h>
#include <usb.h>
#include <ast_loader.h>
#include <scu_ast2700.h>

LOG_MODULE_REGISTER(usb_dma_stop, CONFIG_SOC_FMC_LOG_LEVEL); //LOG_LEVEL_DBG

#define USB_POLL_STEP_US	10

/* One physical controller instance: its base, whether we own it (not
 * PCIe's, not the wrong mode), and whether its clock/reset are up.
 */
struct usb_port {
	uint32_t base;
	bool owned;
	bool active;
};

/*
 * Poll addr until (*addr & mask) == match, or give up after timeout_us.
 */
static int usb_reg_poll(uint32_t addr, uint32_t mask, uint32_t match, uint32_t timeout_us)
{
	uint32_t iter = timeout_us / USB_POLL_STEP_US;

	while ((sys_read32(addr) & mask) != match) {
		if (iter == 0)
			return -ETIMEDOUT;
		iter--;
		k_busy_wait(USB_POLL_STEP_US);
	}

	return 0;
}

static void usb_warn_timeout(const char *ip, uint32_t base, const char *what)
{
	LOG_WRN("%s@0x%08x: %s timeout", ip, base, what);
}

/*
 * A controller whose capability register reads back 0 hasn't actually
 * come up yet (xHCI/EHCI capability registers are never 0 bytes long),
 * even if SCU says its clock/reset are fine. Trusting that 0 as an
 * offset is how Port A's xHCI got hung: base+0 loops back to CAPLENGTH
 * itself instead of the real USBCMD register.
 */
static bool usb_hc_caplen_valid(uint32_t base, uint32_t caplen, const char *ip)
{
	if (caplen == 0) {
		LOG_WRN("%s@0x%08x: caplen=0", ip, base);
		return false;
	}

	return true;
}

/*
 * A WDT/warm reset can leave a USB block's clock either running (it was
 * already active) or gated (it was never brought up this boot). Touching
 * a gated block's registers can wedge the AHB/AXI bus instead of just
 * reading back garbage -- this is what hung Port A's xHCI -- so every
 * port is checked against SCU0/SCU1 before it's touched.
 */
static bool usb_scu0_port_active(struct ast2700_scu0 *scu, uint32_t clk_bit, uint32_t rst_bit)
{
	return !(readl(&scu->clkgate_ctrl) & clk_bit) && !(readl(&scu->modrst2_ctrl) & rst_bit);
}

static bool usb_scu1_port_active(struct ast2700_scu1 *scu, uint32_t clk_bit, uint32_t rst_bit)
{
	return !(readl(&scu->clkgate_ctrl2) & clk_bit) && !(readl(&scu->modrst2_ctrl) & rst_bit);
}

static uint32_t usb_ctrl_sel(struct ast2700_scu1 *scu, uint32_t shift)
{
	return (readl(&scu->usb_ctrl) >> shift) & ASPEED_USB_CTRL_SEL_MASK;
}

/* Runs stop() on every owned+active port; logs (at DBG) why the rest were
 * skipped. Common to EHCI/XHCI/UHCI/VHUB so each only builds its port table.
 */
static int usb_stop_ports(const char *ip, const struct usb_port *ports, int n,
			   int (*stop)(uint32_t base))
{
	int ret = 0;
	int i;

	for (i = 0; i < n; i++) {
		if (!ports[i].owned) {
			LOG_DBG("%s@0x%08x: not ours", ip, ports[i].base);
		} else if (ports[i].active) {
			int rc = stop(ports[i].base);

			if (rc) {
				LOG_WRN("%s@0x%08x: error (%d)", ip, ports[i].base, rc);
				ret = rc;
			} else {
				LOG_INF("%s@0x%08x: done", ip, ports[i].base);
			}
		} else {
			LOG_DBG("%s@0x%08x: gated", ip, ports[i].base);
		}
	}

	return ret;
}

/* Only the registers EHCI's stop sequence actually touches. */
static void ehci_dump(const char *tag, uint32_t base, uint32_t op)
{
	LOG_DBG("%s EHCI@0x%08x: USBCMD=0x%08x USBSTS=0x%08x USBINTR=0x%08x", tag, base,
		sys_read32(op + ASPEED_USB_HC_USBCMD), sys_read32(op + ASPEED_USB_HC_USBSTS),
		sys_read32(op + ASPEED_USB_HC_USBINTR));
}

/*
 * EHCI can't have USBCMD.Run/Stop cleared directly: the async/periodic
 * schedules must be disabled first and given time to actually halt
 * (mirrors Linux's ehci_quiesce() + ehci_halt()).
 */
static int ehci_stop_port(uint32_t base)
{
	uint32_t caplen, op;
	int ret = 0;

	/* Printed before any register access, so a hang always shows which
	 * controller it hung on -- raise the log level to DBG to see it.
	 */
	LOG_DBG("EHCI@0x%08x", base);

	caplen = sys_read32(base) & ASPEED_USB_HC_CAPLENGTH_MASK;
	if (!usb_hc_caplen_valid(base, caplen, "EHCI"))
		return -EIO;
	op = base + caplen;

	ehci_dump("pre", base, op);

	sys_write32(0, op + ASPEED_USB_HC_USBINTR);

	clrbits_le32(op + ASPEED_USB_HC_USBCMD,
		     ASPEED_USB_EHCI_CMD_ASE | ASPEED_USB_EHCI_CMD_PSE);
	if (usb_reg_poll(op + ASPEED_USB_HC_USBSTS,
			  ASPEED_USB_EHCI_STS_ASS | ASPEED_USB_EHCI_STS_PSS, 0, 2000)) {
		usb_warn_timeout("EHCI", base, "ASE/PSE");
		ret = -ETIMEDOUT;
	}

	clrbits_le32(op + ASPEED_USB_HC_USBCMD, ASPEED_USB_EHCI_CMD_RUN);
	if (usb_reg_poll(op + ASPEED_USB_HC_USBSTS,
			  ASPEED_USB_EHCI_STS_HALT, ASPEED_USB_EHCI_STS_HALT, 2000)) {
		usb_warn_timeout("EHCI", base, "halt");
		ret = -ETIMEDOUT;
	}

	ehci_dump("post", base, op);

	return ret;
}

/*
 * ehci0/1 (ports A/B) are on the CPU die and reachable over the AHB
 * bus, so a WDT/EXTRST reset can safely include them directly (see
 * extrst_ast2700.c/wdt_config_reset()) without risking a DRAMC/SLI
 * hang -- no need to quiesce them from software first. Ports C/D
 * (IO die, SCU1) reach here over SLI, where resetting an IP while a
 * DMA transfer is still in flight can hang that link, so they're
 * still stopped from software below before anything gets reset.
 */
int usb_ehci_stop(struct ast_chip *chip)
{
	struct ast2700_scu1 *scu1 = chip->scu1;
	struct usb_port ports[] = {
		{ ASPEED_EHCI2_BASE,
		  usb_ctrl_sel(scu1, ASPEED_USB_CTRL_USBC_SEL_SHIFT) == ASPEED_USB_CTRL_USBC_SEL_EHCI,
		  usb_scu1_port_active(scu1, SCU1_CLKGATE2_USB2C, SCU1_RSTCTL2_USB2C) },
		{ ASPEED_EHCI3_BASE,
		  usb_ctrl_sel(scu1, ASPEED_USB_CTRL_USBD_SEL_SHIFT) == ASPEED_USB_CTRL_USBD_SEL_EHCI,
		  usb_scu1_port_active(scu1, SCU1_CLKGATE2_USB2D, SCU1_RSTCTL2_USB2D) },
	};

	return usb_stop_ports("EHCI", ports, ARRAY_SIZE(ports), ehci_stop_port);
}

/*
 * xhci0/1, same as uhci0, are currently unreachable from BootMCU over
 * the AHB bus matrix -- every read comes back 0 regardless of
 * clock/reset/mode, which is why CAPLENGTH always read 0 here. The full
 * host/device-mode stop logic is kept below but compiled out to save
 * code space until that's fixed; flip this to 1 once a bus master that
 * can actually reach xhci0/1 is available.
 */
#define ASPEED_USB_XHCI_REACHABLE	0

#if ASPEED_USB_XHCI_REACHABLE

/* Only the registers xHCI's stop sequence actually touches. */
static void xhci_dump(const char *tag, uint32_t base, uint32_t op)
{
	LOG_DBG("%s XHCI@0x%08x: USBCMD=0x%08x USBSTS=0x%08x", tag, base,
		sys_read32(op + ASPEED_USB_HC_USBCMD), sys_read32(op + ASPEED_USB_HC_USBSTS));
}

/*
 * Device-mode Run/Stop pair: DCTL.RUN_STOP -> poll DSTS.DEVCTRLHLT. Used
 * instead of the host-mode USBCMD/USBSTS pair below when GCTL says this
 * DRD port is currently acting as a UDC gadget, not an xHCI host
 * (mirrors the Linux USB3 gadget driver's run/stop teardown path).
 */
static int xhci_device_stop_port(uint32_t base)
{
	int ret;

	clrbits_le32(base + ASPEED_USB_XHCI_DCTL, ASPEED_USB_XHCI_DCTL_RUN_STOP);

	ret = usb_reg_poll(base + ASPEED_USB_XHCI_DSTS, ASPEED_USB_XHCI_DSTS_DEVCTRLHLT,
			    ASPEED_USB_XHCI_DSTS_DEVCTRLHLT, 32000);
	if (ret)
		usb_warn_timeout("XHCI", base, "DCTL halt");

	return ret;
}

/*
 * xhci0/1 are on the CPU die (no SLI-hang risk), but talk to DRAM over
 * AXI directly -- resetting mid-DMA-transfer can hang DRAMC instead,
 * so this still needs to quiesce before anything gets reset.
 *
 * xHCI's USBCMD.Run/Stop can be cleared directly (mirrors Linux's
 * xhci_quiesce() + xhci_halt()).
 */
static int xhci_stop_port(uint32_t base)
{
	uint32_t caplen, op, cmd, prtcap;
	int ret;

	LOG_DBG("XHCI@0x%08x", base);

	prtcap = (sys_read32(base + ASPEED_USB_XHCI_GCTL) &
		  ASPEED_USB_XHCI_GCTL_PRTCAPDIR_MASK) >> 12;
	if (prtcap == ASPEED_USB_XHCI_GCTL_PRTCAP_DEVICE) {
		LOG_DBG("XHCI@0x%08x: in device mode, using DCTL/DSTS", base);
		return xhci_device_stop_port(base);
	}

	caplen = sys_read32(base) & ASPEED_USB_HC_CAPLENGTH_MASK;
	if (!usb_hc_caplen_valid(base, caplen, "XHCI"))
		return -EIO;
	op = base + caplen;

	xhci_dump("pre", base, op);

	cmd = sys_read32(op + ASPEED_USB_HC_USBCMD) & ~ASPEED_USB_XHCI_CMD_RUN;
	sys_write32(cmd, op + ASPEED_USB_HC_USBCMD);

	ret = usb_reg_poll(op + ASPEED_USB_HC_USBSTS,
			    ASPEED_USB_XHCI_STS_HALT, ASPEED_USB_XHCI_STS_HALT, 32000);
	if (ret)
		usb_warn_timeout("XHCI", base, "halt");

	xhci_dump("post", base, op);

	return ret;
}

#else /* !ASPEED_USB_XHCI_REACHABLE */

static int xhci_stop_port(uint32_t base)
{
	LOG_INF("XHCI@0x%08x: BootMCU unreachable", base);
	return -ENOTSUP;
}

#endif /* ASPEED_USB_XHCI_REACHABLE */

int usb_xhci_stop(struct ast_chip *chip)
{
	struct ast2700_scu0 *scu0 = chip->scu0;
	uint32_t func_ctrl = readl(&scu0->usb_func_ctrl);
	struct usb_port ports[] = {
		{ ASPEED_XHCI0_BASE, !!(func_ctrl & ASPEED_USB_FUNC_XHCI_PORTA_BMC),
		  usb_scu0_port_active(scu0, SCU0_CLKGATE1_USBA,
				       SCU0_RST2_USBA_PHY3 | SCU0_RST2_USBA_XHCI) },
		{ ASPEED_XHCI1_BASE, !!(func_ctrl & ASPEED_USB_FUNC_XHCI_PORTB_BMC),
		  usb_scu0_port_active(scu0, SCU0_CLKGATE1_USBB,
				       SCU0_RST2_USBB_PHY3 | SCU0_RST2_USBB_XHCI) },
	};

	return usb_stop_ports("XHCI", ports, ARRAY_SIZE(ports), xhci_stop_port);
}

/* Only the registers UHCI's stop sequence actually touches. */
static void uhci_dump(const char *tag, uint32_t base)
{
	LOG_DBG("%s UHCI@0x%08x: USBCMD=0x%08x USBSTS=0x%08x", tag, base,
		sys_read32(base + ASPEED_USB_UHCI_USBCMD), sys_read32(base + ASPEED_USB_UHCI_USBSTS));
}

/* No HCRESET here: that's a full controller reset, not just a DMA stop. */
static int uhci_stop_port(uint32_t base)
{
	int ret;

	if (!(sys_read32(base + ASPEED_USB_UHCI_USBCMD) & ASPEED_USB_UHCI_USBCMD_RS)) {
		LOG_DBG("UHCI@0x%08x: not running", base);
		return 0;
	}

	LOG_DBG("UHCI@0x%08x", base);
	uhci_dump("pre", base);

	clrbits_le32(base + ASPEED_USB_UHCI_USBCMD, ASPEED_USB_UHCI_USBCMD_RS);

	ret = usb_reg_poll(base + ASPEED_USB_UHCI_USBSTS,
			    ASPEED_USB_UHCI_STS_HCH, ASPEED_USB_UHCI_STS_HCH, 2000);
	if (ret)
		usb_warn_timeout("UHCI", base, "halt");

	uhci_dump("post", base);

	return ret;
}

/*
 * uhci0 (ports A/B) is on the CPU die and reachable over the AHB bus,
 * so a WDT/EXTRST reset can safely include it directly (see
 * extrst_ast2700.c/wdt_config_reset()) without risking a DRAMC/SLI
 * hang -- no need to quiesce it from software first. uhci1 (Port C/D,
 * IO die, SCU1) reaches here over SLI, where resetting an IP while a
 * DMA transfer is still in flight can hang that link, so it's still
 * stopped from software below before anything gets reset.
 */
int usb_uhci_stop(struct ast_chip *chip)
{
	struct ast2700_scu1 *scu1 = chip->scu1;
	struct usb_port ports[] = {
		{ ASPEED_UHCI1_BASE, true,
		  usb_scu1_port_active(scu1, SCU1_CLKGATE2_UHCI, SCU1_RSTCTL2_UHCI) },
	};

	return usb_stop_ports("UHCI", ports, ARRAY_SIZE(ports), uhci_stop_port);
}

#define VHUB_DUMP_PER_LINE	7

/* Shared by vhub_dump()'s two register groups below: reads `count` regs
 * (stride apart, starting at block_base + reg_off) and prints them at
 * most VHUB_DUMP_PER_LINE to a line.
 */
static void vhub_dump_group(const char *tag, uint32_t base, const char *label,
			     uint32_t block_base, uint32_t stride, uint32_t reg_off,
			     uint32_t count)
{
	char buf[VHUB_DUMP_PER_LINE * 11 + 1];
	uint32_t i, n, len;

	for (n = 0; n < count; n += VHUB_DUMP_PER_LINE) {
		for (i = n, len = 0; i < n + VHUB_DUMP_PER_LINE && i < count; i++)
			len += snprintf(buf + len, sizeof(buf) - len, "0x%08x ",
					 sys_read32(base + block_base + stride * i + reg_off));
		LOG_DBG("%s VHUB@0x%08x: %s[%u..%u]= %s", tag, base, label, n, i - 1, buf);
	}
}

/*
 * Only the registers vHub's stop sequence actually touches: the main
 * control reg plus every per-device and per-endpoint enable/config reg.
 */
static void vhub_dump(const char *tag, uint32_t base)
{
	LOG_DBG("%s VHUB@0x%08x: CTRL=0x%08x", tag, base, sys_read32(base + ASPEED_USB_VHUB_CTRL));

	vhub_dump_group(tag, base, "DEV_EN", ASPEED_USB_VHUB_DEV_BLOCK_BASE,
			ASPEED_USB_VHUB_DEV_BLOCK_STRIDE, ASPEED_USB_VHUB_DEV_EN_CTRL,
			ASPEED_USB_VHUB_NUM_DEVS);

	vhub_dump_group(tag, base, "EP_CFG", ASPEED_USB_VHUB_EP_BLOCK_BASE,
			ASPEED_USB_VHUB_EP_BLOCK_STRIDE, ASPEED_USB_VHUB_EP_CONFIG,
			ASPEED_USB_VHUB_NUM_GEN_EPS);
}

/*
 * Disable every downstream device port and every generic endpoint, then
 * drop the upstream connection -- the same state left behind by the
 * Linux aspeed-vhub driver's remove() path, without touching the SCU
 * reset line (that's usb_init()'s job, not this defensive stop's).
 */
static int vhub_stop_port(uint32_t base)
{
	uint32_t i;

	LOG_DBG("VHUB@0x%08x", base);
	vhub_dump("pre", base);

	for (i = 0; i < ASPEED_USB_VHUB_NUM_DEVS; i++)
		clrbits_le32(base + ASPEED_USB_VHUB_DEV_BLOCK_BASE +
			     ASPEED_USB_VHUB_DEV_BLOCK_STRIDE * i + ASPEED_USB_VHUB_DEV_EN_CTRL,
			     ASPEED_USB_VHUB_DEV_EN_ENABLE_PORT);

	for (i = 0; i < ASPEED_USB_VHUB_NUM_GEN_EPS; i++)
		clrbits_le32(base + ASPEED_USB_VHUB_EP_BLOCK_BASE +
			     ASPEED_USB_VHUB_EP_BLOCK_STRIDE * i + ASPEED_USB_VHUB_EP_CONFIG,
			     ASPEED_USB_VHUB_EP_CFG_ENABLE);

	clrbits_le32(base + ASPEED_USB_VHUB_CTRL, ASPEED_USB_VHUB_CTRL_UPSTREAM_CONNECT);

	vhub_dump("post", base);

	return 0;
}

/*
 * vhub0/vhub1 (ports A/B) are on the CPU die and reachable over the AHB
 * bus, so a WDT/EXTRST reset can safely include them directly (see
 * extrst_ast2700.c/wdt_config_reset()) without risking a DRAMC/SLI
 * hang -- no need to quiesce them from software first. Ports C/D
 * (IO die, SCU1) reach here over SLI, where resetting an IP while a
 * DMA transfer is still in flight can hang that link, so they're
 * still stopped from software below before anything gets reset.
 */
int usb_vhub_stop(struct ast_chip *chip)
{
	struct ast2700_scu1 *scu1 = chip->scu1;
	struct usb_port ports[] = {
		/*
		 * usb_ctrl (SCU1 0x3b0) select value's bit 1 says whether
		 * vHub is on the path (0/1: UART+vHub or plain vHub) or
		 * bypassed (2/3: EHCI or UART-only).
		 */
		{ AST_VHUBC_BASE,
		  !(usb_ctrl_sel(scu1, ASPEED_USB_CTRL_USBC_SEL_SHIFT) &
		    ASPEED_USB_FUNC_MODE_VHUB_BYPASS),
		  usb_scu1_port_active(scu1, SCU1_CLKGATE2_USB2C, SCU1_RSTCTL2_USB2C) },
		{ ASPEED_VHUBD_BASE,
		  !(usb_ctrl_sel(scu1, ASPEED_USB_CTRL_USBD_SEL_SHIFT) &
		    ASPEED_USB_FUNC_MODE_VHUB_BYPASS),
		  usb_scu1_port_active(scu1, SCU1_CLKGATE2_USB2D, SCU1_RSTCTL2_USB2D) },
	};

	return usb_stop_ports("VHUB", ports, ARRAY_SIZE(ports), vhub_stop_port);
}
