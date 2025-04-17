/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include "gpio/gpio_aspeed.h"
#include "gpio/platform/gpio_oks.h"
#include "platform_monitor_ctrl.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "Smbus_mailbox/Smbus_mailbox.h"


/* Defined in AspeedStateMachine.h */
// #define PFR_SYSTEM_BMC_BOOTED BIT(0)

#define PLATFORM_OKS_HPM_STBY_RDY           BIT(0)
#define PLATFORM_OKS_SMBUS0_RDY             BIT(1)
#define PLATFORM_OKS_SMBUS1_RDY             BIT(2)
#define PLATFORM_OKS_CPU0_AUX_PWRGD         BIT(3)
#define PLATFORM_OKS_CPU1_AUX_PWRGD         BIT(4)
#define PLATFORM_OKS_CPU0_PLTRST_SYNC       BIT(5)
#define PLATFORM_OKS_CPU1_PLTRST_SYNC       BIT(6)
#define PLATFORM_OKS_BMC_ONCTL              BIT(7)
#define PLATFORM_OKS_PLTRST_SYNC_FALLBACK   BIT(30)
#define PLATFORM_OKS_FALLBACK               BIT(31)

K_EVENT_DEFINE(pfr_oks_event);

LOG_MODULE_REGISTER(monitor_oks, CONFIG_LOG_DEFAULT_LEVEL);

extern struct k_sem pltrst_sem;

static struct gpio_callback hpm_stby_rdy_cb_data;
static struct gpio_callback smbus_rdy_cb_data;
static struct gpio_callback cpu_aux_pwrgd_cb_data;
static struct gpio_callback bmc_onctl_cb_data;
static struct gpio_callback rst_pltrst_cb_data;

struct gpio_dt_spec hpm_stby_rdy =
	GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), hpm_stby_rdy_in_gpios, 0);

struct gpio_dt_spec smbus0_rdy =
	GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), smbus0_rdy_in_gpios, 0);
struct gpio_dt_spec smbus1_rdy =
	GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), smbus1_rdy_in_gpios, 0);

struct gpio_dt_spec cpu0_aux_pwrgd =
	GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), cpu0_aux_pwrgd_in_gpios, 0);
struct gpio_dt_spec cpu1_aux_pwrgd =
	GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), cpu1_aux_pwrgd_in_gpios, 0);

struct gpio_dt_spec cpu0_rst_pltrst =
	GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), cpu0_pltrst_sync_in_gpios, 0);
struct gpio_dt_spec cpu1_rst_pltrst =
	GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), cpu1_pltrst_sync_in_gpios, 0);

struct gpio_dt_spec bmc_onctl =
	GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), bmc_onctl_in_gpios, 0);

static void platform_oks_hpm_stby_rdy_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);
	LOG_INF("[CPLD->PFR] HPM_STBY_RDY[%s %d] = %d", dev->name, gpio_pin, ret);

	if (ret == 0) {
		k_event_post(&pfr_oks_event, PLATFORM_OKS_FALLBACK);
	} else {
		k_event_post(&pfr_oks_event, PLATFORM_OKS_HPM_STBY_RDY);
	}
}

static void platform_oks_hpm_stby_monitor_init(void)
{
	int ret;

	ret = gpio_pin_configure_dt(&hpm_stby_rdy, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", hpm_stby_rdy.port->name, hpm_stby_rdy.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&hpm_stby_rdy, GPIO_INT_EDGE_BOTH);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&hpm_stby_rdy_cb_data, platform_oks_hpm_stby_rdy_handler, BIT(hpm_stby_rdy.pin));
	ret = gpio_add_callback(hpm_stby_rdy.port, &hpm_stby_rdy_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);
}

static void platform_oks_smbus_rdy_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	int ret;
	int id;
	const struct device *port;
	gpio_pin_t pin;


	if (pins & BIT(smbus0_rdy.pin)) {
		id = 0;
		port = smbus0_rdy.port;
		pin = smbus0_rdy.pin;
	} else {
		id = 1;
		port = smbus1_rdy.port;
		pin = smbus1_rdy.pin;
	}

	ret = gpio_pin_get(port, pin);

	LOG_INF("[CPLD->PFR] SMBUS_RDY%d[%s %d] = %d", id, dev->name, smbus1_rdy.pin, ret);

	if (ret == 0) {
		k_event_post(&pfr_oks_event, PLATFORM_OKS_FALLBACK);
	} else {
		k_event_post(&pfr_oks_event, (id == 0) ? PLATFORM_OKS_SMBUS0_RDY : PLATFORM_OKS_SMBUS1_RDY);
	}
}

static void platform_oks_smbus_rdy_monitor_init(void)
{
	int ret;

	ret = gpio_pin_configure_dt(&smbus0_rdy, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", smbus0_rdy.port->name, smbus0_rdy.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&smbus0_rdy, GPIO_INT_EDGE_BOTH);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&smbus_rdy_cb_data, platform_oks_smbus_rdy_handler, BIT(smbus0_rdy.pin));

#ifdef DUAL_NODE
	ret = gpio_pin_configure_dt(&smbus1_rdy, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", smbus1_rdy.port->name, smbus1_rdy.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&smbus1_rdy, GPIO_INT_EDGE_BOTH);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&smbus_rdy_cb_data, platform_oks_smbus_rdy_handler, BIT(smbus1_rdy.pin));
#endif
}

static void platform_oks_bmc_onctl_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	int ret = gpio_pin_get(dev, bmc_onctl.pin);
	LOG_INF("[BMC->PFR] BMC_ONCTL[%s %d] = %d", dev->name, bmc_onctl.pin, ret);

	if (ret == 0) {
		// TODO: Clarify the expected behavior when BMC_ONCTL is deasserted
	} else {
		k_event_post(&pfr_oks_event, PLATFORM_OKS_BMC_ONCTL);
	}
}

static void platform_oks_bmc_onctl_monitor_init(void)
{
	int ret;

	ret = gpio_pin_configure_dt(&bmc_onctl, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", bmc_onctl.port->name, bmc_onctl.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&bmc_onctl, GPIO_INT_EDGE_BOTH);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&bmc_onctl_cb_data, platform_oks_bmc_onctl_handler, BIT(bmc_onctl.pin));
	ret = gpio_add_callback(bmc_onctl.port, &bmc_onctl_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);
}

static void platform_oks_cpu_aux_pwrgd_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	int ret;
	int id;
	const struct device *port;
	gpio_pin_t pin;

	if (pins & BIT(cpu0_aux_pwrgd.pin)) {
		id = 0;
		port = cpu0_aux_pwrgd.port;
		pin = cpu0_aux_pwrgd.pin;
	} else {
		id = 1;
		port = cpu1_aux_pwrgd.port;
		pin = cpu1_aux_pwrgd.pin;
	}

	ret = gpio_pin_get(port, pin);

	LOG_INF("[CPLD->PFR] AUX_PWRGD%d[%s %d] = %d", id, dev->name, pin, ret);

	if (ret == 0) {
		k_event_post(&pfr_oks_event, PLATFORM_OKS_FALLBACK);
	} else {
		k_event_post(&pfr_oks_event, (id == 0) ? PLATFORM_OKS_CPU0_AUX_PWRGD : PLATFORM_OKS_CPU1_AUX_PWRGD);
	}
}

static void platform_oks_cpu_aux_pwrgd_monitor_init(void)
{
	int ret;

	ret = gpio_pin_configure_dt(&cpu0_aux_pwrgd, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", cpu0_aux_pwrgd.port->name, cpu0_aux_pwrgd.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&cpu0_aux_pwrgd, GPIO_INT_EDGE_BOTH);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&cpu_aux_pwrgd_cb_data, platform_oks_cpu_aux_pwrgd_handler, BIT(cpu0_aux_pwrgd.pin));
	ret = gpio_add_callback(cpu0_aux_pwrgd.port, &cpu_aux_pwrgd_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);
#ifdef DUAL_NODE
	ret = gpio_pin_configure_dt(&cpu1_aux_pwrgd, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", cpu1_aux_pwrgd.port->name, cpu1_aux_pwrgd.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&cpu1_aux_pwrgd, GPIO_INT_EDGE_BOTH);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&cpu_aux_pwrgd_cb_data, platform_oks_cpu_aux_pwrgd_handler, BIT(cpu1_aux_pwrgd.pin));
	ret = gpio_add_callback(cpu1_aux_pwrgd.port, &cpu_aux_pwrgd_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);
#endif
}

/**
 * Arm the ACM watchdog timer when ROT firmware detects a platform reset
 * through PLTRST# GPI signal.
 */
static void platform_oks_reset_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	int ret;
	int id;
	const struct device *port;
	gpio_pin_t pin;

	if (pins & BIT(cpu0_rst_pltrst.pin)) {
		id = 0;
		port = cpu0_rst_pltrst.port;
		pin = cpu0_rst_pltrst.pin;
	} else {
		id = 1;
		port = cpu1_rst_pltrst.port;
		pin = cpu1_rst_pltrst.pin;
	}

	ret = gpio_pin_get(port, pin);

	LOG_INF("[CPLD->PFR] PLTRST_SYNC%d[%s %d] = %d", id, dev->name, pin, ret);
	if (ret == 0) {
		ClearS0Attestation();
		ClearBtgAttestation();
		k_event_post(&pfr_oks_event, PLATFORM_OKS_PLTRST_SYNC_FALLBACK);
	} else {
		k_event_post(&pfr_oks_event, (id == 0) ? PLATFORM_OKS_CPU0_PLTRST_SYNC : PLATFORM_OKS_CPU1_PLTRST_SYNC);
	}
}

// TODO: Implement the attestation functions
bool perform_s5_attestation(void)
{
	return true;
}

bool perform_s0_attestation(void)
{
	return true;
}

bool perform_btg_attestation(void)
{
	return true;
}

int oks_s5_attestation(void)
{
	uint8_t provision_state = GetUfmStatusValue();
	bool s5_attestation_pass = false;

	if (!(provision_state & UFM_PROVISIONED)) {
		s5_attestation_pass = true;
	} else {
		// TODO: Perform s5 attestation
		s5_attestation_pass = perform_s5_attestation();
	}

	S5AttestationDone(s5_attestation_pass);

	return 0;
}

int oks_s0_attestation(void)
{
	uint8_t provision_state = GetUfmStatusValue();
	bool s0_attestation_pass = false;

	if (!(provision_state & UFM_PROVISIONED)) {
		s0_attestation_pass = true;
	} else {
		// TODO: Perform s0 attestation
		s0_attestation_pass = perform_s0_attestation();
	}

	S0AttestationDone(s0_attestation_pass);

	return 0;
}

int oks_btg_attestation(void)
{
	uint8_t provision_state = GetUfmStatusValue();
	bool btg_attestation_pass = false;

	// check povision status
	if (!(provision_state & UFM_PROVISIONED)) {
		btg_attestation_pass = true;
	} else {
		btg_attestation_pass = perform_btg_attestation();
	}

	BtgAttestationDone(btg_attestation_pass);

	if (btg_attestation_pass) {
		extern bool pltrst_sync;
		pltrst_sync = true;
#if defined(CONFIG_PFR_MCTP_I3C)
		k_sem_give(&pltrst_sem);
#endif
	}

	return 0;
}

/* Monitor Platform Reset Status */
static void platform_oks_reset_monitor_init(void)
{
	int ret;

	ret = gpio_pin_configure_dt(&cpu0_rst_pltrst, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", cpu0_rst_pltrst.port->name, cpu0_rst_pltrst.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&cpu0_rst_pltrst, GPIO_INT_EDGE_BOTH);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&rst_pltrst_cb_data, platform_oks_reset_handler, BIT(cpu0_rst_pltrst.pin));
	ret = gpio_add_callback(cpu0_rst_pltrst.port, &rst_pltrst_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);

#ifdef DUAL_NODE
	ret = gpio_pin_configure_dt(&cpu1_rst_pltrst, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", cpu1_rst_pltrst.port->name, cpu1_rst_pltrst.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&cpu1_rst_pltrst, GPIO_INT_EDGE_BOTH);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&rst_pltrst_cb_data, platform_oks_reset_handler, BIT(cpu1_rst_pltrst.pin));
	ret = gpio_add_callback(cpu1_rst_pltrst.port, &rst_pltrst_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);
#endif
}

static void platform_oks_hpm_stby_monitor_remove(void)
{
	gpio_pin_interrupt_configure_dt(&hpm_stby_rdy, GPIO_INT_DISABLE);
	gpio_remove_callback(hpm_stby_rdy.port, &hpm_stby_rdy_cb_data);
}

static void platform_oks_smbus_rdy_monitor_remove(void)
{
	gpio_pin_interrupt_configure_dt(&smbus0_rdy, GPIO_INT_DISABLE);
	gpio_remove_callback(smbus0_rdy.port, &smbus_rdy_cb_data);
#ifdef DUAL_NODE
	gpio_pin_interrupt_configure_dt(&smbus1_rdy, GPIO_INT_DISABLE);
	gpio_remove_callback(smbus1_rdy.port, &smbus_rdy_cb_data);
#endif
}

static void platform_oks_cpu_aux_pwrgd_monitor_remove(void)
{
	gpio_pin_interrupt_configure_dt(&cpu0_aux_pwrgd, GPIO_INT_DISABLE);
	gpio_remove_callback(cpu0_aux_pwrgd.port, &cpu_aux_pwrgd_cb_data);
#ifdef DUAL_NODE
	gpio_pin_interrupt_configure_dt(&cpu1_aux_pwrgd, GPIO_INT_DISABLE);
	gpio_remove_callback(cpu1_aux_pwrgd.port, &cpu_aux_pwrgd_cb_data);
#endif
}

static void platform_oks_bmc_onctl_monitor_remove(void)
{
	gpio_pin_interrupt_configure_dt(&bmc_onctl, GPIO_INT_DISABLE);
	gpio_remove_callback(bmc_onctl.port, &bmc_onctl_cb_data);
}

static void platform_oks_reset_monitor_remove(void)
{

	gpio_pin_interrupt_configure_dt(&cpu0_rst_pltrst, GPIO_INT_DISABLE);
	gpio_remove_callback(cpu0_rst_pltrst.port, &rst_pltrst_cb_data);

#ifdef DUAL_NODE
	gpio_pin_interrupt_configure_dt(&cpu1_rst_pltrst, GPIO_INT_DISABLE);
	gpio_remove_callback(cpu1_rst_pltrst.port, &rst_pltrst_cb_data);
#endif
}

void platform_oks_monitor_init(void)
{
	LOG_INF("OKS Monitor init");
	platform_oks_hpm_stby_monitor_init();
	platform_oks_smbus_rdy_monitor_init();
	platform_oks_cpu_aux_pwrgd_monitor_init();
	platform_oks_bmc_onctl_monitor_init();
	platform_oks_reset_monitor_init();
}

void platform_oks_monitor_remove(void)
{
	LOG_INF("OKS Monitor remove");
	platform_oks_hpm_stby_monitor_remove();
	platform_oks_smbus_rdy_monitor_remove();
	platform_oks_cpu_aux_pwrgd_monitor_remove();
	platform_oks_bmc_onctl_monitor_remove();
	platform_oks_reset_monitor_remove();
}

struct k_work pwr_btn_work;
static struct gpio_callback fp_pwr_btn_cb_data;

static void power_btn_passthrough_update()
{
	struct gpio_dt_spec cpu0_power_btn_in =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), fp0_pwr_btn_in_gpios, 0);
	struct gpio_dt_spec power_btn_out =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), bmc_pwr_btn_out_gpios, 0);
	int ret = gpio_pin_get(cpu0_power_btn_in.port, cpu0_power_btn_in.pin);

	LOG_INF("[FP->PFR] PWR_BTN[%s %d] = %d", cpu0_power_btn_in.port->name, cpu0_power_btn_in.pin, ret);
	gpio_pin_set(power_btn_out.port, power_btn_out.pin, ret);
	gpio_pin_configure_dt(&power_btn_out, GPIO_OUTPUT);
	LOG_INF("[PFR->BMC] PWR_BTN[%s %d] = %d", power_btn_out.port->name, power_btn_out.pin, ret);

	// TODO: CPU1
}

static void power_btn_work_handler(struct k_work *item)
{
	power_btn_passthrough_update();
}

void power_btn_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	LOG_INF("[FP->PFR] PWN_BTN Interrupt");
	k_work_submit(&pwr_btn_work);
}

void oks_power_btn(bool enable)
{
	static bool init_done = false;
	struct gpio_dt_spec cpu0_power_btn_in =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), fp0_pwr_btn_in_gpios, 0);
	struct gpio_dt_spec cpu0_power_btn_out =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), bmc_pwr_btn_out_gpios, 0);

	if (!init_done) {
		k_work_init(&pwr_btn_work, power_btn_work_handler);
		gpio_init_callback(&fp_pwr_btn_cb_data, power_btn_handler, BIT(cpu0_power_btn_in.pin));
		init_done = true;
	}

	LOG_INF("[FP->PFR] Monitor PWN_BTN[%s %d] %s",
			cpu0_power_btn_in.port->name, cpu0_power_btn_in.pin, enable ? "registered" : "removed");
	if (enable) {
		/* Register input */
		gpio_pin_configure_dt(&cpu0_power_btn_in, GPIO_INPUT);
		gpio_add_callback(cpu0_power_btn_in.port, &fp_pwr_btn_cb_data);
		gpio_pin_interrupt_configure_dt(&cpu0_power_btn_in, GPIO_INT_EDGE_BOTH);

		/* Update PIN state at T0 */
		power_btn_passthrough_update();
	} else {
		/* Remove the callback */
		gpio_pin_interrupt_configure_dt(&cpu0_power_btn_in, GPIO_INT_DISABLE);
		gpio_remove_callback(cpu0_power_btn_in.port, &fp_pwr_btn_cb_data);

		/* Force to high at T-1 */
		LOG_INF("[PFR->BMC] T-1 PWR_BTN[%s %d] force to 1",
	  		cpu0_power_btn_out.port->name, cpu0_power_btn_out.pin);
		gpio_pin_set(cpu0_power_btn_out.port, cpu0_power_btn_out.pin, 1);
	}

	// TODO: CPU1
}

void oks_power_sequence_start(uint32_t events)
{
	int ret;
	static bool first_time_boot = true;

	LOG_INF("OKS Power sequence start");

	/* Workaround
	   HPMStandbyReset should be set to true before BMC bootup, otherwise,
	   BMC's LTPI won't link up.
	   Only perform at first time

	   In normal bootup, it should be set after bmc boot completed.
	 */

	if (first_time_boot) {
		// Set HPM_STBY_RDY to input
		gpio_pin_configure_dt(&hpm_stby_rdy, GPIO_INPUT);
		ret = gpio_pin_get(hpm_stby_rdy.port, hpm_stby_rdy.pin);
		if (ret == 0) {
			LOG_INF("Waiting for HPM_STBY_RDY[%s %d] Assert",
				hpm_stby_rdy.port->name, hpm_stby_rdy.pin);
			k_event_wait(&pfr_oks_event, PLATFORM_OKS_HPM_STBY_RDY, true, K_FOREVER);
		} else {
			LOG_INF("[CPLD->PFR] HPM_STBY_RDY[%s %d] Assert",
				hpm_stby_rdy.port->name, hpm_stby_rdy.pin);
		}
		HPMStandbyReset(true);
		// Wait BMC boot done
		k_event_wait(&pfr_system_event, PFR_SYSTEM_BMC_BOOTED, false, K_FOREVER);
		first_time_boot = false;
	}

	// Check if the power sequence is triggered by a PLTRST_SYNC fallback event
	if (events & PLATFORM_OKS_PLTRST_SYNC_FALLBACK)
		goto global_rst_sync;

	// Read SMBUS0_RDY
	gpio_pin_configure_dt(&smbus0_rdy, GPIO_INPUT);
	ret = gpio_pin_get(smbus0_rdy.port, smbus0_rdy.pin);
	if (ret == 0) {
		LOG_INF("Waiting for SMBUS0_RDY[%s %d] Assert",
			smbus0_rdy.port->name, smbus0_rdy.pin);
		k_event_wait(&pfr_oks_event, PLATFORM_OKS_SMBUS0_RDY, true, K_FOREVER);
	} else {
		k_event_clear(&pfr_oks_event, PLATFORM_OKS_SMBUS0_RDY);
	}

	LOG_INF("[CPLD->PFR] SMBUS0_RDY[%s %d] Assert",
			smbus0_rdy.port->name, smbus0_rdy.pin);

	// Perform S5 attestation
	ret = oks_s5_attestation();
	if (ret != 0) {
		// Attestation failed, terminate the power sequence
		LOG_ERR("S5 attestation failed");
		return;
	}

	// Read CPU0_AUX_PWRGD
	gpio_pin_configure_dt(&cpu0_aux_pwrgd, GPIO_INPUT);
	ret = gpio_pin_get(cpu0_aux_pwrgd.port, cpu0_aux_pwrgd.pin);
	if (ret == 0) {
		LOG_INF("Waiting for CPU0_AUX_PWRGD[%s %d] Assert",
			cpu0_aux_pwrgd.port->name, cpu0_aux_pwrgd.pin);
		k_event_wait(&pfr_oks_event, PLATFORM_OKS_CPU0_AUX_PWRGD, true, K_FOREVER);
	} else {
		k_event_clear(&pfr_oks_event, PLATFORM_OKS_CPU0_AUX_PWRGD);
	}

	// Set AUX_PWRGD
	AUXPowerGoodControl(true);

global_rst_sync:
	// Wait for BMC onctl = 1
	gpio_pin_configure_dt(&bmc_onctl, GPIO_INPUT);
	ret = gpio_pin_get(bmc_onctl.port, bmc_onctl.pin);
	if (ret == 0) {
		LOG_INF("Waiting for BMC_ONCTL[%s %d] Assert",
			bmc_onctl.port->name, bmc_onctl.pin);
		k_event_wait(&pfr_oks_event, PLATFORM_OKS_BMC_ONCTL, true, K_FOREVER);
	} else {
		k_event_clear(&pfr_oks_event, PLATFORM_OKS_BMC_ONCTL);
	}

	// Perform S0 attestation
	ret = oks_s0_attestation();
	if (ret != 0) {
		// Attestation failed, terminate the power sequence
		LOG_ERR("S0 attestation failed");
		return;
	}

	// Read PLTRST_SYNC
	gpio_pin_configure_dt(&cpu0_rst_pltrst, GPIO_INPUT);
	ret = gpio_pin_get(cpu0_rst_pltrst.port, cpu0_rst_pltrst.pin);
	if (ret == 0) {
		LOG_INF("Waiting for CPU0_PLTRST_SYNC[%s %d] Assert",
			cpu0_rst_pltrst.port->name, cpu0_rst_pltrst.pin);
		k_event_wait(&pfr_oks_event, PLATFORM_OKS_CPU0_PLTRST_SYNC, true, K_FOREVER);
	} else {
		k_event_clear(&pfr_oks_event, PLATFORM_OKS_CPU0_PLTRST_SYNC);
	}

	// Perform BTG attestation
	ret = oks_btg_attestation();
	if (ret != 0) {
		// Attestation failed, terminate the power sequence
		LOG_ERR("BTG attestation failed");
		return;
	}
}

static const struct platform_monitor_ctrl_ops oks_platform_monitor_ops = {
	.init = platform_oks_monitor_init,
	.remove = platform_oks_monitor_remove,
	.power_btn = oks_power_btn,
};

const struct platform_monitor_ctrl_ops *get_platform_monitor_ctrl_ops(void)
{
	return &oks_platform_monitor_ops;
}

