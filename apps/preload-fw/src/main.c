/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <zephyr.h>
#include <build_config.h>
#include <shell/shell.h>
#include <drivers/gpio.h>
#if defined(CONFIG_AST1060_PROGRAMMER_MP)
#include "mp/mp_util.h"
#else
#include "certificate/cert_prov.h"
#endif
#include "gpio/gpio_ctrl.h"

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

extern void aspeed_print_sysrst_info(void);

void main(void)
{

	BMCBootHold();
	PCHBootHold();

	LOG_INF("*** ASPEED Preload FW version v%02d.%02d Board:%s ***", PROJECT_VERSION_MAJOR, PROJECT_VERSION_MINOR, CONFIG_BOARD);
	aspeed_print_sysrst_info();
#if defined(CONFIG_AST1060_PROGRAMMER_MP)
	int ret;
	uint32_t time_start, time_end;
	time_start = k_uptime_get_32();
	ret = prog_otp_and_rot();
	if (ret == 0) {
		LOG_INF("OTP and firmware image have been programmed successfully");
		time_end = k_uptime_get_32();
		LOG_INF("MP flow completed, elapsed time = %u milliseconds",
				(time_end - time_start));
	} else {
		LOG_ERR("Failed to update OTP and firmware image");
	}
#else
	PROV_STATUS ret;
	ret = cert_provision();

	if (ret == PROV_ROT_UPDATE) {
		BMCBootRelease();
		PCHBootRelease();
	}
#endif
}

static int do_mp_inject(const struct shell *shell, size_t argc, char **argv)
{
	const struct gpio_dt_spec mp_status1 = GPIO_DT_SPEC_GET_BY_IDX(
			DT_INST(0, aspeed_pfr_gpio_mp), mp_status1_out_gpios, 0);
	const struct gpio_dt_spec mp_status2 = GPIO_DT_SPEC_GET_BY_IDX(
			DT_INST(0, aspeed_pfr_gpio_mp), mp_status2_out_gpios, 0);
	if (!strcmp(argv[1], "inprog")) {
		gpio_pin_set(mp_status1.port, mp_status1.pin, 0);
		gpio_pin_set(mp_status2.port, mp_status2.pin, 0);
	} else if (!strcmp(argv[1], "otp")) {
		gpio_pin_set(mp_status1.port, mp_status1.pin, 0);
		gpio_pin_set(mp_status2.port, mp_status2.pin, 1);
	} else if (!strcmp(argv[1], "fw")) {
		gpio_pin_set(mp_status1.port, mp_status1.pin, 1);
		gpio_pin_set(mp_status2.port, mp_status2.pin, 0);
	} else if (!strcmp(argv[1], "done")) {
		gpio_pin_set(mp_status1.port, mp_status1.pin, 1);
		gpio_pin_set(mp_status2.port, mp_status2.pin, 1);
	}
}

SHELL_STATIC_SUBCMD_SET_CREATE(mp_cmds,
		SHELL_CMD_ARG(inject_state, NULL, "inject state: <inprog|fw|otp|done>", do_mp_inject, 2, 0),
		SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(mp, &mp_cmds, "Test MP flow Commands", NULL);
