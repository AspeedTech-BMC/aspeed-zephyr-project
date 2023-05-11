/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <zephyr.h>
#include <build_config.h>
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
	}
	time_end = k_uptime_get_32();
	LOG_INF("MP flow completed, elapsed time = %u milliseconds",
			(time_end - time_start));
#else
	PROV_STATUS ret;
	ret = cert_provision();

	if (ret == PROV_ROT_UPDATE) {
		BMCBootRelease();
		PCHBootRelease();
	}
#endif
}
