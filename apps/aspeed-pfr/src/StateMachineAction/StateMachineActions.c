/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include "StateMachineActions.h"
#include "AspeedStateMachine/common_smc.h"
#include "include/SmbusMailBoxCom.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_authentication.h"
#include "pfr/pfr_verification.h"
#include "pfr/pfr_update.h"
#include "flash/flash_aspeed.h"
#include <watchdog/watchdog_aspeed.h>
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "spi_filter/spi_filter_wrapper.h"
#include "logging/debug_log.h"// State Machine log saving
#include "AspeedStateMachine/AspeedStateMachine.h"

LOG_MODULE_DECLARE(aspeed_state_machine, CONFIG_LOG_DEFAULT_LEVEL);

#define RELEASE_PLATFORM 1

#define MAX_BUFFER_CHECK 79
#define MAX_LENGTH 32
#define SMBUS_WRITE 0x45

static void wdt_callback_bmc_timeout(void)
{
	LOG_ERR("BMC Boot WDT Timeout");
	union aspeed_event_data data = {0};
	data.bit8[0] = BMC_EVENT;
	GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
	SetLastPanicReason(BMC_WDT_EXPIRE);
}

static void wdt_callback_pch_timeout(void)
{
	LOG_ERR("PCH Boot WDT Timeout");
	union aspeed_event_data data = {0};
	data.bit8[0] = PCH_EVENT;
	GenerateStateMachineEvent(WDT_TIMEOUT, data.ptr);
	SetLastPanicReason(ACM_WDT_EXPIRE);
}

void AspeedPFR_EnableTimer(int type)
{
	struct watchdog_config wdt_config;
	const struct device *wdt_dev = NULL;
	int ret = 0;

	wdt_config.wdt_cfg.window.min = 0;
	wdt_config.reset_option = WDT_FLAG_RESET_NONE;

	if (type == BMC_EVENT) {
		LOG_INF("Start BMC Timer");
		wdt_config.wdt_cfg.window.max = BMC_MAXTIMEOUT;
		wdt_config.wdt_cfg.callback = wdt_callback_bmc_timeout;
		wdt_dev = device_get_binding(WDT_Devices_List[0]);
		gBmcBootDone = FALSE;
	} else if (type == PCH_EVENT) {
		LOG_INF("Start PCH Timer");
		wdt_config.wdt_cfg.window.max = BIOS_MAXTIMEOUT;
		wdt_config.wdt_cfg.callback = wdt_callback_pch_timeout;
		wdt_dev = device_get_binding(WDT_Devices_List[1]);
		gBiosBootDone = FALSE;
	}
	if (!wdt_dev) {
		LOG_ERR("wdt_timer_err: cannot find wdt device.");
		return;
	}
	ret = watchdog_init(wdt_dev, &wdt_config);

	watchdog_feed(wdt_dev, 0);
}

void AspeedPFR_DisableTimer(int type)
{
	const struct device *wdt_dev;

	if (type == BMC_EVENT) {
		LOG_INF("Disable BMC Timer");
		wdt_dev = device_get_binding(WDT_Devices_List[0]);

	} else if (type == PCH_EVENT) {
		LOG_INF("Disable PCH Timer");
		wdt_dev = device_get_binding(WDT_Devices_List[1]);

	}
	watchdog_disable(wdt_dev);
}

