/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include "StateMachineActions.h"
#include "state_machine/common_smc.h"
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

#if PF_STATUS_DEBUG
#define DEBUG_PRINTF LOG_INF
#else
#define DEBUG_PRINTF(...)
#endif

static EVENT_CONTEXT BmcData[2], PchData[2], TemperlateEvent;
AO_DATA BmcActiveObjectData, PchActiveObjectData;

static void wdt_callback_bmc_timeout(void)
{
	DEBUG_PRINTF("enter %s", __func__);
	SetLastPanicReason(BMC_WDT_EXPIRE);
	GenerateStateMachineEvent(WDT_TIMEOUT, NULL);
}

static void wdt_callback_pch_timeout(void)
{
	DEBUG_PRINTF("enter %s", __func__);
	SetLastPanicReason(ACM_WDT_EXPIRE);
	GenerateStateMachineEvent(WDT_TIMEOUT, NULL);
}

void AspeedPFR_EnableTimer(int type)
{
	struct watchdog_config wdt_config;
	const struct device *wdt_dev;
	int ret = 0;
	uint32_t count = 0;

	wdt_config.wdt_cfg.window.min = 0;
	wdt_config.reset_option = WDT_FLAG_RESET_NONE;

	if (type == BMC_EVENT) {
		DEBUG_PRINTF("---------------------------------------");
		DEBUG_PRINTF("     Start BMC Timer");
		DEBUG_PRINTF("---------------------------------------");
		wdt_config.wdt_cfg.window.max = BMC_MAXTIMEOUT;
		wdt_config.wdt_cfg.callback = wdt_callback_bmc_timeout;
		wdt_dev = device_get_binding(WDT_Devices_List[0]);

	} else if (type == PCH_EVENT) {
		DEBUG_PRINTF("---------------------------------------");
		DEBUG_PRINTF("     Start PCH Timer");
		DEBUG_PRINTF("---------------------------------------");
		wdt_config.wdt_cfg.window.max = BIOS_MAXTIMEOUT;
		wdt_config.wdt_cfg.callback = wdt_callback_pch_timeout;
		wdt_dev = device_get_binding(WDT_Devices_List[1]);
	}
	if (!wdt_dev) {
		DEBUG_PRINTF("wdt_timer_err: cannot find wdt device.");
		return;
	}
	ret = watchdog_init(wdt_dev, &wdt_config);

	watchdog_feed(wdt_dev, 0);
}

void AspeedPFR_DisableTimer(int type)
{
	const struct device *wdt_dev;

	if (type == BMC_EVENT) {
		DEBUG_PRINTF("---------------------------------------");
		DEBUG_PRINTF("     Disable BMC Timer");
		DEBUG_PRINTF("---------------------------------------");
		wdt_dev = device_get_binding(WDT_Devices_List[0]);

	} else if (type == PCH_EVENT) {
		DEBUG_PRINTF("---------------------------------------");
		DEBUG_PRINTF("     Disable PCH Timer");
		DEBUG_PRINTF("---------------------------------------");
		wdt_dev = device_get_binding(WDT_Devices_List[1]);

	}
	watchdog_disable(wdt_dev);
}

