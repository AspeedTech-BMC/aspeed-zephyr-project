/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <zephyr.h>

#include "state_machine.h"
#include "common_smc.h"
#include "common/common.h"
#include "include/SmbusMailBoxCom.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "intel_pfr/intel_pfr_verification.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "pfr/pfr_common.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "platform_monitor/platform_monitor.h"
#include <logging/logging_wrapper.h>
#include "AspeedStateMachine/AspeedStateMachine.h"

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

#define DEBUG_HALT() {				  \
		volatile int halt = 1;		  \
		while (halt) {			  \
			__asm__ volatile ("nop"); \
		}				  \
}

void main(void)
{
	int status = 0;

	LOG_INF("*** ASPEED_PFR version 01.01 Board:%s ***", CONFIG_BOARD);

	aspeed_print_sysrst_info();

	AspeedStateMachine();
}
