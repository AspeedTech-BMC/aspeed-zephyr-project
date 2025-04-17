
# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
if (CONFIG_DT_HAS_ASPEED_PFR_GPIO_BHS_ENABLED)
	target_sources(app PRIVATE platform/platform_monitor_bhs.c)
elseif (CONFIG_DT_HAS_ASPEED_PFR_GPIO_EGS_ENABLED)
	target_sources(app PRIVATE platform/platform_monitor_egs.c)
elseif (CONFIG_DT_HAS_ASPEED_PFR_GPIO_GENOA_ENABLED)
	target_sources(app PRIVATE platform/platform_monitor_genoa.c)
elseif (CONFIG_DT_HAS_ASPEED_PFR_GPIO_OKS_ENABLED)
	target_sources(app PRIVATE platform/platform_monitor_oks.c)
else ()
	message(STATUS "No platform_monitor driver for this board")
endif()

target_sources(app PRIVATE platform_monitor.c spim_monitor.c)
