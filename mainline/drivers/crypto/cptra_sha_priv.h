/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2021 ASPEED Technology Inc.
 */

#ifndef ASPEED_CPTRA_SHA_PRIV_H_
#define ASPEED_CPTRA_SHA_PRIV_H_

#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/clock.h>

#define reg_read_poll_timeout(map, reg, val, cond, sleep_us, timeout_ms)	    \
	({									    \
		uint32_t __timeout_tick = Z_TIMEOUT_MS(timeout_ms).ticks;	    \
		uint32_t __start = sys_clock_tick_get_32();			    \
		int __ret = 0;							    \
		for (;;) {							    \
			val.value = map->reg.value;				    \
			if (cond) {						    \
				break;						    \
			}							    \
			if ((sys_clock_tick_get_32() - __start) > __timeout_tick) { \
				__ret = -ETIMEDOUT;				    \
				break;						    \
			}							    \
			if (sleep_us) {						    \
				k_usleep(sleep_us);				    \
			}							    \
		}								    \
		__ret;								    \
	})

#endif /* ASPEED_CPTRA_SHA_PRIV_H_ */
