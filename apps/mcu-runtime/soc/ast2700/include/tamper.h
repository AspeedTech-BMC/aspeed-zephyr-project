#ifndef _TAMPER_H
#define _TAMPER_H

#include <chip.h>

#define TAMPER_STATUS_REG	0x12c021c4
#define TAMPER_ALERT		BIT(3)

int tamper_init(int step, int diff);
int tamper_kick(void);
int tamper_check(void);
int tamper_stop(void);
int tamper_reboot(void);
int pll_calibration(int step, int diff);
#endif
