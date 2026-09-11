#ifndef _TAMPER_H
#define _TAMPER_H

#include <chip.h>

int tamper_init(int step, int diff);
int tamper_kick(void);
int tamper_check(void);
int tamper_stop(void);
int tamper_reboot(void);
int pll_calibration(int step, int diff);
#endif
