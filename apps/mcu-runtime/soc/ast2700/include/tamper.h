#ifndef _TAMPER_H
#define _TAMPER_H

#include <chip.h>

#define TAMPER_STATUS_REG	0x12c021c4
#define TAMPER_ALERT		BIT(3)

/* MPLL (SCU0+0x310): Fout = Fref(25MHz) * NF / NR / OD, fields packed as
 * NF=bits[12:0], NR-1=bits[18:13], OD-1=bits[22:19]. Shared between
 * tamper.c's pll_calibration() and sdram_ast2700.c's sdramc_pll_reset().
 */
#define MPLL_CTRL_REG		0x12c02310
#define MPLL_STATUS_REG	0x12c02314
#define MPLL_RESET_BIT		BIT(25)
#define MPLL_BYPASS_BIT	BIT(24)
#define MPLL_CLKNF_MASK	GENMASK(12, 0)	/* NF */
#define MPLL_CLKNR_MASK	GENMASK(18, 13)	/* NR - 1 */
#define MPLL_CLKOD_MASK	GENMASK(22, 19)	/* OD - 1 */
#define MPLL_LOCK_BIT		BIT(31)
#define MPLL_LOCK_TIMEOUT_US	100000

int tamper_init(int step, int diff);
int tamper_kick(void);
int tamper_check(void);
int tamper_stop(void);
int tamper_reboot(void);
int pll_calibration(int step, int diff);
#endif
