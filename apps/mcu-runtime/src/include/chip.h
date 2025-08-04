#ifndef _AST_CHIP_H
#define _AST_CHIP_H

enum boot_mode_type {
	BOOT_DEVICE_RAM = 0,
	BOOT_DEVICE_MMC1,
	BOOT_DEVICE_SATA,
	BOOT_DEVICE_UART,
	BOOT_DEVICE_USB,
	BOOT_DEVICE_I2C,
	BOOT_DEVICE_I3C,
	BOOT_DEV_MAX,
};

struct ast_chip;
struct ast_loader;

struct peripheral {
	char *name;
	int (*init)(struct ast_chip *chip);
	void *priv; /* private data for the init function */
};

struct ast_board {
	struct ast_chip *chip;
	void *priv;
	const char *bootmodestr;

	struct peripheral *peri;

	struct ast_loader *loader;
	int (*load_image)(void);
	void (*boot)(void);
};

struct ast_chip {
	uint32_t rev_id;
	uint32_t bootmode;

	struct peripheral *peripheral;
	int peri_num;

	struct ast_board *board;

	int (*new)(void *priv);
};

struct ast_chip *ast_create_chip(void);
struct ast_board *ast_create_board(struct ast_chip *chip);
#endif
