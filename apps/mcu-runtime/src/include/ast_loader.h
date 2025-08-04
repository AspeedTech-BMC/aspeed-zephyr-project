/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Aspeed Technology Inc.
 */

#ifndef _AST_LOADER_H
#define _AST_LOADER_H

#include <manifest.h>

#define IS_RECOVERY(n) ((n) > BOOT_UFS)

#define ast_loader_get_ops(loader) \
                ((struct ast_loader_ops *)(loader)->ops)

#define readl(addr) (sys_read32((void *)(addr)))
#define writel(val, addr) (sys_write32((val), (void *)(addr)))

struct udevice {

};

struct ast_chip;
struct ast_loader;

struct ast_loader_ops {
        int (*init)(struct device *dev);
        int (*copy)(struct device *dev, uint32_t *dst, uint32_t src, uint32_t len);
        int (*load)(struct device *dev, uint32_t *dst, uint32_t *len);
};

struct ast_loader {
        struct device *dev;
        int bootmode;

//	void *priv;

        struct ast_loader_ops *ops;

        int (*load)(struct ast_loader *loader, uint32_t type, uint32_t *dst, uint32_t *len);
        int (*verify)(uint32_t type, uint32_t *message, uint32_t len);

        int rev_id;

};

struct stor_ops {
        int (*init)(struct device *dev);
        int (*copy)(struct device *dev, uint32_t *dst, uint32_t *src, uint32_t len);
};

/* external use */
int ast_loader_read(uint32_t *dst, uint32_t src, uint32_t len);
int ast_loader_load_image(uint32_t type, uint32_t *dst, bool verify);
void *memcpy32(uint32_t *dst, uint32_t *src, uint32_t len);

/* internal use */
int ast_loader_init(struct ast_chip *chip);
int stor_init(struct ast_loader *loader);
int recovery_init(struct ast_loader *loader);

int mmc_register(struct ast_loader *loader);
int spi_register(struct ast_loader *loader);
int ufs_register(struct ast_loader *loader);
int i2c_register(struct ast_loader *loader);
int i3c_register(struct ast_loader *loader);
int usb_register(struct ast_loader *loader);
int uart_register(struct ast_loader *loader);
#endif
