/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _AST_LOADER_H
#define _AST_LOADER_H

#include <manifest.h>

#define IS_RECOVERY(n) ((n) > BOOT_UFS)

#define ast_loader_get_ops(loader) \
                ((struct ast_loader_ops *)(loader)->ops)

#define readl(addr) (sys_read32((uintptr_t)(addr)))
#define writel(val, addr) (sys_write32((val), (uintptr_t)(addr)))
#define setbits_le32(addr, set) sys_write32(sys_read32((uintptr_t)(addr)) | (set), (uintptr_t)(addr))
#define clrbits_le32(addr, clr) sys_write32(sys_read32((uintptr_t)(addr)) & (~(clr)), (uintptr_t)(addr))
#define clrsetbits_le32(addr, clr, set) sys_write32((sys_read32((uintptr_t)(addr)) & (~(clr))) | (set), (uintptr_t)(addr));

struct udevice {

};

struct ast_chip;
struct ast_loader;

struct ast_loader_ops {
        int (*init)(struct ast_loader *loader);
        int (*copy)(struct ast_loader *loader, uint32_t *dst, uint32_t src, uint32_t len);
        int (*load)(struct ast_loader *loader, uint32_t *dst, uint32_t *len);
        int (*deinit)(struct ast_loader *loader);
};

struct ast_loader {
        struct device *dev;
        int bootmode;

//	void *priv;

        struct ast_loader_ops *ops;

        int (*load)(struct ast_loader *loader, uint32_t type, uint32_t *dst, uint32_t *len);
        int (*verify)(uint32_t type, uint32_t *message, uint32_t len, uint32_t buf_len);

        int rev_id;

	uint8_t *dma_pool;
};

struct stor_ops {
        int (*init)(struct device *dev);
        int (*copy)(struct device *dev, uint32_t *dst, uint32_t *src, uint32_t len);
};

/* external use */
int ast_loader_read(uint32_t *dst, uint32_t src, uint32_t len);
int ast_loader_load_image(uint32_t type, uint32_t *dst, uint32_t dst_check_len, bool verify);
int ast_loader_load_manifest_image(uint32_t type, uint32_t *dst, bool verify, uint32_t *img_read_size);
void *memcpy32(uint32_t *dst, uint32_t *src, uint32_t len);

/* internal use */
int ast_loader_init(struct ast_chip *chip);
int ast_loader_deinit(struct ast_chip *chip);
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
