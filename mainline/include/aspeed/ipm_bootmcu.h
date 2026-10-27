/*
 * Copyright (c) 2023 - 2025 ASPEED Technology Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ASPEED_IPM_BOOTMCU_H_
#define ASPEED_IPM_BOOTMCU_H_

#include <zephyr/drivers/ipm.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IPC_SHARE_MEM_SRAM_SIZE		(0x1000) /* 4KB */

#define IPC_SHARE_MEM_LOCAL_S_CA35_DATA                                                            \
	__attribute__((__section__("IPC_SHARE_MEM_LOCAL_S_CA35_DATA")))
#define IPC_SHARE_MEM_LOCAL_NS_CA35_DATA                                                           \
	__attribute__((__section__("IPC_SHARE_MEM_LOCAL_NS_CA35_DATA")))
#define IPC_SHARE_MEM_REMOTE_BOOTMCU_DATA                                                          \
	__attribute__((__section__("IPC_SHARE_MEM_REMOTE_BOOTMCU_DATA")))
#define IPC_SHARE_MEM_REMOTE_BOOTMCU_CALIPTRA                                                      \
	__attribute__((__section__("IPC_SHARE_MEM_REMOTE_BOOTMCU_CALIPTRA")))
#define IPC_SHARE_MEM_LOCAL_BOOTMCU_DATA                                                           \
	__attribute__((__section__("IPC_SHARE_MEM_LOCAL_BOOTMCU_DATA")))
#define IPC_SHARE_MEM_LOCAL_BOOTMCU_CALIPTRA                                                       \
	__attribute__((__section__("IPC_SHARE_MEM_LOCAL_BOOTMCU_CALIPTRA")))

#define IPC_CHANNEL_ID_CH0			0
#define IPC_CHANNEL_0_SSP_IN_ADDR		(0x70004000)
#define IPC_CHANNEL_0_SSP_OUT_ADDR		(0x70002000)
#define IPC_CHANNEL_0_BOOTMCU_IN_ADDR		(0x70004000)
#define IPC_CHANNEL_0_BOOTMCU_OUT_ADDR		(0x70002000)
#define IPC_CHANNEL_ID_CPTRA			1
#define IPC_CHANNEL_1_SSP_IN_ADDR		(0x70005000)
#define IPC_CHANNEL_1_SSP_OUT_ADDR		(0x70003000)
#define IPC_CHANNEL_1_BOOTMCU_IN_ADDR		(0x70005000)
#define IPC_CHANNEL_1_BOOTMCU_OUT_ADDR		(0x70003000)
#define IPC_CHANNEL_1_BUFF_SIZE			(1024 * 1024)

/** Register the callback for one BootMCU message ID (0 through 3). */
void ipm_bootmcu_register_id_callback(const struct device *dev, uint32_t id,
				    ipm_callback_t cb, void *user_data);

/** Enable or disable one BootMCU message ID (0 through 3). */
int ipm_bootmcu_set_id_enabled(const struct device *dev, uint32_t id, int enable);

/* Show share memory information */
void ast_ipm_list(const struct device *dev);

/* Get tx share memory size */
int ast_ipm_max_tx_shmem_size(const struct device *dev, uint32_t channel);

/* Write the tx shmem */
int ast_ipm_shmem_write(const struct device *dev, uint32_t channel,
uint32_t offset, const void *buf, uint32_t size);

/* Get rx share memory size */
int ast_ipm_max_rx_shmem_size(const struct device *dev, uint32_t channel);

/* Read the rx shmem */
int ast_ipm_shmem_read(const struct device *dev, uint32_t channel,
uint32_t offset, void **buf, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif /* ASPEED_IPM_BOOTMCU_H_ */
