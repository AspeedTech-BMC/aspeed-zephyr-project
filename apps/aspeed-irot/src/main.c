/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <state_machine/irot_fsm.h>

LOG_MODULE_REGISTER(aspeed_irot);

int main() {
	LOG_INF("Aspeed IROT module initialized.");

	irot_send_event(START_STATE_MACHINE, NULL);

	return 0;
}

#define DEBUG_HALT() { \
	volatile int halt = 1; \
	while (halt) { \
		__asm__ volatile ("nop"); \
	} \
}

static int jtag_init(void)
{

	printk("Enable JTAG PIN Mux\n");
	uint32_t SCU0_408 = 0x72c02408;
	sys_write32(0x820, SCU0_408);

	// DEBUG_HALT();

	return 0;
}

SYS_INIT(jtag_init, EARLY, 0);


#if defined(CONFIG_SHELL)
#include <zephyr/shell/shell.h>

static int cmd_jtag_psp(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Switch to PSP for JTAG debug\n");
	uint32_t SCU0_408 = 0x72c02408;
	sys_write32(0x000, SCU0_408);
	return 0;
}

static int cmd_jtag_ssp(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Switch to SSP for JTAG debug\n");
	uint32_t SCU0_408 = 0x72c02408;
	sys_write32(0x820, SCU0_408);
	return 0;
}

static int cmd_jtag_tsp(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t SCU0_408 = 0x72c02408;
	sys_write32(0x840, SCU0_408);
	return 0;
}


SHELL_STATIC_SUBCMD_SET_CREATE(sub_jtag,
	SHELL_CMD(psp, NULL, "Switch CPU for JTAG debug", cmd_jtag_psp),
	SHELL_CMD(ssp, NULL, "Switch SSP for JTAG debug", cmd_jtag_ssp),
	SHELL_CMD(tsp, NULL, "Switch TSP for JTAG debug", cmd_jtag_tsp),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(jtag, &sub_jtag, "Halt CPU for JTAG debug", NULL);

#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
static int cmd_flash_read(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Flash read command executed\n");

	const struct device *fmc_dev = device_get_binding(argv[1]);
	if (!fmc_dev) {
		shell_print(shell, "Failed to get %s device binding\n", argv[1]);
		return -ENODEV;
	}

	uint32_t flash_addr = strtoul(argv[2], NULL, 0);
	uint32_t ddr_addr = strtoul(argv[3], NULL, 0);
	uint32_t size = strtoul(argv[4], NULL, 0);

	int ret = flash_read(fmc_dev, flash_addr, (uint8_t *)ddr_addr, size);
	if (ret != 0) {
		shell_print(shell, "Failed to read from flash device %s at address 0x%08X\n", argv[1], flash_addr);
		return ret;
	} else {
		shell_print(shell, "Successfully read %u bytes from flash device %s at address 0x%08X to RAM address 0x%08X\n",
			size, argv[1], flash_addr, ddr_addr);
	}

	return 0;
}

#include <mbedtls/sha512.h>
static int cmd_mbedtls_sha384(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "mbedtls hash command executed\n");

	uint32_t data_off = strtoul(argv[1], NULL, 0);
	uint32_t data_size = strtoul(argv[2], NULL, 0);

	mbedtls_sha512_context sha_ctx;
	mbedtls_sha512_init(&sha_ctx);
	mbedtls_sha512_starts(&sha_ctx, 1);

	mbedtls_sha512_update(&sha_ctx, (const uint8_t *)data_off, data_size);

	uint8_t hash_output[48];
	mbedtls_sha512_finish(&sha_ctx, hash_output);
	shell_print(shell, "SHA384 hash of data at 0x%08X (size %u) is:", data_off, data_size);
	shell_hexdump(shell, hash_output, sizeof(hash_output));
	mbedtls_sha512_free(&sha_ctx);

	return 0;
}

#include <zephyr/multi_heap/shared_multi_heap.h>
#include <zephyr/devicetree.h>

#define NONCACHE_NODE DT_NODELABEL(dram_nc_region)
#define NONCACHE_ADDR DT_REG_ADDR(NONCACHE_NODE)
#define NONCACHE_SIZE DT_REG_SIZE(NONCACHE_NODE)

static int cmd_multi_heap_init(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Multi-heap test command executed\n");
	
	struct shared_multi_heap_region region = {
		.addr = NONCACHE_ADDR,	
		.size = NONCACHE_SIZE,
		.attr = SMH_REG_ATTR_NON_CACHEABLE,
	};	

	shared_multi_heap_pool_init();
	shared_multi_heap_add(&region, NULL);

	return 0;
}

static int cmd_multi_heap_alloc(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Multi-heap alloc command executed\n");
	
	size_t alloc_size = strtoul(argv[1], NULL, 0);
	void *ptr = shared_multi_heap_alloc(SMH_REG_ATTR_NON_CACHEABLE, alloc_size);
	if (ptr) {
		shell_print(shell, "Allocated %u bytes from shared multi-heap at address 0x%08X", alloc_size, (uint32_t)ptr);
	} else {
		shell_print(shell, "Failed to allocate memory from shared multi-heap");
	}

	return 0;
}

static int cmd_multi_heap_free(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Multi-heap free command executed\n");
	
	uint32_t addr = strtoul(argv[1], NULL, 0);
	void *ptr = (void *)addr;
	shared_multi_heap_free(ptr);

	shell_print(shell, "Freed memory at address 0x%08X back to shared multi-heap", addr);

	return 0;
}

static int cmd_multi_heap_status(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Multi-heap status command executed\n");
	

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_test,
	SHELL_CMD_ARG(flash_read, NULL, "Read data from <device> <flash_off> <ram_addr> <size>", cmd_flash_read, 6, 0),
	SHELL_CMD_ARG(mbedtls_sha384, NULL, "Perform mbedtls hash operation", cmd_mbedtls_sha384, 3, 0),
	SHELL_CMD_ARG(multi_heap_init, NULL, "Initialize shared multi-heap pool", cmd_multi_heap_init, 1, 0),
	SHELL_CMD_ARG(multi_heap_alloc, NULL, "Allocate memory from shared multi-heap", cmd_multi_heap_alloc, 2, 0),
	SHELL_CMD_ARG(multi_heap_free, NULL, "Free memory back to shared multi-heap", cmd_multi_heap_free, 2, 0),
	SHELL_CMD_ARG(multi_heap_status, NULL, "Show shared multi-heap status", cmd_multi_heap_status, 1, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(test, &sub_test, "test shell commands", NULL);
#endif
