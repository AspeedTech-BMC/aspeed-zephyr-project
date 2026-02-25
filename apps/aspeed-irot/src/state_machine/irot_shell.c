/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <state_machine/irot_fsm.h>
#include <zephyr/shell/shell.h>

// Send event
static int cmd_irot_send_event(const struct shell *shell, size_t argc, char **argv, void *data)
{
	enum IROT_EVENT event = (enum IROT_EVENT)data;

	irot_send_event(event, NULL);
	
	shell_print(shell, "iRoT FSM event %d sent", event);
	
	return 0;
}

SHELL_SUBCMD_DICT_SET_CREATE(sub_event, cmd_irot_send_event,
	(INIT_DONE, INIT_DONE, "Init Done"),
	(INIT_FAILED, INIT_FAILED, "Init Failed"),
	(VERIFY_DONE, VERIFY_DONE, "Verify Done"),
	(VERIFY_FAILED, VERIFY_FAILED, "Verify Failed"),
	(VERIFY_SKIPED, VERIFY_SKIPED, "Verify Skiped"),
	(ARMING_DONE, ARMING_DONE, "Arming Done"),
	(ARMING_FAILED, ARMING_FAILED, "Arming Failed"),
	(UPDATE_REQUESTED, UPDATE_REQUESTED, "Update Requested"),
	(UPDATE_COMPLETED, UPDATE_COMPLETED, "Update Completed"),
	(UPDATE_FAILED, UPDATE_FAILED, "Update Failed")
);


#include <zephyr/multi_heap/shared_multi_heap.h>
#include <zephyr/drivers/flash.h>
#include <mbedtls/sha512.h>

static int cmd_irot_alloc(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t size = strtoul(argv[1], NULL, 0);
	volatile void *ptr = shared_multi_heap_aligned_alloc(SMH_REG_ATTR_NON_CACHEABLE, 16, size);
	if (!ptr) {
		shell_print(shell, "Failed to allocate memory for iRoT FSM");
		return -ENOMEM;
	}
	shell_print(shell, "iRoT FSM memory allocated at %p", ptr);
	return 0;
}

static int cmd_irot_free(const struct shell *shell, size_t argc, char **argv)
{
	void *ptr = (void *)strtoul(argv[1], NULL, 0);
	shared_multi_heap_free(ptr);
	shell_print(shell, "iRoT FSM memory freed at %p", ptr);
	return 0;
}

static int cmd_irot_flash_read(const struct shell *shell, size_t argc, char **argv)
{
	const struct device *dev = device_get_binding(argv[1]);
	uint32_t offset = strtoul(argv[2], NULL, 0);
	uint32_t size = strtoul(argv[3], NULL, 0);
	void *buffer = strtoul(argv[4], NULL, 0);
	
	shell_print(shell, "Device: %s, Offset: %u, Size: %u", dev->name, offset, size);

	if (!buffer) {
		shell_print(shell, "Failed to allocate memory for buffer");
		return -ENOMEM;
	}

	if (flash_read(dev, offset, buffer, size) != 0) {
		shell_print(shell, "Failed to read from flash");
		return -EIO;
	}

	shell_hexdump(shell, buffer, 128);
	shell_hexdump(shell, (uint8_t *)buffer + size - 128, 128);
	return 0;
}

static int cmd_irot_sha384(const struct shell *shell, size_t argc, char **argv)
{
	void *buffer = (void *)strtoul(argv[1], NULL, 0);
	uint32_t size = strtoul(argv[2], NULL, 0);

	uint8_t hash[48];
	mbedtls_sha512((const unsigned char *)buffer, size, hash, 1);
	shell_print(shell, "SHA384 hash of buffer at %p with size %u:", buffer, size);
	shell_hexdump(shell, hash, sizeof(hash));

	return 0;
}

static int cmd_irot_flash_read_and_sha384(const struct shell *shell, size_t argc, char **argv)
{
	const struct device *dev = device_get_binding(argv[1]);
	uint32_t offset = strtoul(argv[2], NULL, 0);
	uint32_t size = strtoul(argv[3], NULL, 0);
	void *buffer = (void *)strtoul(argv[4], NULL, 0);
	uint32_t delay = strtoul(argv[5], NULL, 0);

	shell_print(shell, "Device: %s, Offset: %u, Size: %u", dev->name, offset, size);

	if (!buffer) {
		shell_print(shell, "Failed to allocate memory for buffer");
		return -ENOMEM;
	}

	if (flash_read(dev, offset, buffer, size) != 0) {
		shell_print(shell, "Failed to read from flash");
		return -EIO;
	}

	if (delay) {
		shell_print(shell, "Delaying for %u ms before hashing", delay);
		k_msleep(delay);
	}

	uint8_t hash[48];
	mbedtls_sha512((const unsigned char *)buffer, size, hash, 1);
	shell_print(shell, "SHA384 hash of flash data at offset %u with size %u:", offset, size);
	shell_hexdump(shell, hash, sizeof(hash));

	shell_print(shell, "Clearing buffer at %p len %d", buffer, size);
	memset(buffer, 0, size);

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE( sub_irot,
	SHELL_CMD(event, &sub_event, "iRoT FSM event commands", NULL),
	SHELL_CMD(alloc, NULL, "Allocate memory for iRoT FSM", cmd_irot_alloc),
	SHELL_CMD(free, NULL, "Free memory for iRoT FSM", cmd_irot_free),
	SHELL_CMD(flash_read, NULL, "Read data from flash", cmd_irot_flash_read),
	SHELL_CMD(sha384, NULL, "Calculate SHA384 hash", cmd_irot_sha384),
	SHELL_CMD(read_and_sha384, NULL, "Read data from flash and calculate SHA384 hash\n\tread_and_hash <device> <offset> <length> <buffer> <delay>", cmd_irot_flash_read_and_sha384),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(irot, &sub_irot, "iRoT FSM commands", NULL);
