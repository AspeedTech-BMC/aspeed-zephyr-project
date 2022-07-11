/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <flash/flash_wrapper.h>
#include <logging/logging.h>
#include <logging/debug_log.h>
#include <logging/logging_flash.h>
#include <logging/logging_memory.h>

#define LOGGING_FLASH_DEVICE_SIZE       0x1000000       // logging flash device size supported
#define LOGGING_FLASH_BASE_ADDRESS      0               // flash base address for logging

#define DBG_LOG_TST_WR_SIZE 4096
#define DBG_LOG_TST_RD_SIZE 4096

#define DBG_LOG_TST_SPI_SIZE 8192

#define LOG_TO_MEMORY        1
#define LOG_ENTRY_COUNT      128
#define LOG_ENTRY_SIZE       21

static struct spi_engine_wrapper logFlash;      // logging flash implementations info
struct flash_master_wrapper spi;                // interface to the SPI master connected to a flash device.

/**
 * @brief Initializes logging features.
 *
 * Initializes flash device and APIs.
 * input argument of logging will be updated as logging flash if flash device and logging flash are success to initialize.
 *
 * @return Completion status, 0 if success or an error code.
 */
int logging_flash_wrapper_init(struct logging_flash *logging)
{
	int status;     // initialization status

	printk("\nlogging_flash_wrapper_init\n ");

	if (logging == NULL) {
		return -1;      // empty logging argument
	}

	status = flash_master_wrapper_init(&spi);
	if (status != 0) {
		return status;
	}
	/* Initializes SPI flash access functions and corresponding commands.
	 * spi variable is unused argument in flash_wrapper_init function. */
	status = flash_wrapper_init(&logFlash, &spi);

	if (status != 0) {
		return status;  // failed to flash wrapper initialization
	}

	logFlash.spi.device_id[0] = ROT_INTERNAL_LOG;// Access fmc_cs0 ROT_INTERNAL_LOG
	/* retrieves flash device size. */
#if 0
	status = logFlash.spi.base.get_device_size((struct flash *)&logFlash.spi, &logFlash.spi.device_size);
#else
	status = spi_flash_set_device_size(&logFlash.spi, LOGGING_FLASH_DEVICE_SIZE);   // set flash device size
#endif

	if (status != 0) {
		return status;  // failed to retrieves flash device size
	}
	status = logging_flash_init(logging, &logFlash.spi, LOGGING_FLASH_BASE_ADDRESS);

	if (status != 0) {
		return status;  // failed to initializes logging flash
	}
	return 0;               // debug_log info updated
}


int logging_memory_wrapper_init(struct logging_memory *logging)
{
	return (logging_memory_init(logging, LOG_ENTRY_COUNT, LOG_ENTRY_SIZE));
}

/**
 * Print out content in buffer.
 *
 * @param buf The buffer info.
 * @param length The length of the buffer.
 * @param string The message.
 *
 */
static void debug_msg_display(void *buf, size_t length, char *string)
{
	if (string) {
		printk("%s\n", string);
	}

	for (size_t i = 0; i < 16; i++) {
		if (!(i % 16)) {
			printk("\n%04x ", i);
		}
		printk("%02x ", i);
	}

	for (size_t i = 0; i < length; i++) {
		if (!(i % 16)) {
			printk("\n%04x ", i);
		}
		printk("%02x ", *((uint8_t *)(buf + i)));
	}

	printk("\n");
}

/**
 * Clear content in buffer.
 *
 * @param buf The buffer info.
 * @param length The length of the buffer.
 *
 */
static void debug_msg_clear(void *buf, size_t length)
{
	for (size_t i = 0; i < length; i++)
		*((uint8_t *)(buf + i)) = 0x00;
}

// State Machine log saving>
int debug_log_init(void)
{

#ifdef LOG_TO_MEMORY
	debug_log = malloc(sizeof(struct logging_memory));

	if (debug_log == NULL) {
		return __LINE__;
	}

	if (logging_memory_wrapper_init(debug_log)) {
		return __LINE__;
	}
#else
	debug_log = malloc(sizeof(struct logging_flash));

	if (debug_log == NULL) {
		return __LINE__;
	}
	if (logging_flash_wrapper_init(debug_log)) {
		return __LINE__;
	}
#endif
	if (debug_log_clear()) {
		return __LINE__;
	}
}

#ifndef LOG_TO_MEMORY
// State Machine log saving<

/**
 * Test function: for debug log.
 *
 * @param buf The buffer info.
 * @param length The length of the buffer.
 *
 * @return Completion status, 0 if success or an error code.
 */
int debug_log_test(void)
{
	uint8_t *flash_read_contents;
	uint8_t *log_read_contents;

	debug_log = malloc(sizeof(struct logging_flash));

	if (debug_log == NULL) {
		return __LINE__;
	}

	flash_read_contents = malloc(DBG_LOG_TST_WR_SIZE);

	if (flash_read_contents == NULL) {
		return __LINE__;
	}

	log_read_contents = malloc(DBG_LOG_TST_RD_SIZE);

	if (log_read_contents == NULL) {
		free(flash_read_contents);
		return __LINE__;
	}

	if (logging_flash_wrapper_init((struct logging_flash *)debug_log)) {
		return __LINE__;
	}

	if (debug_log_clear()) {
		return __LINE__;
	}

	// Step 1: (normal add/ flush/ read content/ clear)***************************************
	// add 1.5KB -> flush -> check (compare buffer & SPI), match!
	debug_msg_clear((((struct logging_flash *)debug_log)->entry_buffer), DBG_LOG_TST_RD_SIZE);
	for (size_t i = 0; i < 54; i++) // 1.5KB
		if (debug_log_create_entry(1 % DEBUG_LOG_NUM_SEVERITY, (uint8_t)i, (uint8_t)i + 1, i, i + 1)) {
			return (i << 16) | __LINE__;
		}
	printk("Log size=%d\n", debug_log_get_size());// 1512 bytes = 54 logs, pass

	debug_log_flush();
	printk("Log size=%d\n", debug_log_get_size());// 1512 bytes = 54 logs, pass

	debug_msg_display((((struct logging_flash *)debug_log)->entry_buffer), DBG_LOG_TST_RD_SIZE, "read from buffer");

	debug_log_read_contents(0, log_read_contents, 4096);
	debug_msg_display(log_read_contents, DBG_LOG_TST_RD_SIZE, "Log function [debug_log_read_contents]:");   // 0~0x5E8, data is correct, pass

	debug_log_clear();                                                                                      // Boundry has not be cleared, pass.

	// Step 2: (buffer full testing)***********************************************************
	// add 5KB -> check (compare buffer & SPI)
	// Buffer: Saved: 4088 bytes + 7bytes terminated, then resave data from 0~0x380=896.
	// SPI Saved: 4088 bytes + 7bytes terminated
	debug_msg_clear((((struct logging_flash *)debug_log)->entry_buffer), DBG_LOG_TST_RD_SIZE);

	for (size_t i = 0; i < 0xB2; i++)       // 5KB
		if (debug_log_create_entry(1 % DEBUG_LOG_NUM_SEVERITY, (uint8_t)i, (uint8_t)i + 1, i, i + 1)) {
			return (i << 16) | __LINE__;
		}

	printk("Log size=%d\n", debug_log_get_size());// 4984 bytes = 4088 + 896, pass

	// Boundry has not be changed, pass.

	debug_msg_display((((struct logging_flash *)debug_log)->entry_buffer), DBG_LOG_TST_RD_SIZE, "read from buffer");
	// Buffer: Saved: 4088 bytes + 7bytes terminated, then resave data from 0~0x380=896.
	// Data: 0x92~0xb1(resave 0~0x380) + 0x20~0x91

	debug_log_read_contents(2048, log_read_contents, 4096); // "SPI: 0x800" + "buffer: 0xb78" = 4984 bytes
	debug_msg_display(log_read_contents, DBG_LOG_TST_RD_SIZE, "Log function [debug_log_read_contents]:");
	// Data: 0x49~0x92(SPI) + 0x93~0xb1(buffer) + 0x00

	// return 0;// //Boundry has not be changed, pass.
	debug_log_flush();
	// Buffer: Saved: 4088 bytes + 7bytes terminated, then resave data from 0~0x380.
	// SPI: Start from 0xf0000. Saved: 4088 bytes + 7bytes terminated (Data: 0x00~0x91)
	//	  0xf1000~0x380	(Data: 0x92~0xb1)

	debug_log_clear();

	// Step 3: (SPI full testing)**************************************************************
	// add 9KB -> check
	debug_msg_clear((((struct logging_flash *)debug_log)->entry_buffer), DBG_LOG_TST_RD_SIZE);
	for (size_t i = 0; i < 0x142; i++)      // 9016 bytes
		if (debug_log_create_entry(1 % DEBUG_LOG_NUM_SEVERITY, (uint8_t)i, (uint8_t)i + 1, i, i + 1)) {
			return (i << 16) | __LINE__;
		}
	// block1=4088 bytes + 7 bytes terminate + 1 byte left = 4096
	// block2=4088 bytes + 7 bytes terminate + 1 byte left = 4096
	// SPI only saved real data 4088*2 bytes = 8176 bytes

	printk("Log size=%d\n", debug_log_get_size());// 9016 bytes, pass
	// return 0;	//Boundry has not be changed, pass.
	debug_msg_display((((struct logging_flash *)debug_log)->entry_buffer), DBG_LOG_TST_RD_SIZE, "read from buffer");
	// buffer= block2 , then resave data from 0~0x348=840 bytes(9016 - 8176 bytes)

	debug_log_read_contents(2048, log_read_contents, 4096);
	debug_msg_display(log_read_contents, DBG_LOG_TST_RD_SIZE, "Log function [debug_log_read_contents]:");

	debug_log_flush();
	// SPI= block1 ("840 bytes" + "3256 bytes empty") + block2(4088 bytes + 7 bytes terminate + 1 byte left = 4096), pass

	printk("Log size=%d\n", debug_log_get_size());          // "840 bytes" + "4088 bytes" = 4928 bytes(valid data), pass

	debug_log_read_contents(2048, log_read_contents, 4096); // get valid byte (not include terminated)
	debug_msg_display(log_read_contents, DBG_LOG_TST_RD_SIZE, "Log function [debug_log_read_contents]:");
	// Data: "block1 [0x24~0x41 (840 bytes)]" + "block2 [0x92~0xff~0x23]"

	debug_log_clear();              // Boundry has not be changed, pass.

	free(flash_read_contents);      // just for debug even didn't free the variables
	free(log_read_contents);

	return 0;
}
#endif
