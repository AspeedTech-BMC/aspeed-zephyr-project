/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/util.h>

#include "lstp_mtd_client.h"

#define LSTP_MTD_SHELL_READ_CHUNK 128U
#define LSTP_MTD_SHELL_MAX_READ   4096U
#define LSTP_MTD_SHELL_MAX_WRITE  256U

static int parse_u32(const char *text, uint32_t *value)
{
	char *end;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 0);
	if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX) {
		return -EINVAL;
	}

	*value = (uint32_t)parsed;
	return 0;
}

static int cmd_lstp_mtd_id(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t id[3];
	int ret;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ret = lstp_mtd_read_jedec_id(id);
	if (ret != 0) {
		shell_error(sh, "LSTP MTD RDID failed: %d", ret);
		return ret;
	}

	shell_print(sh, "JEDEC ID: %02x %02x %02x", id[0], id[1], id[2]);
	return 0;
}

static int cmd_lstp_mtd_read(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t data[LSTP_MTD_SHELL_READ_CHUNK];
	uint32_t offset;
	uint32_t length;
	uint32_t done = 0U;
	int ret;

	ARG_UNUSED(argc);

	if (parse_u32(argv[1], &offset) != 0 || parse_u32(argv[2], &length) != 0 || length == 0U ||
	    length > LSTP_MTD_SHELL_MAX_READ || (uint64_t)offset + length > UINT64_C(0x100000000)) {
		shell_error(sh, "Usage: obmf mtd read <offset> <length>; length 1..4096");
		return -EINVAL;
	}

	while (done < length) {
		size_t chunk = MIN((size_t)(length - done), sizeof(data));

		ret = lstp_mtd_read(offset + done, data, chunk);
		if (ret != 0) {
			shell_error(sh, "LSTP MTD read failed at 0x%08x: %d", offset + done, ret);
			return ret;
		}

		for (size_t pos = 0; pos < chunk; pos += 16U) {
			shell_hexdump_line(sh, offset + done + pos, data + pos,
					   MIN((size_t)16U, chunk - pos));
		}
		done += chunk;
	}

	return 0;
}

static int cmd_lstp_mtd_write(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t data[LSTP_MTD_SHELL_MAX_WRITE];
	uint32_t offset;
	size_t hex_len = strlen(argv[2]);
	size_t data_len;
	int ret;

	ARG_UNUSED(argc);

	if (parse_u32(argv[1], &offset) != 0 || hex_len == 0U || (hex_len & 1U) != 0U ||
	    hex_len > sizeof(data) * 2U) {
		shell_error(sh, "Usage: obmf mtd write <offset> <hex-bytes>; max 256 bytes");
		return -EINVAL;
	}

	data_len = hex2bin(argv[2], hex_len, data, sizeof(data));
	if (data_len * 2U != hex_len || (uint64_t)offset + data_len > UINT64_C(0x100000000)) {
		shell_error(sh, "Invalid hexadecimal write data");
		return -EINVAL;
	}

	ret = lstp_mtd_write(offset, data, data_len);
	if (ret != 0) {
		shell_error(sh, "LSTP MTD write failed at 0x%08x: %d", offset, ret);
		return ret;
	}

	shell_print(sh, "Wrote %zu byte(s) at 0x%08x", data_len, offset);
	return 0;
}

static int cmd_lstp_mtd_erase(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t offset;
	uint32_t length;
	int ret;

	ARG_UNUSED(argc);

	if (parse_u32(argv[1], &offset) != 0 || parse_u32(argv[2], &length) != 0 ||
	    (uint64_t)offset + length > UINT64_C(0x100000000)) {
		shell_error(sh, "Usage: obmf mtd erase <offset> <length>");
		return -EINVAL;
	}

	ret = lstp_mtd_erase(offset, length);
	if (ret != 0) {
		shell_error(sh, "LSTP MTD erase failed at 0x%08x: %d", offset, ret);
		return ret;
	}

	shell_print(sh, "Erased 0x%x byte(s) at 0x%08x", length, offset);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_lstp_mtd, SHELL_CMD_ARG(id, NULL, "Read remote MTD JEDEC ID", cmd_lstp_mtd_id, 1, 0),
	SHELL_CMD_ARG(read, NULL, "Read: <offset> <length>", cmd_lstp_mtd_read, 3, 0),
	SHELL_CMD_ARG(write, NULL, "Program: <offset> <hex-bytes>", cmd_lstp_mtd_write, 3, 0),
	SHELL_CMD_ARG(erase, NULL, "Erase: <offset> <length>, 4 KiB aligned", cmd_lstp_mtd_erase, 3,
		      0),
	SHELL_SUBCMD_SET_END);

SHELL_SUBCMD_ADD((obmf), mtd, &sub_lstp_mtd, "Operate Linux MTD through LSTP SPI",
		 NULL, 1, 0);
