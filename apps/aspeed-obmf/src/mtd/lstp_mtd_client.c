/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include "lstp/lstp_backend.h"
#include "lstp/lstp_common.h"
#include "lstp_mtd_client.h"
#include "lstp/lstp_transaction.h"

#define LSTP_MTD_CHANNEL_ID      LSTP_SPI_CHANNEL_ID
#define LSTP_MTD_CMD_FLAGS       (LSTP_SPI_CS_ASSERT | LSTP_SPI_CS_DEASSERT)
#define LSTP_MTD_REQUEST_TIMEOUT K_SECONDS(5)
#define LSTP_MTD_PROGRAM_TIMEOUT_MS 100U
#define LSTP_MTD_ERASE_TIMEOUT_MS   120000U
#define LSTP_MTD_WIP_POLL_MS        1
#define LSTP_MTD_PAGE_SIZE       256U
#define LSTP_MTD_ERASE_SIZE_4K   0x1000U
#define LSTP_MTD_ERASE_SIZE_32K  0x8000U
#define LSTP_MTD_ERASE_SIZE_64K  0x10000U
#define LSTP_MTD_3BYTE_LIMIT     0x1000000ULL
#define LSTP_MTD_ADDRESS_LIMIT   0x100000000ULL

#define SPI_NOR_CMD_READ_FAST       0x0bU
#define SPI_NOR_CMD_READ_FAST_4B    0x0cU
#define SPI_NOR_CMD_PAGE_PROGRAM    0x02U
#define SPI_NOR_CMD_PAGE_PROGRAM_4B 0x12U
#define SPI_NOR_CMD_WREN            0x06U
#define SPI_NOR_CMD_RDSR            0x05U
#define SPI_NOR_STATUS_WIP          BIT(0)
#define SPI_NOR_CMD_RDID            0x9fU
#define SPI_NOR_CMD_ERASE_4K        0x20U
#define SPI_NOR_CMD_ERASE_4K_4B     0x21U
#define SPI_NOR_CMD_ERASE_32K       0x52U
#define SPI_NOR_CMD_ERASE_32K_4B    0x5cU
#define SPI_NOR_CMD_ERASE_64K       0xd8U
#define SPI_NOR_CMD_ERASE_64K_4B    0xdcU

static int lstp_status_to_errno(lstp_status_t status)
{
	switch (status) {
	case LSTP_STATUS_SUCCESS:
		return 0;
	case LSTP_STATUS_TIMEOUT:
		return -ETIMEDOUT;
	case LSTP_STATUS_BUSY:
		return -EBUSY;
	case LSTP_STATUS_NAK:
		return -EACCES;
	case LSTP_STATUS_NOT_SUPPORTED:
		return -ENOTSUP;
	case LSTP_STATUS_TOO_LARGE:
		return -EMSGSIZE;
	default:
		return -EIO;
	}
}

static int lstp_mtd_exchange(uint8_t command, const void *request, size_t request_len,
			     void *response, size_t response_capacity, size_t expected_response_len,
			     k_timeout_t timeout)
{
	lstp_status_t status;
	size_t response_len = 0U;
	int ret;

	ret = lstp_transaction_request(LSTP_MTD_CHANNEL_ID, command, request, request_len, response,
				       response_capacity, &response_len, &status, timeout);
	if (ret != 0) {
		return ret;
	}

	ret = lstp_status_to_errno(status);
	if (ret != 0) {
		return ret;
	}

	return response_len == expected_response_len ? 0 : -EMSGSIZE;
}

static int lstp_mtd_write_command(const uint8_t *request, size_t request_len, k_timeout_t timeout)
{
	uint8_t response;

	return lstp_mtd_exchange(LSTP_SPI_CMD_WRITE | LSTP_MTD_CMD_FLAGS, request, request_len,
				 &response, sizeof(response), sizeof(response), timeout);
}

static int lstp_mtd_write_enable(void)
{
	const uint8_t command = SPI_NOR_CMD_WREN;

	return lstp_mtd_write_command(&command, sizeof(command), LSTP_MTD_REQUEST_TIMEOUT);
}

/*
 * The peer acknowledges a program/erase as soon as CS deasserts, long before
 * the flash is done, and the flash ignores WREN/PP/erase while WIP is set.
 */
static int lstp_mtd_wait_ready(uint32_t timeout_ms)
{
	const uint8_t request[2] = {SPI_NOR_CMD_RDSR};
	uint8_t response[sizeof(request)];
	int64_t deadline = k_uptime_get() + timeout_ms;
	int ret;

	for (;;) {
		ret = lstp_mtd_exchange(LSTP_SPI_CMD_WRITE_READ | LSTP_MTD_CMD_FLAGS, request,
					sizeof(request), response, sizeof(response),
					sizeof(response), LSTP_MTD_REQUEST_TIMEOUT);
		if (ret != 0) {
			return ret;
		}
		if ((response[1] & SPI_NOR_STATUS_WIP) == 0U) {
			return 0;
		}
		if (k_uptime_get() >= deadline) {
			return -ETIMEDOUT;
		}
		k_msleep(LSTP_MTD_WIP_POLL_MS);
	}
}

static void lstp_mtd_put_address(uint8_t *buf, uint32_t address, size_t address_len)
{
	for (size_t i = 0; i < address_len; i++) {
		buf[address_len - 1U - i] = (uint8_t)(address >> (i * 8U));
	}
}

int lstp_mtd_read_jedec_id(uint8_t id[3])
{
	uint8_t request[4] = {SPI_NOR_CMD_RDID};
	uint8_t response[sizeof(request)];
	int ret;

	if (id == NULL) {
		return -EINVAL;
	}

	ret = lstp_mtd_exchange(LSTP_SPI_CMD_WRITE_READ | LSTP_MTD_CMD_FLAGS, request,
				sizeof(request), response, sizeof(response), sizeof(response),
				LSTP_MTD_REQUEST_TIMEOUT);
	if (ret == 0) {
		memcpy(id, response + 1, 3U);
	}
	return ret;
}

int lstp_mtd_read(uint32_t offset, void *buf, size_t len)
{
	uint8_t request[LSTP_MAX_PAYLOAD_SIZE];
	uint8_t response[LSTP_MAX_PAYLOAD_SIZE];
	uint8_t *output = buf;
	uint64_t current = offset;
	uint64_t end = current + len;

	if ((len != 0U && buf == NULL) || end > LSTP_MTD_ADDRESS_LIMIT) {
		return -EINVAL;
	}

	while (current < end) {
		bool address_4b = current >= LSTP_MTD_3BYTE_LIMIT;
		size_t address_len = address_4b ? 4U : 3U;
		size_t header_len = 1U + address_len + 1U;
		size_t chunk = MIN((size_t)(end - current), LSTP_MAX_PAYLOAD_SIZE - header_len);
		int ret;

		if (!address_4b) {
			chunk = MIN(chunk, (size_t)(LSTP_MTD_3BYTE_LIMIT - current));
		}

		memset(request, 0, header_len + chunk);
		request[0] = address_4b ? SPI_NOR_CMD_READ_FAST_4B : SPI_NOR_CMD_READ_FAST;
		lstp_mtd_put_address(request + 1, (uint32_t)current, address_len);

		ret = lstp_mtd_exchange(LSTP_SPI_CMD_WRITE_READ | LSTP_MTD_CMD_FLAGS, request,
					header_len + chunk, response, header_len + chunk,
					header_len + chunk, LSTP_MTD_REQUEST_TIMEOUT);
		if (ret != 0) {
			return ret;
		}

		memcpy(output, response + header_len, chunk);
		output += chunk;
		current += chunk;
	}

	return 0;
}

int lstp_mtd_write(uint32_t offset, const void *buf, size_t len)
{
	uint8_t request[1U + 4U + LSTP_MTD_PAGE_SIZE];
	const uint8_t *input = buf;
	uint64_t current = offset;
	uint64_t end = current + len;

	if ((len != 0U && buf == NULL) || end > LSTP_MTD_ADDRESS_LIMIT) {
		return -EINVAL;
	}

	while (current < end) {
		bool address_4b = current >= LSTP_MTD_3BYTE_LIMIT;
		size_t address_len = address_4b ? 4U : 3U;
		size_t page_remaining =
			LSTP_MTD_PAGE_SIZE - ((size_t)current & (LSTP_MTD_PAGE_SIZE - 1U));
		size_t chunk = MIN((size_t)(end - current), page_remaining);
		int ret;

		if (!address_4b) {
			chunk = MIN(chunk, (size_t)(LSTP_MTD_3BYTE_LIMIT - current));
		}

		ret = lstp_mtd_write_enable();
		if (ret != 0) {
			return ret;
		}

		request[0] = address_4b ? SPI_NOR_CMD_PAGE_PROGRAM_4B : SPI_NOR_CMD_PAGE_PROGRAM;
		lstp_mtd_put_address(request + 1, (uint32_t)current, address_len);
		memcpy(request + 1U + address_len, input, chunk);

		ret = lstp_mtd_write_command(request, 1U + address_len + chunk,
					     LSTP_MTD_REQUEST_TIMEOUT);
		if (ret == 0) {
			ret = lstp_mtd_wait_ready(LSTP_MTD_PROGRAM_TIMEOUT_MS);
		}
		if (ret != 0) {
			return ret;
		}

		input += chunk;
		current += chunk;
	}

	return 0;
}

int lstp_mtd_erase(uint32_t offset, size_t len)
{
	uint8_t request[5];
	uint64_t current = offset;
	uint64_t end = current + len;

	if (len == 0U || (offset & (LSTP_MTD_ERASE_SIZE_4K - 1U)) != 0U ||
	    (len & (LSTP_MTD_ERASE_SIZE_4K - 1U)) != 0U || end > LSTP_MTD_ADDRESS_LIMIT) {
		return -EINVAL;
	}

	while (current < end) {
		bool address_4b = current >= LSTP_MTD_3BYTE_LIMIT;
		size_t address_len = address_4b ? 4U : 3U;
		size_t remaining = end - current;
		size_t erase_len;
		int ret;

		if ((current & (LSTP_MTD_ERASE_SIZE_64K - 1U)) == 0U &&
		    remaining >= LSTP_MTD_ERASE_SIZE_64K) {
			request[0] = address_4b ? SPI_NOR_CMD_ERASE_64K_4B : SPI_NOR_CMD_ERASE_64K;
			erase_len = LSTP_MTD_ERASE_SIZE_64K;
		} else if ((current & (LSTP_MTD_ERASE_SIZE_32K - 1U)) == 0U &&
			   remaining >= LSTP_MTD_ERASE_SIZE_32K) {
			request[0] = address_4b ? SPI_NOR_CMD_ERASE_32K_4B : SPI_NOR_CMD_ERASE_32K;
			erase_len = LSTP_MTD_ERASE_SIZE_32K;
		} else {
			request[0] = address_4b ? SPI_NOR_CMD_ERASE_4K_4B : SPI_NOR_CMD_ERASE_4K;
			erase_len = LSTP_MTD_ERASE_SIZE_4K;
		}

		ret = lstp_mtd_write_enable();
		if (ret != 0) {
			return ret;
		}

		lstp_mtd_put_address(request + 1, (uint32_t)current, address_len);
		ret = lstp_mtd_write_command(request, 1U + address_len, LSTP_MTD_REQUEST_TIMEOUT);
		if (ret == 0) {
			ret = lstp_mtd_wait_ready(LSTP_MTD_ERASE_TIMEOUT_MS);
		}
		if (ret != 0) {
			return ret;
		}

		current += erase_len;
	}

	return 0;
}
