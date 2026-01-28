/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include "yModem.h"

struct device *g_uart_dev;

/**********************
 * Protocol constants *
 **********************/
#define SOH	0x01	/* 128-byte packet */
#define STX	0x02	/* 1024-byte packet */
#define EOT	0x04
#define ACK	0x06
#define NAK	0x15
#define CAN	0x18
#define BSP	0x08
#define CRC	0x43	/* 'C' */

#define YMODEM_PACKET_128	128
#define YMODEM_PACKET_1K	1024
#define YMODEM_HEADER_SIZE	3	/* [SOH/STX][seq][~seq] */
#define YMODEM_TRAILER_SIZE	2	/* CRC16 */
#define YMODEM_PACKET_OVERHEAD	(YMODEM_HEADER_SIZE + YMODEM_TRAILER_SIZE)

/**********************
 * Utility: CRC-16/IBM *
 **********************/
static uint16_t y_crc16(const uint8_t *data, uint32_t len)
{
	uint16_t crc = 0;
	uint32_t i;
	int b;

	for (i = 0; i < len; i++) {
		crc ^= (uint16_t)data[i] << 8;
		for (b = 0; b < 8; b++)
			crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
	}

	return crc;
}

static void y_putc(struct ymodem_port *p, char c)
{
	k_usleep(50000);
	if (p && p->write)
		p->write(c);
}

int readc(uint8_t *buf, uint32_t len, uint32_t timeout_ms)
{

	int64_t now_ms = k_uptime_get();
	int i;
	bool gotten = false;

	for (i = 0; i < len; i++) {
		while (uart_poll_in(g_uart_dev, (buf + i)) != 0) {
			if (k_uptime_get() - now_ms > timeout_ms)
				return 0;
		}

		if (!gotten) {
			timeout_ms += 2000;
			gotten = true;
		}
	}

	return len;
}

void writec(char y)
{
	uart_poll_out(g_uart_dev, y);
}

/**
 * ymodem_receive_into() - receive a file directly into a user buffer
 * @port: transport + callbacks
 * @buf: destination buffer
 * @out_size: returns received size (can be NULL)
 * @out_name: optional, buffer to store file name (can be NULL)
 * @name_cap: size of @out_name
 *
 * Copies the received payload into @buf. If the incoming file exceeds
 */
enum ymodem_status ymodem_receive_into(struct ymodem_port *port,
				       uint8_t *buf,
				       uint32_t *out_size,
				       char *out_name, uint32_t name_cap)
{
	uint8_t retries, seq;
	uint32_t to;
	uint8_t mark, hdr[2], crc_b[2];
	uint8_t payload[1024];
	uint8_t pkt_seq, pkt_inv;
	uint16_t recv_crc, calc_crc;
	char fname_local[128] = { 0 };
	char *fname = out_name ? out_name : fname_local;
	uint32_t fname_cap = out_name ? name_cap : sizeof(fname_local);
	uint32_t fsize = 0, total = 0;
	enum y_state st = YS_WAIT_HEADER;
	int r;
	uint8_t dummy;

	if (!port || !port->read || !port->write || !buf)
		return YMODEM_ERR_IO;

	retries = port->max_retries ? port->max_retries : 10;
	to = port->rx_timeout_ms ? port->rx_timeout_ms : 1000;

	y_putc(port, CRC);

	seq = 0;

	for (;;) {
		r = port->read(&mark, 1, to);
		if (r <= 0) {
			if (!retries--)
				return YMODEM_ERR_IO;

			y_putc(port, CRC);
			continue;
		}

		if (mark == SOH || mark == STX) {
			uint32_t payload_len = (mark == SOH) ?
					YMODEM_PACKET_128 : YMODEM_PACKET_1K;

			if (port->read(hdr, 2, to) <= 0)
				return YMODEM_ERR_IO;

			pkt_seq = hdr[0];
			pkt_inv = hdr[1];
			if ((uint8_t)(pkt_seq + pkt_inv) != 0xFF) {
				y_putc(port, NAK);
				continue;
			}

			if (port->read(payload, payload_len, to) <= 0)
				return YMODEM_ERR_IO;

			if (port->read(crc_b, 2, to) <= 0)
				return YMODEM_ERR_IO;

			recv_crc = ((uint16_t)crc_b[0] << 8) | crc_b[1];
			calc_crc = y_crc16(payload, payload_len);
			if (recv_crc != calc_crc) {
				y_putc(port, NAK);
				continue;
			}

			if (st == YS_WAIT_FINAL_HDR && pkt_seq == 0) {
				bool all_zero = true;
				for (size_t k = 0; k < payload_len; k++) {
					if (payload[k] != 0) {
						all_zero = false;
						break;
					}
				}

				if (all_zero) {
					y_putc(port, ACK);
					if (out_size)
						*out_size = fsize;
					return YMODEM_OK;
				}

				y_putc(port, NAK);
				continue;
			}

			if (st == YS_WAIT_HEADER && pkt_seq == 0) {
				/* header with name + size */
				if (payload[0] == 0) {
					y_putc(port, ACK);
					if (out_size)
						*out_size = total;

					return total ? YMODEM_OK : YMODEM_ERR_PROTO;
				}

				uint32_t i = 0, j = 0;
				while (i < payload_len && payload[i] && j + 1 < fname_cap)
					fname[j++] = (char)payload[i++];
				if (fname_cap)
					fname[j] = 0;
				i++;
				fsize = 0;
				while (i < payload_len && payload[i] != 0x20)
					fsize = fsize * 10 + (payload[i++] - '0');

				while (uart_poll_in(g_uart_dev, &dummy) == 0);
				k_usleep(50000);
				while (uart_poll_in(g_uart_dev, &dummy) == 0);

				y_putc(port, ACK);
				y_putc(port, CRC);
				seq = 1;
				total = 0;
				st = YS_RECV_DATA;
				continue;
			}

			if (st == YS_RECV_DATA && pkt_seq == seq) {
				uint32_t to_copy = (fsize && (total + payload_len > fsize)) ?
						 (fsize - total) : payload_len;

				memcpy(buf + total, payload, to_copy);

				total += to_copy;
				if (out_size)
					*out_size = total;

				y_putc(port, ACK);
				seq = (uint8_t)(seq + 1);
				continue;
			}

			y_putc(port, NAK);
			continue;

		} else if (mark == EOT) {

			if (st != YS_RECV_DATA) {
				y_putc(port, NAK);
				k_usleep(50000);
				continue;
			}

			y_putc(port, NAK);
			k_usleep(50000);
			if (port->read(&mark, 1, to) <= 0)
				return YMODEM_ERR_IO;

			if (mark == EOT) {
				y_putc(port, ACK);
				k_usleep(50000);
				/* ask for final empty header */
				y_putc(port, CRC);
				st = YS_WAIT_FINAL_HDR;
				continue;
			}
		} else if (mark == CAN) {
			if (port->read(&mark, 1, to) <= 0)
				return YMODEM_ERR_ABORT;

			return (mark == CAN) ? YMODEM_ERR_ABORT : YMODEM_ERR_PROTO;
		} else {
			/* ignore */
			continue;
		}
	}
	/* not reached */
}

int ymodem_open(struct device *dev)
{
	g_uart_dev = dev;

	return 0;
}

int ymodem_close(void)
{
	k_usleep(500000);
	return 0;
}
