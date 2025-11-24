/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _XYZMODEM_H_
#define _XYZMODEM_H_

struct ymodem_port {
	/* Blocking write of len bytes to the transport (e.g., UART). */
	void (*write)(char c);

	/* Read up to len bytes with timeout_ms.
	 * Return bytes read (0 on timeout), <0 on error.
	 */
	int (*read)(uint8_t *buf, uint32_t len, uint32_t timeout_ms);

	/* Maximum timeouts/retries (tunable). */
	uint32_t rx_timeout_ms;	/* default 1000 ms */
	uint8_t max_retries;	/* default 10 */
};

enum ymodem_status {
	YMODEM_OK = 0,
	YMODEM_ERR_IO = -1,
	YMODEM_ERR_PROTO = -2,
	YMODEM_ERR_CRC = -3,
	YMODEM_ERR_ABORT = -4,
	YMODEM_ERR_NOSPACE = -5,
};

enum y_state {
	YS_WAIT_HEADER,
	YS_RECV_DATA,
	YS_WAIT_FINAL_HDR
};

int readc(uint8_t *buf, uint32_t len, uint32_t timeout_ms);
void writec(char y);
enum ymodem_status ymodem_receive_into(struct ymodem_port *port,
				       uint8_t *buf,
				       uint32_t *out_size,
				       char *out_name, uint32_t name_cap);
int ymodem_open(struct device *dev);
int ymodem_close(void);

#endif /* _XYZMODEM_H_ */
