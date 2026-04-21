/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/util.h>
#include <string.h>

#include "lstp_common.h"
#include "lstp_task.h"
#include "lstp_usb.h"
#include "lstp_i2c.h"
#include "lstp_spi.h"
#include "lstp_uart.h"

LOG_MODULE_REGISTER(lstp_task, LOG_LEVEL_ERR);

#define LSTP_MSG_QUEUE_SIZE     4
#define LSTP_IRQ_QUEUE_SIZE     8

/* -----------------------------------------------------------------------
 * Message types
 * ----------------------------------------------------------------------- */

struct lstp_task_msg {
	uint8_t buffer[LSTP_MSG_SIZE];
	size_t  len;
};

struct lstp_irq_msg {
	uint16_t gpio_index;
	uint8_t  value; /* lstp_gpio_state_t */
};

K_MSGQ_DEFINE(lstp_req_queue, sizeof(struct lstp_task_msg), LSTP_MSG_QUEUE_SIZE, 4);
K_MSGQ_DEFINE(lstp_irq_queue, sizeof(struct lstp_irq_msg),  LSTP_IRQ_QUEUE_SIZE, 4);

/* -----------------------------------------------------------------------
 * Per-GPIO IRQ state (mirrors LstpTask::_irq_states in OpenSMA)
 * ----------------------------------------------------------------------- */
static uint8_t _irq_states[LSTP_GPIO_NUM]; /* lstp_gpio_irq_config_t values */

struct lstp_gpio_irq_bank {
	const char *dev_name;
	uint16_t base_index;
	const struct device *dev;
	struct gpio_callback cb;
	bool registered;
};

static struct lstp_gpio_irq_bank gpio_irq_banks[] = {
	{ .dev_name = "sgpiom_a_d", .base_index = 0U },
	{ .dev_name = "sgpiom_e_h", .base_index = 32U },
	{ .dev_name = "sgpiom_i_l", .base_index = 64U },
	{ .dev_name = "sgpiom_m_p", .base_index = 96U },
};

/* -----------------------------------------------------------------------
 * Forward declarations
 * ----------------------------------------------------------------------- */
static void lstp_task_thread_main(void *, void *, void *);
static void lstp_gpio_irq_handler(const struct device *port,
				  struct gpio_callback *cb,
				  gpio_port_pins_t pins);

K_THREAD_DEFINE(lstp_task_id, 8192,
		lstp_task_thread_main, NULL, NULL, NULL,
		K_PRIO_COOP(5), 0, 0);

/* -----------------------------------------------------------------------
 * GPIO device lookup
 * Maps a logical LSTP GPIO index (0..LSTP_GPIO_NUM-1) to a Zephyr GPIO
 * device + pin.  Currently one block: sgpiom_a_d, pins 0-31.
 * ----------------------------------------------------------------------- */
static const struct device *get_gpio_device(uint16_t index, uint8_t *pin)
{
	if (index >= LSTP_GPIO_NUM) {
		return NULL;
	}
	*pin = index % 32;
	int block = index / 32;

	switch (block) {
	case 0: return device_get_binding("sgpiom_a_d");
	case 1: return device_get_binding("sgpiom_e_h");
	case 2: return device_get_binding("sgpiom_i_l");
	case 3: return device_get_binding("sgpiom_m_p");
	default: return NULL;
	}
}

/* -----------------------------------------------------------------------
 * IRQ config → Zephyr gpio_flags_t
 * ----------------------------------------------------------------------- */
static gpio_flags_t irq_config_to_zephyr_flags(lstp_gpio_irq_config_t irq_type)
{
	switch (irq_type) {
	case LSTP_GPIO_IRQ_RISING:    return GPIO_INT_EDGE_RISING;
	case LSTP_GPIO_IRQ_FALLING:   return GPIO_INT_EDGE_FALLING;
	case LSTP_GPIO_IRQ_BOTH_EDGE: return GPIO_INT_EDGE_BOTH;
	case LSTP_GPIO_IRQ_HIGH:      return GPIO_INT_LEVEL_HIGH;
	case LSTP_GPIO_IRQ_LOW:       return GPIO_INT_LEVEL_LOW;
	case LSTP_GPIO_IRQ_DISABLED:
	default:                      return GPIO_INT_DISABLE;
	}
}

static void lstp_gpio_irq_handler(const struct device *port,
				  struct gpio_callback *cb,
				  gpio_port_pins_t pins)
{
	ARG_UNUSED(port);

	for (size_t bank_idx = 0; bank_idx < ARRAY_SIZE(gpio_irq_banks); bank_idx++) {
		struct lstp_gpio_irq_bank *bank = &gpio_irq_banks[bank_idx];

		if (&bank->cb != cb) {
			continue;
		}

		for (uint8_t pin = 0; pin < 32U; pin++) {
			if ((pins & BIT(pin)) == 0U) {
				continue;
			}

			uint16_t gpio_index = bank->base_index + pin;

			if (gpio_index >= LSTP_GPIO_NUM) {
				break;
			}

			lstp_task_submit_gpio_irq(gpio_index);
		}

		return;
	}
}

static void register_gpio_irq_callbacks(void)
{
	for (size_t bank_idx = 0; bank_idx < ARRAY_SIZE(gpio_irq_banks); bank_idx++) {
		struct lstp_gpio_irq_bank *bank = &gpio_irq_banks[bank_idx];
		int ret;

		if (bank->base_index >= LSTP_GPIO_NUM) {
			break;
		}

		if (bank->registered) {
			continue;
		}

		bank->dev = device_get_binding(bank->dev_name);
		if (!bank->dev || !device_is_ready(bank->dev)) {
			LOG_WRN("GPIO IRQ bank %s not ready", bank->dev_name);
			continue;
		}

		gpio_init_callback(&bank->cb, lstp_gpio_irq_handler, GENMASK(31, 0));
		ret = gpio_add_callback(bank->dev, &bank->cb);
		if (ret < 0) {
			LOG_ERR("gpio_add_callback failed for %s: %d", bank->dev_name, ret);
			continue;
		}

		bank->registered = true;
	}
}

/* -----------------------------------------------------------------------
 * process_gpio_req
 *
 * Matches OpenSMA LstpTask::process_gpio_req wire format exactly:
 *
 *   GetValue request per-GPIO:  {uint16_t gpio_index}          (2 bytes)
 *   GetValue response per-GPIO: {uint8_t value}                (1 byte)
 *
 *   SetValue request per-GPIO:  {uint16_t gpio_index, uint8_t value} (3 bytes)
 *   SetValue response payload:  empty (success) / empty (error via status)
 *
 *   GetIrqConfig request:  {uint16_t gpio_index}      (2 bytes)
 *   GetIrqConfig response: {uint8_t irq_type}          (1 byte)
 *
 *   SetIrqConfig request:  {uint16_t gpio_index, uint8_t irq_type} (3 bytes)
 *   SetIrqConfig response: empty
 *
 * The GPIO command is in hdr->cmd_status_code & LSTP_GPIO_CMD_MASK,
 * NOT in the payload (this was the primary bug in the original port).
 * ----------------------------------------------------------------------- */
static size_t process_gpio_req(struct lstp_hdr *req_hdr, uint8_t *req_payload,
			       size_t req_payload_len,
			       uint8_t *resp_buf, size_t max_resp_len)
{
	lstp_gpio_command_t cmd =
		(lstp_gpio_command_t)(req_hdr->cmd_status_code & LSTP_GPIO_CMD_MASK);

	/* resp_buf layout: [lstp_hdr][payload...] */
	struct lstp_hdr *resp_hdr = (struct lstp_hdr *)resp_buf;
	uint8_t *resp_payload = resp_buf + sizeof(struct lstp_hdr);
	size_t   resp_payload_len = 0;
	size_t   resp_payload_max = max_resp_len - sizeof(struct lstp_hdr);

	lstp_status_t status = LSTP_STATUS_SUCCESS;

	const size_t req_size = req_payload_len; /* payload bytes only */

	switch (cmd) {

	/* ------------------------------------------------------------------
	 * GetValue: iterate LstpGpioGetValueRequest entries (2 bytes each).
	 * Append one LstpGpioGetValueResponse (1 byte) per entry.
	 * ------------------------------------------------------------------ */
	case LSTP_GPIO_CMD_GET_VALUE: {
		size_t req_offset = 0;

		while (req_offset + sizeof(struct lstp_gpio_get_value_request) <= req_size) {
			const struct lstp_gpio_get_value_request *req =
				(const struct lstp_gpio_get_value_request *)
				(req_payload + req_offset);
			req_offset += sizeof(struct lstp_gpio_get_value_request);

			if (req->gpio_index >= LSTP_GPIO_NUM) {
				LOG_WRN("GetValue: gpio_index %u out of range", req->gpio_index);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

			if (resp_payload_len + sizeof(struct lstp_gpio_get_value_response)
			    > resp_payload_max) {
				LOG_WRN("GetValue: response buffer overflow");
				status = LSTP_STATUS_ERROR;
				goto done;
			}

			uint8_t pin;
			const struct device *dev = get_gpio_device(req->gpio_index, &pin);

			if (!dev || !device_is_ready(dev)) {
				LOG_WRN("GetValue: GPIO dev not ready, idx=%u", req->gpio_index);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

			int raw = gpio_pin_get_raw(dev, pin);

			if (raw < 0) {
				LOG_ERR("GetValue: gpio_pin_get_raw failed: %d", raw);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

			struct lstp_gpio_get_value_response *resp =
				(struct lstp_gpio_get_value_response *)
				(resp_payload + resp_payload_len);
			resp->value = (raw == 1)
				? (uint8_t)LSTP_GPIO_STATE_HIGH
				: (uint8_t)LSTP_GPIO_STATE_LOW;
			resp_payload_len += sizeof(struct lstp_gpio_get_value_response);
		}
		break;
	}

	/* ------------------------------------------------------------------
	 * SetValue: iterate LstpGpioSetValueRequest entries (3 bytes each).
	 * Write GPIO, then read back to verify. Response payload empty.
	 * ------------------------------------------------------------------ */
	case LSTP_GPIO_CMD_SET_VALUE: {
		size_t req_offset = 0;

		while (req_offset + sizeof(struct lstp_gpio_set_value_request) <= req_size) {
			const struct lstp_gpio_set_value_request *req =
				(const struct lstp_gpio_set_value_request *)
				(req_payload + req_offset);
			req_offset += sizeof(struct lstp_gpio_set_value_request);

			if (req->gpio_index >= LSTP_GPIO_NUM) {
				LOG_WRN("SetValue: gpio_index %u out of range", req->gpio_index);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

			if (req->value != LSTP_GPIO_STATE_LOW &&
			    req->value != LSTP_GPIO_STATE_HIGH) {
				LOG_WRN("SetValue: invalid value %u", req->value);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

			uint8_t pin;
			const struct device *dev = get_gpio_device(req->gpio_index, &pin);

			if (!dev || !device_is_ready(dev)) {
				LOG_WRN("SetValue: GPIO dev not ready, idx=%u", req->gpio_index);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

			int write_val = (req->value == LSTP_GPIO_STATE_HIGH) ? 1 : 0;
			int ret = gpio_pin_set_raw(dev, pin, write_val);

			if (ret < 0) {
				LOG_ERR("SetValue: gpio_pin_set_raw failed: %d", ret);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

			// It is not necessary to read back the value to verify the write for sgpio devices.
			/* Readback to verify (matches OpenSMA's push-pull verification). */
			// int read_val = gpio_pin_get_raw(dev, pin);
			//
			// if (read_val < 0 || read_val != write_val) {
			// 	LOG_ERR("SetValue: readback mismatch idx=%u wrote=%d got=%d",
			// 		req->gpio_index, write_val, read_val);
			// 	status = LSTP_STATUS_ERROR;
			// 	goto done;
			// }
		}
		/* resp_payload_len stays 0 — empty payload on success */
		break;
	}

	/* ------------------------------------------------------------------
	 * GetIrqConfig: single LstpGpioGetIrqConfigRequest (2 bytes).
	 * Returns LstpGpioGetIrqConfigResponse (1 byte) from stored state.
	 * ------------------------------------------------------------------ */
	case LSTP_GPIO_CMD_GET_IRQ_CONFIG: {
		if (req_size < sizeof(struct lstp_gpio_get_irq_config_request)) {
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		const struct lstp_gpio_get_irq_config_request *req =
			(const struct lstp_gpio_get_irq_config_request *)req_payload;

		if (req->gpio_index >= LSTP_GPIO_NUM) {
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		if (resp_payload_len + sizeof(struct lstp_gpio_get_irq_config_response)
		    > resp_payload_max) {
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		struct lstp_gpio_get_irq_config_response *resp =
			(struct lstp_gpio_get_irq_config_response *)resp_payload;
		resp->irq_type = _irq_states[req->gpio_index];
		resp_payload_len += sizeof(struct lstp_gpio_get_irq_config_response);
		break;
	}

	/* ------------------------------------------------------------------
	 * SetIrqConfig: single LstpGpioSetIrqConfigRequest (3 bytes).
	 * Configure the Zephyr GPIO interrupt, store state. Empty response.
	 * ------------------------------------------------------------------ */
	case LSTP_GPIO_CMD_SET_IRQ_CONFIG: {
		if (req_size < sizeof(struct lstp_gpio_set_irq_config_request)) {
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		const struct lstp_gpio_set_irq_config_request *req =
			(const struct lstp_gpio_set_irq_config_request *)req_payload;

		if (req->gpio_index >= LSTP_GPIO_NUM ||
		    req->irq_type > (uint8_t)LSTP_GPIO_IRQ_MAX) {
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		uint8_t pin;
		const struct device *dev = get_gpio_device(req->gpio_index, &pin);

		if (!dev || !device_is_ready(dev)) {
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		gpio_flags_t flags = irq_config_to_zephyr_flags(
			(lstp_gpio_irq_config_t)req->irq_type);
		int ret = gpio_pin_interrupt_configure(dev, pin, flags);

		if (ret < 0) {
			LOG_ERR("SetIrqConfig: gpio_pin_interrupt_configure failed: %d", ret);
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		_irq_states[req->gpio_index] = req->irq_type;
		/* resp_payload_len stays 0 */
		break;
	}

	/* ------------------------------------------------------------------
	 * IrqEvent: sent by firmware to host only, never expected as a request.
	 * ------------------------------------------------------------------ */
	case LSTP_GPIO_CMD_IRQ_EVENT:
	default:
		status = LSTP_STATUS_NOT_SUPPORTED;
		goto done;
	}

done:
	/* Build response header */
	memcpy(resp_hdr, req_hdr, sizeof(struct lstp_hdr));
	resp_hdr->cmd_status_code = (uint8_t)status | LSTP_RESPONSE_BIT;
	resp_hdr->len_lsb = resp_payload_len & LSB_MASK;
	resp_hdr->len_msb = (resp_payload_len >> BYTE1_SHIFT) & LSB_MASK;

	return sizeof(struct lstp_hdr) + resp_payload_len;
}

/* -----------------------------------------------------------------------
 * process_gpio_irq — drain the IRQ event queue, send IRQ event packets.
 * Matches OpenSMA LstpTask::process_gpio_irq.
 * ----------------------------------------------------------------------- */
static void process_gpio_irq(void)
{
	struct lstp_irq_msg irq_msg;

	while (k_msgq_get(&lstp_irq_queue, &irq_msg, K_NO_WAIT) == 0) {
		/*
		 * Build an IrqEvent packet (firmware → host unsolicited).
		 * Format: [lstp_hdr][lstp_gpio_irq_event_request]
		 * This mirrors LstpRouter::send_gpio_irq_event in OpenSMA.
		 */
		uint8_t irq_buf[sizeof(struct lstp_hdr) +
				sizeof(struct lstp_gpio_irq_event_request)];

		struct lstp_hdr *hdr = (struct lstp_hdr *)irq_buf;
		struct lstp_gpio_irq_event_request *evt =
			(struct lstp_gpio_irq_event_request *)
			(irq_buf + sizeof(struct lstp_hdr));

		const size_t payload_len = sizeof(struct lstp_gpio_irq_event_request);

		/* GPIO channel is channel 3 in this demo. */
		hdr->channel_id      = 3;
		hdr->cmd_status_code = (uint8_t)LSTP_GPIO_CMD_IRQ_EVENT;
		hdr->len_lsb         = payload_len & LSB_MASK;
		hdr->len_msb         = (payload_len >> BYTE1_SHIFT) & LSB_MASK;

		evt->gpio_index = irq_msg.gpio_index;
		evt->value      = irq_msg.value;

		int ret = lstp_usb_send(irq_buf, sizeof(irq_buf));

		if (ret < 0) {
			LOG_ERR("IRQ event USB send failed: %d", ret);
		}
	}
}

/* -----------------------------------------------------------------------
 * Task thread
 * ----------------------------------------------------------------------- */
static void lstp_task_thread_main(void *p1, void *p2, void *p3)
{
	struct lstp_task_msg msg;
	uint8_t resp_buf[LSTP_MSG_SIZE];

	LOG_INF("OBMF background task started");

	while (1) {
		if (k_msgq_get(&lstp_req_queue, &msg, K_FOREVER) == 0) {
			if (msg.len < sizeof(struct lstp_hdr)) {
				process_gpio_irq();
				continue;
			}

			struct lstp_hdr *hdr     = (struct lstp_hdr *)msg.buffer;
			uint8_t         *payload = msg.buffer + sizeof(struct lstp_hdr);
			size_t  payload_len      = hdr->len_lsb | (hdr->len_msb << BYTE1_SHIFT);

			LOG_DBG("Task dequeued msg for channel %d", hdr->channel_id);

			size_t resp_len = 0;

			if (hdr->channel_id == 1 /* SPI Channel */) {
				/*
				 * SPI transfers must run in thread context (blocking).
				 * Call lstp_spi_receive here, build header, compute
				 * total response length.
				 */
				struct lstp_hdr *resp_hdr = (struct lstp_hdr *)resp_buf;
				uint8_t *resp_payload = resp_buf + sizeof(struct lstp_hdr);
				size_t resp_payload_len = 0;
				bool send_response = true;

				lstp_status_t status = lstp_spi_receive(
					hdr->channel_id, hdr,
					payload, payload_len,
					resp_payload, &resp_payload_len,
					&send_response);
				if (send_response) {
					resp_hdr->channel_id      = hdr->channel_id;
					resp_hdr->cmd_status_code = (uint8_t)status | LSTP_RESPONSE_BIT;
					resp_hdr->len_lsb = resp_payload_len & LSB_MASK;
					resp_hdr->len_msb = (resp_payload_len >> BYTE1_SHIFT) & LSB_MASK;

					resp_len = sizeof(struct lstp_hdr) + resp_payload_len;
				}
			} else if (hdr->channel_id == 2 /* I2C Channel */) {
				/*
				 * I2C transfers must run in thread context (blocking).
				 * Call lstp_i2c_receive here, build header, compute
				 * total response length.
				 */
				struct lstp_hdr *resp_hdr = (struct lstp_hdr *)resp_buf;
				uint8_t *resp_payload = resp_buf + sizeof(struct lstp_hdr);
				size_t resp_payload_len = 0;

				lstp_status_t status = lstp_i2c_receive(
					hdr->channel_id, hdr,
					payload, payload_len,
					resp_payload, &resp_payload_len);

				resp_hdr->channel_id      = hdr->channel_id;
				resp_hdr->cmd_status_code = (uint8_t)status | LSTP_RESPONSE_BIT;
				resp_hdr->len_lsb = resp_payload_len & LSB_MASK;
				resp_hdr->len_msb = (resp_payload_len >> BYTE1_SHIFT) & LSB_MASK;

				resp_len = sizeof(struct lstp_hdr) + resp_payload_len;
			} else if (hdr->channel_id == 3 /* GPIO Channel */) {
				resp_len = process_gpio_req(
					hdr, payload, payload_len,
					resp_buf, sizeof(resp_buf));
			} else if (hdr->channel_id == 4 /* UART Channel */) {
				struct lstp_hdr *resp_hdr = (struct lstp_hdr *)resp_buf;
				uint8_t *resp_payload = resp_buf + sizeof(struct lstp_hdr);
				size_t resp_payload_len = 0;

				lstp_status_t status = lstp_uart_receive(
					hdr->channel_id, hdr,
					payload, payload_len,
					resp_payload, &resp_payload_len);

				resp_hdr->channel_id      = hdr->channel_id;
				resp_hdr->cmd_status_code = (uint8_t)status | LSTP_RESPONSE_BIT;
				resp_hdr->len_lsb = resp_payload_len & LSB_MASK;
				resp_hdr->len_msb = (resp_payload_len >> BYTE1_SHIFT) & LSB_MASK;

				resp_len = sizeof(struct lstp_hdr) + resp_payload_len;
			} else {
				LOG_WRN("Unhandled channel in task: %d", hdr->channel_id);
				struct lstp_hdr *resp_hdr = (struct lstp_hdr *)resp_buf;
				memcpy(resp_hdr, hdr, sizeof(struct lstp_hdr));
				resp_hdr->cmd_status_code =
					LSTP_STATUS_NOT_SUPPORTED | LSTP_RESPONSE_BIT;
				resp_hdr->len_lsb = 0;
				resp_hdr->len_msb = 0;
				resp_len = sizeof(struct lstp_hdr);
			}

			if (resp_len > 0) {
				int ret = lstp_usb_send(resp_buf, resp_len);
				if (ret < 0) {
					LOG_ERR("Task failed to send USB resp: %d", ret);
				}
			}

			/* Drain any pending IRQ events while we're awake */
			process_gpio_irq();
		}
	}
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

void lstp_task_init(void)
{
	memset(_irq_states, LSTP_GPIO_IRQ_DISABLED, sizeof(_irq_states));
	register_gpio_irq_callbacks();
	LOG_INF("OBMF background task initialized");
	/* Thread and Queue are statically allocated/initialized via macros */
}

int lstp_task_submit_req(uint8_t *buffer, size_t len)
{
	if (len > LSTP_MSG_SIZE) {
		return -EINVAL;
	}

	struct lstp_task_msg msg;
	msg.len = len;
	memcpy(msg.buffer, buffer, len);

	return k_msgq_put(&lstp_req_queue, &msg, K_NO_WAIT);
}

void lstp_task_submit_gpio_irq(uint16_t gpio_index)
{
	if (gpio_index >= LSTP_GPIO_NUM) {
		return;
	}

	uint8_t pin;
	const struct device *dev = get_gpio_device(gpio_index, &pin);

	if (!dev || !device_is_ready(dev)) {
		return;
	}

	int raw = gpio_pin_get_raw(dev, pin);
	if (raw < 0) {
		return;
	}

	struct lstp_irq_msg irq_msg = {
		.gpio_index = gpio_index,
		.value      = (raw == 1)
			? (uint8_t)LSTP_GPIO_STATE_HIGH
			: (uint8_t)LSTP_GPIO_STATE_LOW,
	};

	/* ISR-safe: use K_NO_WAIT, drop event if full (matches OpenSMA behaviour) */
	(void)k_msgq_put(&lstp_irq_queue, &irq_msg, K_NO_WAIT);

	{
		struct lstp_task_msg wake_msg = { 0 };

		(void)k_msgq_put(&lstp_req_queue, &wake_msg, K_NO_WAIT);
	}
}
