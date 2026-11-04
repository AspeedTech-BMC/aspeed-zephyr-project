/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <string.h>

#include "lstp/lstp_common.h"
#include "lstp/lstp_backend.h"
#include "lstp/lstp_channel.h"
#include "lstp_gpio.h"
#include "lstp/lstp_router.h"
#include "lstp/lstp_task.h"

LOG_MODULE_REGISTER(lstp_gpio, LOG_LEVEL_ERR);

#define LSTP_IRQ_QUEUE_SIZE     8
#define LSTP_GPIO_EVENT_RETRY   K_MSEC(5)

struct lstp_irq_msg {
	uint16_t gpio_index;
	uint8_t  value; /* lstp_gpio_state_t */
};

K_MSGQ_DEFINE(lstp_irq_queue, sizeof(struct lstp_irq_msg),  LSTP_IRQ_QUEUE_SIZE, 4);
static atomic_t lstp_gpio_irq_queue_drops;
static atomic_t lstp_gpio_event_drops;
static uint32_t lstp_gpio_reset_generation;

static const struct lstp_gpio_vwire_ops *vwire_ops;

static void event_retry_expiry(struct k_timer *timer)
{
	ARG_UNUSED(timer);
	lstp_task_kick();
}

/* Re-runs process_gpio_irq() once the USB event queue has drained a little. */
K_TIMER_DEFINE(lstp_gpio_event_retry_timer, event_retry_expiry, NULL);

static uint8_t _irq_states[LSTP_GPIO_NUM]; /* lstp_gpio_irq_config_t values */
/*
 * Level type of a one-shot IRQ that fired and is waiting for its event to be
 * delivered (DISABLED otherwise). If the event is dropped (queue full, no
 * host), the line is re-armed with it instead of staying silently disarmed.
 */
static uint8_t _irq_fired_level[LSTP_GPIO_NUM];
static bool _irq_resample_pending[LSTP_GPIO_NUM];

struct lstp_gpio_irq_bank {
	uint16_t base_index;
	const struct device *dev;
	struct gpio_callback cb;
	bool registered;
};

#define LSTP_GPIO_BANK(node_id, prop, idx) \
	{ \
		.base_index = (idx) * 32U, \
		.dev = DEVICE_DT_GET(DT_PHANDLE_BY_IDX(node_id, prop, idx)), \
	},

static struct lstp_gpio_irq_bank gpio_irq_banks[] = {
	DT_FOREACH_PROP_ELEM(LSTP_BACKEND_NODE, gpio_controllers, LSTP_GPIO_BANK)
};

/*
 * The BMC cannot change a pin's direction; it trusts what is reported here.
 * Only pins listed in gpio-output-lines may be driven (an allow-list: the
 * exported banks also hold pinmuxed, strap and reset pins). Every other
 * direct GPIO is reported as an input; gpio-input-lines marks the inputs
 * that are configured as such at init and can take an IRQ configuration.
 */
#define LSTP_GPIO_INPUT_LINE_COUNT DT_PROP_LEN_OR(LSTP_BACKEND_NODE, gpio_input_lines, 0)
#define LSTP_GPIO_OUTPUT_LINE_COUNT DT_PROP_LEN_OR(LSTP_BACKEND_NODE, gpio_output_lines, 0)

#define LSTP_GPIO_ASSERT_DIRECT_LINE(node_id, prop, idx) \
	BUILD_ASSERT(DT_PROP_BY_IDX(node_id, prop, idx) < LSTP_DIRECT_GPIO_NUM, \
		     "GPIO line must be below LSTP_DIRECT_GPIO_NUM");

#if DT_NODE_HAS_PROP(LSTP_BACKEND_NODE, gpio_input_lines)
DT_FOREACH_PROP_ELEM(LSTP_BACKEND_NODE, gpio_input_lines, LSTP_GPIO_ASSERT_DIRECT_LINE)
#endif
#if DT_NODE_HAS_PROP(LSTP_BACKEND_NODE, gpio_output_lines)
DT_FOREACH_PROP_ELEM(LSTP_BACKEND_NODE, gpio_output_lines, LSTP_GPIO_ASSERT_DIRECT_LINE)
#endif

static const uint16_t lstp_gpio_input_lines[] =
	DT_PROP_OR(LSTP_BACKEND_NODE, gpio_input_lines, {0});
static const uint16_t lstp_gpio_output_lines[] =
	DT_PROP_OR(LSTP_BACKEND_NODE, gpio_output_lines, {0});

static bool lstp_gpio_line_listed(const uint16_t *lines, size_t count, uint16_t gpio_index)
{
	for (size_t i = 0; i < count; i++) {
		if (lines[i] == gpio_index) {
			return true;
		}
	}
	return false;
}

static bool lstp_gpio_is_input_line(uint16_t gpio_index)
{
	return lstp_gpio_line_listed(lstp_gpio_input_lines, LSTP_GPIO_INPUT_LINE_COUNT,
				     gpio_index);
}

/* A pin listed as both is treated as an input: never driven (warned at init). */
static bool lstp_gpio_is_output_line(uint16_t gpio_index)
{
	return lstp_gpio_line_listed(lstp_gpio_output_lines, LSTP_GPIO_OUTPUT_LINE_COUNT,
				     gpio_index) &&
	       !lstp_gpio_is_input_line(gpio_index);
}

static void fill_gpio_config(uint16_t gpio_index, struct lstp_gpio_config *cfg)
{
	uint16_t vwire_index = UINT16_MAX;

	memset(cfg, 0, sizeof(*cfg));
	cfg->default_output = LSTP_GPIO_STATE_LOW;
	cfg->output_drive_config = LSTP_GPIO_OUTPUT_DRIVE_PUSH_PULL;
	cfg->output_persist_state = 0;
	cfg->bias_pull_config = LSTP_GPIO_BIAS_NO_PULL;

#if LSTP_VWIRE_GPIO_COUNT > 0
	if (gpio_index >= LSTP_VWIRE_GPIO_BASE &&
	    gpio_index < LSTP_VWIRE_GPIO_BASE + LSTP_VWIRE_GPIO_COUNT) {
		vwire_index = gpio_index - LSTP_VWIRE_GPIO_BASE;
	}
#endif

	switch (vwire_index) {
	case 0:
		strncpy((char *)cfg->gpio_name, "PLTRST_N", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_INPUT;
		break;
	case 1:
		strncpy((char *)cfg->gpio_name, "SLP_S3_N", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_INPUT;
		break;
	case 2:
		strncpy((char *)cfg->gpio_name, "SLP_S4_N", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_INPUT;
		break;
	case 3:
		strncpy((char *)cfg->gpio_name, "SLP_S5_N", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_INPUT;
		break;
	case 4:
		strncpy((char *)cfg->gpio_name, "HOST_RST_WARN", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_INPUT;
		break;
	case 5:
		strncpy((char *)cfg->gpio_name, "OOB_RST_WARN", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_INPUT;
		break;
	case 6:
		strncpy((char *)cfg->gpio_name, "SMI_N", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_OUTPUT;
		break;
	case 7:
		strncpy((char *)cfg->gpio_name, "SCI_N", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_OUTPUT;
		break;
	case 8:
		strncpy((char *)cfg->gpio_name, "HOST_RST_ACK", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_OUTPUT;
		break;
	case 9:
		strncpy((char *)cfg->gpio_name, "OOB_RST_ACK", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_OUTPUT;
		break;
	case 10:
		strncpy((char *)cfg->gpio_name, "RST_CPU_INIT", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_OUTPUT;
		break;
	case 11:
		strncpy((char *)cfg->gpio_name, "TARGET_BOOT_DONE", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_OUTPUT;
		break;
	case 12:
		strncpy((char *)cfg->gpio_name, "TARGET_BOOT_STS", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_OUTPUT;
		break;
	case 13:
		strncpy((char *)cfg->gpio_name, "PME_N", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_OUTPUT;
		break;
	case 14:
		strncpy((char *)cfg->gpio_name, "WAKE_N", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_OUTPUT;
		break;
	case 15:
		strncpy((char *)cfg->gpio_name, "RCIN_N", sizeof(cfg->gpio_name) - 1);
		cfg->direction = LSTP_GPIO_DIRECTION_OUTPUT;
		break;
	default:
		snprintk((char *)cfg->gpio_name, sizeof(cfg->gpio_name), "GPIO%u", gpio_index);
		cfg->direction = lstp_gpio_is_output_line(gpio_index) ?
				 LSTP_GPIO_DIRECTION_OUTPUT : LSTP_GPIO_DIRECTION_INPUT;
		break;
	}
}

#define LSTP_GPIO_CFG_HEAD_SIZE  sizeof(struct lstp_gpio_channel_config)
#define LSTP_GPIO_CFG_ENTRY_SIZE sizeof(struct lstp_gpio_config)

/* GPIO config is a byte-addressable blob: one header byte, then 48 bytes per pin.
 * Requests may start or end within an entry. */
static lstp_status_t read_gpio_config_helper(uint16_t req_offset, uint16_t req_length,
					     uint8_t *resp_buf, size_t max_resp_len,
					     size_t *resp_len)
{
	const size_t blob_size = LSTP_GPIO_CFG_HEAD_SIZE +
				 (size_t)LSTP_GPIO_NUM * LSTP_GPIO_CFG_ENTRY_SIZE;
	size_t length;
	size_t pos = req_offset;
	size_t out = 0;

	if ((size_t)req_offset > blob_size) {
		return LSTP_STATUS_ERROR;
	}

	length = (req_length == 0U) ? blob_size : (size_t)req_length;
	length = MIN(length, blob_size - req_offset);
	length = MIN(length, max_resp_len);

	while (pos < (size_t)req_offset + length) {
		const size_t remaining = (size_t)req_offset + length - pos;
		size_t chunk;

		if (pos < LSTP_GPIO_CFG_HEAD_SIZE) {
			struct lstp_gpio_channel_config head = {
				.channel_num_gpio = (uint8_t)LSTP_GPIO_NUM,
			};

			chunk = MIN(LSTP_GPIO_CFG_HEAD_SIZE - pos, remaining);
			memcpy(resp_buf + out, (const uint8_t *)&head + pos, chunk);
		} else {
			const size_t entry_pos = pos - LSTP_GPIO_CFG_HEAD_SIZE;
			const uint16_t pin = entry_pos / LSTP_GPIO_CFG_ENTRY_SIZE;
			const size_t in_entry = entry_pos % LSTP_GPIO_CFG_ENTRY_SIZE;
			struct lstp_gpio_config cfg;

			fill_gpio_config(pin, &cfg);
			chunk = MIN(LSTP_GPIO_CFG_ENTRY_SIZE - in_entry, remaining);
			memcpy(resp_buf + out, (const uint8_t *)&cfg + in_entry, chunk);
		}

		out += chunk;
		pos += chunk;
	}

	*resp_len = out;
	return LSTP_STATUS_SUCCESS;
}

static const struct device *get_gpio_device(uint16_t index, uint8_t *pin)
{
	if (index >= LSTP_GPIO_NUM) {
		return NULL;
	}
	if (index >= LSTP_DIRECT_GPIO_NUM) {
		return NULL;
	}

	*pin = index % 32U;
	return gpio_irq_banks[index / 32U].dev;
}


static gpio_flags_t irq_config_to_zephyr_flags(lstp_gpio_irq_config_t irq_type)
{
	switch (irq_type) {
	case LSTP_GPIO_IRQ_RISING:    return GPIO_INT_EDGE_RISING;
	case LSTP_GPIO_IRQ_FALLING:   return GPIO_INT_EDGE_FALLING;
	case LSTP_GPIO_IRQ_BOTH_EDGE: return GPIO_INT_EDGE_BOTH;
	/*
	 * Level types are one-shot, so they are armed as the matching edge; the
	 * caller fires at once if the level already holds. A real level IRQ
	 * would storm: the GPIO drivers unmask it again after the callback.
	 */
	case LSTP_GPIO_IRQ_HIGH:      return GPIO_INT_EDGE_RISING;
	case LSTP_GPIO_IRQ_LOW:       return GPIO_INT_EDGE_FALLING;
	case LSTP_GPIO_IRQ_DISABLED:
	default:                      return GPIO_INT_DISABLE;
	}
}

/* Vwire GPIOs 0-5 are host-to-AST1040 inputs; 6-15 are outputs. */
#define LSTP_VWIRE_GPIO_INPUT_COUNT 6U

static bool is_vwire_gpio(uint16_t index)
{
	return LSTP_VWIRE_GPIO_COUNT > 0 && index >= LSTP_VWIRE_GPIO_BASE &&
	       index < LSTP_VWIRE_GPIO_BASE + LSTP_VWIRE_GPIO_COUNT;
}

/* The device (or vwire owner) behind a line is there to take a request. */
static bool gpio_line_backend_ready(uint16_t gpio_index)
{
	uint8_t pin;
	const struct device *dev;

	if (is_vwire_gpio(gpio_index)) {
		return vwire_ops != NULL;
	}
	dev = get_gpio_device(gpio_index, &pin);
	return dev != NULL && device_is_ready(dev);
}

/*
 * A one-shot level IRQ whose event never reached the host: arm it again with
 * the same type (unless the host has reconfigured the line meanwhile), so the
 * line is not left silently disarmed. ISR- and thread-safe.
 */
static void rearm_fired_level(uint16_t gpio_index)
{
	unsigned int key = irq_lock();
	uint8_t type = _irq_fired_level[gpio_index];

	_irq_fired_level[gpio_index] = LSTP_GPIO_IRQ_DISABLED;
	if (type != LSTP_GPIO_IRQ_DISABLED &&
	    _irq_states[gpio_index] == LSTP_GPIO_IRQ_DISABLED) {
		uint8_t pin;
		const struct device *dev = (gpio_index < LSTP_DIRECT_GPIO_NUM) ?
					   get_gpio_device(gpio_index, &pin) : NULL;

		_irq_states[gpio_index] = type;
		if (dev != NULL) {
			(void)gpio_pin_interrupt_configure(dev, pin,
				irq_config_to_zephyr_flags((lstp_gpio_irq_config_t)type));
			_irq_resample_pending[gpio_index] = true;
		}
	}
	irq_unlock(key);
}

static void queue_irq_event(uint16_t gpio_index, uint8_t value)
{
	struct lstp_irq_msg irq_msg = {
		.gpio_index = gpio_index,
		.value      = value ? (uint8_t)LSTP_GPIO_STATE_HIGH
				    : (uint8_t)LSTP_GPIO_STATE_LOW,
	};

	/* ISR-safe: use K_NO_WAIT; a dropped one-shot level is re-armed. */
	if (k_msgq_put(&lstp_irq_queue, &irq_msg, K_NO_WAIT) != 0) {
		atomic_inc(&lstp_gpio_irq_queue_drops);
		rearm_fired_level(gpio_index);
	}

	lstp_task_kick();
}


/* Only lines the channel reports as inputs can take an IRQ configuration. */
static bool lstp_gpio_is_irq_capable(uint16_t index)
{
	if (is_vwire_gpio(index)) {
		return index - LSTP_VWIRE_GPIO_BASE < LSTP_VWIRE_GPIO_INPUT_COUNT;
	}

	return lstp_gpio_is_input_line(index);
}

/*
 * Vwire changes arrive as edges from the eSPI bridge, so the IRQ type is
 * applied here. Level types are one-shot, as for direct lines; the eSPI
 * callback and the task thread both get here, so check-and-clear is atomic.
 */
static bool vwire_irq_fires(uint16_t index, uint8_t value)
{
	unsigned int key = irq_lock();
	uint8_t state = _irq_states[index];
	bool fires;

	switch (state) {
	case LSTP_GPIO_IRQ_RISING:
		fires = value != 0U;
		break;
	case LSTP_GPIO_IRQ_FALLING:
		fires = value == 0U;
		break;
	case LSTP_GPIO_IRQ_BOTH_EDGE:
		fires = true;
		break;
	case LSTP_GPIO_IRQ_HIGH:
	case LSTP_GPIO_IRQ_LOW:
		fires = (value != 0U) == (state == LSTP_GPIO_IRQ_HIGH);
		if (fires) {
			_irq_states[index] = LSTP_GPIO_IRQ_DISABLED;
			_irq_fired_level[index] = state;
		}
		break;
	default:
		fires = false;
		break;
	}

	irq_unlock(key);
	return fires;
}

static void vwire_set_irq_config(uint16_t index, uint8_t irq_type)
{
	unsigned int key = irq_lock();

	_irq_states[index] = irq_type;
	_irq_fired_level[index] = LSTP_GPIO_IRQ_DISABLED;
	_irq_resample_pending[index] = false;
	irq_unlock(key);

	/* A level that already holds fires at once, as a real level IRQ would. */
	if ((irq_type == LSTP_GPIO_IRQ_HIGH || irq_type == LSTP_GPIO_IRQ_LOW) &&
	    vwire_ops != NULL) {
		int ret = vwire_ops->get_pin(index - LSTP_VWIRE_GPIO_BASE);
		uint8_t value = (ret > 0) ? 1U : 0U;

		if (ret >= 0 && vwire_irq_fires(index, value)) {
			queue_irq_event(index, value);
		}
	}
}

/*
 * Report the level the IRQ type implies: a short pulse may already be gone
 * when the callback runs, so reading the pin would report a rising edge as 0.
 * Only BOTH_EDGE has to sample the pin to tell the direction.
 */
static void queue_gpio_irq(uint16_t gpio_index, uint8_t irq_type)
{
	if (gpio_index >= LSTP_GPIO_NUM) {
		return;
	}

	switch (irq_type) {
	case LSTP_GPIO_IRQ_RISING:
	case LSTP_GPIO_IRQ_HIGH:
		queue_irq_event(gpio_index, 1U);
		return;
	case LSTP_GPIO_IRQ_FALLING:
	case LSTP_GPIO_IRQ_LOW:
		queue_irq_event(gpio_index, 0U);
		return;
	default:
		break;
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

	queue_irq_event(gpio_index, raw == 1);
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

			/* A late edge from a pin the host has just disabled. */
			if (_irq_states[gpio_index] == LSTP_GPIO_IRQ_DISABLED) {
				continue;
			}

			uint8_t irq_type = _irq_states[gpio_index];

			/* Level IRQs are one-shot; the host re-arms with SetIrqConfig. */
			if (irq_type == LSTP_GPIO_IRQ_HIGH || irq_type == LSTP_GPIO_IRQ_LOW) {
				(void)gpio_pin_interrupt_configure(bank->dev, pin,
								   GPIO_INT_DISABLE);
				_irq_states[gpio_index] = LSTP_GPIO_IRQ_DISABLED;
				_irq_fired_level[gpio_index] = irq_type;
			}

			queue_gpio_irq(gpio_index, irq_type);
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

		if (!device_is_ready(bank->dev)) {
			LOG_WRN("GPIO IRQ bank %s not ready", bank->dev->name);
			continue;
		}

		gpio_init_callback(&bank->cb, lstp_gpio_irq_handler, GENMASK(31, 0));
		ret = gpio_add_callback(bank->dev, &bank->cb);
		if (ret < 0) {
			LOG_ERR("gpio_add_callback failed for %s: %d", bank->dev->name, ret);
			continue;
		}

		bank->registered = true;
	}
}

/* GPIO commands are encoded in hdr->cmd_status_code, not in the payload. */
static lstp_status_t lstp_gpio_receive(uint8_t channel_id, struct lstp_hdr *req_hdr,
				       uint8_t *req_payload, size_t req_payload_len,
				       uint8_t *resp_payload, size_t *resp_payload_len_out,
				       bool *send_response)
{
	lstp_gpio_command_t cmd =
		(lstp_gpio_command_t)(req_hdr->cmd_status_code & LSTP_GPIO_CMD_MASK);

	size_t   resp_payload_len = 0;
	size_t   resp_payload_max = LSTP_MAX_PAYLOAD_SIZE;

	ARG_UNUSED(channel_id);
	ARG_UNUSED(send_response);

	lstp_status_t status = LSTP_STATUS_SUCCESS;

	const size_t req_size = req_payload_len; /* payload bytes only */

	switch (cmd) {

	case LSTP_GPIO_CMD_GET_VALUE: {
		size_t req_offset = 0;

		while (req_offset + sizeof(struct lstp_gpio_get_value_request) <= req_size) {
			const struct lstp_gpio_get_value_request *req =
				(const struct lstp_gpio_get_value_request *)
				(req_payload + req_offset);
			uint16_t gpio_index = sys_le16_to_cpu(req->gpio_index);

			req_offset += sizeof(struct lstp_gpio_get_value_request);

			if (gpio_index >= LSTP_GPIO_NUM) {
				LOG_WRN("GetValue: gpio_index %u out of range", gpio_index);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

			if (resp_payload_len + sizeof(struct lstp_gpio_get_value_response)
			    > resp_payload_max) {
				LOG_WRN("GetValue: response buffer overflow");
				status = LSTP_STATUS_ERROR;
				goto done;
			}

#if LSTP_VWIRE_GPIO_COUNT > 0
			if (is_vwire_gpio(gpio_index)) {
				if (vwire_ops == NULL) {
					status = LSTP_STATUS_ERROR;
					goto done;
				}

				int val = vwire_ops->get_pin(
					gpio_index - LSTP_VWIRE_GPIO_BASE);
				if (val < 0) {
					status = LSTP_STATUS_ERROR;
					goto done;
				}
				struct lstp_gpio_get_value_response *resp =
					(struct lstp_gpio_get_value_response *)
					(resp_payload + resp_payload_len);
				resp->value = (val == 1)
					? (uint8_t)LSTP_GPIO_STATE_HIGH
					: (uint8_t)LSTP_GPIO_STATE_LOW;
				resp_payload_len += sizeof(struct lstp_gpio_get_value_response);
				continue;
			}
#endif

			uint8_t pin;
			const struct device *dev = get_gpio_device(gpio_index, &pin);

			if (!dev || !device_is_ready(dev)) {
				LOG_WRN("GetValue: GPIO dev not ready, idx=%u", gpio_index);
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

	case LSTP_GPIO_CMD_SET_VALUE: {
		size_t req_offset = 0;

		/*
		 * Validate the whole batch before driving anything, so a bad entry
		 * cannot leave earlier pins changed behind an ERROR status.
		 */
		for (size_t off = 0; off + sizeof(struct lstp_gpio_set_value_request) <= req_size;
		     off += sizeof(struct lstp_gpio_set_value_request)) {
			const struct lstp_gpio_set_value_request *chk =
				(const struct lstp_gpio_set_value_request *)(req_payload + off);
			uint16_t gpio_index = sys_le16_to_cpu(chk->gpio_index);

			if (gpio_index >= LSTP_GPIO_NUM ||
			    (chk->value != LSTP_GPIO_STATE_LOW &&
			     chk->value != LSTP_GPIO_STATE_HIGH)) {
				LOG_WRN("SetValue: bad entry idx=%u value=%u",
					gpio_index, chk->value);
				status = LSTP_STATUS_ERROR;
				goto done;
			}
			if (is_vwire_gpio(gpio_index) ?
			    (gpio_index - LSTP_VWIRE_GPIO_BASE < LSTP_VWIRE_GPIO_INPUT_COUNT) :
			    !lstp_gpio_is_output_line(gpio_index)) {
				status = LSTP_STATUS_NOT_SUPPORTED;
				goto done;
			}
			if (!gpio_line_backend_ready(gpio_index)) {
				status = LSTP_STATUS_ERROR;
				goto done;
			}
		}

		while (req_offset + sizeof(struct lstp_gpio_set_value_request) <= req_size) {
			const struct lstp_gpio_set_value_request *req =
				(const struct lstp_gpio_set_value_request *)
				(req_payload + req_offset);
			uint16_t gpio_index = sys_le16_to_cpu(req->gpio_index);

			req_offset += sizeof(struct lstp_gpio_set_value_request);

			if (gpio_index >= LSTP_GPIO_NUM) {
				LOG_WRN("SetValue: gpio_index %u out of range", gpio_index);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

			if (req->value != LSTP_GPIO_STATE_LOW &&
			    req->value != LSTP_GPIO_STATE_HIGH) {
				LOG_WRN("SetValue: invalid value %u", req->value);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

#if LSTP_VWIRE_GPIO_COUNT > 0
			if (is_vwire_gpio(gpio_index)) {
				if (vwire_ops == NULL) {
					status = LSTP_STATUS_ERROR;
					goto done;
				}

				if (!lstp_router_host_active()) {
					status = LSTP_STATUS_ERROR;
					goto done;
				}
				if (vwire_ops->set_pin(gpio_index - LSTP_VWIRE_GPIO_BASE,
						       req->value) < 0) {
					status = LSTP_STATUS_NOT_SUPPORTED;
					goto done;
				}
				continue;
			}
#endif

			/* Only allow-listed pins may be driven. */
			if (!lstp_gpio_is_output_line(gpio_index)) {
				status = LSTP_STATUS_NOT_SUPPORTED;
				goto done;
			}

			uint8_t pin;
			const struct device *dev = get_gpio_device(gpio_index, &pin);

			if (!dev || !device_is_ready(dev)) {
				LOG_WRN("SetValue: GPIO dev not ready, idx=%u", gpio_index);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

			gpio_flags_t out_flags = (req->value == LSTP_GPIO_STATE_HIGH)
						 ? GPIO_OUTPUT_HIGH : GPIO_OUTPUT_LOW;
			/* Serialize the write with the host reset ISR. */
			unsigned int key = irq_lock();

			if (!lstp_router_host_active()) {
				irq_unlock(key);
				status = LSTP_STATUS_ERROR;
				goto done;
			}
			int ret = gpio_pin_configure(dev, pin, out_flags);

			irq_unlock(key);
			if (ret < 0) {
				LOG_ERR("SetValue: gpio_pin_configure failed: %d", ret);
				status = LSTP_STATUS_ERROR;
				goto done;
			}

		}
		break;
	}

	case LSTP_GPIO_CMD_GET_IRQ_CONFIG: {
		if (req_size < sizeof(struct lstp_gpio_get_irq_config_request)) {
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		const struct lstp_gpio_get_irq_config_request *req =
			(const struct lstp_gpio_get_irq_config_request *)req_payload;
		uint16_t gpio_index = sys_le16_to_cpu(req->gpio_index);

		if (gpio_index >= LSTP_GPIO_NUM) {
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
		resp->irq_type = _irq_states[gpio_index];
		resp_payload_len += sizeof(struct lstp_gpio_get_irq_config_response);
		break;
	}

	case LSTP_GPIO_CMD_SET_IRQ_CONFIG: {
		if (req_size < sizeof(struct lstp_gpio_set_irq_config_request)) {
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		const struct lstp_gpio_set_irq_config_request *req =
			(const struct lstp_gpio_set_irq_config_request *)req_payload;
		uint16_t gpio_index = sys_le16_to_cpu(req->gpio_index);

		if (gpio_index >= LSTP_GPIO_NUM ||
		    req->irq_type > (uint8_t)LSTP_GPIO_IRQ_MAX) {
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		/*
		 * Only IRQ-capable inputs are touched at all. Disabling another pin is
		 * a no-op success: its interrupt (strap, reset, button) belongs to
		 * other code, and the host only means "no events for this line".
		 */
		if (!lstp_gpio_is_irq_capable(gpio_index)) {
			status = (req->irq_type == LSTP_GPIO_IRQ_DISABLED) ?
				 LSTP_STATUS_SUCCESS : LSTP_STATUS_NOT_SUPPORTED;
			goto done;
		}

		if (is_vwire_gpio(gpio_index)) {
			vwire_set_irq_config(gpio_index, req->irq_type);
			break;
		}

		uint8_t pin;
		const struct device *dev = get_gpio_device(gpio_index, &pin);

		if (!dev || !device_is_ready(dev)) {
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		gpio_flags_t flags = irq_config_to_zephyr_flags(
			(lstp_gpio_irq_config_t)req->irq_type);
		bool level = req->irq_type == LSTP_GPIO_IRQ_HIGH ||
			     req->irq_type == LSTP_GPIO_IRQ_LOW;

		/*
		 * State, arming and the initial-level check form one step: an old
		 * edge in between must not see half of it.
		 */
		unsigned int key = irq_lock();
		uint8_t prev_irq_type = _irq_states[gpio_index];

		_irq_states[gpio_index] = req->irq_type;
		if (!lstp_router_host_active()) {
			_irq_states[gpio_index] = prev_irq_type;
			irq_unlock(key);
			status = LSTP_STATUS_ERROR;
			goto done;
		}
		int ret = gpio_pin_interrupt_configure(dev, pin, flags);

		if (ret < 0) {
			_irq_states[gpio_index] = prev_irq_type;
			irq_unlock(key);
			LOG_ERR("SetIrqConfig: gpio_pin_interrupt_configure failed: %d", ret);
			status = LSTP_STATUS_ERROR;
			goto done;
		}

		_irq_fired_level[gpio_index] = LSTP_GPIO_IRQ_DISABLED;
		_irq_resample_pending[gpio_index] = false;

		/* A level that already holds fires at once, as a real level IRQ would. */
		if (level && gpio_pin_get_raw(dev, pin) ==
			     (req->irq_type == LSTP_GPIO_IRQ_HIGH ? 1 : 0)) {
			(void)gpio_pin_interrupt_configure(dev, pin, GPIO_INT_DISABLE);
			_irq_states[gpio_index] = LSTP_GPIO_IRQ_DISABLED;
			_irq_fired_level[gpio_index] = req->irq_type;
			irq_unlock(key);
			queue_gpio_irq(gpio_index, req->irq_type);
			break;
		}
		irq_unlock(key);
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
	*resp_payload_len_out = resp_payload_len;
	return status;
}

static int send_gpio_irq_event(uint16_t gpio_index, uint8_t value)
{
	struct lstp_gpio_irq_event_request req = {
		.gpio_index = sys_cpu_to_le16(gpio_index),
		.value = value,
	};

	if (!lstp_router_host_active()) {
		return -EHOSTDOWN;
	}

	/* The GPIO channel is the only one carrying unsolicited IRQ events. */
	return lstp_router_send_event(LSTP_GPIO_CHANNEL_ID, LSTP_GPIO_CMD_IRQ_EVENT,
				      &req, sizeof(req));
}

static void process_gpio_irq(void)
{
	struct lstp_irq_msg irq_msg;

	while (true) {
		unsigned int key = irq_lock();
		uint32_t generation = lstp_gpio_reset_generation;

		if (k_msgq_peek(&lstp_irq_queue, &irq_msg) != 0) {
			irq_unlock(key);
			break;
		}
		irq_unlock(key);

		int ret = send_gpio_irq_event(irq_msg.gpio_index, irq_msg.value);

		key = irq_lock();
		/* Reset purged the peeked event; leave the new head for the next pass. */
		if (generation != lstp_gpio_reset_generation) {
			irq_unlock(key);
			continue;
		}
		if (ret == -ENOSPC) {
			irq_unlock(key);
			/* USB event queue full: keep the event and retry shortly. */
			k_timer_start(&lstp_gpio_event_retry_timer, LSTP_GPIO_EVENT_RETRY,
				      K_NO_WAIT);
			return;
		}
		if (k_msgq_get(&lstp_irq_queue, &irq_msg, K_NO_WAIT) != 0) {
			irq_unlock(key);
			continue;
		}
		if (ret == 0) {
			_irq_fired_level[irq_msg.gpio_index] = LSTP_GPIO_IRQ_DISABLED;
		} else {
			rearm_fired_level(irq_msg.gpio_index);
		}
		irq_unlock(key);
		if (ret == -EHOSTDOWN || ret == -ENODEV) {
			/* Pre-enumeration edges can be dropped; the host reads current state on attach. */
			LOG_DBG("Dropped GPIO IRQ event for pin %u, no host (%d)",
				irq_msg.gpio_index, ret);
		} else if (ret < 0) {
			atomic_inc(&lstp_gpio_event_drops);
			LOG_ERR("Failed to send GPIO IRQ event for pin %u: %d",
				irq_msg.gpio_index, ret);
		}
	}

	/* Sample each re-armed line once; a later drop schedules another pass. */
	for (uint16_t idx = 0; idx < LSTP_DIRECT_GPIO_NUM; idx++) {
		unsigned int key = irq_lock();
		uint8_t type = _irq_states[idx];
		bool pending = _irq_resample_pending[idx];

		_irq_resample_pending[idx] = false;
		if (pending && (type == LSTP_GPIO_IRQ_HIGH || type == LSTP_GPIO_IRQ_LOW)) {
			uint8_t pin;
			const struct device *dev = get_gpio_device(idx, &pin);

			if (dev != NULL && gpio_pin_get_raw(dev, pin) ==
					   (type == LSTP_GPIO_IRQ_HIGH ? 1 : 0)) {
				(void)gpio_pin_interrupt_configure(dev, pin, GPIO_INT_DISABLE);
				_irq_states[idx] = LSTP_GPIO_IRQ_DISABLED;
				_irq_fired_level[idx] = type;
				irq_unlock(key);
				queue_gpio_irq(idx, type);
				continue;
			}
		}
		irq_unlock(key);
	}
}

/*
 * ISR context. IRQ arming and queued events belong to the host that went
 * away: disarm every line it armed and drop its pending events, so the next
 * host neither inherits its configuration nor gets its stale events.
 */
static void lstp_gpio_host_reset(void)
{
	unsigned int key = irq_lock();

	for (uint16_t idx = 0; idx < LSTP_GPIO_NUM; idx++) {
		if (_irq_states[idx] != LSTP_GPIO_IRQ_DISABLED && idx < LSTP_DIRECT_GPIO_NUM) {
			uint8_t pin;
			const struct device *dev = get_gpio_device(idx, &pin);

			if (dev != NULL) {
				(void)gpio_pin_interrupt_configure(dev, pin, GPIO_INT_DISABLE);
			}
		}
		_irq_states[idx] = LSTP_GPIO_IRQ_DISABLED;
		_irq_fired_level[idx] = LSTP_GPIO_IRQ_DISABLED;
		_irq_resample_pending[idx] = false;
		if (lstp_gpio_is_output_line(idx)) {
			uint8_t pin;
			const struct device *dev = get_gpio_device(idx, &pin);

			if (dev != NULL && device_is_ready(dev)) {
				(void)gpio_pin_set_raw(dev, pin, 0);
			}
		}
	}
	lstp_gpio_reset_generation++;
	k_msgq_purge(&lstp_irq_queue);
	irq_unlock(key);
}

static lstp_status_t lstp_gpio_read_config(const struct lstp_channel_config_read_request *req,
					   uint8_t *buf, size_t cap, size_t *len)
{
	return read_gpio_config_helper(req->offset, req->length, buf, cap, len);
}

static int lstp_gpio_init(void)
{
	memset(_irq_states, LSTP_GPIO_IRQ_DISABLED, sizeof(_irq_states));
	memset(_irq_fired_level, LSTP_GPIO_IRQ_DISABLED, sizeof(_irq_fired_level));
	register_gpio_irq_callbacks();

	for (size_t i = 0; i < LSTP_GPIO_OUTPUT_LINE_COUNT; i++) {
		if (lstp_gpio_is_input_line(lstp_gpio_output_lines[i])) {
			LOG_ERR("GPIO%u is in both gpio-input-lines and gpio-output-lines; "
				"treated as input", lstp_gpio_output_lines[i]);
		}
	}

	/* Allow-listed outputs start driven LOW, matching what read_config reports. */
	for (size_t i = 0; i < LSTP_GPIO_OUTPUT_LINE_COUNT; i++) {
		uint8_t pin;
		uint16_t idx = lstp_gpio_output_lines[i];
		const struct device *dev;

		if (!lstp_gpio_is_output_line(idx)) {
			continue;
		}
		dev = get_gpio_device(idx, &pin);
		if (dev == NULL || !device_is_ready(dev) ||
		    gpio_pin_configure(dev, pin, GPIO_OUTPUT_LOW) < 0) {
			LOG_ERR("Cannot make GPIO%u an output", idx);
		}
	}

	/* Declared inputs must not be left driving whatever they last output. */
	for (size_t i = 0; i < LSTP_GPIO_INPUT_LINE_COUNT; i++) {
		uint8_t pin;
		const struct device *dev = get_gpio_device(lstp_gpio_input_lines[i], &pin);

		if (dev == NULL || !device_is_ready(dev) ||
		    gpio_pin_configure(dev, pin, GPIO_INPUT) < 0) {
			LOG_ERR("Cannot make GPIO%u an input", lstp_gpio_input_lines[i]);
		}
	}

	return 0;
}

LSTP_CHANNEL_DEFINE(lstp_gpio_channel,
	.id = LSTP_GPIO_CHANNEL_ID,
	.type = LSTP_CHANNEL_TYPE_GPIO,
	.name = "GPIO",
	.init = lstp_gpio_init,
	.read_config = lstp_gpio_read_config,
	.receive = lstp_gpio_receive,
	.poll = process_gpio_irq,
	.host_reset = lstp_gpio_host_reset,
);

void lstp_gpio_set_vwire_ops(const struct lstp_gpio_vwire_ops *ops)
{
	vwire_ops = ops;
}

void lstp_gpio_vwire_event(uint16_t pin, uint8_t value)
{
	uint16_t index = LSTP_VWIRE_GPIO_BASE + pin;

	if (pin >= LSTP_VWIRE_GPIO_COUNT || !vwire_irq_fires(index, value)) {
		return;
	}

	queue_irq_event(index, value);
}

uint32_t lstp_gpio_get_irq_drops(void)
{
	return atomic_get(&lstp_gpio_irq_queue_drops);
}

uint32_t lstp_gpio_get_event_drops(void)
{
	return atomic_get(&lstp_gpio_event_drops);
}
