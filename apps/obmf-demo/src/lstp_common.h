/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */
#ifndef LSTP_COMMON_H
#define LSTP_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************
 * Bit manipulation constants
 *****************************************************/
#define BYTE1_SHIFT 8
#define BYTE2_SHIFT 16
#define BYTE3_SHIFT 24
#define LSB_MASK    0xff
#define MSB_MASK    0xff00

/*****************************************************
 * LSTP General
 *****************************************************/
#define LSTP_VERSION      1
#define LSTP_MAX_CHANNELS 255
#define LSTP_NUM_CHANNELS 5

typedef enum {
	LSTP_CHANNEL_TYPE_MANAGEMENT = 0,
	LSTP_CHANNEL_TYPE_SPI        = 1,
	LSTP_CHANNEL_TYPE_GPIO       = 2,
	LSTP_CHANNEL_TYPE_I2C        = 3,
	LSTP_CHANNEL_TYPE_UART       = 4,
	LSTP_CHANNEL_TYPE_IPMI       = 5
} lstp_channel_type_t;

typedef enum {
	LSTP_STATUS_SUCCESS       = 0x00,
	LSTP_STATUS_ERROR         = 0x01,
	LSTP_STATUS_TIMEOUT       = 0x02,
	LSTP_STATUS_BUSY          = 0x03,
	LSTP_STATUS_NAK           = 0x04,
	LSTP_STATUS_ARB_LOST      = 0x05,
	LSTP_STATUS_NOT_SUPPORTED = 0x06,
	LSTP_STATUS_IRQ_INTERRUPT = 0xFF,
} lstp_status_t;

#define LSTP_RESPONSE_BIT 0x80

struct lstp_hdr {
	uint8_t channel_id;
	uint8_t cmd_status_code;  /* Bit 7 is reserved for request (=0) and response (=1) flag */
	uint8_t len_lsb;
	uint8_t len_msb;
} __attribute__((packed));

#define LSTP_MSG_SIZE         512
#define LSTP_MAX_PAYLOAD_SIZE (LSTP_MSG_SIZE - sizeof(struct lstp_hdr))

struct lstp_channel_config_write_request {
	uint8_t  channel_id;
	uint16_t offset;
} __attribute__((packed));

struct lstp_channel_config_read_request {
	uint8_t  channel_id;
	uint16_t offset;
	uint16_t length;
} __attribute__((packed));

struct lstp_channel_config_blob {
	uint8_t channel_type;
	uint8_t channel_enabled;
	uint8_t channel_name[16];
	/* Followed by channel-specific config data */
} __attribute__((packed));

/*****************************************************
 * LSTP Management Channel (Ch0)
 *****************************************************/
typedef enum {
	LSTP_MGMT_CMD_READ_CONFIG  = 0x08,
	LSTP_MGMT_CMD_WRITE_CONFIG = 0x09,
	LSTP_MGMT_CMD_LOCK         = 0x0A,
} lstp_management_cmd_t;

struct lstp_management_config {
	uint8_t lstp_version;
	uint8_t num_channels;
} __attribute__((packed));

/*****************************************************
 * LSTP GPIO Channel
 *****************************************************/

/**
 * Number of logical GPIO indices exposed over LSTP.
 * Currently maps to one SGPIO block (sgpiom_a_d, pins 0-31).
 */
#define LSTP_GPIO_NUM 128

/**
 * Mask to strip the response/request bit (bit 7) from cmd_status_code
 * before interpreting it as a GPIO command.
 * Matches OpenSMA's LstpGpioCmdMask = 0x7F.
 */
#define LSTP_GPIO_CMD_MASK 0x7F

#define LSTP_GPIO_NAME_MAX_LEN    32U
/** Maximum GPIO entries per LSTP packet (capacity guard). */
#define LSTP_MAX_GPIOS_PER_PACKET 10U

typedef enum {
	LSTP_GPIO_DIRECTION_OUTPUT = 0,
	LSTP_GPIO_DIRECTION_INPUT  = 1,
} lstp_gpio_direction_t;

typedef enum {
	LSTP_GPIO_OUTPUT_DRIVE_PUSH_PULL   = 0,
	LSTP_GPIO_OUTPUT_DRIVE_OPEN_DRAIN  = 1,
	LSTP_GPIO_OUTPUT_DRIVE_OPEN_SOURCE = 2,
} lstp_gpio_output_drive_config_t;

typedef enum {
	LSTP_GPIO_BIAS_NO_PULL   = 0,
	LSTP_GPIO_BIAS_PULL_UP   = 1,
	LSTP_GPIO_BIAS_PULL_DOWN = 2,
} lstp_gpio_bias_pull_config_t;

typedef enum {
	LSTP_GPIO_CMD_GET_VALUE      = 0x00,
	LSTP_GPIO_CMD_SET_VALUE      = 0x01,
	LSTP_GPIO_CMD_GET_IRQ_CONFIG = 0x02,
	LSTP_GPIO_CMD_SET_IRQ_CONFIG = 0x03,
	LSTP_GPIO_CMD_IRQ_EVENT      = 0x04,
} lstp_gpio_command_t;

typedef enum {
	LSTP_GPIO_STATE_LOW  = 0,
	LSTP_GPIO_STATE_HIGH = 1,
} lstp_gpio_state_t;

typedef enum {
	LSTP_GPIO_IRQ_DISABLED  = 0,
	LSTP_GPIO_IRQ_RISING    = 1,
	LSTP_GPIO_IRQ_FALLING   = 2,
	LSTP_GPIO_IRQ_BOTH_EDGE = 3,
	LSTP_GPIO_IRQ_HIGH      = 4,
	LSTP_GPIO_IRQ_LOW       = 5,
	LSTP_GPIO_IRQ_MAX       = LSTP_GPIO_IRQ_LOW,
} lstp_gpio_irq_config_t;

/**
 * Appended after lstp_channel_config_blob in a ReadConfig response
 * for the GPIO channel, matching OpenSMA's LstpGpioChannelConfig.
 */
struct lstp_gpio_channel_config {
	uint8_t channel_num_gpio;
	/* Optionally followed by channel_num_gpio * lstp_gpio_config entries */
} __attribute__((packed));

struct lstp_gpio_config {
	uint8_t  gpio_name[LSTP_GPIO_NAME_MAX_LEN];
	uint8_t  direction;             /* lstp_gpio_direction_t */
	uint8_t  default_output;        /* lstp_gpio_state_t */
	uint8_t  output_drive_config;   /* lstp_gpio_output_drive_config_t */
	uint8_t  output_persist_state;  /* bool */
	uint8_t  bias_pull_config;      /* lstp_gpio_bias_pull_config_t */
	uint16_t bias_pull_strength;    /* 16 ohm increments */
	uint16_t output_drive_strength; /* mA */
	uint16_t slew_rate;             /* 100 ps increments */
	uint16_t input_debounce_time;   /* us */
	uint8_t  rsvd_0;
	uint8_t  rsvd_1;
	uint8_t  rsvd_2;
} __attribute__((packed));

_Static_assert(sizeof(struct lstp_gpio_config) == 48,
	       "lstp_gpio_config size must be 48 bytes");

/* ---- GetValue ---- */
/* Request:  [gpio_index : uint16_t] per GPIO (2 bytes each)
 * Response: [value : uint8_t]       per GPIO (1 byte each) */
struct lstp_gpio_get_value_request {
	uint16_t gpio_index;
} __attribute__((packed));

struct lstp_gpio_get_value_response {
	uint8_t value; /* lstp_gpio_state_t */
} __attribute__((packed));

/* ---- SetValue ---- */
/* Request:  [gpio_index : uint16_t, value : uint8_t] per GPIO (3 bytes each)
 * Response: empty payload on success */
struct lstp_gpio_set_value_request {
	uint16_t gpio_index;
	uint8_t  value; /* lstp_gpio_state_t */
} __attribute__((packed));

/* ---- GetIrqConfig ---- */
/* Request:  [gpio_index : uint16_t] (2 bytes)
 * Response: [irq_type : uint8_t]   (1 byte) */
struct lstp_gpio_get_irq_config_request {
	uint16_t gpio_index;
} __attribute__((packed));

struct lstp_gpio_get_irq_config_response {
	uint8_t irq_type; /* lstp_gpio_irq_config_t */
} __attribute__((packed));

/* ---- SetIrqConfig ---- */
/* Request:  [gpio_index : uint16_t, irq_type : uint8_t] (3 bytes)
 * Response: empty payload on success */
struct lstp_gpio_set_irq_config_request {
	uint16_t gpio_index;
	uint8_t  irq_type; /* lstp_gpio_irq_config_t */
} __attribute__((packed));

/* ---- IrqEvent (firmware → host unsolicited) ---- */
/* Payload: [gpio_index : uint16_t, value : uint8_t] (3 bytes) */
struct lstp_gpio_irq_event_request {
	uint16_t gpio_index;
	uint8_t  value; /* lstp_gpio_state_t */
} __attribute__((packed));

/*****************************************************
 * LSTP SPI Channel
 *****************************************************/

#define LSTP_SPI_MAX_CS 4

struct lstp_spi_channel_config {
	uint8_t  channel_num_cs;
	uint32_t freq_hz;
} __attribute__((packed));

/**
 * SPI command codes, matching OpenSMA's FlashromCmdCode.
 * Command byte layout:
 *   Bits [7:6] = CS select (SPI_CS_MASK)
 *   Bit  [5]   = CS deassert flag (SPI_CS_DEASSERT)
 *   Bit  [4]   = CS assert flag (SPI_CS_ASSERT)
 *   Bits [3:0] = Command code (CMD_CODE_MASK)
 */
#define LSTP_SPI_CMD_CODE_MASK   0x0F
#define LSTP_SPI_CS_ASSERT       0x20
#define LSTP_SPI_CS_DEASSERT     0x10
#define LSTP_SPI_CS_MASK         0xC0
#define LSTP_SPI_CS0             0x00
#define LSTP_SPI_CS1             0x40
#define LSTP_SPI_CS2             0x80
#define LSTP_SPI_CS3             0xC0

typedef enum {
	LSTP_SPI_CMD_CONFIG       = 0x00,
	LSTP_SPI_CMD_READ         = 0x01,
	LSTP_SPI_CMD_WRITE        = 0x02,
	LSTP_SPI_CMD_WRITE_READ   = 0x03,
	LSTP_SPI_CMD_POSTED_WRITE = 0x04,
	LSTP_SPI_CMD_END          = 0x07,
	LSTP_SPI_CMD_SUCCESS_RSP  = 0x80  /* Used in response cmd_status_code */
} lstp_spi_command_t;

/* ---- Config ---- */
/* Request:  empty payload
 * Response: [speed_hz : uint32_t] (4 bytes, little-endian) */

/* ---- Read ---- */
/* Request:  [read_count : uint32_t] (4 bytes, little-endian)
 * Response: [read_count bytes] in one or more packets */

/* ---- Write ---- */
/* Request:  [N bytes of write data]
 * Response: [0x00] (1 byte status) */

/* ---- WriteRead ---- */
/* Request:  [M bytes of write data]
 * Response: [M bytes of read data] */

/* ---- PostedWrite ---- */
/* Request:  [N bytes of write data]
 * Response: none (fire-and-forget) */

/*****************************************************
 * LSTP I2C Channel
 *****************************************************/

typedef enum {
	LSTP_I2C_SPEED_STANDARD = 0x00,  /* 100 kHz */
	LSTP_I2C_SPEED_FAST     = 0x01,  /* 400 kHz */
	LSTP_I2C_SPEED_FAST_PLUS= 0x02,  /* 1 MHz */
	LSTP_I2C_SPEED_HIGH     = 0x03,  /* 3.4 MHz */
} lstp_i2c_speed_t;

struct lstp_i2c_channel_config {
	uint8_t speed; /* lstp_i2c_speed_t */
} __attribute__((packed));

/**
 * Mask for the I2C command in cmd_status_code.
 * Bit 7 = response/request flag, Bit 6 = NoStop flag (must be masked off).
 * Matches OpenSMA: LstpI2cCmdMask = 0xBF
 */
#define LSTP_I2C_CMD_MASK    0xBF
/** Bit 6 of cmd_status_code: if set, don't send STOP condition after transfer. */
#define LSTP_I2C_NOSTOP_FLAG 0x40

typedef enum {
	LSTP_I2C_CMD_BUS_RECOVERY  = 0x00,
	LSTP_I2C_CMD_READ          = 0x01,
	LSTP_I2C_CMD_WRITE         = 0x02,
	LSTP_I2C_CMD_READ_RECV_LEN = 0x03,
	LSTP_I2C_CMD_WRITE_READ    = 0x04,
} lstp_i2c_command_t;

/* ---- Read ---- */
/* Request:  {address : uint8_t, read_len : uint16_t} (3 bytes)
 * Response: [read_len bytes of data] */
struct lstp_i2c_read_request {
	uint8_t  address;
	uint16_t read_len;
} __attribute__((packed));

/* ---- Write ---- */
/* Request:  {address : uint8_t} followed by N bytes of write data
 * Response: empty on success */
struct lstp_i2c_write_request {
	uint8_t address;
	/* Followed by N bytes of write data */
} __attribute__((packed));

/* ---- ReadRecvLen (SMBus block read) ---- */
/* Request:  {address : uint8_t} (1 byte)
 * Response: first byte received is the length, followed by that many bytes */
struct lstp_i2c_read_recv_len_request {
	uint8_t address;
} __attribute__((packed));

/* ---- WriteRead ---- */
/* Request:  {address : uint8_t, read_len : uint16_t} followed by M bytes of write data
 * Response: [read_len bytes of data] */
struct lstp_i2c_write_read_request {
	uint8_t  address;
	uint16_t read_len;
	/* Followed by M bytes of write data */
} __attribute__((packed));

/*****************************************************
 * LSTP UART Channel
 *****************************************************/

typedef enum {
	LSTP_UART_CMD_WRITE = 0x00,
} lstp_uart_command_t;

struct lstp_uart_channel_config {
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif /* LSTP_COMMON_H */
