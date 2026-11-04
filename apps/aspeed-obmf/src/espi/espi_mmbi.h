/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ESPI_MMBI_H
#define ESPI_MMBI_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <zephyr/toolchain.h>
#include <zephyr/sys/util.h>
#include "lstp/lstp_common.h"

/* The MMBI descriptor must start at the host LGMR base. Keep OBMF mirrors above it. */
#define MMBI_INSTANCE_OFFSET    0x0000U
#define MMBI_INSTANCE_SIZE      0x8000U /* 32 KiB */
#define MMBI_HALF_SIZE          (MMBI_INSTANCE_SIZE / 2U)

#define MMBI_DESCRIPTOR_OFFSET  MMBI_INSTANCE_OFFSET
#define MMBI_DESCRIPTOR_SIZE    64U

#define MMBI_HROP_OFFSET        (MMBI_DESCRIPTOR_OFFSET + MMBI_DESCRIPTOR_SIZE)
#define MMBI_HROP_SIZE          8U

#define MMBI_B2H_CB_OFFSET      (MMBI_HROP_OFFSET + MMBI_HROP_SIZE)
#define MMBI_B2H_CB_SIZE        (MMBI_HALF_SIZE - MMBI_DESCRIPTOR_SIZE - MMBI_HROP_SIZE)

#define MMBI_HRWP_OFFSET        (MMBI_INSTANCE_OFFSET + MMBI_HALF_SIZE)
#define MMBI_HRWP_SIZE          8U

#define MMBI_H2B_CB_OFFSET      (MMBI_HRWP_OFFSET + MMBI_HRWP_SIZE)
#define MMBI_H2B_CB_SIZE        (MMBI_HALF_SIZE - MMBI_HRWP_SIZE)

#define MMBI_SIGNATURE          "#MMBI$"
#define MMBI_VERSION            1U
#define MMBI_OS_USE             1U
#define MMBI_BUFFER_TYPE_VPSCB1 0x01U

/* The host rejects interrupt type 0, even though this bridge polls.
 * Type 1 uses host MSI and a BMC doorbell write relative to MmbiBase. */
#define MMBI_INT_TYPE_DEFAULT   0x01U
/* Doorbell lands in the descriptor's trailing reserved bytes, which nothing reads. */
#define MMBI_BMC_INT_LOCATION   0x38U
#define MMBI_BMC_INT_VALUE      0x01U

int espi_mmbi_set_intr(uint8_t h_int_t, uint8_t bmc_int_t);
void espi_mmbi_get_intr(uint8_t *h_int_t, uint8_t *bmc_int_t);

/* HROP/HRWP pointers are byte offsets in bits [31:2]; mask them without shifting. */
#define MMBI_PTR_MASK           0xFFFFFFFCU

#define MMBI_HROS0_B_RST        BIT(0) /* BMC reset request */
#define MMBI_HROS0_B_UP         BIT(1) /* BMC interface up */
#define MMBI_HROS1_B_RDY        BIT(0) /* BMC ready */

#define MMBI_HRWS0_H_RST        BIT(0) /* Host reset request */
#define MMBI_HRWS0_H_UP         BIT(1) /* Host interface up */
#define MMBI_HRWS1_H_RDY        BIT(0) /* Host ready */

struct mmbi_buffer_type_desc {
	uint32_t h_ros_p;      /* Host read-only structure pointer, 8-byte units */
	uint32_t h_rws_p;      /* Host read-write structure pointer, 8-byte units */
	uint8_t  h_int_t;      /* Host interrupt type */
	uint8_t  h_int_l;      /* Host interrupt location */
	uint8_t  reserved1[3];
	uint8_t  h_int_v;      /* Host interrupt value */
	uint8_t  bmc_int_t;    /* BMC interrupt type */
	uint32_t bmc_int_l;    /* BMC interrupt location */
	uint8_t  reserved2[4];
	uint8_t  bmc_int_v;    /* BMC interrupt value */
} __packed;

struct mmbi_cap_desc {
	uint8_t  signature[6];
	uint8_t  version;
	uint8_t  os_use;
	uint32_t b2h_ba;       /* B2H buffer base, 8-byte units from this descriptor */
	uint32_t h2b_ba;       /* H2B buffer base, 8-byte units from this descriptor */
	uint32_t b2h_l;        /* B2H buffer length in bytes */
	uint32_t h2b_l;        /* H2B buffer length in bytes */
	uint8_t  buffer_type;
	uint8_t  reserved1[7];
	struct mmbi_buffer_type_desc bt_desc;
	uint8_t  reserved2[8];
} __packed;

BUILD_ASSERT(sizeof(struct mmbi_buffer_type_desc) == 24, "buffer type descriptor must be 24 B");
BUILD_ASSERT(sizeof(struct mmbi_cap_desc) == MMBI_DESCRIPTOR_SIZE,
	     "MMBI capability descriptor must be 64 B");
BUILD_ASSERT((MMBI_B2H_CB_SIZE % 4U) == 0U, "B2H buffer length must be 4-byte aligned");
BUILD_ASSERT((MMBI_H2B_CB_SIZE % 4U) == 0U, "H2B buffer length must be 4-byte aligned");

/* Match the AST2700 LSTP IPMI payload limit; oversized messages are discarded by the peer. */
#define MMBI_IPMI_PAYLOAD_MAX   254U
#define MMBI_IPMI_PAYLOAD_MIN   2U

#define MMBI_IPMI_RESP_TIMEOUT_MS 5000U
#define MMBI_CC_TIMEOUT         0xC3U /* Timeout while processing command */
#define MMBI_CC_RESP_TOO_LONG   0xCAU /* Cannot return number of requested data bytes */

#define MMBI_HEADER_SIZE        4U
#define MMBI_10_HEADER_SIZE     12U
#define MMBI_PKT_TYPE_VENDOR    0x05U
#define MMBI_VENDOR_IANA        343U     /* Intel IANA: 0x00000157 */
#define MMBI_PROTOCOL_IPMI      0x01U
#define MMBI_PROTOCOL_SEAMLESS  0x02U
#define MMBI_PROTOCOL_RAS       0x03U

int espi_mmbi_init(void);

void espi_mmbi_poll(void);

lstp_status_t espi_mmbi_handle_ipmi_resp(const uint8_t *payload, size_t payload_len);

struct espi_mmbi_stats {
	uint32_t req_count;      /* Total IPMI requests received from Host */
	uint32_t resp_count;     /* Total IPMI responses forwarded to Host */
	uint32_t drop_count;     /* Dropped/unsupported packets */
	uint32_t host_reset_cnt; /* Host reset events detected */
	uint8_t  last_req_netfn;
	uint8_t  last_req_cmd;
	uint8_t  last_resp_netfn;
	uint8_t  last_resp_cmd;
	uint8_t  last_resp_cc;
	bool     trace_enabled;
	bool     is_mmbi10;      /* True if MMBI 1.0 (12-byte header) is active */
};

void espi_mmbi_get_stats(struct espi_mmbi_stats *stats);
void espi_mmbi_reset_stats(void);
void espi_mmbi_set_trace(bool enable);
bool espi_mmbi_get_trace(void);

#endif /* ESPI_MMBI_H */
