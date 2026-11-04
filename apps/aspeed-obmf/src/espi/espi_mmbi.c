/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>
#include <string.h>
#include <stdio.h>

#include "espi_bridge.h"
#include "espi_mmbi.h"
#include "lstp/lstp_backend.h"
#include "lstp/lstp_channel.h"
#include "lstp/lstp_router.h"

LOG_MODULE_REGISTER(espi_mmbi, CONFIG_LOG_DEFAULT_LEVEL);

/*
 * Guards every piece of MMBI state below and the ring accesses. The poll runs
 * on the espi_bridge workqueue while BMC responses arrive on the LSTP task;
 * k_mutex is recursive for its owner, so nested public calls are fine.
 */
static K_MUTEX_DEFINE(s_mmbi_lock);

static uint32_t s_h2b_rp;
static uint32_t s_b2h_wp;
static bool s_host_ready;
static uint8_t s_h_int_t = MMBI_INT_TYPE_DEFAULT;
static uint8_t s_bmc_int_t = MMBI_INT_TYPE_DEFAULT;
static bool s_use_mmbi10 = true; /* Default to MMBI 1.0 framing as used by UEFI MmbiV1Toolx64.efi */

static bool s_reset_acked;

/* Host-written ring pointers out of range: logged once until the host resets. */
static bool s_bad_h2b_wp_logged;
static bool s_bad_b2h_rp_logged;
/* The head request is waiting for the USB host; poll retries it every 1 ms. */
static bool s_req_deferred;
static int64_t s_req_deferred_since_ms; /* when the current request was first deferred */

/* Track consumed H2B requests so an unresponsive BMC can be timed out. */
static struct {
	bool active;
	int64_t sent_ms;
	uint8_t netfn_lun;
	uint8_t cmd;
} s_inflight;

/*
 * After a timeout the BMC's reply may still come. IPMI carries no sequence
 * number here, so no new request goes out until that reply is drained or one
 * more timeout passes; otherwise it could complete the next request.
 */
static int64_t s_drain_until_ms;

/* Retain the response while B2H is full or the host is not ready. */
static struct {
	bool valid;
	int64_t next_retry_ms; /* poll runs at 1 kHz; do not retry at that rate */
	size_t len;
	uint8_t data[MMBI_IPMI_PAYLOAD_MAX];
} s_pending_resp;

#define MMBI_RESP_RETRY_INTERVAL_MS 50

static struct espi_mmbi_stats s_stats = {
	.trace_enabled = false,
	.is_mmbi10 = true,
};

/* Shell entry points take s_mmbi_lock: the poll work and LSTP task use the same state. */
void espi_mmbi_get_stats(struct espi_mmbi_stats *stats)
{
	if (stats != NULL) {
		k_mutex_lock(&s_mmbi_lock, K_FOREVER);
		*stats = s_stats;
		k_mutex_unlock(&s_mmbi_lock);
	}
}

void espi_mmbi_reset_stats(void)
{
	k_mutex_lock(&s_mmbi_lock, K_FOREVER);
	bool trace = s_stats.trace_enabled;
	bool m10 = s_stats.is_mmbi10;
	memset(&s_stats, 0, sizeof(s_stats));
	s_stats.trace_enabled = trace;
	s_stats.is_mmbi10 = m10;
	k_mutex_unlock(&s_mmbi_lock);
}

void espi_mmbi_set_trace(bool enable)
{
	k_mutex_lock(&s_mmbi_lock, K_FOREVER);
	s_stats.trace_enabled = enable;
	k_mutex_unlock(&s_mmbi_lock);
}

bool espi_mmbi_get_trace(void)
{
	bool enabled;

	k_mutex_lock(&s_mmbi_lock, K_FOREVER);
	enabled = s_stats.trace_enabled;

	k_mutex_unlock(&s_mmbi_lock);
	return enabled;
}

static void mmbi_trace_hex(const char *prefix, const uint8_t *data, size_t len)
{
	if (!s_stats.trace_enabled || data == NULL || len == 0) {
		return;
	}
	printk("%s (%zu B):", prefix, len);
	size_t show_len = MIN(len, 32U);
	for (size_t i = 0; i < show_len; i++) {
		printk(" %02x", data[i]);
	}
	if (len > show_len) {
		printk(" ...");
	}
	printk("\n");
}

static int send_ipmi_req(const uint8_t *data, size_t len)
{
	if (LSTP_HAS_IPMI_CHANNEL && !lstp_router_host_active()) {
		return -EHOSTDOWN;
	}

	return lstp_router_send_event(LSTP_IPMI_CHANNEL_ID, 0x00 /* LSTP_IPMI_CMD_MESSAGE */,
				      data, len);
}

static void mmbi_h2b_read(uint32_t *rp, uint8_t *dst, size_t count)
{
	size_t remaining = count;
	size_t dst_offset = 0;

	while (remaining > 0) {
		size_t chunk = MIN(remaining, (size_t)(MMBI_H2B_CB_SIZE - *rp));

		(void)espi_perif_mem_read(MMBI_H2B_CB_OFFSET + *rp, dst + dst_offset, chunk);
		dst_offset += chunk;
		remaining -= chunk;
		*rp += chunk;
		if (*rp >= MMBI_H2B_CB_SIZE) {
			*rp = 0;
		}
	}
}

/* Publish s_h2b_rp to the host in HROP[1] bits [31:2]. */
static void mmbi_publish_h2b_rp(void)
{
	uint32_t hrop_high = 0;

	(void)espi_perif_mem_read(MMBI_HROP_OFFSET + 4, &hrop_high, sizeof(hrop_high));
	hrop_high = sys_le32_to_cpu(hrop_high);
	hrop_high = (hrop_high & ~MMBI_PTR_MASK) | (s_h2b_rp & MMBI_PTR_MASK);
	hrop_high = sys_cpu_to_le32(hrop_high);
	(void)espi_perif_mem_write(MMBI_HROP_OFFSET + 4, &hrop_high, sizeof(hrop_high));
}

/* Skip @count bytes of H2B data; callers bound @count by the available data. */
/* wp == rp means empty, so the ring holds at most one dword less than its size. */
#define MMBI_H2B_RING_MAX (MMBI_H2B_CB_SIZE - 4U)

static void mmbi_h2b_skip(uint32_t from_rp, uint32_t count)
{
	s_h2b_rp = (from_rp + count) % MMBI_H2B_CB_SIZE;
	mmbi_publish_h2b_rp();
}

static void mmbi_b2h_write(uint32_t *wp, const uint8_t *src, size_t count)
{
	size_t remaining = count;
	size_t src_offset = 0;

	while (remaining > 0) {
		size_t chunk = MIN(remaining, (size_t)(MMBI_B2H_CB_SIZE - *wp));

		(void)espi_perif_mem_write(MMBI_B2H_CB_OFFSET + *wp, src + src_offset, chunk);
		src_offset += chunk;
		remaining -= chunk;
		*wp += chunk;
		if (*wp >= MMBI_B2H_CB_SIZE) {
			*wp = 0;
		}
	}
}

static int mmbi_init_locked(uint8_t h_int_t, uint8_t bmc_int_t)
{
	struct mmbi_cap_desc desc;
	uint32_t zero = 0;
	uint32_t hrwp_high;
	int rc;

	if (!LSTP_HAS_IPMI_CHANNEL) {
		return -ENOTSUP;
	}
	rc = espi_perif_mem_read(MMBI_HRWP_OFFSET + 4, &hrwp_high, sizeof(hrwp_high));
	if (rc != 0) {
		return rc;
	}
	if (sys_le32_to_cpu(hrwp_high) & MMBI_HRWS1_H_RDY) {
		return -EBUSY;
	}

	s_h_int_t = h_int_t;
	s_bmc_int_t = bmc_int_t;
	s_h2b_rp = 0;
	s_b2h_wp = 0;
	s_host_ready = false;
	/* Nothing from the previous session may reach the fresh ring. */
	if (s_inflight.active) {
		s_drain_until_ms = k_uptime_get() + MMBI_IPMI_RESP_TIMEOUT_MS;
	} else {
		s_drain_until_ms = 0;
	}
	s_inflight.active = false;
	s_pending_resp.valid = false;
	s_reset_acked = false;
	s_req_deferred = false;
	s_req_deferred_since_ms = 0;
	s_bad_h2b_wp_logged = false;
	s_bad_b2h_rp_logged = false;
	s_use_mmbi10 = true;
	s_stats.is_mmbi10 = true;

	/* Initialize BMC-owned pointers only; HRWP belongs to the host. */
	(void)espi_perif_mem_write(MMBI_HROP_OFFSET, &zero, sizeof(zero));
	(void)espi_perif_mem_write(MMBI_HROP_OFFSET + 4, &zero, sizeof(zero));

	memset(&desc, 0, sizeof(desc));
	memcpy(desc.signature, MMBI_SIGNATURE, sizeof(desc.signature));
	desc.version = MMBI_VERSION;
	desc.os_use = MMBI_OS_USE;
	desc.b2h_ba = sys_cpu_to_le32((MMBI_B2H_CB_OFFSET - MMBI_DESCRIPTOR_OFFSET) >> 3);
	desc.h2b_ba = sys_cpu_to_le32((MMBI_H2B_CB_OFFSET - MMBI_DESCRIPTOR_OFFSET) >> 3);
	desc.b2h_l = sys_cpu_to_le32(MMBI_B2H_CB_SIZE);
	desc.h2b_l = sys_cpu_to_le32(MMBI_H2B_CB_SIZE);
	desc.buffer_type = MMBI_BUFFER_TYPE_VPSCB1;
	desc.bt_desc.h_ros_p = sys_cpu_to_le32((MMBI_HROP_OFFSET - MMBI_DESCRIPTOR_OFFSET) >> 3);
	desc.bt_desc.h_rws_p = sys_cpu_to_le32((MMBI_HRWP_OFFSET - MMBI_DESCRIPTOR_OFFSET) >> 3);
	desc.bt_desc.h_int_t = s_h_int_t;
	desc.bt_desc.h_int_l = 0;
	desc.bt_desc.h_int_v = 0;
	desc.bt_desc.bmc_int_t = s_bmc_int_t;
	desc.bt_desc.bmc_int_l = sys_cpu_to_le32(MMBI_BMC_INT_LOCATION);
	desc.bt_desc.bmc_int_v = MMBI_BMC_INT_VALUE;

	(void)espi_perif_mem_write(MMBI_DESCRIPTOR_OFFSET, &desc, sizeof(desc));

	uint32_t hros0 = sys_cpu_to_le32(MMBI_HROS0_B_UP);
	uint32_t hros1 = sys_cpu_to_le32(MMBI_HROS1_B_RDY);

	(void)espi_perif_mem_write(MMBI_HROP_OFFSET, &hros0, sizeof(hros0));
	(void)espi_perif_mem_write(MMBI_HROP_OFFSET + 4, &hros1, sizeof(hros1));

	LOG_INF("MMBI: descriptor published at +0x%x (B2H 0x%x/%u B, H2B 0x%x/%u B)",
		MMBI_DESCRIPTOR_OFFSET, MMBI_B2H_CB_OFFSET, MMBI_B2H_CB_SIZE,
		MMBI_H2B_CB_OFFSET, MMBI_H2B_CB_SIZE);
	return 0;
}

int espi_mmbi_init(void)
{
	int rc;

	k_mutex_lock(&s_mmbi_lock, K_FOREVER);
	rc = mmbi_init_locked(s_h_int_t, s_bmc_int_t);

	k_mutex_unlock(&s_mmbi_lock);
	return rc;
}

int espi_mmbi_set_intr(uint8_t h_int_t, uint8_t bmc_int_t)
{
	int rc;

	k_mutex_lock(&s_mmbi_lock, K_FOREVER);
	rc = mmbi_init_locked(h_int_t, bmc_int_t);

	k_mutex_unlock(&s_mmbi_lock);
	return rc;
}

void espi_mmbi_get_intr(uint8_t *h_int_t, uint8_t *bmc_int_t)
{
	k_mutex_lock(&s_mmbi_lock, K_FOREVER);
	if (h_int_t != NULL) {
		*h_int_t = s_h_int_t;
	}
	if (bmc_int_t != NULL) {
		*bmc_int_t = s_bmc_int_t;
	}
	k_mutex_unlock(&s_mmbi_lock);
}

static lstp_status_t mmbi_write_resp(const uint8_t *payload, size_t payload_len);

static void mmbi_hold_response(const uint8_t *payload, size_t payload_len)
{
	/* Callers cap responses at MMBI_IPMI_PAYLOAD_MAX, the size of the hold buffer. */
	if (s_pending_resp.valid) {
		/* Keep the older response; it owns the next B2H slot. */
		s_stats.drop_count++;
		LOG_WRN("MMBI: response already held, dropping new one (netfn=0x%02x cmd=0x%02x)",
			payload[0] >> 2, (payload_len > 1) ? payload[1] : 0);
		return;
	}
	memcpy(s_pending_resp.data, payload, payload_len);
	s_pending_resp.len = payload_len;
	s_pending_resp.valid = true;
	s_pending_resp.next_retry_ms = k_uptime_get() + MMBI_RESP_RETRY_INTERVAL_MS;
}

/* Complete a consumed host request with only a completion code. */
static void mmbi_complete_error(uint8_t netfn_lun, uint8_t cmd, uint8_t cc)
{
	uint8_t resp[3];

	resp[0] = netfn_lun | BIT(2); /* request NetFn + 1 */
	resp[1] = cmd;
	resp[2] = cc;

	if (!s_host_ready) {
		mmbi_hold_response(resp, sizeof(resp));
	} else {
		(void)mmbi_write_resp(resp, sizeof(resp));
	}
}

static void mmbi_check_inflight(void)
{
	if (!s_inflight.active) {
		return;
	}
	if (k_uptime_get() - s_inflight.sent_ms < (int64_t)MMBI_IPMI_RESP_TIMEOUT_MS) {
		return;
	}

	s_inflight.active = false;
	s_drain_until_ms = k_uptime_get() + MMBI_IPMI_RESP_TIMEOUT_MS;
	s_stats.drop_count++;
	if (s_stats.trace_enabled) {
		printk("[MMBI] No response for NetFn=0x%02x Cmd=0x%02x after %u ms, returning CC=0x%02x\n",
		       s_inflight.netfn_lun >> 2, s_inflight.cmd, MMBI_IPMI_RESP_TIMEOUT_MS,
		       MMBI_CC_TIMEOUT);
	}
	LOG_WRN("MMBI: IPMI response timeout (netfn=0x%02x cmd=0x%02x)",
		s_inflight.netfn_lun >> 2, s_inflight.cmd);

	mmbi_complete_error(s_inflight.netfn_lun, s_inflight.cmd, MMBI_CC_TIMEOUT);
}

static void mmbi_poll_locked(void)
{
	uint32_t hrwp_low = 0;
	uint32_t hrwp_high = 0;

	if (espi_perif_mem_read(MMBI_HRWP_OFFSET, &hrwp_low, sizeof(hrwp_low)) != 0 ||
	    espi_perif_mem_read(MMBI_HRWP_OFFSET + 4, &hrwp_high, sizeof(hrwp_high)) != 0) {
		return;
	}

	hrwp_low = sys_le32_to_cpu(hrwp_low);
	hrwp_high = sys_le32_to_cpu(hrwp_high);

	/* Hold B_RST until the host clears H_RST; perform reset teardown only once. */
	if ((hrwp_low & MMBI_HRWS0_H_RST) != 0) {
		if (!s_reset_acked) {
			if (s_stats.trace_enabled) {
				printk("[MMBI TRACE] Host reset request, acknowledging\n");
			}
			s_stats.host_reset_cnt++;
			s_h2b_rp = 0;
			s_b2h_wp = 0;
			s_host_ready = false;
			if (s_inflight.active) {
				s_drain_until_ms = k_uptime_get() + MMBI_IPMI_RESP_TIMEOUT_MS;
			} else {
				s_drain_until_ms = 0;
			}
			s_inflight.active = false;
			s_pending_resp.valid = false;
			s_bad_h2b_wp_logged = false;
			s_req_deferred = false;
			s_req_deferred_since_ms = 0;
			s_bad_b2h_rp_logged = false;
			s_reset_acked = true;

			uint32_t hros0 = sys_cpu_to_le32(MMBI_HROS0_B_UP | MMBI_HROS0_B_RST);
			uint32_t hros1 = sys_cpu_to_le32(MMBI_HROS1_B_RDY);

			(void)espi_perif_mem_write(MMBI_HROP_OFFSET, &hros0, sizeof(hros0));
			(void)espi_perif_mem_write(MMBI_HROP_OFFSET + 4, &hros1, sizeof(hros1));
		}
		return;
	}

	if (s_reset_acked) {
		uint32_t hros0 = sys_cpu_to_le32(MMBI_HROS0_B_UP);

		(void)espi_perif_mem_write(MMBI_HROP_OFFSET, &hros0, sizeof(hros0));
		s_reset_acked = false;
		if (s_stats.trace_enabled) {
			printk("[MMBI TRACE] Host reset complete\n");
		}
	}

	bool host_ready = (hrwp_high & MMBI_HRWS1_H_RDY) != 0;

	if (!host_ready) {
		if (s_host_ready && s_stats.trace_enabled) {
			printk("[MMBI TRACE] Host ready cleared\n");
		}
		s_host_ready = false;
		s_req_deferred = false;
		s_req_deferred_since_ms = 0;
		return;
	}

	if (!s_host_ready) {
		s_host_ready = true;
		if (s_stats.trace_enabled) {
			printk("[MMBI TRACE] Host ready set\n");
		}
		LOG_INF("MMBI: Host ready");
	}

	if (s_pending_resp.valid && k_uptime_get() >= s_pending_resp.next_retry_ms) {
		if (mmbi_write_resp(s_pending_resp.data, s_pending_resp.len) != LSTP_STATUS_SUCCESS) {
			return;
		}
		s_pending_resp.valid = false;
	} else if (s_pending_resp.valid) {
		return; /* Held response owns B2H until it lands; keep request order. */
	}

	mmbi_check_inflight();
	/* A timeout reply may have just been held: it must land before the next request. */
	if (s_inflight.active || s_pending_resp.valid) {
		return; /* One request at a time, so a response always matches s_inflight. */
	}
	if (k_uptime_get() < s_drain_until_ms) {
		return; /* Still draining a timed-out request's late reply. */
	}

	/* Extract 4-byte aligned pointer, masking off status bits [1:0] */
	uint32_t h2b_wp = hrwp_low & MMBI_PTR_MASK;

	if (h2b_wp >= MMBI_H2B_CB_SIZE) {
		if (!s_bad_h2b_wp_logged) {
			s_bad_h2b_wp_logged = true;
			s_stats.drop_count++;
			LOG_ERR("MMBI: host H2B write pointer 0x%x out of range (size 0x%x), ignoring",
				h2b_wp, MMBI_H2B_CB_SIZE);
		}
		return;
	}

	if (h2b_wp == s_h2b_rp) {
		return;
	}

	uint32_t avail;
	if (h2b_wp >= s_h2b_rp) {
		avail = h2b_wp - s_h2b_rp;
	} else {
		avail = MMBI_H2B_CB_SIZE - s_h2b_rp + h2b_wp;
	}

	if (avail < MMBI_HEADER_SIZE) {
		return;
	}

	uint32_t temp_rp = s_h2b_rp;
	uint8_t peek_hdr[MMBI_HEADER_SIZE];
	mmbi_h2b_read(&temp_rp, peek_hdr, MMBI_HEADER_SIZE);

	/* Static storage is safe because s_mmbi_lock serialises the poll. */
	static uint8_t ipmi_buf[256];
	uint32_t payload_len = 0;
	bool is_10 = ((peek_hdr[3] & 0x0F) == MMBI_PKT_TYPE_VENDOR);

	if (is_10) {
		uint32_t pkt_len = ((uint32_t)peek_hdr[2] << 16) |
				   ((uint32_t)peek_hdr[1] << 8) |
				   ((uint32_t)peek_hdr[0]);
		pkt_len >>= 2;
		uint32_t total_size = (pkt_len + 1) * 4;

		if (total_size < MMBI_10_HEADER_SIZE && avail >= total_size) {
			s_stats.drop_count++;
			/* Skip the malformed frame in dwords to preserve framing. */
			mmbi_h2b_skip(s_h2b_rp, total_size);
			return;
		}

		if (avail < MMBI_10_HEADER_SIZE) {
			return;
		}
		uint8_t hdr10[MMBI_10_HEADER_SIZE];
		memcpy(hdr10, peek_hdr, MMBI_HEADER_SIZE);
		mmbi_h2b_read(&temp_rp, &hdr10[MMBI_HEADER_SIZE], MMBI_10_HEADER_SIZE - MMBI_HEADER_SIZE);

		uint8_t padding = hdr10[0] & 0x03;
		uint32_t iana = ((uint32_t)hdr10[7] << 24) |
				((uint32_t)hdr10[6] << 16) |
				((uint32_t)hdr10[5] << 8) |
				((uint32_t)hdr10[4]);
		uint8_t protocol = hdr10[11];

		if (total_size > MMBI_H2B_RING_MAX) {
			/* Can never fit in the ring; discard what the host has queued. */
			s_stats.drop_count++;
			LOG_ERR("MMBI: MMBI 1.0 packet length %u exceeds H2B ring, flushing %u B",
				total_size, avail);
			mmbi_h2b_skip(s_h2b_rp, avail);
			return;
		}

		if (avail < total_size) {
			return;
		}

		if (iana != MMBI_VENDOR_IANA || protocol != MMBI_PROTOCOL_IPMI) {
			s_stats.drop_count++;
			if (s_stats.trace_enabled) {
				printk("[MMBI TRACE] MMBI 1.0 unhandled (IANA=0x%x proto=0x%02x), skipping %u B\n",
				       iana, protocol, total_size);
			}
			LOG_WRN("MMBI: MMBI 1.0 unhandled (IANA=0x%x proto=0x%02x), skipping %u bytes",
				iana, protocol, total_size);
			mmbi_h2b_skip(s_h2b_rp, total_size);
			return;
		}

		if (total_size < MMBI_10_HEADER_SIZE + padding) {
			s_stats.drop_count++;
			/* total_size is a dword multiple: skipping it keeps the framing. */
			mmbi_h2b_skip(s_h2b_rp, total_size);
			return;
		}

		payload_len = total_size - MMBI_10_HEADER_SIZE - padding;
		if (payload_len > MMBI_IPMI_PAYLOAD_MAX || payload_len < MMBI_IPMI_PAYLOAD_MIN) {
			s_stats.drop_count++;
			if (s_stats.trace_enabled) {
				printk("[MMBI TRACE] Invalid MMBI 1.0 IPMI payload length: %u\n", payload_len);
			}
			LOG_ERR("MMBI: Invalid MMBI 1.0 IPMI payload length %u", payload_len);
			mmbi_h2b_skip(s_h2b_rp, total_size);
			return;
		}

		mmbi_h2b_read(&temp_rp, ipmi_buf, payload_len);
		if (padding > 0) {
			uint8_t pad_trash[4];
			mmbi_h2b_read(&temp_rp, pad_trash, padding);
		}

		s_use_mmbi10 = true;
		s_stats.is_mmbi10 = true;
	} else {
		payload_len = peek_hdr[0] | ((uint32_t)peek_hdr[1] << 8) | ((uint32_t)peek_hdr[2] << 16);
		uint8_t protocol = peek_hdr[3];

		/* Legacy frames are padded to 4 bytes: the ring pointers are dword aligned. */
		uint32_t frame_body = ROUND_UP(payload_len, 4U);

		if (payload_len > MMBI_H2B_RING_MAX ||
		    MMBI_HEADER_SIZE + frame_body > MMBI_H2B_RING_MAX) {
			/* Can never fit in the ring; discard what the host has queued. */
			s_stats.drop_count++;
			LOG_ERR("MMBI: payload length %u exceeds H2B ring, flushing %u B",
				payload_len, avail);
			mmbi_h2b_skip(s_h2b_rp, avail);
			return;
		}

		if (avail < MMBI_HEADER_SIZE + frame_body) {
			return;
		}

		if (protocol != MMBI_PROTOCOL_IPMI) {
			s_stats.drop_count++;
			if (s_stats.trace_enabled) {
				printk("[MMBI TRACE] Unsupported protocol 0x%02x, skipping %u B\n",
				       protocol, payload_len);
			}
			LOG_WRN("MMBI: Unsupported protocol 0x%02x, skipping %u bytes",
				protocol, payload_len);
			mmbi_h2b_skip(temp_rp, frame_body);
			return;
		}

		if (payload_len > MMBI_IPMI_PAYLOAD_MAX || payload_len < MMBI_IPMI_PAYLOAD_MIN) {
			s_stats.drop_count++;
			if (s_stats.trace_enabled) {
				printk("[MMBI TRACE] Invalid IPMI payload length: %u\n", payload_len);
			}
			LOG_ERR("MMBI: Invalid IPMI payload length %u", payload_len);
			mmbi_h2b_skip(temp_rp, frame_body);
			return;
		}

		mmbi_h2b_read(&temp_rp, ipmi_buf, payload_len);
		temp_rp = (temp_rp + frame_body - payload_len) % MMBI_H2B_CB_SIZE;

		s_use_mmbi10 = false;
		s_stats.is_mmbi10 = false;
	}

	/* Count and trace a deferred request once, not on every retry. */
	if (!s_req_deferred) {
		s_stats.req_count++;
		s_stats.last_req_netfn = ipmi_buf[0] >> 2;
		s_stats.last_req_cmd = (payload_len > 1) ? ipmi_buf[1] : 0;
	}

	if (s_stats.trace_enabled && !s_req_deferred) {
		printk("[MMBI TRACE] >> Host IPMI Req (%s): NetFn=0x%02x LUN=%u Cmd=0x%02x (len=%u B, h2b_wp=0x%x, rp=0x%x)\n",
		       s_use_mmbi10 ? "MMBI 1.0" : "Legacy",
		       ipmi_buf[0] >> 2, ipmi_buf[0] & 0x03,
		       (payload_len > 1) ? ipmi_buf[1] : 0, payload_len,
		       h2b_wp, s_h2b_rp);
		mmbi_trace_hex("  Req Data", ipmi_buf, payload_len);
	}

	int rc = send_ipmi_req(ipmi_buf, payload_len);
	if (rc == 0) {
		s_inflight.active = true;
		s_inflight.sent_ms = k_uptime_get();
		s_inflight.netfn_lun = ipmi_buf[0];
		s_inflight.cmd = ipmi_buf[1];
	}
	/*
	 * No USB host yet, or the USB event queue is momentarily full: leave the
	 * request in the H2B ring and retry on the next poll instead of consuming
	 * it, but only for one response timeout; after that it is consumed and
	 * answered with CC=0xC3 below, so one request cannot block the ring.
	 */
	bool transient = rc == -EHOSTDOWN || rc == -ENODEV || rc == -ENOSPC ||
			 rc == -EBUSY || rc == -ESTALE;

	if (transient && !s_req_deferred) {
		s_req_deferred_since_ms = k_uptime_get();
	}
	if (transient && k_uptime_get() - s_req_deferred_since_ms <
			 (int64_t)MMBI_IPMI_RESP_TIMEOUT_MS) {
		if (s_stats.trace_enabled && !s_req_deferred) {
			printk("[MMBI TRACE] cannot forward req now (%d), deferring\n", rc);
		}
		s_req_deferred = true;
		return;
	}
	s_req_deferred = false;
	s_req_deferred_since_ms = 0;

	uint32_t old_rp = s_h2b_rp;
	s_h2b_rp = temp_rp;
	mmbi_publish_h2b_rp();

	if (s_stats.trace_enabled) {
		printk("[MMBI TRACE] -> USB send rc=%d | h2b_rp updated: 0x%x -> 0x%x\n",
		       rc, old_rp, s_h2b_rp);
	}

	if (rc < 0) {
		LOG_ERR("MMBI: Failed to send IPMI request to USB: %d", rc);
		/* The request is consumed; tell the host instead of leaving it waiting. */
		mmbi_complete_error(ipmi_buf[0], ipmi_buf[1], MMBI_CC_TIMEOUT);
	} else {
		LOG_INF("MMBI: Forwarded IPMI req (%s, netfn=0x%02x, cmd=0x%02x, len=%u)",
			s_use_mmbi10 ? "MMBI 1.0" : "Legacy",
			ipmi_buf[0] >> 2, ipmi_buf[1], payload_len);
	}
}

void espi_mmbi_poll(void)
{
	if (!LSTP_HAS_IPMI_CHANNEL) {
		return;
	}

	k_mutex_lock(&s_mmbi_lock, K_FOREVER);
	mmbi_poll_locked();
	k_mutex_unlock(&s_mmbi_lock);
}

/* Write one response to B2H, or hold it while B2H is full. Caller holds s_mmbi_lock. */
static lstp_status_t mmbi_write_resp(const uint8_t *payload, size_t payload_len)
{
	if (payload_len > MMBI_IPMI_PAYLOAD_MAX) {
		return LSTP_STATUS_TOO_LARGE;
	}

	uint32_t hrwp_high = 0;
	(void)espi_perif_mem_read(MMBI_HRWP_OFFSET + 4, &hrwp_high, sizeof(hrwp_high));
	hrwp_high = sys_le32_to_cpu(hrwp_high);
	uint32_t b2h_rp = hrwp_high & MMBI_PTR_MASK;

	uint32_t free_space;
	if (b2h_rp >= MMBI_B2H_CB_SIZE) {
		/* Treat a bogus host read pointer as a full ring; the response is held. */
		if (!s_bad_b2h_rp_logged) {
			s_bad_b2h_rp_logged = true;
			LOG_ERR("MMBI: host B2H read pointer 0x%x out of range (size 0x%x)",
				b2h_rp, MMBI_B2H_CB_SIZE);
		}
		free_space = 0;
	} else if (s_b2h_wp >= b2h_rp) {
		free_space = MMBI_B2H_CB_SIZE - 1 - (s_b2h_wp - b2h_rp);
	} else {
		free_space = b2h_rp - s_b2h_wp - 1;
	}

	size_t header_size = s_use_mmbi10 ? MMBI_10_HEADER_SIZE : MMBI_HEADER_SIZE;
	size_t needed = ROUND_UP(header_size + payload_len, 4U);

	if (free_space < needed) {
		if (!s_pending_resp.valid) {
			s_stats.drop_count++;
			if (s_stats.trace_enabled) {
				printk("[MMBI TRACE] B2H buffer FULL (free=%u, needed=%zu)\n",
				       free_space, needed);
			}
			LOG_ERR("MMBI: B2H buffer full (free=%u, needed=%zu)", free_space, needed);
			mmbi_hold_response(payload, payload_len);
		} else {
			s_pending_resp.next_retry_ms = k_uptime_get() + MMBI_RESP_RETRY_INTERVAL_MS;
		}
		return LSTP_STATUS_BUSY;
	}

	s_stats.resp_count++;
	s_stats.last_resp_netfn = payload[0] >> 2;
	s_stats.last_resp_cmd = (payload_len > 1) ? payload[1] : 0;
	s_stats.last_resp_cc = (payload_len > 2) ? payload[2] : 0;

	if (s_stats.trace_enabled) {
		printk("[MMBI TRACE] << BMC IPMI Resp (%s): NetFn=0x%02x LUN=%u Cmd=0x%02x CC=0x%02x (len=%zu B)\n",
		       s_use_mmbi10 ? "MMBI 1.0" : "Legacy",
		       payload[0] >> 2, payload[0] & 0x03,
		       (payload_len > 1) ? payload[1] : 0,
		       (payload_len > 2) ? payload[2] : 0,
		       payload_len);
		mmbi_trace_hex("  Resp Data", payload, payload_len);
	}

	uint32_t old_wp = s_b2h_wp;

	if (s_use_mmbi10) {
		size_t total_size = MMBI_10_HEADER_SIZE + payload_len;
		uint8_t padding = (4 - (total_size % 4)) % 4;
		total_size += padding;
		uint32_t pkt_len = ((total_size / 4) - 1) << 2;

		uint8_t hdr10[MMBI_10_HEADER_SIZE];
		hdr10[0] = (pkt_len & 0xFF) | (padding & 0x03);
		hdr10[1] = (pkt_len >> 8) & 0xFF;
		hdr10[2] = (pkt_len >> 16) & 0xFF;
		hdr10[3] = MMBI_PKT_TYPE_VENDOR;
		hdr10[4] = MMBI_VENDOR_IANA & 0xFF;
		hdr10[5] = (MMBI_VENDOR_IANA >> 8) & 0xFF;
		hdr10[6] = (MMBI_VENDOR_IANA >> 16) & 0xFF;
		hdr10[7] = (MMBI_VENDOR_IANA >> 24) & 0xFF;
		hdr10[8] = 0;
		hdr10[9] = 0;
		hdr10[10] = 0;
		hdr10[11] = MMBI_PROTOCOL_IPMI;

		mmbi_b2h_write(&s_b2h_wp, hdr10, MMBI_10_HEADER_SIZE);
		mmbi_b2h_write(&s_b2h_wp, payload, payload_len);
		if (padding > 0) {
			uint8_t zero_pad[4] = {0};
			mmbi_b2h_write(&s_b2h_wp, zero_pad, padding);
		}
	} else {
		/* Pad to 4 bytes so HROP can publish the write pointer exactly. */
		size_t padding = ROUND_UP(payload_len, 4U) - payload_len;

		uint8_t hdr[MMBI_HEADER_SIZE];
		hdr[0] = payload_len & 0xFF;
		hdr[1] = (payload_len >> 8) & 0xFF;
		hdr[2] = (payload_len >> 16) & 0xFF;
		hdr[3] = MMBI_PROTOCOL_IPMI;

		mmbi_b2h_write(&s_b2h_wp, hdr, MMBI_HEADER_SIZE);
		mmbi_b2h_write(&s_b2h_wp, payload, payload_len);
		if (padding > 0) {
			uint8_t zero_pad[4] = {0};
			mmbi_b2h_write(&s_b2h_wp, zero_pad, padding);
		}
	}

	uint32_t hrop_low = 0;
	(void)espi_perif_mem_read(MMBI_HROP_OFFSET, &hrop_low, sizeof(hrop_low));
	hrop_low = sys_le32_to_cpu(hrop_low);
	hrop_low = (hrop_low & ~MMBI_PTR_MASK) | (s_b2h_wp & MMBI_PTR_MASK);
	hrop_low = sys_cpu_to_le32(hrop_low);
	(void)espi_perif_mem_write(MMBI_HROP_OFFSET, &hrop_low, sizeof(hrop_low));

	if (s_stats.trace_enabled) {
		printk("[MMBI TRACE] -> B2H write complete: b2h_wp: 0x%x -> 0x%x (b2h_rp=0x%x, free=%u)\n",
		       old_wp, s_b2h_wp, b2h_rp, free_space);
	}

	LOG_INF("MMBI: Wrote IPMI resp to B2H (%s, len=%u, new b2h_wp=0x%x)",
		s_use_mmbi10 ? "MMBI 1.0" : "Legacy", (unsigned int)payload_len, s_b2h_wp);

	return LSTP_STATUS_SUCCESS;
}

lstp_status_t espi_mmbi_handle_ipmi_resp(const uint8_t *payload, size_t payload_len)
{
	lstp_status_t status;

	if (!payload || payload_len == 0) {
		return LSTP_STATUS_ERROR;
	}

	k_mutex_lock(&s_mmbi_lock, K_FOREVER);
	/*
	 * Late (already timed out) or unsolicited: the host was answered once.
	 * A late reply to an earlier request must not complete the current one,
	 * so it has to carry the NetFn pair and the Cmd of s_inflight. IPMI
	 * has no sequence number here, so a late reply to an identical command
	 * still cannot be told apart.
	 */
	if (!s_inflight.active || payload_len < 2U ||
	    ((payload[0] >> 2) | 1U) != ((s_inflight.netfn_lun >> 2) | 1U) ||
	    payload[1] != s_inflight.cmd) {
		/* Only the timed-out request's own (NetFn, Cmd) reply ends the drain. */
		if (!s_inflight.active && s_drain_until_ms != 0 && payload_len >= 2U &&
		    ((payload[0] >> 2) | 1U) == ((s_inflight.netfn_lun >> 2) | 1U) &&
		    payload[1] == s_inflight.cmd) {
			s_drain_until_ms = 0;
		}
		s_stats.drop_count++;
		LOG_WRN("MMBI: dropping unexpected IPMI response (netfn=0x%02x cmd=0x%02x)",
			payload[0] >> 2, (payload_len > 1) ? payload[1] : 0);
		k_mutex_unlock(&s_mmbi_lock);
		return LSTP_STATUS_SUCCESS;
	}
	s_inflight.active = false;
	if (payload_len > MMBI_IPMI_PAYLOAD_MAX) {
		/* Too long for the host's MMBI frame: answer the request with an error. */
		s_stats.drop_count++;
		LOG_WRN("MMBI: IPMI response too long (%zu > %u), returning CC=0x%02x",
			payload_len, MMBI_IPMI_PAYLOAD_MAX, MMBI_CC_RESP_TOO_LONG);
		mmbi_complete_error(s_inflight.netfn_lun, s_inflight.cmd, MMBI_CC_RESP_TOO_LONG);
		k_mutex_unlock(&s_mmbi_lock);
		return LSTP_STATUS_SUCCESS;
	}
	if (!s_host_ready) {
		mmbi_hold_response(payload, payload_len);
		k_mutex_unlock(&s_mmbi_lock);
		return LSTP_STATUS_SUCCESS;
	}
	status = mmbi_write_resp(payload, payload_len);
	if (status == LSTP_STATUS_BUSY && s_pending_resp.valid) {
		/* Held for retry: the response is accepted and will be delivered. */
		status = LSTP_STATUS_SUCCESS;
	}
	k_mutex_unlock(&s_mmbi_lock);

	return status;
}

/* The BMC's IPMI responses arrive as requests on the IPMI channel and take no reply. */
static lstp_status_t lstp_ipmi_receive(uint8_t channel_id, struct lstp_hdr *hdr,
				       uint8_t *payload, size_t payload_len,
				       uint8_t *resp_payload, size_t *resp_payload_len,
				       bool *send_response)
{
	ARG_UNUSED(channel_id);
	ARG_UNUSED(hdr);
	ARG_UNUSED(resp_payload);

	*resp_payload_len = 0;
	*send_response = false;
	return espi_mmbi_handle_ipmi_resp(payload, payload_len);
}

LSTP_CHANNEL_DEFINE(lstp_ipmi_channel,
	.id = LSTP_IPMI_CHANNEL_ID,
	.type = LSTP_CHANNEL_TYPE_IPMI,
	.name = "IPMI",
	.receive = lstp_ipmi_receive,
);
