/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * MCTP evaluation app: an MCTP endpoint built on libmctp, reached over I3C
 * (the i3c0 target message queue) and, with CONFIG_MCTP_EVAL_USB, over USB
 * (DSP0283 on udc0). Each transport has its own libmctp instance, so
 * replies always leave on the bus their request arrived on. libmctp answers
 * MCTP control requests (Set/Get Endpoint ID, Get Version, Get Message
 * Type), so a bus owner such as the BMC can discover the endpoint and assign
 * it an EID. Every other message is logged and counted, and requests can
 * optionally be echoed back to their sender. The mbench commands pair with
 * the BMC's mctp-bench for one-way throughput in either direction. With
 * CONFIG_MCTP_EVAL_PLDM, PLDM messages go to the libpldm responder (pldm.c);
 * with CONFIG_MCTP_EVAL_SPDM_BRIDGE, SPDM goes to the SSMCU (spdm_bridge.c).
 */

#include <stdlib.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/byteorder.h>
#include <libmctp.h>
#include <mctp/mctp_i3c_tmq.h>
#include "mctp_eval.h"
#ifdef CONFIG_MCTP_EVAL_USB
#include <zephyr/usb/usbd.h>
#include <mctp/mctp_usb.h>
#endif

LOG_MODULE_REGISTER(mctp_eval, LOG_LEVEL_INF);

/* DSP0236 reserves EIDs 1-7, and 255 is the broadcast EID */
BUILD_ASSERT(CONFIG_MCTP_EVAL_LOCAL_EID == 0 || CONFIG_MCTP_EVAL_LOCAL_EID >= 8,
	     "CONFIG_MCTP_EVAL_LOCAL_EID must be 0 or 8..254: DSP0236 reserves 1-7");

#define RX_POLL_US		100
#define MCTP_MSG_TYPE_CONTROL	0x00
#define MCTP_TAG_MASK		0x07
#define SEND_MAX_LEN		64

MCTP_I3C_TMQ_DT_DEFINE(mctp_i3c0, DT_NODELABEL(i3c0_tmq));
/* Serializes the I3C rx loop and shell sends on the I3C bus */
static K_MUTEX_DEFINE(i3c_lock);
static struct eval_bus bus_i3c = {
	.name = "i3c",
	.lock = &i3c_lock,
	.tx_errors = &mctp_i3c0.stats.tx_errors,
};

#ifdef CONFIG_MCTP_EVAL_USB
MCTP_USB_DEFINE(mctp_usb0, USBD_MCTP_SUBCLASS_MANAGED_DEVICE_ENDPOINT, USBD_MCTP_PROTOCOL_1_X);
/* The binding holds this lock while it hands received packets to libmctp */
static struct eval_bus bus_usb = {
	.name = "usb",
	.lock = &mctp_usb0.lock,
	.tx_errors = &mctp_usb0.stats.tx_errors,
};

USBD_DEVICE_DEFINE(eval_usbd, DEVICE_DT_GET(DT_NODELABEL(zephyr_udc0)),
		   CONFIG_MCTP_EVAL_USB_VID, CONFIG_MCTP_EVAL_USB_PID);
USBD_DESC_LANG_DEFINE(eval_lang);
USBD_DESC_MANUFACTURER_DEFINE(eval_mfr, "ASPEED");
USBD_DESC_PRODUCT_DEFINE(eval_product, "MCTP eval " CONFIG_BOARD);
/* Bus powered, 250 mA (bMaxPower is in 2 mA units) */
USBD_CONFIGURATION_DEFINE(eval_fs_config, 0, 125);
USBD_CONFIGURATION_DEFINE(eval_hs_config, 0, 125);
#endif

/* Bus that the shell's send and bench commands use */
static struct eval_bus *cur_bus = &bus_i3c;

/*
 * Both buses' rx paths update stats and mb_rx, under different bus locks, so
 * these take stats_lock as well; so do the shell's reads and resets.
 */
static struct k_spinlock stats_lock;

static struct {
	uint32_t msgs;
	uint32_t bytes;
	uint32_t echoed;
	uint32_t tx_errors;
} stats;

static void stats_add(uint32_t *counter, uint32_t n)
{
	k_spinlock_key_t key = k_spin_lock(&stats_lock);

	*counter += n;
	k_spin_unlock(&stats_lock, key);
}

static bool rx_dump = true;
static bool rx_echo;
static atomic_t send_tag;

/*
 * Round-trip benchmark against an echo responder such as the BMC's
 * mctp-echo: requests use mctp-req's format (type 0x7e, vendor ID bytes
 * cc de f0, then a counting payload) and the reply must match it exactly.
 */
#define BENCH_MSG_TYPE		0x7e
#define BENCH_HDR_LEN		4
#define BENCH_TIMEOUT_MS	1000

static const uint8_t bench_hdr[BENCH_HDR_LEN] = {BENCH_MSG_TYPE, 0xcc, 0xde, 0xf0};
static uint8_t bench_msg[CONFIG_MCTP_MAX_MESSAGE_SIZE];
static K_SEM_DEFINE(bench_done, 0, 1);

static struct {
	bool active;
	struct eval_bus *bus;
	uint8_t eid;
	uint8_t tag;
	size_t len;
	bool match;
} bench;

/*
 * One-way throughput against Code Construct's mctp-bench on the BMC. Its
 * messages are type 0x7e with vendor ID bytes cc de f1; all fields are little
 * endian. Offsets below count the message type byte, which libmctp keeps at
 * the front of the message (the Linux socket API strips it).
 *
 * Data:    [4] magic 0xbeca, [6] u32 sequence number, [10..] byte i of the
 *          socket-level message (that is, our byte i + 1) is i & 0xff.
 * Command: [4] magic 0x22dd, [6] version 1, [7] command, [8] u32 instance ID,
 *          [12] body. REQUEST_BENCH (1) asks us to stream data to the sender
 *          (body: u32 flags, u16 message length, u64 message count) and is
 *          answered with a RESPONSE (0) carrying a one-byte status.
 *
 * "mctp-bench send" streams to us; we check and count what arrives.
 * "mctp-bench recv eid <ours>" sends REQUEST_BENCH; a sender thread then
 * streams to it, as does "mbench tx" for a plain "mctp-bench recv".
 */
#define MB_TYPE			0x7e
#define MB_PREFIX_LEN		4
#define MB_MAGIC_OFF		4
#define MB_DATA_MAGIC		0xbeca
#define MB_SEQ_OFF		6
#define MB_DATA_HDR_LEN		10
#define MB_CMD_MAGIC		0x22dd
#define MB_CMD_VERSION		1
#define MB_CMD_RESPONSE		0x00
#define MB_CMD_REQUEST_BENCH	0x01
#define MB_CMD_HDR_LEN		12
#define MB_REQ_BENCH_LEN	(MB_CMD_HDR_LEN + 14)
#define MB_STATUS_SUCCESS	0x00
#define MB_STATUS_UNKNOWN_CMD	0x02
#define MB_STATUS_BAD_ARG	0x03
#define MB_SEQ_START		(UINT32_MAX - 5)
/* mctp-bench recv asks for "nearly 2**64" messages when given no count */
#define MB_COUNT_FOREVER	UINT64_MAX
#define MB_TX_TAG		0
#define MB_TX_STACK_SIZE	2048
/*
 * As low as the shell and logging threads, yielding to them after every
 * message: building a message keeps this CPU busy far longer than the bus
 * makes it wait, so at a higher priority the stream starves the console.
 */
#define MB_TX_PRIORITY		K_LOWEST_APPLICATION_THREAD_PRIO
#define MB_TX_RETRY_MS		1
/*
 * Failed sends in a row before the stream gives up: the peer is gone (USB
 * unplugged, I3C controller not reading), so retrying would never finish
 * and would keep the bus lock busy for nothing.
 */
#define MB_TX_MAX_RETRIES	100

static const uint8_t mb_prefix[MB_PREFIX_LEN] = {MB_TYPE, 0xcc, 0xde, 0xf1};

/* Receive side, updated in the rx callbacks under stats_lock */
static struct {
	bool started;
	uint32_t prev_seq;
	uint32_t msgs;
	uint32_t dropped;
	uint32_t invalid;
	uint64_t bytes;
	int64_t t_first;
	int64_t t_last;
} mb_rx;

/* Send side: one stream at a time, run by mb_tx_thread */
static struct {
	struct eval_bus *bus;
	uint8_t eid;
	size_t len;
	uint64_t count;
	/* Claimed by mb_tx_begin(), which the shell and both buses' rx call */
	atomic_t running;
	volatile bool stop;
	uint64_t sent;
	uint32_t errors;
	int64_t t_start;
	int64_t t_end;
} mb_tx;

/*
 * Guards what the shell reports of mb_tx (bus to t_end but stop), which the
 * stream thread and mb_tx_begin() write while the shell reads them: sent
 * and the times are 64-bit, so a plain read can tear
 */
static struct k_spinlock mb_tx_lock;

static uint8_t mb_tx_msg[CONFIG_MCTP_MAX_MESSAGE_SIZE];
static K_SEM_DEFINE(mb_tx_start, 0, 1);

/* Messages missing between two sequence numbers, as mctp-bench counts them */
static uint32_t mb_seq_gap(uint32_t cur, uint32_t prev)
{
	if (prev < cur) {
		return cur - prev - 1;
	} else if (cur == prev) {
		return 0;
	}
	return UINT32_MAX - prev + cur;
}

static void mb_rx_data(const uint8_t *msg, size_t len)
{
	uint32_t seq = sys_get_le32(&msg[MB_SEQ_OFF]);
	int64_t now = k_uptime_get();
	bool valid = true;
	k_spinlock_key_t key;

	for (size_t i = MB_DATA_HDR_LEN; i < len; i++) {
		if (msg[i] != ((i - 1) & 0xff)) {
			valid = false;
			break;
		}
	}

	key = k_spin_lock(&stats_lock);
	if (!mb_rx.started) {
		mb_rx.started = true;
		mb_rx.t_first = now;
		mb_rx.dropped += mb_seq_gap(seq, MB_SEQ_START);
	} else {
		mb_rx.dropped += mb_seq_gap(seq, mb_rx.prev_seq);
	}

	mb_rx.prev_seq = seq;
	mb_rx.t_last = now;
	mb_rx.msgs++;
	/* Socket-level length, as mctp-bench reports it */
	mb_rx.bytes += len - 1;
	if (!valid) {
		mb_rx.invalid++;
	}
	k_spin_unlock(&stats_lock, key);
}

/* Stream payload: the socket-level message mctp-bench send would build */
static void mb_tx_fill(size_t len)
{
	memcpy(mb_tx_msg, mb_prefix, MB_PREFIX_LEN);
	sys_put_le16(MB_DATA_MAGIC, &mb_tx_msg[MB_MAGIC_OFF]);
	for (size_t i = MB_DATA_HDR_LEN; i < len; i++) {
		mb_tx_msg[i] = (i - 1) & 0xff;
	}
}

/*
 * mctp_message_tx() on a bus, with its lock held. A binding drops a packet it
 * can't send rather than fail it (see mctp_usb_tx()), so a drop shows only in
 * its tx_errors: -EIO if this message lost a packet on the way out.
 */
static int eval_bus_tx(struct eval_bus *bus, uint8_t eid, bool tag_owner, uint8_t tag,
		       const void *msg, size_t len)
{
	uint32_t drops = *bus->tx_errors;
	int ret = mctp_message_tx(bus->mctp, eid, tag_owner, tag, msg, len);

	if (!ret && *bus->tx_errors != drops) {
		ret = -EIO;
	}

	return ret;
}

/* Start a stream; len counts the type byte. Fails if one is running */
static int mb_tx_begin(struct eval_bus *bus, uint8_t eid, size_t len, uint64_t count)
{
	if (len < MB_DATA_HDR_LEN || len > sizeof(mb_tx_msg) || !count) {
		return -EINVAL;
	}

	if (!atomic_cas(&mb_tx.running, 0, 1)) {
		return -EBUSY;
	}

	/* Ours until mb_tx_thread clears running */
	k_spinlock_key_t key = k_spin_lock(&mb_tx_lock);

	mb_tx.bus = bus;
	mb_tx.eid = eid;
	mb_tx.len = len;
	mb_tx.count = count;
	mb_tx.sent = 0;
	mb_tx.errors = 0;
	mb_tx.t_start = k_uptime_get();
	mb_tx.t_end = 0;
	k_spin_unlock(&mb_tx_lock, key);
	mb_tx.stop = false;
	k_sem_give(&mb_tx_start);

	return 0;
}

static void mb_rx_command(struct eval_bus *bus, uint8_t src_eid, uint8_t msg_tag,
			  const uint8_t *msg, size_t len)
{
	uint8_t rsp[MB_CMD_HDR_LEN + 1];
	uint8_t status = MB_STATUS_SUCCESS;
	int ret;

	if (len < MB_CMD_HDR_LEN || msg[6] != MB_CMD_VERSION) {
		LOG_WRN("mbench: bad command from eid 0x%02x (%zu bytes)", src_eid, len);
		return;
	}

	if (msg[7] != MB_CMD_REQUEST_BENCH) {
		status = MB_STATUS_UNKNOWN_CMD;
	} else if (len < MB_REQ_BENCH_LEN) {
		status = MB_STATUS_BAD_ARG;
	} else {
		/* The requested length is the socket-level one, without the type byte */
		size_t msg_len = sys_get_le16(&msg[MB_CMD_HDR_LEN + 4]) + 1;
		uint64_t count = sys_get_le64(&msg[MB_CMD_HDR_LEN + 6]);

		ret = mb_tx_begin(bus, src_eid, msg_len, count);
		if (ret) {
			status = MB_STATUS_BAD_ARG;
			LOG_WRN("mbench: can't stream %zu-byte messages to eid 0x%02x (%d)",
				msg_len - 1, src_eid, ret);
		} else {
			LOG_INF("mbench: streaming %zu-byte messages to eid 0x%02x on %s",
				msg_len - 1, src_eid, bus->name);
		}
	}

	/* Header echoes the request's instance ID; the stream starts after we return */
	memcpy(rsp, msg, MB_CMD_HDR_LEN);
	rsp[7] = MB_CMD_RESPONSE;
	rsp[MB_CMD_HDR_LEN] = status;
	ret = eval_bus_tx(bus, src_eid, false, msg_tag, rsp, sizeof(rsp));
	if (ret) {
		LOG_ERR("mbench: response to eid 0x%02x failed (%d)", src_eid, ret);
	}
}

/* Called from the rx callback with the bus lock held; true if it was mctp-bench's */
static bool mbench_rx(struct eval_bus *bus, uint8_t src_eid, bool tag_owner, uint8_t msg_tag,
		      const uint8_t *msg, size_t len)
{
	uint16_t magic;

	if (!tag_owner || len < MB_SEQ_OFF || memcmp(msg, mb_prefix, MB_PREFIX_LEN)) {
		return false;
	}

	magic = sys_get_le16(&msg[MB_MAGIC_OFF]);
	if (magic == MB_DATA_MAGIC && len >= MB_DATA_HDR_LEN) {
		mb_rx_data(msg, len);
	} else if (magic == MB_CMD_MAGIC) {
		mb_rx_command(bus, src_eid, msg_tag, msg, len);
	} else {
		stats_add(&mb_rx.invalid, 1);
	}

	return true;
}

static void mb_tx_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (true) {
		struct eval_bus *bus;
		uint32_t seq = MB_SEQ_START;
		uint32_t retries = 0;
		k_spinlock_key_t key;
		int ret;

		k_sem_take(&mb_tx_start, K_FOREVER);
		bus = mb_tx.bus;
		mb_tx_fill(mb_tx.len);

		while (!mb_tx.stop &&
		       (mb_tx.count == MB_COUNT_FOREVER || mb_tx.sent < mb_tx.count)) {
			sys_put_le32(seq, &mb_tx_msg[MB_SEQ_OFF]);

			k_mutex_lock(bus->lock, K_FOREVER);
			ret = eval_bus_tx(bus, mb_tx.eid, true, MB_TX_TAG, mb_tx_msg, mb_tx.len);
			k_mutex_unlock(bus->lock);

			if (ret) {
				/*
				 * Not sent, or lost a packet that the receiver
				 * discards it for: a retry reuses the number,
				 * so the receiver sees no gap
				 */
				key = k_spin_lock(&mb_tx_lock);
				mb_tx.errors++;
				k_spin_unlock(&mb_tx_lock, key);
				if (++retries >= MB_TX_MAX_RETRIES) {
					LOG_WRN("mbench: %u sends in a row to eid 0x%02x failed (%d), "
						"stopping", retries, mb_tx.eid, ret);
					break;
				}
				k_msleep(MB_TX_RETRY_MS);
				continue;
			}

			retries = 0;
			seq++;
			key = k_spin_lock(&mb_tx_lock);
			mb_tx.sent++;
			k_spin_unlock(&mb_tx_lock, key);
			k_yield();
		}

		key = k_spin_lock(&mb_tx_lock);
		mb_tx.t_end = k_uptime_get();
		k_spin_unlock(&mb_tx_lock, key);
		/* Before clearing running: a stream started after it reuses mb_tx */
		LOG_INF("mbench: sent %llu messages to eid 0x%02x, %u errors",
			(unsigned long long)mb_tx.sent, mb_tx.eid, mb_tx.errors);
		atomic_clear(&mb_tx.running);
	}
}

K_THREAD_DEFINE(mb_tx_tid, MB_TX_STACK_SIZE, mb_tx_thread, NULL, NULL, NULL, MB_TX_PRIORITY, 0,
		0);

/* Every packet in and out, control traffic included; the bus lock is held */
static void mctp_eval_capture(struct mctp_pktbuf *pkt, bool outgoing, void *user)
{
	const struct eval_bus *bus = user;
	/* Whole packet; mctp_pktbuf_data() would skip the MCTP header */
	const uint8_t *hdr = (const uint8_t *)mctp_pktbuf_hdr(pkt);
	size_t len = mctp_pktbuf_size(pkt);

	if (!rx_dump) {
		return;
	}

	if (len < sizeof(struct mctp_hdr)) {
		LOG_INF("%s %s %zu-byte runt", bus->name, outgoing ? "tx" : "rx", len);
		return;
	}

	LOG_INF("%s %s pkt %zu bytes: dst 0x%02x src 0x%02x flags 0x%02x", bus->name,
		outgoing ? "tx" : "rx", len, hdr[1], hdr[2], hdr[3]);
	LOG_HEXDUMP_INF(hdr, len, outgoing ? "tx" : "rx");
}

/* Called from inside mctp_bus_rx(), with the bus lock held */
static void mctp_eval_rx(uint8_t src_eid, bool tag_owner, uint8_t msg_tag, void *data,
			 void *msg, size_t len)
{
	struct eval_bus *bus = data;
	uint8_t type = len ? ((uint8_t *)msg)[0] & MCTP_MSG_TYPE_MASK : 0;
	k_spinlock_key_t key;
	int ret;

	if (bench.active && bus == bench.bus && !tag_owner && src_eid == bench.eid &&
	    msg_tag == bench.tag) {
		bench.match = len == bench.len && !memcmp(msg, bench_msg, len);
		k_sem_give(&bench_done);
		return;
	}

	if (mbench_rx(bus, src_eid, tag_owner, msg_tag, msg, len)) {
		return;
	}

#ifdef CONFIG_MCTP_EVAL_PLDM
	if (mctp_eval_pldm_rx(bus, src_eid, tag_owner, msg_tag, msg, len)) {
		return;
	}
#endif

#ifdef CONFIG_MCTP_EVAL_SPDM_BRIDGE
	if (mctp_eval_spdm_rx(bus, src_eid, tag_owner, msg_tag, msg, len)) {
		return;
	}
#endif

	key = k_spin_lock(&stats_lock);
	stats.msgs++;
	stats.bytes += len;
	k_spin_unlock(&stats_lock, key);

	LOG_INF("%s rx msg from eid 0x%02x: type 0x%02x, %zu bytes, %s tag %u", bus->name,
		src_eid, type, len, tag_owner ? "request" : "response", msg_tag);

	/* Echo requests only, never responses, so two echoing ends can't loop */
	if (!rx_echo || !tag_owner || type == MCTP_MSG_TYPE_CONTROL) {
		return;
	}

	ret = eval_bus_tx(bus, src_eid, false, msg_tag, msg, len);
	if (ret) {
		stats_add(&stats.tx_errors, 1);
		LOG_ERR("%s echo to eid 0x%02x failed (%d)", bus->name, src_eid, ret);
		return;
	}
	stats_add(&stats.echoed, 1);
}

uint8_t mctp_eval_next_tag(void)
{
	return atomic_inc(&send_tag) & MCTP_TAG_MASK;
}

static int mctp_eval_bus_init(struct eval_bus *bus, struct mctp_binding *binding)
{
	int ret;

	bus->mctp = mctp_init();
	if (!bus->mctp) {
		LOG_ERR("%s: mctp_init failed", bus->name);
		return -ENOMEM;
	}

	mctp_set_rx_all(bus->mctp, mctp_eval_rx, bus);
	mctp_set_capture_handler(bus->mctp, mctp_eval_capture, bus);

#ifdef CONFIG_MCTP_EVAL_PLDM
	ret = mctp_eval_pldm_bus_init(bus);
	if (ret) {
		LOG_ERR("%s: adding PLDM message type failed (%d)", bus->name, ret);
		goto err;
	}
#endif

#ifdef CONFIG_MCTP_EVAL_SPDM_BRIDGE
	ret = mctp_eval_spdm_bus_init(bus);
	if (ret) {
		LOG_ERR("%s: adding SPDM message type failed (%d)", bus->name, ret);
		goto err;
	}
#endif

	ret = mctp_register_bus(bus->mctp, binding, CONFIG_MCTP_EVAL_LOCAL_EID);
	if (ret) {
		LOG_ERR("%s: mctp_register_bus failed (%d)", bus->name, ret);
		goto err;
	}

	return 0;

err:
	mctp_destroy(bus->mctp);
	bus->mctp = NULL;
	return ret;
}

#ifdef CONFIG_MCTP_EVAL_USB
static int mctp_eval_usb_add_config(const enum usbd_speed speed,
				    struct usbd_config_node *const config)
{
	int err;

	err = usbd_add_configuration(&eval_usbd, speed, config);
	if (err) {
		LOG_ERR("usb: add %s configuration failed (%d)",
			speed == USBD_SPEED_HS ? "HS" : "FS", err);
		return err;
	}

	err = usbd_register_all_classes(&eval_usbd, speed, 1);
	if (err) {
		LOG_ERR("usb: register classes failed (%d)", err);
		return err;
	}

	/* The MCTP class code lives in the interface descriptor */
	return usbd_device_set_code_triple(&eval_usbd, speed, 0, 0, 0);
}

static int mctp_eval_usb_init(void)
{
	int err;

	err = usbd_add_descriptor(&eval_usbd, &eval_lang);
	err = err ? err : usbd_add_descriptor(&eval_usbd, &eval_mfr);
	err = err ? err : usbd_add_descriptor(&eval_usbd, &eval_product);
	if (err) {
		LOG_ERR("usb: add string descriptors failed (%d)", err);
		return err;
	}

	if (usbd_caps_speed(&eval_usbd) == USBD_SPEED_HS) {
		err = mctp_eval_usb_add_config(USBD_SPEED_HS, &eval_hs_config);
		if (err) {
			return err;
		}
	}

	err = mctp_eval_usb_add_config(USBD_SPEED_FS, &eval_fs_config);
	if (err) {
		return err;
	}

	err = usbd_init(&eval_usbd);
	if (err) {
		LOG_ERR("usb: usbd_init failed (%d)", err);
		return err;
	}

	err = usbd_enable(&eval_usbd);
	if (err) {
		LOG_ERR("usb: usbd_enable failed (%d)", err);
		/* The caller destroys the bus: leave no class bound to it */
		(void)usbd_shutdown(&eval_usbd);
	}

	return err;
}
#endif

int main(void)
{
	int ret;

#ifdef CONFIG_MCTP_EVAL_PLDM
	/*
	 * Before the buses: their rx callbacks hand PLDM to it. Without it
	 * the buses still run, and PLDM messages are handled like any other.
	 */
	ret = mctp_eval_pldm_init();
	if (ret) {
		LOG_ERR("PLDM responder not started (%d)", ret);
	}
#endif

#ifdef CONFIG_MCTP_EVAL_SPDM_BRIDGE
	/* Likewise for SPDM */
	ret = mctp_eval_spdm_init();
	if (ret) {
		return ret;
	}
#endif

	/* Each bus runs on its own: one failing to start leaves the other up */
	if (!mctp_eval_bus_init(&bus_i3c, &mctp_i3c0.binding)) {
		LOG_INF("MCTP eval: i3c endpoint on %s, local eid 0x%02x", mctp_i3c0.tmq->name,
			CONFIG_MCTP_EVAL_LOCAL_EID);
	}

#ifdef CONFIG_MCTP_EVAL_USB
	if (!mctp_eval_bus_init(&bus_usb, &mctp_usb0.binding)) {
		if (mctp_eval_usb_init()) {
			/* Not reachable, so not offered to the shell either */
			k_mutex_lock(bus_usb.lock, K_FOREVER);
			mctp_destroy(bus_usb.mctp);
			bus_usb.mctp = NULL;
			k_mutex_unlock(bus_usb.lock);
		} else {
			LOG_INF("MCTP eval: usb endpoint on %s, %04x:%04x",
				DEVICE_DT_GET(DT_NODELABEL(zephyr_udc0))->name,
				CONFIG_MCTP_EVAL_USB_VID, CONFIG_MCTP_EVAL_USB_PID);
		}
	}

	if (!bus_i3c.mctp) {
		cur_bus = &bus_usb;
	}
#endif

	if (!bus_i3c.mctp) {
		/* USB runs from the USB stack's threads; nothing left to poll */
		return 0;
	}

	while (true) {
		k_mutex_lock(bus_i3c.lock, K_FOREVER);
		ret = mctp_i3c_tmq_poll(&mctp_i3c0);
		k_mutex_unlock(bus_i3c.lock);

		if (ret <= 0) {
			k_usleep(RX_POLL_US);
		}
	}

	return 0;
}

static int cmd_stats(const struct shell *sh, size_t argc, char **argv)
{
	__typeof__(stats) app;
	k_spinlock_key_t key;

	if (argc > 1 && !strcmp(argv[1], "reset")) {
		key = k_spin_lock(&stats_lock);
		memset(&stats, 0, sizeof(stats));
		k_spin_unlock(&stats_lock, key);
		/* The bindings count under their bus locks */
		k_mutex_lock(bus_i3c.lock, K_FOREVER);
		memset(&mctp_i3c0.stats, 0, sizeof(mctp_i3c0.stats));
		k_mutex_unlock(bus_i3c.lock);
#ifdef CONFIG_MCTP_EVAL_USB
		k_mutex_lock(bus_usb.lock, K_FOREVER);
		memset(&mctp_usb0.stats, 0, sizeof(mctp_usb0.stats));
		k_mutex_unlock(bus_usb.lock);
#endif
		return 0;
	}

	shell_print(sh, "i3c binding rx packets: %u", mctp_i3c0.stats.rx_pkts);
	shell_print(sh, "i3c binding rx drops:   %u", mctp_i3c0.stats.rx_drops);
	shell_print(sh, "i3c binding rx PEC err: %u", mctp_i3c0.stats.rx_pec_errors);
	shell_print(sh, "i3c binding tx packets: %u", mctp_i3c0.stats.tx_pkts);
	shell_print(sh, "i3c binding tx errors:  %u", mctp_i3c0.stats.tx_errors);
#ifdef CONFIG_MCTP_EVAL_USB
	shell_print(sh, "usb binding rx packets: %u", mctp_usb0.stats.rx_pkts);
	shell_print(sh, "usb binding rx drops:   %u", mctp_usb0.stats.rx_drops);
	shell_print(sh, "usb binding rx starved: %u", (uint32_t)atomic_get(&mctp_usb0.stats.rx_out_starved));
	shell_print(sh, "usb binding tx packets: %u", mctp_usb0.stats.tx_pkts);
	shell_print(sh, "usb binding tx errors:  %u", mctp_usb0.stats.tx_errors);
#endif
	key = k_spin_lock(&stats_lock);
	app = stats;
	k_spin_unlock(&stats_lock, key);

	shell_print(sh, "app rx messages:        %u", app.msgs);
	shell_print(sh, "app rx bytes:           %u", app.bytes);
	shell_print(sh, "app echoed:             %u", app.echoed);
	shell_print(sh, "app tx errors:          %u", app.tx_errors);

	return 0;
}

static int cmd_dump(const struct shell *sh, size_t argc, char **argv)
{
	rx_dump = strtoul(argv[1], NULL, 0) != 0;
	shell_print(sh, "packet dump %s", rx_dump ? "on" : "off");

	return 0;
}

static int cmd_echo(const struct shell *sh, size_t argc, char **argv)
{
	rx_echo = strtoul(argv[1], NULL, 0) != 0;
	shell_print(sh, "echo %s", rx_echo ? "on" : "off");

	return 0;
}

/* The bus send, bench and mbench tx use, or NULL if it isn't running */
static struct eval_bus *shell_bus(const struct shell *sh)
{
	struct eval_bus *bus = cur_bus;

	if (!bus->mctp) {
		shell_error(sh, "%s: not running", bus->name);
		return NULL;
	}

	return bus;
}

static int cmd_bus(const struct shell *sh, size_t argc, char **argv)
{
	if (argc > 1) {
		struct eval_bus *bus;

		if (!strcmp(argv[1], bus_i3c.name)) {
			bus = &bus_i3c;
#ifdef CONFIG_MCTP_EVAL_USB
		} else if (!strcmp(argv[1], bus_usb.name)) {
			bus = &bus_usb;
#endif
		} else {
			shell_error(sh, "unknown bus %s", argv[1]);
			return -EINVAL;
		}

		if (!bus->mctp) {
			shell_error(sh, "%s: not running", bus->name);
			return -ENODEV;
		}
		cur_bus = bus;
	}

	shell_print(sh, "send/bench bus: %s", cur_bus->name);

	return 0;
}

static int cmd_send(const struct shell *sh, size_t argc, char **argv)
{
	struct eval_bus *bus = shell_bus(sh);
	uint8_t msg[SEND_MAX_LEN];
	uint8_t eid = strtoul(argv[1], NULL, 0);
	size_t len = argc - 2;
	uint8_t tag;
	int ret;

	if (!bus) {
		return -ENODEV;
	}

	if (len > sizeof(msg)) {
		shell_error(sh, "at most %zu bytes", sizeof(msg));
		return -EINVAL;
	}

	for (size_t i = 0; i < len; i++) {
		msg[i] = strtoul(argv[2 + i], NULL, 0);
	}

	k_mutex_lock(bus->lock, K_FOREVER);
	tag = mctp_eval_next_tag();
	ret = eval_bus_tx(bus, eid, true, tag, msg, len);
	k_mutex_unlock(bus->lock);

	if (ret) {
		stats_add(&stats.tx_errors, 1);
		shell_error(sh, "%s: send to eid 0x%02x failed (%d%s)", bus->name, eid, ret,
			    ret == -EIO ? ", the binding dropped a packet" : "");
		return ret;
	}

	shell_print(sh, "%s: sent %zu bytes to eid 0x%02x, tag %u", bus->name, len, eid, tag);

	return 0;
}

static int cmd_bench(const struct shell *sh, size_t argc, char **argv)
{
	struct eval_bus *bus = shell_bus(sh);
	uint8_t eid = strtoul(argv[1], NULL, 0);
	unsigned long payload = strtoul(argv[2], NULL, 0);
	size_t len;
	uint32_t count = argc > 3 ? strtoul(argv[3], NULL, 0) : 100;
	uint64_t sum_rtt = 0, sum_tx = 0;
	uint32_t min_rtt = UINT32_MAX, max_rtt = 0;
	uint32_t ok = 0, t0, t1, t2, rtt, tx;
	int ret = 0;

	if (!bus) {
		return -ENODEV;
	}

	/* Checked before adding the header, so a huge or negative one can't wrap */
	if (argv[2][0] == '-' || payload > sizeof(bench_msg) - BENCH_HDR_LEN || !count) {
		shell_error(sh, "payload must be 0..%zu bytes, count >= 1",
			    sizeof(bench_msg) - BENCH_HDR_LEN);
		return -EINVAL;
	}
	len = BENCH_HDR_LEN + payload;

	memcpy(bench_msg, bench_hdr, BENCH_HDR_LEN);
	for (size_t i = BENCH_HDR_LEN; i < len; i++) {
		bench_msg[i] = i - BENCH_HDR_LEN;
	}

	bench.bus = bus;
	bench.eid = eid;
	bench.len = len;

	for (uint32_t n = 0; n < count; n++) {
		k_sem_reset(&bench_done);

		k_mutex_lock(bus->lock, K_FOREVER);
		bench.tag = mctp_eval_next_tag();
		bench.active = true;
		t0 = k_cycle_get_32();
		/* I3C returns once the bus owner has read every packet; USB once queued */
		ret = eval_bus_tx(bus, eid, true, bench.tag, bench_msg, len);
		t1 = k_cycle_get_32();
		k_mutex_unlock(bus->lock);

		if (ret) {
			shell_error(sh, "#%u: send failed (%d)", n, ret);
			break;
		}

		if (k_sem_take(&bench_done, K_MSEC(BENCH_TIMEOUT_MS))) {
			shell_error(sh, "#%u: no reply within %d ms", n, BENCH_TIMEOUT_MS);
			ret = -ETIMEDOUT;
			break;
		}
		t2 = k_cycle_get_32();

		if (!bench.match) {
			shell_error(sh, "#%u: reply does not match the request", n);
			ret = -EIO;
			break;
		}

		ok++;
		rtt = k_cyc_to_us_near32(t2 - t0);
		tx = k_cyc_to_us_near32(t1 - t0);
		sum_rtt += rtt;
		sum_tx += tx;
		min_rtt = MIN(min_rtt, rtt);
		max_rtt = MAX(max_rtt, rtt);
	}

	/* Under the lock the rx callback reads it with */
	k_mutex_lock(bus->lock, K_FOREVER);
	bench.active = false;
	k_mutex_unlock(bus->lock);

	shell_print(sh, "%u/%u ok on %s, %zu-byte payload (%zu-byte message) to eid 0x%02x", ok,
		    count, bus->name, len - BENCH_HDR_LEN, len, eid);
	if (ok) {
		/* At least 1 us, for the throughput division */
		uint32_t avg = MAX(sum_rtt / ok, 1);

		shell_print(sh, "rtt us: min %u avg %u max %u", min_rtt, avg, max_rtt);
		shell_print(sh, "  send:  avg %u us", (uint32_t)(sum_tx / ok));
		shell_print(sh, "  reply: avg %u us", avg - (uint32_t)(sum_tx / ok));
		shell_print(sh, "echo throughput: %u KB/s",
			    (uint32_t)(2ULL * (len - BENCH_HDR_LEN) * 1000000ULL / avg / 1000));
	}

	return ret;
}

/* kB/s as mctp-bench prints it (1024-byte kB), with two decimals */
static void mb_print_rate(const struct shell *sh, const char *what, uint64_t bytes, int64_t ms)
{
	uint64_t centi = ms > 0 ? bytes * 100000ULL / 1024 / (uint64_t)ms : 0;

	shell_print(sh, "%s: %llu.%02llu kB/s over %lld ms", what,
		    (unsigned long long)(centi / 100), (unsigned long long)(centi % 100), ms);
}

static int cmd_mbench_rx(const struct shell *sh, size_t argc, char **argv)
{
	__typeof__(mb_rx) rx;
	k_spinlock_key_t key = k_spin_lock(&stats_lock);

	if (argc > 1 && !strcmp(argv[1], "reset")) {
		memset(&mb_rx, 0, sizeof(mb_rx));
		k_spin_unlock(&stats_lock, key);
		return 0;
	}
	rx = mb_rx;
	k_spin_unlock(&stats_lock, key);

	shell_print(sh, "received: %u msgs, %llu bytes | dropped: %u | invalid: %u", rx.msgs,
		    (unsigned long long)rx.bytes, rx.dropped, rx.invalid);
	/* Rate from the first message on, which mctp-bench recv excludes from its count */
	if (rx.msgs > 1) {
		mb_print_rate(sh, "throughput", rx.bytes * (rx.msgs - 1) / rx.msgs,
			      rx.t_last - rx.t_first);
	}

	return 0;
}

static int cmd_mbench_tx(const struct shell *sh, size_t argc, char **argv)
{
	struct eval_bus *bus;
	uint8_t eid;
	size_t len;
	uint64_t count;
	int ret;

	if (argc == 1) {
		k_spinlock_key_t key = k_spin_lock(&mb_tx_lock);
		/* t_end is set just before running is cleared, so read them together */
		bool running = atomic_get(&mb_tx.running) && !mb_tx.t_end;
		const char *name = mb_tx.bus ? mb_tx.bus->name : "-";
		uint8_t eid = mb_tx.eid;
		size_t len = mb_tx.len;
		uint64_t sent = mb_tx.sent;
		uint32_t errors = mb_tx.errors;
		int64_t start = mb_tx.t_start;
		int64_t end = running ? k_uptime_get() : mb_tx.t_end;

		k_spin_unlock(&mb_tx_lock, key);

		shell_print(sh, "%s: %llu msgs to eid 0x%02x on %s, %u errors",
			    running ? "running" : "idle", (unsigned long long)sent, eid, name,
			    errors);
		if (sent) {
			mb_print_rate(sh, "throughput", sent * (len - 1), end - start);
		}
		return 0;
	}

	if (argc < 3) {
		shell_error(sh, "usage: mbench tx <eid> <len> [count]");
		return -EINVAL;
	}

	bus = shell_bus(sh);
	if (!bus) {
		return -ENODEV;
	}

	eid = strtoul(argv[1], NULL, 0);
	/* len as mctp-bench counts it: without the type byte */
	len = strtoul(argv[2], NULL, 0) + 1;
	count = argc > 3 ? strtoull(argv[3], NULL, 0) : MB_COUNT_FOREVER;

	ret = mb_tx_begin(bus, eid, len, count);
	if (ret == -EBUSY) {
		shell_error(sh, "a stream is already running (mbench stop)");
	} else if (ret) {
		shell_error(sh, "len must be %u..%zu, count >= 1", MB_DATA_HDR_LEN - 1,
			    sizeof(mb_tx_msg) - 1);
	} else {
		shell_print(sh, "streaming %zu-byte messages to eid 0x%02x on %s", len - 1, eid,
			    bus->name);
	}

	return ret;
}

static int cmd_mbench_stop(const struct shell *sh, size_t argc, char **argv)
{
	mb_tx.stop = true;

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_mbench,
	SHELL_CMD_ARG(rx, NULL, "Messages from mctp-bench send: rx [reset]", cmd_mbench_rx, 1, 1),
	SHELL_CMD_ARG(tx, NULL,
		      "Stream to mctp-bench recv, or show the stream: tx [<eid> <len> [count]]",
		      cmd_mbench_tx, 1, 3),
	SHELL_CMD(stop, NULL, "Stop the stream", cmd_mbench_stop),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_mctp_eval,
	SHELL_CMD_ARG(stats, NULL, "Show counters: stats [reset]", cmd_stats, 1, 1),
	SHELL_CMD_ARG(dump, NULL, "Log every packet in and out: dump <0|1>", cmd_dump, 2, 0),
	SHELL_CMD_ARG(echo, NULL, "Echo rx requests to the sender: echo <0|1>", cmd_echo, 2, 0),
	SHELL_CMD_ARG(bus, NULL, "Bus for send and bench: bus [i3c|usb]", cmd_bus, 1, 1),
	SHELL_CMD_ARG(bench, NULL,
		      "Round trips against mctp-echo: bench <eid> <payload len> [count]",
		      cmd_bench, 3, 1),
	SHELL_CMD_ARG(send, NULL, "Send a request: send <eid> <type> [byte ...]", cmd_send, 3,
		      SEND_MAX_LEN - 1),
	SHELL_CMD(mbench, &sub_mbench, "Throughput with the BMC's mctp-bench", NULL),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(mctp_eval, &sub_mctp_eval, "MCTP evaluation (I3C, USB)", NULL);
