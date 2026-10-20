/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * PLDM over MCTP (DSP0241) responder built on libpldm: its control responder
 * answers type 0 (GetTID, GetPLDMVersion, GetPLDMTypes, GetPLDMCommands) and
 * its firmware device responder runs type 5 (DSP0267) firmware updates.
 *
 * Each component the FD reports has its own flash partition:
 * - 0x0001, the boot image: pldm_update_partition
 * - 0x0002, the SSMCU XIP ROM: pldm_rom_partition, if the board defines it
 *   and CONFIG_MCTP_EVAL_PLDM_UNSAFE_COMPONENTS is set
 * - 0x0003, the IDevID certificate store: pldm_cert_partition, likewise
 * With CONFIG_MCTP_EVAL_PLDM_FLASH a component image is downloaded into flash:
 * each sector is erased just before the first chunk that lands in it, and
 * verify reads it back, PLDM_VERIFY_STEP at a time, and checks its CRC32
 * against the one of the data received. The erase runs in the bus rx
 * callback, so it holds up that bus for the sector erase time. If the board
 * defines pldm_staging_partition, the boot image downloads there, and apply
 * copies it into pldm_update_partition, PLDM_APPLY_STEP at a time, reading
 * each chunk back against the same CRC32: a transfer that fails or is
 * cancelled, or an image that doesn't verify, leaves the boot image as it
 * was, and only a reset during apply leaves it half written. Every other
 * component downloads straight into its partition. Without
 * CONFIG_MCTP_EVAL_PLDM_FLASH only the boot image component is offered, and
 * its image goes to a sink that counts and CRC32s it. Either way apply and
 * activate move the version strings along, and with
 * CONFIG_MCTP_EVAL_PLDM_REBOOT activation reboots into the new images.
 * "pldm" in the shell shows the result.
 *
 * Requests are answered in the bus rx callback, on the bus they came in on.
 * During an update the FD drives the transfer (RequestFirmwareData,
 * TransferComplete, VerifyComplete, ApplyComplete); those requests come out
 * of pldm_fd_progress(), which a thread calls whenever a response arrives and
 * at least once a second for retries and timeouts. The FD knows its peers by
 * a handle per (bus, EID), so the same EID on two buses is two peers: FD
 * requests go back to the bus the update agent is on, and the same EID on the
 * other bus can't act as the update agent. libpldm is not
 * thread-safe, so every call into it holds pldm_lock. Lock order is bus lock,
 * then pldm_lock: the rx path already holds its bus lock, and the progress
 * thread drops pldm_lock before taking one.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/crc.h>
#include <zephyr/sys/util.h>
#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
#include <zephyr/storage/flash_map.h>
#endif
#ifdef CONFIG_MCTP_EVAL_PLDM_REBOOT
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/sys/reboot.h>
#endif
#include <libpldm/base.h>
#include <libpldm/control.h>
#include <libpldm/firmware_fd.h>
#include <libpldm/firmware_update.h>
#include <libpldm/sizes.h>
#include "mctp_eval.h"

LOG_MODULE_REGISTER(mctp_eval_pldm, LOG_LEVEL_INF);

/* PLDM message buffers, after the MCTP message type byte */
#define PLDM_MSG_MAX		(CONFIG_MCTP_MAX_MESSAGE_SIZE - 1)
#define PLDM_HDR_LEN		3
#define PLDM_HDR_RQ		BIT(7)
#define PLDM_HDR_TYPE_MASK	0x3f
#define PLDM_PROGRESS_INTERVAL	K_MSEC(1000)
#define PLDM_THREAD_STACK_SIZE	2048
#define PLDM_THREAD_PRIORITY	K_LOWEST_APPLICATION_THREAD_PRIO
#define PLDM_COMP_ID_IMAGE	0x0001
#define PLDM_COMP_ID_ROM	0x0002
#define PLDM_COMP_ID_CERT	0x0003
#define PLDM_VERSION_STR	"mctp-eval " CONFIG_BOARD " " CONFIG_MCTP_EVAL_PLDM_VERSION
/* The app can't tell what the ROM and the certificates in flash are */
#define PLDM_ROM_VERSION_STR	"ssmcu-rom " CONFIG_BOARD
#define PLDM_CERT_VERSION_STR	"idevid-certs " CONFIG_BOARD
/* SPI NOR erases 4 KiB sectors */
#define PLDM_FLASH_SECTOR_SIZE	4096
#define PLDM_FLASH_READ_CHUNK	512
/*
 * Read back per verify call: pldm_lock, which the rx paths wait for with
 * their bus lock held, is held for this much at a time, not the whole image
 */
#define PLDM_VERIFY_STEP	(64 * 1024)
/* Copied per apply call; each step erases its sectors first */
#define PLDM_APPLY_STEP		(16 * 1024)
#define PLDM_REBOOT_DELAY	K_MSEC(500)
/* Distinct (bus, EID) pairs that can send firmware update messages */
#define PLDM_MAX_PEERS		16

/* Opaque in libpldm; sized from its internals by <libpldm/sizes.h> */
static struct pldm_control control;
static struct pldm_fd fd;
static K_MUTEX_DEFINE(pldm_lock);
static K_SEM_DEFINE(pldm_kick, 0, 1);

/*
 * Firmware update peers, under pldm_lock. Each bus is its own libmctp
 * instance with its own EIDs, so libpldm is given a peer's handle, its slot
 * + 1, as the address instead of the EID. Only a request takes a slot; with
 * the table full it takes the least recently heard one, except the update
 * agent's, whose handle libpldm keeps.
 */
static struct {
	struct eval_bus *bus;
	uint8_t eid;
	int64_t last_rx;
} peers[PLDM_MAX_PEERS];
/* Handle of the peer whose RequestUpdate was last accepted; 0 if none */
static pldm_tid_t ua_peer;
/* Set once the responder is up; until then PLDM is not served */
static bool pldm_ready;

/* rx path response buffer, under pldm_lock until sent */
static uint8_t rsp_buf[1 + PLDM_MSG_MAX];
/* Progress thread request buffer, used by that thread only */
static uint8_t req_buf[1 + PLDM_MSG_MAX];

static uint8_t uuid[16];
static const struct pldm_descriptor descriptors[] = {
	{
		.descriptor_type = PLDM_FWUP_UUID,
		.descriptor_length = sizeof(uuid),
		.descriptor_data = uuid,
	},
};

/* A firmware component, and the flash partition it is programmed into */
struct eval_comp {
	const char *name;
	struct pldm_firmware_component_standalone desc;
#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
	uint8_t fa_id;
	const struct flash_area *fa;
#endif
};

#define EVAL_COMP(_name, _id, _stamp, _version, _label)                                           \
	{                                                                                          \
		.name = (_name),                                                                   \
		.desc = {                                                                          \
			.comp_classification = PLDM_COMP_FIRMWARE,                                 \
			.comp_identifier = (_id),                                                  \
			.comp_classification_index = 0,                                            \
			.active_ver = {                                                            \
				.comparison_stamp = (_stamp),                                      \
				.str = {                                                           \
					.str_type = PLDM_STR_TYPE_ASCII,                           \
					.str_len = sizeof(_version) - 1,                           \
					.str_data = _version,                                      \
				},                                                                 \
			},                                                                         \
			.pending_ver = {                                                           \
				.str = {.str_type = PLDM_STR_TYPE_UNKNOWN},                        \
			},                                                                         \
			/* What it updates is only read at boot */                                 \
			IF_ENABLED(CONFIG_MCTP_EVAL_PLDM_FLASH, (.comp_activation_methods = {      \
				.value = BIT(PLDM_ACTIVATION_SYSTEM_REBOOT)},))                    \
		},                                                                                 \
		IF_ENABLED(CONFIG_MCTP_EVAL_PLDM_FLASH, (.fa_id = FIXED_PARTITION_ID(_label),))    \
	}

/* The first one is the image set: its versions are the ones the FD reports */
static struct eval_comp comps[] = {
	EVAL_COMP("image", PLDM_COMP_ID_IMAGE, 1, PLDM_VERSION_STR, pldm_update_partition),
/* It depends on CONFIG_MCTP_EVAL_PLDM_FLASH */
#ifdef CONFIG_MCTP_EVAL_PLDM_UNSAFE_COMPONENTS
#if FIXED_PARTITION_EXISTS(pldm_rom_partition)
	/* Stamp 0: any package's ROM or certificates count as newer */
	EVAL_COMP("xip-rom", PLDM_COMP_ID_ROM, 0, PLDM_ROM_VERSION_STR, pldm_rom_partition),
#endif
#if FIXED_PARTITION_EXISTS(pldm_cert_partition)
	EVAL_COMP("cert-store", PLDM_COMP_ID_CERT, 0, PLDM_CERT_VERSION_STR, pldm_cert_partition),
#endif
#endif /* CONFIG_MCTP_EVAL_PLDM_UNSAFE_COMPONENTS */
};
static const struct pldm_firmware_component_standalone *components_list[ARRAY_SIZE(comps)];

/* The update sink */
static struct {
	enum {
		IMG_IDLE,
		IMG_DOWNLOAD,
		IMG_VERIFIED,
		IMG_APPLIED,
		IMG_ACTIVATED,
		IMG_CANCELLED,
		IMG_FAILED,
	} state;
	/* The component being updated */
	struct eval_comp *comp;
	uint32_t size;
	uint32_t received;
	uint32_t chunks;
	uint32_t duplicates;
	uint32_t crc;
	/*
	 * Flash: where the image downloads (the component's partition or the
	 * staging one), bytes of it erased so far, read back, and their CRC32;
	 * then bytes copied into the component's partition and their CRC32
	 */
	const struct flash_area *dl_fa;
	uint32_t erased;
	uint32_t verified;
	uint32_t flash_crc;
	uint32_t applied;
	uint32_t apply_crc;
	int64_t t_start;
	int64_t t_end;
	struct pldm_firmware_string version;
} img;

#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
static uint8_t flash_read_buf[PLDM_FLASH_READ_CHUNK];
#if FIXED_PARTITION_EXISTS(pldm_staging_partition)
/* Where the boot image downloads, to be copied into place at apply */
static const struct flash_area *staging_fa;
#endif
#endif

static const char *const img_state_names[] = {
	"idle", "download", "verified", "applied", "activated", "cancelled", "failed",
};

static int fd_device_identifiers(void *ctx, uint8_t *count, const struct pldm_descriptor **descs)
{
	*count = ARRAY_SIZE(descriptors);
	*descs = descriptors;
	return 0;
}

static int fd_components(void *ctx, uint16_t *count,
			 const struct pldm_firmware_component_standalone ***entries)
{
	*count = ARRAY_SIZE(components_list);
	*entries = components_list;
	return 0;
}

static int fd_imageset_versions(void *ctx, struct pldm_firmware_string *active,
				struct pldm_firmware_string *pending)
{
	*active = comps[0].desc.active_ver.str;
	*pending = comps[0].desc.pending_ver.str;
	return 0;
}

/* libpldm only passes on components that fd_components() lists */
static struct eval_comp *comp_find(uint16_t id)
{
	ARRAY_FOR_EACH_PTR(comps, c) {
		if (c->desc.comp_identifier == id) {
			return c;
		}
	}

	return NULL;
}

static enum pldm_component_response_codes
fd_update_component(void *ctx, bool update, const struct pldm_firmware_update_component *comp)
{
	struct eval_comp *c = comp_find(comp->comp_identifier);

	if (!c) {
		return PLDM_CRC_COMP_NOT_SUPPORTED;
	}

#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
	const struct flash_area *dl_fa = c->fa;

#if FIXED_PARTITION_EXISTS(pldm_staging_partition)
	if (c->desc.comp_identifier == PLDM_COMP_ID_IMAGE) {
		dl_fa = staging_fa;
	}
#endif
	if (comp->comp_image_size > MIN(c->fa->fa_size, dl_fa->fa_size)) {
		LOG_ERR("pldm: %u-byte %s image doesn't fit the %zu-byte partition",
			comp->comp_image_size, c->name, MIN(c->fa->fa_size, dl_fa->fa_size));
		return PLDM_CRC_COMP_PREREQUISITES_NOT_MET;
	}
#endif

	/* PassComponentTable (update false) only asks; UpdateComponent starts it */
	if (!update) {
		return PLDM_CRC_COMP_CAN_BE_UPDATED;
	}

	memset(&img, 0, sizeof(img));
	img.state = IMG_DOWNLOAD;
	img.comp = c;
	img.size = comp->comp_image_size;
	img.version = comp->version;
	img.t_start = k_uptime_get();
#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
	img.dl_fa = dl_fa;
#endif
	LOG_INF("pldm: update component 0x%04x (%s), %u bytes, version \"%.*s\"",
		comp->comp_identifier, c->name, img.size, img.version.str_len,
		img.version.str_data);

	return PLDM_CRC_COMP_CAN_BE_UPDATED;
}

static uint32_t fd_transfer_size(void *ctx, uint32_t ua_max_transfer_size)
{
	return MIN(ua_max_transfer_size, CONFIG_MCTP_EVAL_PLDM_TRANSFER_SIZE);
}

static uint8_t fd_firmware_data(void *ctx, uint32_t offset, const uint8_t *data, uint32_t len,
				const struct pldm_firmware_update_component *comp)
{
	/* As written, offset + len could wrap */
	if (len > img.size || offset > img.size - len) {
		img.state = IMG_FAILED;
		return PLDM_FWUP_TRANSFER_ERROR_IMAGE_CORRUPT;
	}

	/* A retried request can deliver a chunk we already have */
	if (offset < img.received) {
		img.duplicates++;
		return PLDM_FWUP_TRANSFER_SUCCESS;
	}

	if (offset != img.received) {
		img.state = IMG_FAILED;
		return PLDM_FWUP_TRANSFER_ERROR_IMAGE_CORRUPT;
	}

#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
	int ret;

	while (img.erased < offset + len) {
		ret = flash_area_erase(img.dl_fa, img.erased, PLDM_FLASH_SECTOR_SIZE);
		if (ret) {
			LOG_ERR("pldm: flash erase at 0x%x failed (%d)", img.erased, ret);
			goto storage_error;
		}
		img.erased += PLDM_FLASH_SECTOR_SIZE;
	}

	ret = flash_area_write(img.dl_fa, offset, data, len);
	if (ret) {
		LOG_ERR("pldm: flash write at 0x%x failed (%d)", offset, ret);
		goto storage_error;
	}
#endif

	img.crc = crc32_ieee_update(img.crc, data, len);
	img.received += len;
	img.chunks++;
	if (img.received == img.size) {
		img.t_end = k_uptime_get();
	}

	return PLDM_FWUP_TRANSFER_SUCCESS;

#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
storage_error:
	img.state = IMG_FAILED;
	return PLDM_FWUP_FD_ABORTED_TRANSFER_STORAGE_ISSUE;
#endif
}

static uint8_t fd_verify(void *ctx, const struct pldm_firmware_update_component *comp,
			 bool *pending, uint8_t *progress_percent)
{
	*pending = false;

	if (img.received != img.size) {
		img.state = IMG_FAILED;
		return PLDM_FWUP_VERIFY_ERROR_IMAGE_INCOMPLETE;
	}

#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
	uint32_t end = MIN(img.size, img.verified + PLDM_VERIFY_STEP);

	if (!img.verified) {
		LOG_INF("pldm: received %u bytes in %u chunks, crc32 0x%08x", img.received,
			img.chunks, img.crc);
	}

	/* Read back what was programmed, a step per call */
	for (uint32_t off = img.verified; off < end; off += PLDM_FLASH_READ_CHUNK) {
		size_t n = MIN(PLDM_FLASH_READ_CHUNK, end - off);
		int ret = flash_area_read(img.dl_fa, off, flash_read_buf, n);

		if (ret) {
			LOG_ERR("pldm: flash read at 0x%x failed (%d)", off, ret);
			img.state = IMG_FAILED;
			return PLDM_FWUP_VERIFY_ERROR_VERIFICATION_FAILURE;
		}
		img.flash_crc = crc32_ieee_update(img.flash_crc, flash_read_buf, n);
	}
	img.verified = end;

	if (end < img.size) {
		/* libpldm calls again from the next progress; make that now */
		*pending = true;
		*progress_percent = (uint64_t)end * 100 / img.size;
		k_sem_give(&pldm_kick);
		return PLDM_FWUP_VERIFY_SUCCESS;
	}

	if (img.flash_crc != img.crc) {
		LOG_ERR("pldm: flash readback crc32 0x%08x, expected 0x%08x", img.flash_crc,
			img.crc);
		img.state = IMG_FAILED;
		return PLDM_FWUP_VERIFY_ERROR_VERIFICATION_FAILURE;
	}
	LOG_INF("pldm: flash readback matches");
#else
	LOG_INF("pldm: received %u bytes in %u chunks, crc32 0x%08x", img.received, img.chunks,
		img.crc);
#endif

	img.state = IMG_VERIFIED;

	return PLDM_FWUP_VERIFY_SUCCESS;
}

#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
/*
 * Copies the next PLDM_APPLY_STEP of a staged image into the component's
 * partition, reading each chunk back. Returns 0, or a negative errno.
 */
static int apply_step(void)
{
	const struct flash_area *fa = img.comp->fa;
	uint32_t end = MIN(img.size, img.applied + PLDM_APPLY_STEP);
	int ret;

	if (!img.applied) {
		LOG_INF("pldm: copying the staged %s into place", img.comp->name);
	}

	/* Partitions are whole sectors, so this stays inside fa */
	ret = flash_area_erase(fa, img.applied,
			       ROUND_UP(end - img.applied, PLDM_FLASH_SECTOR_SIZE));
	if (ret) {
		LOG_ERR("pldm: flash erase at 0x%x failed (%d)", img.applied, ret);
		return ret;
	}

	for (uint32_t off = img.applied; off < end; off += PLDM_FLASH_READ_CHUNK) {
		size_t n = MIN(PLDM_FLASH_READ_CHUNK, end - off);

		ret = flash_area_read(img.dl_fa, off, flash_read_buf, n);
		if (ret) {
			LOG_ERR("pldm: staging read at 0x%x failed (%d)", off, ret);
			return ret;
		}
		ret = flash_area_write(fa, off, flash_read_buf, n);
		if (ret) {
			LOG_ERR("pldm: flash write at 0x%x failed (%d)", off, ret);
			return ret;
		}
		ret = flash_area_read(fa, off, flash_read_buf, n);
		if (ret) {
			LOG_ERR("pldm: flash read at 0x%x failed (%d)", off, ret);
			return ret;
		}
		img.apply_crc = crc32_ieee_update(img.apply_crc, flash_read_buf, n);
	}
	img.applied = end;

	return 0;
}
#endif

static uint8_t fd_apply(void *ctx, const struct pldm_firmware_update_component *comp,
			bool *pending, uint8_t *progress_percent)
{
	*pending = false;

#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
	if (img.dl_fa != img.comp->fa) {
		if (apply_step()) {
			img.state = IMG_FAILED;
			return PLDM_FWUP_APPLY_FAILURE_MEMORY_ISSUE;
		}
		if (img.applied < img.size) {
			/* libpldm calls again from the next progress; make that now */
			*pending = true;
			*progress_percent = (uint64_t)img.applied * 100 / img.size;
			k_sem_give(&pldm_kick);
			return PLDM_FWUP_APPLY_SUCCESS;
		}
		if (img.apply_crc != img.crc) {
			LOG_ERR("pldm: %s readback crc32 0x%08x, expected 0x%08x",
				img.comp->name, img.apply_crc, img.crc);
			img.state = IMG_FAILED;
			return PLDM_FWUP_APPLY_FAILURE_MEMORY_ISSUE;
		}
		LOG_INF("pldm: %s copied into place, readback matches", img.comp->name);
	}
#endif

	img.state = IMG_APPLIED;
	img.comp->desc.pending_ver.comparison_stamp = comp->comp_comparison_stamp;
	img.comp->desc.pending_ver.str = comp->version;

	return PLDM_FWUP_APPLY_SUCCESS;
}

#ifdef CONFIG_MCTP_EVAL_PLDM_REBOOT
static void pldm_reboot_handler(struct k_work *work)
{
	/* Flush the deferred log, which the reset would otherwise lose */
	LOG_PANIC();
	sys_reboot(SYS_REBOOT_COLD);
}

static K_WORK_DELAYABLE_DEFINE(pldm_reboot_work, pldm_reboot_handler);
#endif

static uint8_t fd_activate(void *ctx, bool self_contained, uint16_t *estimated_time)
{
	bool activated = false;

	*estimated_time = 0;

	/* Every component applied in this update, which can be more than one */
	ARRAY_FOR_EACH_PTR(comps, c) {
		struct pldm_firmware_version *pending = &c->desc.pending_ver;

		if (pending->str.str_type == PLDM_STR_TYPE_UNKNOWN) {
			continue;
		}

		c->desc.active_ver = *pending;
		pending->comparison_stamp = 0;
		pending->str.str_type = PLDM_STR_TYPE_UNKNOWN;
		pending->str.str_len = 0;
		LOG_INF("pldm: activated %s \"%.*s\"", c->name, c->desc.active_ver.str.str_len,
			c->desc.active_ver.str.str_data);
		activated = true;
	}

	if (activated) {
		img.state = IMG_ACTIVATED;
#ifdef CONFIG_MCTP_EVAL_PLDM_REBOOT
		/* After the ActivateFirmware response has gone out */
		LOG_INF("pldm: rebooting into it");
		k_work_schedule(&pldm_reboot_work, PLDM_REBOOT_DELAY);
#elif defined(CONFIG_MCTP_EVAL_PLDM_FLASH)
		LOG_INF("pldm: reset to boot it");
#endif
	}

	return PLDM_SUCCESS;
}

static void fd_cancel_update_component(void *ctx,
				       const struct pldm_firmware_update_component *comp)
{
	img.state = IMG_CANCELLED;
	LOG_INF("pldm: update cancelled at %u of %u bytes", img.received, img.size);
#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
	if (img.applied) {
		LOG_WRN("pldm: the %s partition is left partly written; the staged image "
			"is intact", img.comp->name);
	} else if (img.erased && img.dl_fa == img.comp->fa) {
		LOG_WRN("pldm: the %s partition is left partly written", img.comp->name);
	}
#endif
}

static uint64_t fd_now(void *ctx)
{
	return k_uptime_get();
}

static const struct pldm_fd_ops fd_ops = {
	.device_identifiers = fd_device_identifiers,
	.components = fd_components,
	.imageset_versions = fd_imageset_versions,
	.update_component = fd_update_component,
	.transfer_size = fd_transfer_size,
	.firmware_data = fd_firmware_data,
	.verify = fd_verify,
	/* pldm_fd_setup() doesn't check it, but the apply state calls it */
	.apply = fd_apply,
	.activate = fd_activate,
	.cancel_update_component = fd_cancel_update_component,
	.now = fd_now,
};

/*
 * The handle of (bus, eid). A request from a new peer adds it; anything else
 * from one returns 0, since we only wait on responses from known peers.
 */
static pldm_tid_t pldm_peer_handle(struct eval_bus *bus, uint8_t eid, bool request)
{
	int64_t now = k_uptime_get();
	size_t slot = ARRAY_SIZE(peers);

	ARRAY_FOR_EACH(peers, i) {
		if (peers[i].bus == bus && peers[i].eid == eid) {
			peers[i].last_rx = now;
			return i + 1;
		}
	}

	if (!request) {
		return 0;
	}

	ARRAY_FOR_EACH(peers, i) {
		if (!peers[i].bus) {
			slot = i;
			break;
		}
		if (i + 1 != ua_peer &&
		    (slot == ARRAY_SIZE(peers) || peers[i].last_rx < peers[slot].last_rx)) {
			slot = i;
		}
	}

	if (slot == ARRAY_SIZE(peers)) {
		return 0;
	}

	if (peers[slot].bus) {
		LOG_INF("pldm: peer %zu now %s eid 0x%02x, was %s eid 0x%02x", slot + 1,
			bus->name, eid, peers[slot].bus->name, peers[slot].eid);
	}
	peers[slot].bus = bus;
	peers[slot].eid = eid;
	peers[slot].last_rx = now;

	return slot + 1;
}

/* Answer a request of a type we don't serve */
static int pldm_reply_invalid_type(const uint8_t *req, uint8_t *rsp, size_t *rsp_len)
{
	if (*rsp_len < PLDM_HDR_LEN + 1 ||
	    encode_cc_only_resp(req[0] & 0x1f, req[1] & PLDM_HDR_TYPE_MASK, req[2],
				PLDM_ERROR_INVALID_PLDM_TYPE, (struct pldm_msg *)rsp)) {
		return -EINVAL;
	}

	*rsp_len = PLDM_HDR_LEN + 1;
	return 0;
}

bool mctp_eval_pldm_rx(struct eval_bus *bus, uint8_t src_eid, bool tag_owner, uint8_t msg_tag,
		       const uint8_t *msg, size_t len)
{
	const uint8_t *pldm = msg + 1;
	size_t pldm_len = len - 1;
	size_t rsp_len = PLDM_MSG_MAX;
	uint8_t type;
	bool request;
	int ret;

	if (!pldm_ready || len < 1 || (msg[0] & MCTP_MSG_TYPE_MASK) != MCTP_MSG_TYPE_PLDM) {
		return false;
	}

	if (pldm_len < PLDM_HDR_LEN) {
		return true;
	}

	type = pldm[1] & PLDM_HDR_TYPE_MASK;
	request = (pldm[0] & PLDM_HDR_RQ) != 0;
	/* A PLDM request travels as an MCTP request, its response as a response */
	if (request != tag_owner) {
		return true;
	}

	k_mutex_lock(&pldm_lock, K_FOREVER);

	if (type == PLDM_FWUP) {
		pldm_tid_t peer = pldm_peer_handle(bus, src_eid, request);

		if (peer) {
			ret = pldm_fd_handle_msg(&fd, peer, pldm, pldm_len, &rsp_buf[1], &rsp_len);
			/* Its completion code follows the header */
			if (!ret && request && pldm[2] == PLDM_REQUEST_UPDATE &&
			    rsp_len > PLDM_HDR_LEN && rsp_buf[1 + PLDM_HDR_LEN] == PLDM_SUCCESS) {
				ua_peer = peer;
			}
		} else {
			/* A response we can't be waiting for */
			ret = 0;
			rsp_len = 0;
		}
	} else if (!request) {
		/* We send only firmware update requests */
		ret = 0;
		rsp_len = 0;
	} else if (type == PLDM_BASE) {
		ret = pldm_control_handle_msg(&control, pldm, pldm_len, &rsp_buf[1], &rsp_len);
	} else {
		ret = pldm_reply_invalid_type(pldm, &rsp_buf[1], &rsp_len);
	}

	if (ret) {
		LOG_WRN("pldm: type %u command 0x%02x from %s eid 0x%02x not handled (%d)", type,
			pldm[2], bus->name, src_eid, ret);
	} else if (request && rsp_len) {
		rsp_buf[0] = MCTP_MSG_TYPE_PLDM;
		ret = mctp_message_tx(bus->mctp, src_eid, false, msg_tag, rsp_buf, rsp_len + 1);
		if (ret) {
			LOG_ERR("pldm: %s response to eid 0x%02x failed (%d)", bus->name, src_eid,
				ret);
		}
	}

	k_mutex_unlock(&pldm_lock);

	/* A response or a request can both move an update along */
	if (type == PLDM_FWUP) {
		k_sem_give(&pldm_kick);
	}

	return true;
}

/* Sends the FD's own requests: firmware data, and the completion reports */
static void pldm_progress_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (true) {
		struct eval_bus *bus = NULL;
		size_t req_len = PLDM_MSG_MAX;
		pldm_tid_t peer = 0;
		uint8_t eid = 0;
		int ret;

		(void)k_sem_take(&pldm_kick, PLDM_PROGRESS_INTERVAL);

		k_mutex_lock(&pldm_lock, K_FOREVER);
		ret = pldm_fd_progress(&fd, &req_buf[1], &req_len, &peer);
		/* The handle of the update agent, from pldm_peer_handle() */
		if (!ret && req_len && peer >= 1 && peer <= ARRAY_SIZE(peers)) {
			bus = peers[peer - 1].bus;
			eid = peers[peer - 1].eid;
		}
		k_mutex_unlock(&pldm_lock);

		if (!bus) {
			continue;
		}

		req_buf[0] = MCTP_MSG_TYPE_PLDM;
		k_mutex_lock(bus->lock, K_FOREVER);
		ret = mctp_message_tx(bus->mctp, eid, true, mctp_eval_next_tag(), req_buf,
				      req_len + 1);
		k_mutex_unlock(bus->lock);

		if (ret) {
			/* The FD retries it from a later progress call */
			LOG_WRN("pldm: %s request to eid 0x%02x failed (%d)", bus->name, eid, ret);
		}
	}
}

K_THREAD_DEFINE(pldm_tid, PLDM_THREAD_STACK_SIZE, pldm_progress_thread, NULL, NULL, NULL,
		PLDM_THREAD_PRIORITY, 0, SYS_FOREVER_MS);

/* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", dashes optional */
static int pldm_parse_uuid(const char *str, uint8_t out[16])
{
	char hex[33];
	size_t n = 0;

	for (; *str && n < sizeof(hex) - 1; str++) {
		if (*str != '-') {
			hex[n++] = *str;
		}
	}
	hex[n] = '\0';

	if (n != 32 || *str || hex2bin(hex, n, out, 16) != 16) {
		return -EINVAL;
	}

	return 0;
}

int mctp_eval_pldm_init(void)
{
	int ret;

	ret = pldm_parse_uuid(CONFIG_MCTP_EVAL_PLDM_UUID, uuid);
	if (ret) {
		LOG_ERR("pldm: bad CONFIG_MCTP_EVAL_PLDM_UUID \"%s\"", CONFIG_MCTP_EVAL_PLDM_UUID);
		return ret;
	}

	ARRAY_FOR_EACH(comps, i) {
		struct eval_comp *c = &comps[i];

		components_list[i] = &c->desc;
#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
		ret = flash_area_open(c->fa_id, &c->fa);
		if (ret) {
			LOG_ERR("pldm: opening the %s partition failed (%d)", c->name, ret);
			return ret;
		}
		LOG_INF("pldm: component 0x%04x (%s) updates %s at 0x%lx, %zu bytes",
			c->desc.comp_identifier, c->name, c->fa->fa_dev->name, (long)c->fa->fa_off,
			c->fa->fa_size);
#endif
	}

#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
#if FIXED_PARTITION_EXISTS(pldm_staging_partition)
	ret = flash_area_open(FIXED_PARTITION_ID(pldm_staging_partition), &staging_fa);
	if (ret) {
		LOG_ERR("pldm: opening the staging partition failed (%d)", ret);
		return ret;
	}
	LOG_INF("pldm: component 0x%04x downloads to %s at 0x%lx, %zu bytes",
		PLDM_COMP_ID_IMAGE, staging_fa->fa_dev->name, (long)staging_fa->fa_off,
		staging_fa->fa_size);
#endif
#endif

	ret = pldm_control_setup(&control, PLDM_SIZEOF_PLDM_CONTROL);
	if (ret) {
		LOG_ERR("pldm: control setup failed (%d)", ret);
		return ret;
	}

	/* Registers type 5 with the control responder too */
	ret = pldm_fd_setup(&fd, PLDM_SIZEOF_PLDM_FD, &fd_ops, NULL, &control);
	if (ret) {
		LOG_ERR("pldm: firmware device setup failed (%d)", ret);
		return ret;
	}

	pldm_ready = true;
	k_thread_start(pldm_tid);
	LOG_INF("pldm: responder for types 0 and 5, uuid %s", CONFIG_MCTP_EVAL_PLDM_UUID);

	return 0;
}

int mctp_eval_pldm_bus_init(struct eval_bus *bus)
{
	/* Don't advertise a responder that didn't start */
	if (!pldm_ready) {
		return 0;
	}

	return mctp_control_add_type(bus->mctp, MCTP_MSG_TYPE_PLDM);
}

static int cmd_pldm(const struct shell *sh, size_t argc, char **argv)
{
	int64_t end;
	int64_t ms;

	if (!pldm_ready) {
		shell_error(sh, "PLDM responder not started");
		return -ENODEV;
	}

	k_mutex_lock(&pldm_lock, K_FOREVER);
	end = img.t_end ? img.t_end : k_uptime_get();
	ms = img.t_start ? end - img.t_start : 0;

	ARRAY_FOR_EACH_PTR(comps, c) {
		const struct pldm_firmware_version *active = &c->desc.active_ver;
		const struct pldm_firmware_version *pending = &c->desc.pending_ver;

		shell_print(sh, "component 0x%04x (%s):", c->desc.comp_identifier, c->name);
		shell_print(sh, "  active version:  \"%.*s\"", active->str.str_len,
			    active->str.str_data);
		shell_print(sh, "  pending version: \"%.*s\"", pending->str.str_len,
			    pending->str.str_data);
#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
		shell_print(sh, "  target: %s at 0x%lx, %zu bytes", c->fa->fa_dev->name,
			    (long)c->fa->fa_off, c->fa->fa_size);
#if FIXED_PARTITION_EXISTS(pldm_staging_partition)
		if (c->desc.comp_identifier == PLDM_COMP_ID_IMAGE) {
			shell_print(sh, "  staged in: %s at 0x%lx, %zu bytes",
				    staging_fa->fa_dev->name, (long)staging_fa->fa_off,
				    staging_fa->fa_size);
		}
#endif
#else
		shell_print(sh, "  target: sink (no pldm_update_partition)");
#endif
	}
	shell_print(sh, "update: %s%s%s, %u of %u bytes in %u chunks (%u repeated), crc32 0x%08x",
		    img_state_names[img.state], img.comp ? " " : "",
		    img.comp ? img.comp->name : "", img.received, img.size, img.chunks,
		    img.duplicates, img.crc);
#ifdef CONFIG_MCTP_EVAL_PLDM_FLASH
	shell_print(sh, "readback crc32 0x%08x", img.flash_crc);
	if (img.comp && img.dl_fa != img.comp->fa) {
		shell_print(sh, "applied %u of %u bytes, readback crc32 0x%08x", img.applied,
			    img.size, img.apply_crc);
	}
#endif
	if (ms > 0 && img.received) {
		shell_print(sh, "download: %lld ms, %llu B/s", ms,
			    (unsigned long long)img.received * 1000 / ms);
	}
	ARRAY_FOR_EACH(peers, i) {
		if (!peers[i].bus) {
			break;
		}
		shell_print(sh, "peer %zu: %s eid 0x%02x%s", i + 1, peers[i].bus->name, peers[i].eid,
			    i + 1 == ua_peer ? " (update agent)" : "");
	}
	k_mutex_unlock(&pldm_lock);

	return 0;
}

SHELL_CMD_REGISTER(pldm, NULL, "PLDM responder status", cmd_pldm);
