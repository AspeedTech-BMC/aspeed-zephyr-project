/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#ifndef _FIT_H
#define _FIT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>
#include <soc.h>
#include <errno.h>
#include <libfdt.h>
#include <stor.h>
#include <fit_image.h>

enum u_boot_phase {
	PHASE_NONE,	/* Invalid phase, signifying before U-Boot */
	PHASE_TPL,	/* Running in TPL */
	PHASE_VPL,	/* Running in VPL */
	PHASE_IROT,	/* Running in IROT */
	PHASE_BOARD_F,	/* Running in U-Boot before relocation */
	PHASE_BOARD_R,	/* Running in U-Boot after relocation */
	PHASE_COUNT,
};

#define IH_MAGIC	0x27051956	/* Image Magic Number		*/
#define IH_NMLEN		32	/* Image Name Length		*/

typedef struct table_entry {
	int	id;
	char	*sname;		/* short (input) name to find table entry */
	char	*lname;		/* long (output) name to print for messages */
} table_entry_t;

struct legacy_img_hdr {
	uint32_t	ih_magic;	/* Image Header Magic Number	*/
	uint32_t	ih_hcrc;	/* Image Header CRC Checksum	*/
	uint32_t	ih_time;	/* Image Creation Timestamp	*/
	uint32_t	ih_size;	/* Image Data Size		*/
	uint32_t	ih_load;	/* Data  Load  Address		*/
	uint32_t	ih_ep;		/* Entry Point Address		*/
	uint32_t	ih_dcrc;	/* Image Data CRC Checksum	*/
	uint8_t		ih_os;		/* Operating System		*/
	uint8_t		ih_arch;	/* CPU architecture		*/
	uint8_t		ih_type;	/* Image Type			*/
	uint8_t		ih_comp;	/* Compression Type		*/
	uint8_t		ih_name[IH_NMLEN];	/* Image Name		*/
};

#define uimage_to_cpu(x)		sys_be32_to_cpu(x)

#define image_get_hdr_l(f) \
	static inline uint32_t image_get_##f(const struct legacy_img_hdr *hdr) \
	{ \
		return uimage_to_cpu(hdr->ih_##f); \
	}
image_get_hdr_l(magic)		/* image_get_magic */
image_get_hdr_l(hcrc)		/* image_get_hcrc */
image_get_hdr_l(time)		/* image_get_time */
image_get_hdr_l(size)		/* image_get_size */
image_get_hdr_l(load)		/* image_get_load */
image_get_hdr_l(ep)		/* image_get_ep */
image_get_hdr_l(dcrc)		/* image_get_dcrc */

#define IMAGE_HASH_VERIFIED 0x9500
#define IMAGE_SIGN_VERIFIED 0x0027

#define FDT_MAGIC	0xd00dfeed
#define FDT_ERROR	((uint32_t)(-1))

#define SOC_FMC_FIT_FOUND	      2

#define FIT_IMAGES_PATH		"/images"
#define FIT_CONFS_PATH		"/configurations"

/* hash/signature/key node */
#define FIT_HASH_NODENAME	"hash"
#define FIT_ALGO_PROP		"algo"
#define FIT_VALUE_PROP		"value"
#define FIT_IGNORE_PROP		"uboot-ignore"
#define FIT_SIG_NODENAME	"signature"
#define FIT_KEY_REQUIRED	"required"
#define FIT_KEY_HINT		"key-name-hint"

/* cipher node */
#define FIT_CIPHER_NODENAME	"cipher"
#define FIT_ALGO_PROP		"algo"

/* image node */
#define FIT_DATA_PROP		"data"
#define FIT_DATA_POSITION_PROP	"data-position"
#define FIT_DATA_OFFSET_PROP	"data-offset"
#define FIT_DATA_SIZE_PROP	"data-size"
#define FIT_TIMESTAMP_PROP	"timestamp"
#define FIT_DESC_PROP		"description"
#define FIT_ARCH_PROP		"arch"
#define FIT_TYPE_PROP		"type"
#define FIT_OS_PROP		"os"
#define FIT_COMP_PROP		"compression"
#define FIT_ENTRY_PROP		"entry"
#define FIT_LOAD_PROP		"load"

/* configuration node */
#define FIT_KERNEL_PROP		"kernel"
#define FIT_RAMDISK_PROP	"ramdisk"
#define FIT_FDT_PROP		"fdt"
#define FIT_LOADABLE_PROP	"loadables"
#define FIT_DEFAULT_PROP	"default"
#define FIT_SETUP_PROP		"setup"
#define FIT_FPGA_PROP		"fpga"
#define FIT_FIRMWARE_PROP	"firmware"
#define FIT_STANDALONE_PROP	"standalone"
#define FIT_SCRIPT_PROP		"script"
#define FIT_PHASE_PROP		"phase"

#define FIT_MAX_HASH_LEN	HASH_MAX_DIGEST_SIZE

//enum HASH_ALGO {
//	HASH_ALGO_UNSUPPORTED,
//	HASH_ALGO_SHA1,
//	HASH_ALGO_SHA256,
//	HASH_ALGO_SHA384,
//	HASH_ALGO_SHA512,
//};

struct fit_image_info {
	const char *name;
	uint8_t os;
	uintptr_t load_addr;
	uintptr_t entry_point;
	void *fdt_addr;
	uint32_t boot_device;
	uint32_t offset;
	uint32_t size;
	uint32_t flags;
	void *arg;
#ifdef CONFIG_SOC_FMC_LEGACY_IMAGE_CRC_CHECK
	ulong dcrc_data;
	ulong dcrc_length;
	ulong dcrc;
#endif
};

struct fit_info {
	const void *fit;	/* Pointer to a valid FIT blob */
	size_t ext_data_offset; /* Offset to FIT external data (end of FIT) */
	int images_node;	/* FDT offset to "/images" node */
	int conf_node;		/* FDT offset to selected configuration node */
};

struct fit_load_info {
	void *dev;
	void *priv;
	int bl_len;
	const char *filename;
	/**
	 * read() - Read from device
	 *
	 * @load: Information about the load state
	 * @sector: Sector number to read from (each @load->bl_len bytes)
	 * @count: Number of sectors to read
	 * @buf: Buffer to read into
	 * @return number of sectors read, 0 on error
	 */
	uint32_t (*read)(struct fit_load_info *load, uint32_t sector, uint32_t count,
		      void *buf);
};

static inline const char *fit_phase_name(enum u_boot_phase phase)
{
	switch (phase) {
	case PHASE_IROT:
		return "IROT";
	case PHASE_BOARD_F:
	case PHASE_BOARD_R:
		return "U-Boot";
	default:
		return "phase?";
	}
}

static inline enum u_boot_phase fit_next_phase(void)
{
	return PHASE_BOARD_F;
}

void board_fit_image_post_process(const void *fit, int node, void **p_image, size_t *p_size);
int fit_load_image(enum boot_mode_type boot_mode, struct fit_image_info *fit_image);
int fit_verify_image(const void *fit, int image_offset, void *data, int size);

#endif
