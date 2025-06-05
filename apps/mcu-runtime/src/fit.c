/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <fit.h>
#include <spi.h>
#include <mmc.h>
#include <ufs.h>

LOG_MODULE_REGISTER(fit, CONFIG_SOC_FMC_LOG_LEVEL);

#define ARCH_DMA_MINALIGN 32

static int get_aligned_image_overhead(struct fit_load_info *info, int offset)
{
	/*
	 * If it is a FS read, get the difference between the offset and
	 * the first address before offset which is aligned to
	 * ARCH_DMA_MINALIGN. If it is raw read return the offset within the
	 * block.
	 */
	if (info->filename)
		return offset & (ARCH_DMA_MINALIGN - 1);

	return offset % info->bl_len;
}

static int get_aligned_image_offset(struct fit_load_info *info, int offset)
{
	/*
	 * If it is a FS read, get the first address before offset which is
	 * aligned to ARCH_DMA_MINALIGN. If it is raw read return the
	 * block number to which offset belongs.
	 */
	if (info->filename)
		return offset & ~(ARCH_DMA_MINALIGN - 1);

	return offset / info->bl_len;
}

static int get_aligned_image_size(struct fit_load_info *info, int data_size,
				  int offset)
{
	data_size = data_size + get_aligned_image_overhead(info, offset);

	if (info->filename)
		return data_size;

	return (data_size + info->bl_len - 1) / info->bl_len;
}

struct legacy_img_hdr *fit_get_load_buffer(int offset, size_t size)
{
	return (struct legacy_img_hdr *)CONFIG_SYS_LOAD_ADDR;
}

void *board_fit_fit_buffer_addr(uint32_t fit_size, int sectors, int bl_len)
{
	return (void *)fit_get_load_buffer(sectors, bl_len);
}

uint64_t board_fit_fit_size_align(uint64_t size)
{
	return size;
}

#define FIT_IMAGES_PATH		   "/images"
#define FIT_CONFS_PATH		   "/configurations"

__weak int board_fit_config_name_match(const char *name)
{
	return -EINVAL;
}

static int fit_find_config_node(const void *fdt)
{
	const char *name;
	int conf, node, len;
	const char *dflt_conf_name;
	const char *dflt_conf_desc = NULL;
	int dflt_conf_node = -ENOENT;

	conf = fdt_path_offset(fdt, FIT_CONFS_PATH);
	if (conf < 0) {
		LOG_DBG("%s: Cannot find /configurations node: %d", __func__,
		      conf);
		return -EINVAL;
	}

	dflt_conf_name = fdt_getprop(fdt, conf, "default", &len);

	for (node = fdt_first_subnode(fdt, conf);
	     node >= 0;
	     node = fdt_next_subnode(fdt, node)) {
		name = fdt_getprop(fdt, node, "description", &len);
		if (!name) {
#ifdef CONFIG_SOC_FMC_LIBCOMMON_SUPPORT
			LOG_DBG("%s: Missing FDT description in DTB",
			       __func__);
#endif
			return -EINVAL;
		}

		if (dflt_conf_name) {
			const char *node_name = fdt_get_name(fdt, node, NULL);
			if (strcmp(dflt_conf_name, node_name) == 0) {
				dflt_conf_node = node;
				dflt_conf_desc = name;
			}
		}

		if (board_fit_config_name_match(name))
			continue;

		LOG_DBG("Selecting config '%s'", name);

		return node;
	}

	if (dflt_conf_node != -ENOENT) {
		LOG_DBG("Selecting default config '%s'", dflt_conf_desc);
		return dflt_conf_node;
	}

	return -ENOENT;
}

static int fdt_find_or_add_subnode(void *fdt, int parentoffset, const char *name)
{
	int offset;

	offset = fdt_subnode_offset(fdt, parentoffset, name);

	if (offset == -FDT_ERR_NOTFOUND)
		offset = fdt_add_subnode(fdt, parentoffset, name);

	if (offset < 0)
		LOG_DBG("%s: %s: %s", __func__, name, fdt_strerror(offset));

	return offset;
}

static int fdt_record_loadable(void *blob, uint32_t index, const char *name,
			uintptr_t load_addr, uint32_t size, uintptr_t entry_point,
			const char *type, const char *os, const char *arch)
{
	int err, node;

	err = fdt_check_header(blob);
	if (err < 0) {
		LOG_DBG("%s: %s", __func__, fdt_strerror(err));
		return err;
	}

	/* find or create "/fit-images" node */
	node = fdt_find_or_add_subnode(blob, 0, "fit-images");
	if (node < 0)
		return node;

	/* find or create "/fit-images/<name>" node */
	node = fdt_find_or_add_subnode(blob, node, name);
	if (node < 0)
		return node;

	fdt_setprop_u64(blob, node, "load", load_addr);
	if (entry_point != -1)
		fdt_setprop_u64(blob, node, "entry", entry_point);

	fdt_setprop_u32(blob, node, "size", size);
	if (type)
		fdt_setprop_string(blob, node, "type", type);
	if (os)
		fdt_setprop_string(blob, node, "os", os);
	if (arch)
		fdt_setprop_string(blob, node, "arch", arch);

	return node;
}

static bool os_takes_devicetree(uint8_t os)
{
	switch (os) {
	case IH_OS_U_BOOT:
		return true;
	case IH_OS_LINUX:
		return false;
	default:
		return false;
	}
}

static int fit_get_image_name(const struct fit_info *ctx,
				  const char *type, int index,
				  const char **outname)
{
	const char *name, *str;
	int len, i;
	bool found = true;

	name = fdt_getprop(ctx->fit, ctx->conf_node, type, &len);
	if (!name) {
		LOG_DBG("cannot find property '%s': %d", type, len);
		return -EINVAL;
	}

	str = name;
	for (i = 0; i < index; i++) {
		str = strchr(str, '\0') + 1;
		if (!str || (str - name >= len)) {
			found = false;
			break;
		}
	}

	if (!found) {
		LOG_DBG("no string for index %d", index);
		return -E2BIG;
	}

	*outname = str;
	return 0;
}

static int fit_get_image_node(const struct fit_info *ctx,
				  const char *type, int index)
{
	const char *str;
	int err;
	int node;

	err = fit_get_image_name(ctx, type, index, &str);
	if (err)
		return err;

	LOG_DBG("%s: '%s'", type, str);

	node = fdt_subnode_offset(ctx->fit, ctx->images_node, str);
	if (node < 0) {
		LOG_ERR("cannot find image node '%s': %d", str, node);
		return -EINVAL;
	}

	return node;
}

static int fit_record_loadable(const struct fit_info *ctx, int index,
				   void *blob, struct fit_image_info *image)
{
	int ret = 0;
	const char *name;
	int node;

//	  if (IS_ENABLED(CONFIG_FIT_IMAGE_TINY))
		return 0;

	ret = fit_get_image_name(ctx, "loadables", index, &name);
	if (ret < 0)
		return ret;

	node = fit_get_image_node(ctx, "loadables", index);

	ret = fdt_record_loadable(blob, index, name, image->load_addr,
				  image->size, image->entry_point,
				  fdt_getprop(ctx->fit, node, "type", NULL),
				  fdt_getprop(ctx->fit, node, "os", NULL),
				  fdt_getprop(ctx->fit, node, "arch", NULL));
	return ret;
}

int fit_load_fit_image(struct fit_load_info *info, uint64_t sector,
			const struct fit_info *ctx, int node,
			struct fit_image_info *image_info)
{
	int offset;
	size_t length;
	int len;
	uint64_t load_addr;
	void *load_ptr;
	void *src;
	uint32_t overhead;
	int nr_sectors;
	const void *data;
	const void *fit = ctx->fit;
	bool external_data = false;

	if (fit_image_get_load(fit, node, &load_addr)) {
		if (!image_info->load_addr) {
			LOG_DBG("Can't load %s: No load address and no buffer",
			       fit_get_name(fit, node, NULL));
			return -ENOBUFS;
		}
		load_addr = image_info->load_addr;
	}

	if (!fit_image_get_data_position(fit, node, &offset)) {
		external_data = true;
	} else if (!fit_image_get_data_offset(fit, node, &offset)) {
		offset += ctx->ext_data_offset;
		external_data = true;
	}

	if (external_data) {
		void *src_ptr;

		/* External data */
		if (fit_image_get_data_size(fit, node, &len))
			return -ENOENT;

		/* Dont bother to copy 0 byte data, but warn, though */
		if (!len) {
			LOG_DBG("%s: Skip load '%s': image size is 0!",
				    __func__, fit_get_name(fit, node, NULL));
			return 0;
		}

		src_ptr = (void *)((uintptr_t)load_addr);
		length = len;

		overhead = get_aligned_image_overhead(info, offset);
		nr_sectors = get_aligned_image_size(info, length, offset);

		if (info->read(info,
			       sector + get_aligned_image_offset(info, offset),
			       nr_sectors, src_ptr) != nr_sectors)
			return -EIO;

		LOG_DBG("External data: dst=%p, offset=%x, size=%lx",
		      src_ptr, offset, (unsigned long)length);
		src = (void *)((uint32_t)src_ptr + overhead);
	} else {
		/* Embedded data */
		if (fit_image_get_data(fit, node, &data, &length)) {
			puts("Cannot get image data/size");
			return -ENOENT;
		}
		LOG_DBG("Embedded data: dst=%llx, size=%x", load_addr,
		      (unsigned int)length);
		src = (void *)data;	/* cast away const */
	}

	if (IS_ENABLED(CONFIG_FIT_SIGNATURE)) {
		LOG_DBG("## Checking hash(es) for Image %s ... ",
		fit_get_name(fit, node, NULL));

		if (fit_verify_image(fit, node, src, length))
			return -EPERM;

		puts("OK");
	}

	board_fit_image_post_process(fit, node, &src, &length);

	load_ptr = (void *)((uintptr_t)load_addr);

	memcpy(load_ptr, src, length);

	if (image_info) {
		uint64_t entry_point;

		image_info->load_addr = load_addr;
		image_info->size = length;

		if (!fit_image_get_entry(fit, node, &entry_point))
			image_info->entry_point = entry_point;
		else
			image_info->entry_point = FDT_ERROR;
	}

	return 0;
}

static int fit_append_fdt(struct fit_image_info *fit_image,
			      struct fit_load_info *info, uint64_t sector,
			      const struct fit_info *ctx)
{
	struct fit_image_info image_info;
	int node, ret = 0, index = 0;

	/*
	 * Use the address following the image as target address for the
	 * device tree.
	 */
	image_info.load_addr = fit_image->load_addr + fit_image->size;

	/* Figure out which device tree the board wants to use */
	node = fit_get_image_node(ctx, FIT_FDT_PROP, index++);
	if (node < 0) {
		LOG_DBG("%s: cannot find FDT node", __func__);

		return node;
	} else {
		ret = fit_load_fit_image(info, sector, ctx, node,
					 &image_info);
		if (ret < 0)
			return ret;
	}

	/* Make the load-address of the FDT available for the IROT framework */
	fit_image->fdt_addr = (void *)image_info.load_addr;

	return ret;
}

static int fit_simple_fit_parse(struct fit_info *ctx)
{
	/* Find the correct subnode under "/configurations" */
	ctx->conf_node = fit_find_config_node(ctx->fit);
	if (ctx->conf_node < 0)
		return -EINVAL;

#if 0
	if (IS_ENABLED(CONFIG_SOC_FMC_FIT_SIGNATURE)) {
		LOG_DBG("## Checking hash(es) for config %s ... ",
		       fit_get_name(ctx->fit, ctx->conf_node, NULL));
		if (fit_config_verify(ctx->fit, ctx->conf_node))
			return -EPERM;
		puts("OK");
	}
#endif

	/* find the node holding the images information */
	ctx->images_node = fdt_path_offset(ctx->fit, FIT_IMAGES_PATH);
	if (ctx->images_node < 0) {
		LOG_DBG("%s: Cannot find /images node: %d", __func__,
		      ctx->images_node);
		return -EINVAL;
	}

	return 0;
}

static int fit_simple_fit_read(struct fit_info *ctx,
			       struct fit_load_info *info, uint32_t sector,
			       const void *fit_header)
{
	unsigned int count, size;
	int sectors;
	void *buf;

	/*
	 * For FIT with external data, figure out where the external images
	 * start. This is the base for the data-offset properties in each
	 * image.
	 */
	  //size = ALIGN(fdt_totalsize(fit_header), 4);
	  size = fdt_totalsize(fit_header);
	  size = board_fit_fit_size_align(size);
	  ctx->ext_data_offset = size;//ALIGN(size, 4);

	/*
	 * So far we only have one block of data from the FIT. Read the entire
	 * thing, including that first block.
	 *
	 * For FIT with data embedded, data is loaded as part of FIT image.
	 * For FIT with external data, data is not loaded in this step.
	 */
	sectors = get_aligned_image_size(info, size, 0);
	buf = board_fit_fit_buffer_addr(size, sectors, info->bl_len);

	count = info->read(info, sector, sectors, buf);
	ctx->fit = buf;
	LOG_DBG("fit read sector %x, sectors=%d, dst=%p, count=%x, size=0x%x",
	      sector, sectors, buf, count, size);

	return (count == 0) ? -EIO : 0;
}

int fit_load_simple_fit(struct fit_image_info *fit_image,
			 struct fit_load_info *info, uint64_t sector, void *fit)
{
	struct fit_image_info image_info;
	struct fit_info ctx;
	int node = -1;
	int ret;
	int index = 0;
	int firmware_node;

	ret = fit_simple_fit_read(&ctx, info, sector, fit);
	if (ret < 0)
		return ret;

	ret = fit_simple_fit_parse(&ctx);
	if (ret < 0)
		return ret;

	if (node < 0)
		node = fit_get_image_node(&ctx, FIT_FIRMWARE_PROP, 0);

	if (node < 0) {
		LOG_DBG("could not find firmware image, trying loadables...");
		node = fit_get_image_node(&ctx, "loadables", 0);
		/*
		 * If we pick the U-Boot image from "loadables", start at
		 * the second image when later loading additional images.
		 */
		index = 1;
	}

	if (node < 0) {
		LOG_DBG("%s: Cannot find u-boot image node: %d",
		      __func__, node);
		return -1;
	}

	/* Load the image and set up the fit_image structure */
	ret = fit_load_fit_image(info, sector, &ctx, node, fit_image);
	if (ret)
		return ret;

	if (!fit_image_get_os(ctx.fit, node, &fit_image->os))
		LOG_DBG("Image OS is %s", genimg_get_os_name(fit_image->os));
	else
		fit_image->os = IH_OS_U_BOOT;

	/*
	 * Booting a next-stage U-Boot may require us to append the FDT.
	 * We allow this to fail, as the U-Boot image might embed its FDT.
	 */
	if (os_takes_devicetree(fit_image->os)) {
		ret = fit_append_fdt(fit_image, info, sector, &ctx);
		if (ret < 0 && fit_image->os != IH_OS_U_BOOT)
			return ret;
	}

	firmware_node = node;
	/* Now check if there are more images for us to load */
	for (; ; index++) {
		uint8_t os_type = IH_OS_INVALID;

		node = fit_get_image_node(&ctx, "loadables", index);
		if (node < 0)
			break;

		/*
		 * if the firmware is also a loadable, skip it because
		 * it already has been loaded. This is typically the case with
		 * u-boot.img generated by mkimage.
		 */
		if (firmware_node == node)
			continue;

		image_info.load_addr = 0;
		ret = fit_load_fit_image(info, sector, &ctx, node, &image_info);
		if (ret < 0) {
			LOG_DBG("%s: can't load image loadables index %d (ret = %d)",
			       __func__, index, ret);
			return ret;
		}

		if (!fit_image_get_os(ctx.fit, node, &os_type))
			LOG_DBG("Loadable is %s", genimg_get_os_name(os_type));

		if (os_takes_devicetree(os_type)) {
			fit_append_fdt(&image_info, info, sector, &ctx);
			fit_image->fdt_addr = image_info.fdt_addr;
		}

		/*
		 * If the "firmware" image did not provide an entry point,
		 * use the first valid entry point from the loadables.
		 */
		if (fit_image->entry_point == FDT_ERROR &&
		    image_info.entry_point != FDT_ERROR)
			fit_image->entry_point = image_info.entry_point;

		/* Record our loadables into the FDT */
		if (fit_image->fdt_addr)
			fit_record_loadable(&ctx, index,
						fit_image->fdt_addr,
						&image_info);
	}

	/*
	 * If a platform does not provide CFG_SYS_UBOOT_START, U-Boot's
	 * Makefile will set it to 0 and it will end up as the entry point
	 * here. What it actually means is: use the load address.
	 */
	if (fit_image->entry_point == FDT_ERROR || fit_image->entry_point == 0)
		fit_image->entry_point = fit_image->load_addr;

	fit_image->flags |= SOC_FMC_FIT_FOUND;

	return ret;
}

int fit_load_image(enum boot_mode_type boot_mode, struct fit_image_info *fit_image)
{
	struct fit_load_info load;
	void *header = NULL;
	uint32_t blk = 0;
	int ret = -1;

	switch (boot_mode) {
	case BOOT_DEV_SPI:
		printf("Trying to boot from RAM\n");
		load.bl_len = 1;
		load.read = fit_ram_load_read;
		header = (void *)CONFIG_SOC_FMC_LOAD_FIT_ADDRESS;
		break;
	case BOOT_DEV_MMC:
		printf("Trying to boot from MMC\n");
		load.bl_len = 0x200;
		load.read = fit_mmc_load_read;

		blk = (CONFIG_SOC_FMC_LOAD_FIT_ADDRESS & 0xfffffff) / load.bl_len;
		header = (void *)CONFIG_SYS_LOAD_ADDR;

		/* Read fit header first */
		ret = fit_mmc_load_read(&load, blk, 1, header);

		break;
	case BOOT_DEV_UFS:
		printf("Trying to boot from UFS\n");
		load.bl_len = 0x1000;
		load.read = fit_scsi_load_read;
		blk = (CONFIG_SOC_FMC_LOAD_FIT_ADDRESS & 0xfffffff) / load.bl_len;
		header = (void *)CONFIG_SYS_LOAD_ADDR;

		/* Read fit header first */
		ret = fit_scsi_load_read(&load, blk, 1, header);

		break;
	case BOOT_DEV_UART:
		printf("Trying to boot from UART\n");
		break;
	case BOOT_DEV_USB:
		printf("Trying to boot from USB\n");
		break;
	case BOOT_DEV_I2C:
		printf("Trying to boot from I2C\n");
		break;
	case BOOT_DEV_I3C:
		printf("Trying to boot from I3C\n");
		break;
	default:
		printf("Unsupported booting device!");
		return ret;
	};

	if (image_get_magic(header) == FDT_MAGIC) {
		LOG_DBG("Found FIT");
		ret = fit_load_simple_fit(fit_image, &load, blk, header);
	} else {
		LOG_DBG("Wrong FDT Magic!!!");
		ret = -1;
	}

	return ret;
}
