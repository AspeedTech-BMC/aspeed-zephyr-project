/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _FIT_IMAGE_H
#define _FIT_IMAGE_H

#include <libfdt.h>

enum {
	IH_COMP_NONE		= 0,	/*  No	 Compression Used	*/
	IH_COMP_GZIP,			/* gzip  Compression Used	*/
	IH_COMP_BZIP2,			/* bzip2 Compression Used	*/
	IH_COMP_LZMA,			/* lzma  Compression Used	*/
	IH_COMP_LZO,			/* lzo	 Compression Used	*/
	IH_COMP_LZ4,			/* lz4	 Compression Used	*/
	IH_COMP_ZSTD,			/* zstd   Compression Used	*/

	IH_COMP_COUNT,
};

enum image_phase_t {
	IH_PHASE_NONE		= 0,
	IH_PHASE_U_BOOT,
	IH_PHASE_IROT,

	IH_PHASE_COUNT,
};

enum image_type_t {
	IH_TYPE_INVALID		= 0,	/* Invalid Image		*/
	IH_TYPE_STANDALONE,		/* Standalone Program		*/
	IH_TYPE_KERNEL,			/* OS Kernel Image		*/
	IH_TYPE_RAMDISK,		/* RAMDisk Image		*/
	IH_TYPE_MULTI,			/* Multi-File Image		*/
	IH_TYPE_FIRMWARE,		/* Firmware Image		*/
	IH_TYPE_SCRIPT,			/* Script file			*/
	IH_TYPE_FILESYSTEM,		/* Filesystem Image (any type)	*/
	IH_TYPE_FLATDT,			/* Binary Flat Device Tree Blob */
	IH_TYPE_KWBIMAGE,		/* Kirkwood Boot Image		*/
	IH_TYPE_IMXIMAGE,		/* Freescale IMXBoot Image	*/
	IH_TYPE_UBLIMAGE,		/* Davinci UBL Image		*/
	IH_TYPE_OMAPIMAGE,		/* TI OMAP Config Header Image	*/
	IH_TYPE_AISIMAGE,		/* TI Davinci AIS Image		*/
	/* OS Kernel Image, can run from any load address */
	IH_TYPE_KERNEL_NOLOAD,
	IH_TYPE_PBLIMAGE,		/* Freescale PBL Boot Image	*/
	IH_TYPE_MXSIMAGE,		/* Freescale MXSBoot Image	*/
	IH_TYPE_GPIMAGE,		/* TI Keystone GPHeader Image	*/
	IH_TYPE_ATMELIMAGE,		/* ATMEL ROM bootable Image	*/
	IH_TYPE_SOCFPGAIMAGE,		/* Altera SOCFPGA CV/AV Preloader */
	IH_TYPE_X86_SETUP,		/* x86 setup.bin Image		*/
	IH_TYPE_LPC32XXIMAGE,		/* x86 setup.bin Image		*/
	IH_TYPE_LOADABLE,		/* A list of typeless images	*/
	IH_TYPE_RKIMAGE,		/* Rockchip Boot Image		*/
	IH_TYPE_RKSD,			/* Rockchip SD card		*/
	IH_TYPE_RKSPI,			/* Rockchip SPI image		*/
	IH_TYPE_ZYNQIMAGE,		/* Xilinx Zynq Boot Image */
	IH_TYPE_ZYNQMPIMAGE,		/* Xilinx ZynqMP Boot Image */
	IH_TYPE_ZYNQMPBIF,		/* Xilinx ZynqMP Boot Image (bif) */
	IH_TYPE_FPGA,			/* FPGA Image */
	IH_TYPE_VYBRIDIMAGE,	/* VYBRID .vyb Image */
	IH_TYPE_TEE,		/* Trusted Execution Environment OS Image */
	IH_TYPE_FIRMWARE_IVT,		/* Firmware Image with HABv4 IVT */
	IH_TYPE_PMMC,		 /* TI Power Management Micro-Controller Firmware */
	IH_TYPE_STM32IMAGE,		/* STMicroelectronics STM32 Image */
	IH_TYPE_SOCFPGAIMAGE_V1,	/* Altera SOCFPGA A10 Preloader */
	IH_TYPE_MTKIMAGE,		/* MediaTek BootROM loadable Image */
	IH_TYPE_IMX8MIMAGE,		/* Freescale IMX8MBoot Image	*/
	IH_TYPE_IMX8IMAGE,		/* Freescale IMX8Boot Image	*/
	IH_TYPE_COPRO,			/* Coprocessor Image for remoteproc*/
	IH_TYPE_SUNXI_EGON,		/* Allwinner eGON Boot Image */
	IH_TYPE_SUNXI_TOC0,		/* Allwinner TOC0 Boot Image */
	IH_TYPE_FDT_LEGACY,		/* Binary Flat Device Tree Blob in a Legacy Image */
	IH_TYPE_RENESAS_SPKG,		/* Renesas SPKG image */
	IH_TYPE_ASTIMAGE,		/* Aspeed Boot Image */

	IH_TYPE_COUNT,			/* Number of image types */
};

enum {
	IH_OS_INVALID		= 0,	/* Invalid OS	*/
	IH_OS_OPENBSD,			/* OpenBSD	*/
	IH_OS_NETBSD,			/* NetBSD	*/
	IH_OS_FREEBSD,			/* FreeBSD	*/
	IH_OS_4_4BSD,			/* 4.4BSD	*/
	IH_OS_LINUX,			/* Linux	*/
	IH_OS_SVR4,			/* SVR4		*/
	IH_OS_ESIX,			/* Esix		*/
	IH_OS_SOLARIS,			/* Solaris	*/
	IH_OS_IRIX,			/* Irix		*/
	IH_OS_SCO,			/* SCO		*/
	IH_OS_DELL,			/* Dell		*/
	IH_OS_NCR,			/* NCR		*/
	IH_OS_LYNXOS,			/* LynxOS	*/
	IH_OS_VXWORKS,			/* VxWorks	*/
	IH_OS_PSOS,			/* pSOS		*/
	IH_OS_QNX,			/* QNX		*/
	IH_OS_U_BOOT,			/* Firmware	*/
	IH_OS_RTEMS,			/* RTEMS	*/
	IH_OS_ARTOS,			/* ARTOS	*/
	IH_OS_UNITY,			/* Unity OS	*/
	IH_OS_INTEGRITY,		/* INTEGRITY	*/
	IH_OS_OSE,			/* OSE		*/
	IH_OS_PLAN9,			/* Plan 9	*/
	IH_OS_OPENRTOS,		/* OpenRTOS	*/
	IH_OS_ARM_TRUSTED_FIRMWARE,	/* ARM Trusted Firmware */
	IH_OS_TEE,			/* Trusted Execution Environment */
	IH_OS_OPENSBI,			/* RISC-V OpenSBI */
	IH_OS_EFI,			/* EFI Firmware (e.g. GRUB2) */

	IH_OS_COUNT,
};

enum {
	IH_ARCH_INVALID		= 0,	/* Invalid CPU	*/
	IH_ARCH_ALPHA,			/* Alpha	*/
	IH_ARCH_ARM,			/* ARM		*/
	IH_ARCH_I386,			/* Intel x86	*/
	IH_ARCH_IA64,			/* IA64		*/
	IH_ARCH_MIPS,			/* MIPS		*/
	IH_ARCH_MIPS64,			/* MIPS  64 Bit */
	IH_ARCH_PPC,			/* PowerPC	*/
	IH_ARCH_S390,			/* IBM S390	*/
	IH_ARCH_SH,			/* SuperH	*/
	IH_ARCH_SPARC,			/* Sparc	*/
	IH_ARCH_SPARC64,		/* Sparc 64 Bit */
	IH_ARCH_M68K,			/* M68K		*/
	IH_ARCH_NIOS,			/* Nios-32	*/
	IH_ARCH_MICROBLAZE,		/* MicroBlaze	*/
	IH_ARCH_NIOS2,			/* Nios-II	*/
	IH_ARCH_BLACKFIN,		/* Blackfin	*/
	IH_ARCH_AVR32,			/* AVR32	*/
	IH_ARCH_ST200,			/* STMicroelectronics ST200  */
	IH_ARCH_SANDBOX,		/* Sandbox architecture (test only) */
	IH_ARCH_NDS32,			/* ANDES Technology - NDS32  */
	IH_ARCH_OPENRISC,		/* OpenRISC 1000  */
	IH_ARCH_ARM64,			/* ARM64	*/
	IH_ARCH_ARC,			/* Synopsys DesignWare ARC */
	IH_ARCH_X86_64,			/* AMD x86_64, Intel and Via */
	IH_ARCH_XTENSA,			/* Xtensa	*/
	IH_ARCH_RISCV,			/* RISC-V */

	IH_ARCH_COUNT,
};

static inline const char *fit_get_name(const void *fit_hdr, int noffset, int *len)
{
	return fdt_get_name(fit_hdr, noffset, len);
}

const char *genimg_get_os_name(uint8_t os);
int genimg_get_os_id(const char *name);
int genimg_get_arch_id(const char *name);
int genimg_get_type_id(const char *name);
int genimg_get_comp_id(const char *name);
int genimg_get_phase_id(const char *name);
int fit_image_get_type(const void *fit, int noffset, uint8_t *type);
int fit_image_get_os(const void *fit, int noffset, uint8_t *os);
int fit_image_get_arch(const void *fit, int noffset, uint8_t *arch);
int fit_image_get_data_position(const void *fit, int noffset,
				int *data_position);
int fit_image_get_data_offset(const void *fit, int noffset, int *data_offset);
int fit_image_get_data_size(const void *fit, int noffset, int *data_size);
int fit_image_get_data(const void *fit, int noffset,
		       const void **data, size_t *size);
int fit_image_get_entry(const void *fit, int noffset, uint64_t *entry);
int fit_image_get_load(const void *fit, int noffset, uint64_t *load);
int fit_image_hash_get_algo(const void *fit, int noffset, const char **algo);
int fit_image_hash_get_value(const void *fit, int noffset, uint8_t **value,
                                int *value_len);
#endif
