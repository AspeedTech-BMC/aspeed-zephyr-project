/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <fit.h>

LOG_MODULE_REGISTER(fit_image, CONFIG_SOC_FMC_LOG_LEVEL);

static inline void *manual_reloc(void *ptr)
{
	return ptr;
}

static const table_entry_t uimage_arch[] = {
	{	IH_ARCH_INVALID,	"invalid",	"Invalid ARCH", },
	{	IH_ARCH_ALPHA,		"alpha",	"Alpha",	},
	{	IH_ARCH_ARM,		"arm",		"ARM",		},
	{	IH_ARCH_I386,		"x86",		"Intel x86",	},
	{	IH_ARCH_IA64,		"ia64",		"IA64",		},
	{	IH_ARCH_M68K,		"m68k",		"M68K",		},
	{	IH_ARCH_MICROBLAZE,	"microblaze",	"MicroBlaze",	},
	{	IH_ARCH_MIPS,		"mips",		"MIPS",		},
	{	IH_ARCH_MIPS64,		"mips64",	"MIPS 64 Bit",	},
	{	IH_ARCH_NIOS2,		"nios2",	"NIOS II",	},
	{	IH_ARCH_PPC,		"powerpc",	"PowerPC",	},
	{	IH_ARCH_PPC,		"ppc",		"PowerPC",	},
	{	IH_ARCH_S390,		"s390",		"IBM S390",	},
	{	IH_ARCH_SH,		"sh",		"SuperH",	},
	{	IH_ARCH_SPARC,		"sparc",	"SPARC",	},
	{	IH_ARCH_SPARC64,	"sparc64",	"SPARC 64 Bit", },
	{	IH_ARCH_BLACKFIN,	"blackfin",	"Blackfin",	},
	{	IH_ARCH_AVR32,		"avr32",	"AVR32",	},
	{	IH_ARCH_NDS32,		"nds32",	"NDS32",	},
	{	IH_ARCH_OPENRISC,	"or1k",		"OpenRISC 1000",},
	{	IH_ARCH_SANDBOX,	"sandbox",	"Sandbox",	},
	{	IH_ARCH_ARM64,		"arm64",	"AArch64",	},
	{	IH_ARCH_ARC,		"arc",		"ARC",		},
	{	IH_ARCH_X86_64,		"x86_64",	"AMD x86_64",	},
	{	IH_ARCH_XTENSA,		"xtensa",	"Xtensa",	},
	{	IH_ARCH_RISCV,		"riscv",	"RISC-V",	},
	{	-1,			"",		"",		},
};

static const table_entry_t uimage_os[] = {
	{	IH_OS_INVALID,	"invalid",	"Invalid OS",		},
	{	IH_OS_ARM_TRUSTED_FIRMWARE, "arm-trusted-firmware", "ARM Trusted Firmware"  },
	{	IH_OS_LINUX,	"linux",	"Linux",		},
	{	IH_OS_NETBSD,	"netbsd",	"NetBSD",		},
	{	IH_OS_OSE,	"ose",		"Enea OSE",		},
	{	IH_OS_PLAN9,	"plan9",	"Plan 9",		},
	{	IH_OS_RTEMS,	"rtems",	"RTEMS",		},
	{	IH_OS_TEE,	"tee",		"Trusted Execution Environment" },
	{	IH_OS_U_BOOT,	"u-boot",	"U-Boot",		},
	{	IH_OS_VXWORKS,	"vxworks",	"VxWorks",		},
#if defined(CONFIG_CMD_ELF) || defined(USE_HOSTCC)
	{	IH_OS_QNX,	"qnx",		"QNX",			},
#endif
#if defined(CONFIG_INTEGRITY) || defined(USE_HOSTCC)
	{	IH_OS_INTEGRITY,"integrity",	"INTEGRITY",		},
#endif
#ifdef USE_HOSTCC
	{	IH_OS_4_4BSD,	"4_4bsd",	"4_4BSD",		},
	{	IH_OS_DELL,	"dell",		"Dell",			},
	{	IH_OS_ESIX,	"esix",		"Esix",			},
	{	IH_OS_FREEBSD,	"freebsd",	"FreeBSD",		},
	{	IH_OS_IRIX,	"irix",		"Irix",			},
	{	IH_OS_NCR,	"ncr",		"NCR",			},
	{	IH_OS_OPENBSD,	"openbsd",	"OpenBSD",		},
	{	IH_OS_PSOS,	"psos",		"pSOS",			},
	{	IH_OS_SCO,	"sco",		"SCO",			},
	{	IH_OS_SOLARIS,	"solaris",	"Solaris",		},
	{	IH_OS_SVR4,	"svr4",		"SVR4",			},
#endif
#if defined(CONFIG_BOOTM_OPENRTOS) || defined(USE_HOSTCC)
	{	IH_OS_OPENRTOS, "openrtos",	"OpenRTOS",		},
#endif
	{	IH_OS_OPENSBI,	"opensbi",	"RISC-V OpenSBI",	},
	{	IH_OS_EFI,	"efi",		"EFI Firmware" },

	{	-1,		"",		"",			},
};

static const table_entry_t uimage_type[] = {
	{	IH_TYPE_AISIMAGE,   "aisimage",   "Davinci AIS image",},
	{	IH_TYPE_FILESYSTEM, "filesystem", "Filesystem Image",	},
	{	IH_TYPE_FIRMWARE,   "firmware",   "Firmware",		},
	{	IH_TYPE_FLATDT,     "flat_dt",	  "Flat Device Tree",	},
	{	IH_TYPE_GPIMAGE,    "gpimage",	  "TI Keystone IROT Image",},
	{	IH_TYPE_KERNEL,     "kernel",	  "Kernel Image",	},
	{	IH_TYPE_KERNEL_NOLOAD, "kernel_noload",  "Kernel Image (no loading done)", },
	{	IH_TYPE_KWBIMAGE,   "kwbimage",   "Kirkwood Boot Image",},
	{	IH_TYPE_IMXIMAGE,   "imximage",   "Freescale i.MX Boot Image",},
	{	IH_TYPE_IMX8IMAGE,  "imx8image",  "NXP i.MX8 Boot Image",},
	{	IH_TYPE_IMX8MIMAGE, "imx8mimage", "NXP i.MX8M Boot Image",},
	{	IH_TYPE_INVALID,    "invalid",	  "Invalid Image",	},
	{	IH_TYPE_MULTI,	    "multi",	  "Multi-File Image",	},
	{	IH_TYPE_OMAPIMAGE,  "omapimage",  "TI OMAP IROT With GP CH",},
	{	IH_TYPE_PBLIMAGE,   "pblimage",   "Freescale PBL Boot Image",},
	{	IH_TYPE_RAMDISK,    "ramdisk",	  "RAMDisk Image",	},
	{	IH_TYPE_SCRIPT,     "script",	  "Script",		},
	{	IH_TYPE_SOCFPGAIMAGE, "socfpgaimage", "Altera SoCFPGA CV/AV preloader",},
	{	IH_TYPE_SOCFPGAIMAGE_V1, "socfpgaimage_v1", "Altera SoCFPGA A10 preloader",},
	{	IH_TYPE_STANDALONE, "standalone", "Standalone Program", },
	{	IH_TYPE_UBLIMAGE,   "ublimage",   "Davinci UBL image",},
	{	IH_TYPE_MXSIMAGE,   "mxsimage",   "Freescale MXS Boot Image",},
	{	IH_TYPE_ATMELIMAGE, "atmelimage", "ATMEL ROM-Boot Image",},
	{	IH_TYPE_X86_SETUP,  "x86_setup",  "x86 setup.bin",    },
	{	IH_TYPE_LPC32XXIMAGE, "lpc32xximage",  "LPC32XX Boot Image", },
	{	IH_TYPE_RKIMAGE,    "rkimage",	  "Rockchip Boot Image" },
	{	IH_TYPE_RKSD,	    "rksd",	  "Rockchip SD Boot Image" },
	{	IH_TYPE_RKSPI,	    "rkspi",	  "Rockchip SPI Boot Image" },
	{	IH_TYPE_VYBRIDIMAGE, "vybridimage",  "Vybrid Boot Image", },
	{	IH_TYPE_ZYNQIMAGE,  "zynqimage",  "Xilinx Zynq Boot Image" },
	{	IH_TYPE_ZYNQMPIMAGE, "zynqmpimage", "Xilinx ZynqMP Boot Image" },
	{	IH_TYPE_ZYNQMPBIF,  "zynqmpbif",  "Xilinx ZynqMP Boot Image (bif)" },
	{	IH_TYPE_FPGA,	    "fpga",	  "FPGA Image" },
	{	IH_TYPE_TEE,	    "tee",	  "Trusted Execution Environment Image",},
	{	IH_TYPE_FIRMWARE_IVT, "firmware_ivt", "Firmware with HABv4 IVT" },
	{	IH_TYPE_PMMC,	     "pmmc",	    "TI Power Management Micro-Controller Firmware",},
	{	IH_TYPE_STM32IMAGE, "stm32image", "STMicroelectronics STM32 Image" },
	{	IH_TYPE_MTKIMAGE,   "mtk_image",   "MediaTek BootROM loadable Image" },
	{	IH_TYPE_COPRO, "copro", "Coprocessor Image"},
	{	IH_TYPE_SUNXI_EGON, "sunxi_egon",  "Allwinner eGON Boot Image" },
	{	IH_TYPE_SUNXI_TOC0, "sunxi_toc0",  "Allwinner TOC0 Boot Image" },
	{	IH_TYPE_FDT_LEGACY, "fdt_legacy", "legacy Image with Flat Device Tree ", },
	{	IH_TYPE_RENESAS_SPKG, "spkgimage", "Renesas SPKG Image" },
	{	IH_TYPE_ASTIMAGE,   "astimage",   "Aspeed Boot Image" },
	{	-1,		    "",		  "",			},
};

static const table_entry_t uimage_comp[] = {
	{	IH_COMP_NONE,	"none",		"uncompressed",		},
	{	IH_COMP_BZIP2,	"bzip2",	"bzip2 compressed",	},
	{	IH_COMP_GZIP,	"gzip",		"gzip compressed",	},
	{	IH_COMP_LZMA,	"lzma",		"lzma compressed",	},
	{	IH_COMP_LZO,	"lzo",		"lzo compressed",	},
	{	IH_COMP_LZ4,	"lz4",		"lz4 compressed",	},
	{	IH_COMP_ZSTD,	"zstd",		"zstd compressed",	},
	{	-1,		"",		"",			},
};


static const table_entry_t uimage_phase[] = {
	{	IH_PHASE_NONE,	"none",		"any",		},
	{	IH_PHASE_U_BOOT, "u-boot",	"U-Boot phase", },
	{	IH_PHASE_IROT,	"irot",		"IROT Phase",	},
	{	-1,		"",		"",		},
};

const table_entry_t *get_table_entry(const table_entry_t *table, int id)
{
	for (; table->id >= 0; ++table) {
		if (table->id == id)
			return table;
	}
	return NULL;
}

int get_table_entry_id(const table_entry_t *table,
		const char *table_name, const char *name)
{
	const table_entry_t *t;

	for (t = table; t->id >= 0; ++t) {
		if (t->sname && !strcasecmp(manual_reloc(t->sname), name))
			return t->id;
	}
	LOG_DBG("Invalid %s Type: %s", table_name, name);

	return -1;
}

char *get_table_entry_name(const table_entry_t *table, char *msg, int id)
{
	table = get_table_entry(table, id);
	if (!table)
		return msg;
	return manual_reloc(table->lname);
}

const char *genimg_get_os_name(uint8_t os)
{
	return (get_table_entry_name(uimage_os, "Unknown OS", os));
}

int genimg_get_os_id(const char *name)
{
	return (get_table_entry_id(uimage_os, "OS", name));
}

int genimg_get_arch_id(const char *name)
{
	return (get_table_entry_id(uimage_arch, "CPU", name));
}

int genimg_get_type_id(const char *name)
{
	return (get_table_entry_id(uimage_type, "Image", name));
}

int genimg_get_comp_id(const char *name)
{
	return (get_table_entry_id(uimage_comp, "Compression", name));
}

int genimg_get_phase_id(const char *name)
{
	return get_table_entry_id(uimage_phase, "Phase", name);
}

static void fit_get_debug(const void *fit, int noffset,
		char *prop_name, int err)
{
	LOG_DBG("Can't get '%s' property from FIT 0x%08x, node: offset %d, name %s (%s)",
	      prop_name, (uint32_t)fit, noffset, fit_get_name(fit, noffset, NULL),
	      fdt_strerror(err));
}

int fit_image_get_type(const void *fit, int noffset, uint8_t *type)
{
	int len;
	const void *data;

	/* Get image type name from property data */
	data = fdt_getprop(fit, noffset, FIT_TYPE_PROP, &len);
	if (data == NULL) {
		fit_get_debug(fit, noffset, FIT_TYPE_PROP, len);
		*type = -1;
		return -1;
	}

	/* Translate image type name to id */
	*type = genimg_get_type_id(data);
	return 0;
}

int fit_image_get_os(const void *fit, int noffset, uint8_t *os)
{
	int len;
	const void *data;

	/* Get OS name from property data */
	data = fdt_getprop(fit, noffset, FIT_OS_PROP, &len);
	if (data == NULL) {
		fit_get_debug(fit, noffset, FIT_OS_PROP, len);
		*os = -1;
		return -1;
	}

	/* Translate OS name to id */
	*os = genimg_get_os_id(data);
	return 0;
}

int fit_image_get_arch(const void *fit, int noffset, uint8_t *arch)
{
	int len;
	const void *data;

	/* Get architecture name from property data */
	data = fdt_getprop(fit, noffset, FIT_ARCH_PROP, &len);
	if (data == NULL) {
		fit_get_debug(fit, noffset, FIT_ARCH_PROP, len);
		*arch = -1;
		return -1;
	}

	/* Translate architecture name to id */
	*arch = genimg_get_arch_id(data);
	return 0;
}

int fit_image_get_data_position(const void *fit, int noffset,
				int *data_position)
{
	const fdt32_t *val;

	val = fdt_getprop(fit, noffset, FIT_DATA_POSITION_PROP, NULL);
	if (!val)
		return -ENOENT;

	*data_position = fdt32_to_cpu(*val);

	return 0;
}

int fit_image_get_data_offset(const void *fit, int noffset, int *data_offset)
{
	const fdt32_t *val;

	val = fdt_getprop(fit, noffset, FIT_DATA_OFFSET_PROP, NULL);
	if (!val)
		return -ENOENT;

	*data_offset = fdt32_to_cpu(*val);

	return 0;
}

int fit_image_get_data_size(const void *fit, int noffset, int *data_size)
{
	const fdt32_t *val;

	val = fdt_getprop(fit, noffset, FIT_DATA_SIZE_PROP, NULL);
	if (!val)
		return -ENOENT;

	*data_size = fdt32_to_cpu(*val);

	return 0;
}

int fit_image_get_data(const void *fit, int noffset,
		const void **data, size_t *size)
{
	int len;

	*data = fdt_getprop(fit, noffset, FIT_DATA_PROP, &len);
	if (*data == NULL) {
		fit_get_debug(fit, noffset, FIT_DATA_PROP, len);
		*size = 0;
		return -1;
	}

	*size = len;
	return 0;
}

static int fit_image_get_address(const void *fit, int noffset, char *name,
			  uint64_t *load)
{
	int len, cell_len;
	const fdt32_t *cell;
	uint64_t load64 = 0;

	cell = fdt_getprop(fit, noffset, name, &len);
	if (cell == NULL) {
		fit_get_debug(fit, noffset, name, len);
		return -1;
	}

	cell_len = len >> 2;
	/* Use load64 to avoid compiling warning for 32-bit target */
	while (cell_len--) {
		load64 = (load64 << 32) | uimage_to_cpu(*cell);
		cell++;
	}

	if (len > sizeof(uint64_t) && (uint32_t)(load64 >> 32)) {
		LOG_DBG("Unsupported %s address size", name);
		return -1;
	}

	*load = (uint64_t)load64;

	return 0;
}

/**
 * fit_image_get_entry() - get entry point address property
 * @fit: pointer to the FIT format image header
 * @noffset: component image node offset
 * @entry: pointer to the uint32_t, will hold entry point address
 *
 * This gets the entry point address property for a given component image
 * node.
 *
 * fit_image_get_entry() finds entry point address property in a given
 * component image node.  If the property is found, its value is returned
 * to the caller.
 *
 * returns:
 *     0, on success
 *     -1, on failure
 */
int fit_image_get_entry(const void *fit, int noffset, uint64_t *entry)
{
	return fit_image_get_address(fit, noffset, FIT_ENTRY_PROP, entry);
}

/**
 * fit_image_get_load() - get load addr property for given component image node
 * @fit: pointer to the FIT format image header
 * @noffset: component image node offset
 * @load: pointer to the uint32_t, will hold load address
 *
 * fit_image_get_load() finds load address property in a given component
 * image node. If the property is found, its value is returned to the caller.
 *
 * returns:
 *     0, on success
 *     -1, on failure
 */
int fit_image_get_load(const void *fit, int noffset, uint64_t *load)
{
	return fit_image_get_address(fit, noffset, FIT_LOAD_PROP, load);
}

/**
 * fit_image_hash_get_algo - get hash algorithm name
 * @fit: pointer to the FIT format image header
 * @noffset: hash node offset
 * @algo: double pointer to char, will hold pointer to the algorithm name
 *
 * fit_image_hash_get_algo() finds hash algorithm property in a given hash node.
 * If the property is found its data start address is returned to the caller.
 *
 * returns:
 *     0, on success
 *     -1, on failure
 */
int fit_image_hash_get_algo(const void *fit, int noffset, const char **algo)
{
	int len;

	*algo = (const char *)fdt_getprop(fit, noffset, FIT_ALGO_PROP, &len);
	if (*algo == NULL) {
		fit_get_debug(fit, noffset, FIT_ALGO_PROP, len);
		return -1;
	}

	return 0;
}

int fit_image_hash_get_value(const void *fit, int noffset, uint8_t **value,
                                int *value_len)
{
        int len;

        *value = (uint8_t *)fdt_getprop(fit, noffset, FIT_VALUE_PROP, &len);
        if (*value == NULL) {
                fit_get_debug(fit, noffset, FIT_VALUE_PROP, len);
                *value_len = 0;
                return -1;
        }

        *value_len = len;
        return 0;
}
