/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr.h>
#include <smf.h>
#include <shell/shell.h>
#include <logging/log.h>
#include <drivers/flash.h>
#include <drivers/misc/aspeed/abr_aspeed.h>

#include "AspeedStateMachine/AspeedStateMachine.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#include "cerberus_pfr/cerberus_pfr_provision.h"
#endif
#include "flash/flash_aspeed.h"
#include "flash/flash_wrapper.h"
#include "gpio/gpio_aspeed.h"
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_util.h"

#include "sys/base64.h"
#include "net/net_ip.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/hmac_drbg.h"
#include <crypto/hash.h>
#include <crypto/hash_aspeed.h>

LOG_MODULE_REGISTER(asm_test, LOG_LEVEL_DBG);

#if defined(CONFIG_ASPEED_STATE_MACHINE_SHELL)
static int cmd_asm_event(const struct shell *shell,
			size_t argc, char **argv, void *data)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	enum aspeed_pfr_event evt = (enum aspeed_pfr_event)((uint32_t)data & 0x000000FF);
	uint32_t evt_data = ((uint32_t)data & 0xFFFFFF00) >> 8;

	shell_print(shell, "Sending event[%d] evt_data[%08x]\n", evt, evt_data);
	GenerateStateMachineEvent(evt, (void *)evt_data);

	return 0;
}

static int cmd_asm_log(const struct shell *shell, size_t argc,
			char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_print(shell, "Event Count = %d\n", event_log_idx);
	shell_hexdump(shell, event_log, sizeof(event_log));
	return 0;
}

static int cmd_asm_abr(const struct shell *shell, size_t argc,
			char **argv)
{
	if (argc > 1 && !strncmp(argv[1], "enable", 6)) {
		shell_print(shell, "Enable ABR FMCWDT2");
#define ABR_CTRL_REG    0x7e620064
		uint32_t reg_val;

		reg_val = sys_read32(ABR_CTRL_REG);
		reg_val |= BIT(0);
		sys_write32(reg_val, ABR_CTRL_REG);
	} else {
		shell_print(shell, "Disable ABR FMCWDT2");
		disable_abr_wdt();
	}

	return 0;
}

static int cmd_asm_flash_cmp(const struct shell *shell, size_t argc,
			char **argv)
{
	if (argc < 4) {
		shell_print(shell, "asm flash_cmp DEVICE OFFSET_A OFFSET_B LENGTH");
		return 0;
	}
	char *dev_name = argv[1];
	size_t offset_a = strtol(argv[2], NULL, 16);
	size_t offset_b = strtol(argv[3], NULL, 16);
	size_t length = strtol(argv[4], NULL, 16);

	shell_print(shell, "Hash Dev:%s Offset_A:%p Offset_B:%p Length:%p", dev_name, offset_a, offset_b, length);

	const struct device *dev = device_get_binding(dev_name);

	if (dev == NULL) {
		shell_print(shell, "Failed to bind device:%s", dev_name);
		return 0;
	}

	char buffer_a[128] = {0};
	char buffer_b[128] = {0};
	size_t byte_read = 0;

	while (byte_read <= length) {
		size_t len = MIN(128, length - byte_read);

		if (len == 0)
			break;
		flash_read(dev, offset_a + byte_read, buffer_a, len);
		flash_read(dev, offset_b + byte_read, buffer_b, len);
		if (memcmp(buffer_a, buffer_b, len) != 0) {
			LOG_ERR("Offset_A=%08x Offset_B=%08x Different", offset_a + byte_read, offset_b + byte_read);
			LOG_HEXDUMP_ERR(buffer_a, len, "Buffer A");
			LOG_HEXDUMP_ERR(buffer_b, len, "Buffer B");
		}
		byte_read += len;
	}

	return 0;
}

static int cmd_asm_flash_copy(const struct shell *shell, size_t argc,
			char **argv)
{
	if (argc < 5) {
		shell_print(shell, "asm flash_cmp DEVICE_SRC OFFSET_SRC DEVICE_DEST OFFSET_DEST LENGTH");
		return 0;
	}

	char *dev_name_a = argv[1];
	size_t offset_a = strtol(argv[2], NULL, 16);
	char *dev_name_b = argv[3];
	size_t offset_b = strtol(argv[4], NULL, 16);
	size_t length = strtol(argv[5], NULL, 16);

	shell_print(shell, "Hash Dev_src:%s Offset_src:%p Dev_dest:%s Offset_dest:%p Length:%p",
			dev_name_a, offset_a, dev_name_b, offset_b, length);

	const struct device *dev_a = device_get_binding(dev_name_a);
	const struct device *dev_b = device_get_binding(dev_name_b);

	if (dev_a == NULL) {
		shell_print(shell, "Failed to bind device:%s", dev_name_a);
		return 0;
	}

	if (dev_b == NULL) {
		shell_print(shell, "Failed to bind device:%s", dev_name_b);
		return 0;
	}

	char buffer_a[128] = {0};
	size_t byte_read = 0;

	flash_erase(dev_b, offset_b, length);

	while (byte_read <= length) {
		size_t len = MIN(128, length - byte_read);

		if (len == 0)
			break;
		flash_read(dev_a,  offset_a + byte_read, buffer_a, len);
		flash_write(dev_b, offset_b + byte_read, buffer_a, len);
		byte_read += len;
	}

	return 0;
}

static int cmd_asm_flash_rebind(const struct shell *shell, size_t argc,
			char **argv)
{
	if (argc != 2) {
		shell_print(shell, "asm flash_rebind spiN_csX");
		return 0;
	}

	const struct device *dev = device_get_binding(argv[1]);
	if (dev == NULL) {
		shell_print(shell, "Device %s not found", argv[1]);
		return 0;
	}

	int ret = spi_nor_re_init(dev);
	shell_print(shell, "spi_nor_re_init(%s) return %d", argv[1], ret);
	return 0;
}

static int cmd_asm_rot_recovery(const struct shell *shell, size_t argc,
			char **argv)
{
	uint8_t status;
	uint32_t region_size = pfr_spi_get_device_size(ROT_INTERNAL_RECOVERY);

	LOG_INF("Erase PFR Active region size=%08x", region_size);
	if (pfr_spi_erase_region(ROT_INTERNAL_ACTIVE, true, 0, region_size)) {
		LOG_ERR("Erase PFR active region failed");
		return 0;
	}

	LOG_INF("Copy PFR Recovery region to Active region");
	status = pfr_spi_region_read_write_between_spi(ROT_INTERNAL_RECOVERY, 0,
			ROT_INTERNAL_ACTIVE, 0, region_size);

	if (!status)
		LOG_INF("Copy PFR Recovery region to Active region done");
	else
		LOG_ERR("Recover PFR active region failed");

	return 0;
}

static int cmd_asm_ufm_status(const struct shell *shell, size_t argc,
			char **argv)
{
	CPLD_STATUS cpld_update_status;

	ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));

	shell_print(shell, "CpldStatus = 0x%02x", cpld_update_status.CpldStatus);
	shell_print(shell, "BmcStatus = 0x%02x", cpld_update_status.BmcStatus);
	shell_print(shell, "PchStatus = 0x%02x", cpld_update_status.PchStatus);
	shell_print(shell, "DecommissionFlag = 0x%02x", cpld_update_status.DecommissionFlag);
	shell_print(shell, "CpldRecovery = 0x%02x", cpld_update_status.CpldRecovery);
	shell_print(shell, "BmcToPchStatus = 0x%02x", cpld_update_status.BmcToPchStatus);

	shell_print(shell, "Region[0].ActiveRegion = %02x", cpld_update_status.Region[0].ActiveRegion);
	shell_print(shell, "Region[0].Recoveryregion = %02x", cpld_update_status.Region[0].Recoveryregion);

	shell_print(shell, "Region[1].ActiveRegion = %02x", cpld_update_status.Region[1].ActiveRegion);
	shell_print(shell, "Region[2].Recoveryregion = %02x", cpld_update_status.Region[1].Recoveryregion);

	shell_print(shell, "Region[1].ActiveRegion = %02x", cpld_update_status.Region[2].ActiveRegion);
	shell_print(shell, "Region[2].Recoveryregion = %02x", cpld_update_status.Region[2].Recoveryregion);


	return 0;
}

static void inject_spi_error(const struct shell *shell, uint32_t flag)
{
	/* Flag defined as:
	 * 0x0F000000: BMC Active PFM
	 * 0x00F00000: BMC Recovery
	 * 0x000F0000: BMC Staging
	 * 0x0000F000: PCH Staging in BMC Flash
	 * 0x00000F00: PCH Active PFM
	 * 0x000000F0: PCH Recovery
	 * 0x0000000F: PCH Staging
	 */
	if (flag & 0x0FFFF000) {
		/* BMC Flash */
		const struct device *dev_mon = device_get_binding("spi_m1");
		const struct device *dev_flash = device_get_binding("spi1_cs0");
		spim_ext_mux_config(dev_mon, SPIM_EXT_MUX_ROT);
		if (flag & 0x0F000000) {
			/* ACT */
			uint32_t address;
			ufm_read(PROVISION_UFM, BMC_ACTIVE_PFM_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi1_cs0", address, 0x10000);
		}
		if (flag & 0x00F00000) {
			/* RCV */
			uint32_t address;
			ufm_read(PROVISION_UFM, BMC_RECOVERY_REGION_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi1_cs0", address, 0x10000);
		}
		if (flag & 0x000F0000) {
			/* STG */
			uint32_t address;
			ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi1_cs0", address, 0x10000);
		}
		if (flag & 0x0000F000) {
			/* PCH STG */
			uint32_t address;
			ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET + CONFIG_BMC_STAGING_SIZE,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi1_cs0", address, 0x10000);
		}
		spim_ext_mux_config(dev_mon, SPIM_EXT_MUX_BMC_PCH);
	}

	if (flag & 0x00000FFF) {
		/* PCH Flash */
		const struct device *dev_mon = device_get_binding("spi_m3");
		const struct device *dev_flash = device_get_binding("spi2_cs0");
		spim_ext_mux_config(dev_mon, SPIM_EXT_MUX_ROT);
		if (flag & 0x00000F00) {
			/* ACT */
			uint32_t address;
			ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "erase dev:%s offset:%08x size:%08x",
					"spi2_cs0", address, 0x10000);
		}
		if (flag & 0x000000F0) {
			/* RCV */
			uint32_t address;
			ufm_read(PROVISION_UFM, PCH_RECOVERY_REGION_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi2_cs0", address, 0x10000);
		}
		if (flag & 0x0000000F) {
			/* STG */
			uint32_t address;
			ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET,
					(uint8_t *)&address, sizeof(address));

			flash_erase(dev_flash, address, 0x10000);
			shell_print(shell, "Erase dev:%s offset:%08x size:%08x",
					"spi2_cs0", address, 0x10000);
		}
		spim_ext_mux_config(dev_mon, SPIM_EXT_MUX_BMC_PCH);
	}
}

static int cmd_asm_spi_error(const struct shell *shell,
			size_t argc, char **argv, void *data)
{
	shell_print(shell, "Test scenario:");
	shell_print(shell, "BMC[ACT:%c RCV:%c STG:%c P-STG:%c] PCH[ACT:%c RCV:%c STG:%c]",
			argv[0][0], argv[0][1], argv[0][2],
			argv[0][3], argv[0][4], argv[0][5], argv[0][6]);

	inject_spi_error(shell, (uint32_t)data);
	GenerateStateMachineEvent(RESET_DETECTED, NULL);

	return 0;
}

SHELL_SUBCMD_DICT_SET_CREATE(sub_event, cmd_asm_event,
	(INIT_DONE, INIT_DONE),
	(VERIFY_UNPROVISIONED, VERIFY_UNPROVISIONED),
	(VERIFY_FAILED, VERIFY_FAILED),
	(VERIFY_DONE, VERIFY_DONE),
	(RECOVERY_DONE, RECOVERY_DONE),
	(RECOVERY_FAILED, RECOVERY_FAILED),
	(RESET_DETECTED, RESET_DETECTED),
	(UPDATE_DONE, UPDATE_DONE),
	(UPDATE_FAILED, UPDATE_FAILED),
	(PROVISION_CMD, PROVISION_CMD),
	(WDT_TIMEOUT_BMC, (WDT_TIMEOUT | BMC_EVENT << 8)),
	(WDT_TIMEOUT_PCH, (WDT_TIMEOUT | PCH_EVENT << 8)),

	/* BMC Update Intent */
	(UPDATE_REQUESTED_BMC_BMC_ACT, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | BmcActiveUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_BMC_RCV, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | BmcRecoveryUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_PCH_ACT, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | PchActiveUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_PCH_RCV, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | PchRecoveryUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_PFR_ACT, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | HROTActiveUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_PFR_RCV, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | HROTRecoveryUpdate << 16)))),
	(UPDATE_REQUESTED_BMC_PFR_ACTRCV, (UPDATE_REQUESTED | ((BmcUpdateIntent << 8 | HROTActiveAndRecoveryUpdate << 16)))),

	/* PCH Update Intent */
	(UPDATE_REQUESTED_PCH_PCH_ACT, (UPDATE_REQUESTED | ((PchUpdateIntent << 8 | PchActiveUpdate << 16)))),
	(UPDATE_REQUESTED_PCH_PCH_RCV, (UPDATE_REQUESTED | ((PchUpdateIntent << 8 | PchRecoveryUpdate << 16))))

);



SHELL_SUBCMD_DICT_SET_CREATE(sub_spi_error, cmd_asm_spi_error,
	(GGGGGGG, 0x00000000),
	(BGGGGGG, 0x0F000000),
	(GBGGGGG, 0x00F00000),
	(BBGGGGG, 0x0FF00000),
	(GGGGBGG, 0x00000F00),
	(GGGGGBG, 0x000000F0),
	(GGGGBBG, 0x00000FF0),
	(GGGGBBB, 0x00000FFF),
	(GGGBBBB, 0x0000FFFF),
	(BGGGBGG, 0x0F000F00),
	(BGGGBBG, 0x0F000FF0),
	(BBGGBGG, 0x0FF00F00),
	(BBGGBBG, 0x0FF00FF0),
	(BBGGBBB, 0x0FF00FFF),
	(BBBBBBB, 0x0FFFFFFF)
);

static int cmd_test_plat_state_led(const struct shell *shell, size_t argc,
			char **argv)
{
	if (argc != 2) {
		shell_print(shell, "asm pstate STATE");
		return 0;
	}

	size_t pstate = strtol(argv[1], NULL, 16);

	if (pstate > LOCKDOWN_ON_PIT_L2_BMC_HASH_MISMATCH) {
		shell_print(shell, "State is not supported");
		return 0;
	}

	SetPlatformState(pstate);
	return 0;
}

#if defined(CONFIG_INTEL_PFR)
static int cmd_afm(const struct shell *shell, size_t argc, char **argv)
{
	if (argc != 3) {
		shell_print(shell, "afm FLASH_DEV FLASH_OFFSET");
		return 0;
	}

	const struct device *dev = device_get_binding(argv[1]);
	if (dev == NULL) {
		shell_print(shell, "Unable to find device: %s", argv[1]);
		return 0;
	}

	size_t offset = strtol(argv[2], NULL, 16);

	PFR_AUTHENTICATION_BLOCK0 block0;
	flash_read(dev, offset, (uint8_t *)&block0, sizeof(block0));

	shell_print(shell, "--- BLOCK 0 ---");
	shell_print(shell, "Tag:0x%08x  PCLength:0x%08x PCType:0x%08x",
		block0.Block0Tag, block0.PcLength, block0.PcType);
	shell_print(shell, "Sha256Pc:");
	shell_hexdump(shell, block0.Sha256Pc, sizeof(block0.Sha256Pc));
	shell_print(shell, "Sha384Pc:");
	shell_hexdump(shell, block0.Sha384Pc, sizeof(block0.Sha384Pc));

	if (block0.Block0Tag != BLOCK0TAG) {
		shell_print(shell, "Block 0 tag mismatch.");
		return 0;
	}

	PFR_AUTHENTICATION_BLOCK1 block1;
	flash_read(dev, offset + 128, (uint8_t *)&block1, sizeof(block1));
	shell_print(shell, "--- BLOCK 1 ---");
	shell_print(shell, "Tag:0x%08x", block1.TagBlock1);
	shell_print(shell, "KEY Tag:0x%08x CurveMagic:0x%08x Permission:0x%08x KeyId:0x%08x",
		block1.RootEntry.Tag, block1.RootEntry.PubCurveMagic, block1.RootEntry.KeyPermission, block1.RootEntry.KeyId);
	shell_print(shell, "Pubkey X:");
	shell_hexdump(shell, block1.RootEntry.PubKeyX, sizeof(block1.RootEntry.PubKeyX));
	shell_print(shell, "Pubkey Y:");
	shell_hexdump(shell, block1.RootEntry.PubKeyY, sizeof(block1.RootEntry.PubKeyY));

	if (block1.TagBlock1 != BLOCK1TAG) {
		shell_print(shell, "Block 1 tag mismatch.");
		return 0;
	}

	AFM_STRUCTURE afm;
	flash_read(dev, offset + 1024, (uint8_t *)&afm, sizeof(afm));
	shell_print(shell, "--- AFM ---");
	shell_print(shell, "Tag:0x%08x SVN:0x%02x Revision:0x%04x Length:0x%08x",
		afm.AfmTag, afm.SVN, afm.AfmRevision, afm.Length);

	if (afm.AfmTag != AFM_TAG) {
		shell_print(shell, "AFM tag mismatch.");
		return 0;
	}

	shell_print(shell, "OEM Speicific Data");
	shell_hexdump(shell, afm.OemSpecificData, sizeof(afm.OemSpecificData));

	for (size_t i=0; i < afm.Length/sizeof(AFM_ADDRESS_DEFINITION); ++i) {
		AFM_ADDRESS_DEFINITION addr;
		const size_t partition_offset = 0x07e00000; /* Test image coming from Archer City */
		flash_read(dev, offset + 1024 + sizeof(AFM_STRUCTURE) + i*sizeof(AFM_ADDRESS_DEFINITION), &addr, sizeof(AFM_ADDRESS_DEFINITION));
		shell_print(shell, "+++ AFM ADDR DEFINITION[%d] +++", i);
		shell_print(shell, "-> Type:0x%02x DevAddr:0x%02x UUID:0x%04x Length:0x%08x AfmAdd:0x%08x",
			addr.AfmDefinitionType, addr.DeviceAddress, addr.UUID, addr.Length, addr.AfmAddress - partition_offset);

		PFR_AUTHENTICATION_BLOCK0 afm_block0;
		flash_read(dev, offset + (addr.AfmAddress - partition_offset),
			(uint8_t *)&afm_block0, sizeof(PFR_AUTHENTICATION_BLOCK0));

		shell_print(shell, "--- AFM[%d] BLOCK 0 ---", i);
		shell_print(shell, "Tag:0x%08x  PCLength:0x%08x PCType:0x%08x",
			afm_block0.Block0Tag, afm_block0.PcLength, afm_block0.PcType);
		shell_print(shell, "Sha256Pc:");
		shell_hexdump(shell, afm_block0.Sha256Pc, sizeof(afm_block0.Sha256Pc));
		shell_print(shell, "Sha384Pc:");
		shell_hexdump(shell, afm_block0.Sha384Pc, sizeof(afm_block0.Sha384Pc));

		if (afm_block0.Block0Tag != BLOCK0TAG) {
			shell_print(shell, "Block 0 tag mismatch.");
			return 0;
		}

		PFR_AUTHENTICATION_BLOCK1 afm_block1;
		flash_read(dev, offset + (addr.AfmAddress - partition_offset) + sizeof(PFR_AUTHENTICATION_BLOCK0),
			(uint8_t *)&afm_block1, sizeof(PFR_AUTHENTICATION_BLOCK1));

		shell_print(shell, "--- AFM[%d] BLOCK 1 ---", i);

		shell_print(shell, "Tag:0x%08x", afm_block1.TagBlock1);
		shell_print(shell, "KEY Tag:0x%08x CurveMagic:0x%08x Permission:0x%08x KeyId:0x%08x",
			afm_block1.RootEntry.Tag, afm_block1.RootEntry.PubCurveMagic, afm_block1.RootEntry.KeyPermission, afm_block1.RootEntry.KeyId);
		shell_print(shell, "Pubkey X:");
		shell_hexdump(shell, afm_block1.RootEntry.PubKeyX, sizeof(afm_block1.RootEntry.PubKeyX));
		shell_print(shell, "Pubkey Y:");
		shell_hexdump(shell, afm_block1.RootEntry.PubKeyY, sizeof(afm_block1.RootEntry.PubKeyY));

		if (afm_block1.TagBlock1 != BLOCK1TAG) {
			shell_print(shell, "Block 1 tag mismatch.");
			return 0;
		}

		AFM_DEVICE_STRUCTURE afm_dev;
		shell_print(shell, "AFM OFFSET 0x%08x", offset + (addr.AfmAddress - partition_offset) + 1024);
		flash_read(dev, offset + (addr.AfmAddress - partition_offset) + 1024,
			&afm_dev, sizeof(AFM_DEVICE_STRUCTURE));
		shell_print(shell, "----> UUID:0x%04x BusID:0x%02x DevAddr:0x%02x Binding:%d BindingRev:0x%04x Policy:0x%02x SVN:0x%02x",
			afm_dev.UUID, afm_dev.BusID, afm_dev.DeviceAddress, afm_dev.BindingSpec, afm_dev.BindingSpecVersion,
			afm_dev.Policy, afm_dev.SVN);
		shell_print(shell, "AfmVer:0x%04x CurveMagic:0x%08x ManuStr:0x%04x ManuId:0x%04x PublicKeyExp:0x%08x",
			afm_dev.AfmVersion, afm_dev.CurveMagic, afm_dev.PlatformManufacturerStr, afm_dev.PlatformManufacturerIDModel,
			afm_dev.PublicKeyExponent);
		shell_print(shell, "PublicKeyXY:");
		shell_hexdump(shell, afm_dev.PublicKeyModuleXY, 96);

		shell_print(shell, "Total Measurements:%u", afm_dev.TotalMeasurements);

		size_t offs_measurem = offset + (addr.AfmAddress - partition_offset) + 1024 + sizeof(AFM_DEVICE_STRUCTURE);
		for (size_t j=0; j<afm_dev.TotalMeasurements; ++j) {
			AFM_DEVICE_MEASUREMENT_VALUE measurement;
			flash_read(dev, offs_measurem, &measurement, sizeof(AFM_DEVICE_MEASUREMENT_VALUE));

			shell_print(shell, "Possible Measurements:%d ValueType:0x%02x ValueSize:0x%04x",
				measurement.PossibleMeasurements, measurement.ValueType, measurement.ValueSize);
			offs_measurem += sizeof(AFM_DEVICE_MEASUREMENT_VALUE);
			for (size_t k=0; k<measurement.PossibleMeasurements; ++k) {
				uint8_t buffer[128];
				shell_print(shell, "Measurement[%d][%d]:", j, k);
				flash_read(dev, offs_measurem, buffer, measurement.ValueSize);
				shell_hexdump(shell, buffer, measurement.ValueSize);
				offs_measurem += measurement.ValueSize;
			}
		}
	}

	return 0;
}
#endif // CONFIG_INTEL_PFR

#if defined(CONFIG_ASPEED_DICE_SHELL)

extern uint8_t buffer[PAGE_SIZE] __aligned(16);

#define CDI_LENGTH                        64
#define CDI_ADDRESS                       0x79001800
#define DEVICE_FIRMWARE_START_ADDRESS     0x10000
#define DEVICE_FIRMWARE_SIZE              0x60000
#define ECDSA384_PRIVATE_KEY_SIZE         SHA384_HASH_LENGTH + 1
#define ECDSA384_PUBLIC_KEY_SIZE          SHA384_HASH_LENGTH * 2 + 1

#define X509_SERIAL_NUM_LENGTH            8


#define DER_MAX_PEM                       0x500
#define DER_MAX_TBS                       0x500
#define DER_MAX_NESTED                    0x10

#define RIOT_X509_KEY_USAGE 0x04    // keyCertSign
#define RIOT_X509_SNUM_LEN  0x08    // In bytes

#define BASE64_LEN(l) ((l == 0) ? (1) : (((((l - 1) / 3) + 1) * 4) + 1))

typedef struct {
	uint8_t serial_num[X509_SERIAL_NUM_LENGTH];
	uint8_t *issuer_common;
	uint8_t *issuer_org;
	uint8_t *issuer_country;
	uint8_t *valid_from;
	uint8_t *valid_to;
	uint8_t *subject_common;
	uint8_t *subject_org;
	uint8_t *subject_country;
} PFR_X509_TBS;

typedef struct
{
	uint8_t *buffer;
	uint32_t length;
	uint32_t position;
	int collection_start[DER_MAX_NESTED];
	int collection_position;
} PFR_DER_CTX;

typedef struct
{
	mbedtls_mpi r;
	mbedtls_mpi s;
} PFR_ECC_SIG;

// OIDs
static int oid_ecdsa_with_sha384[] = { 1,2,840,10045,4,3,3,-1 };
static int oid_common_name[] = { 2,5,4,3,-1 };
static int oid_country_name[] = { 2,5,4,6,-1 };
static int oid_org_name[] = { 2,5,4,10,-1 };
static int oid_ec_pubkey[] = { 1,2,840,10045, 2,1,-1 };
static int oid_curve_ecdsa384[] = { 1,3,132,0,34,-1 };
static int oid_key_usage[] = { 2,5,29,15,-1 };
static int oid_ext_key_usage[] = { 2,5,29,37,-1 };
static int oid_client_auth[] = { 1,3,6,1,5,5,7,3,2,-1 };
static int oid_auth_key_identifier[] = { 2,5,29,35,-1 };
//static int oid_riot[] = { 2,23,133,5,4,1,-1 };
static int oid_sha384[] = { 2,16,840,1,101,3,4,2,2,-1 };
static int oid_basic_constraints[] = { 2,5,29,19,-1 };

static mbedtls_hmac_drbg_context hmac_drbg_ctx = {0};
static uint8_t cdi_digest[SHA384_HASH_LENGTH] = {0};
static uint8_t dev_fwid[SHA384_HASH_LENGTH] = {0};
static uint8_t alias_digest[SHA384_HASH_LENGTH] = {0};

uint8_t devid_priv_key_buf[ECDSA384_PRIVATE_KEY_SIZE] = {0};
uint8_t devid_pub_key_buf[ECDSA384_PUBLIC_KEY_SIZE] = {0};
uint8_t alias_priv_key_buf[ECDSA384_PRIVATE_KEY_SIZE] = {0};
uint8_t alias_pub_key_buf[ECDSA384_PUBLIC_KEY_SIZE] = {0};
uint8_t keybuf[256] = {0};
uint8_t alias_cert[DER_MAX_PEM] = {0};
uint8_t devid_cert[DER_MAX_PEM] = {0};

enum cert_type {
	CERT_TYPE = 0,
	PUBLICKEY_TYPE,
	ECC_PRIVATEKEY_TYPE,
	CERT_REQ_TYPE,
	LAST_CERT_TYPE
};

typedef struct
{
    uint16_t    hLen;
    uint16_t    fLen;
    const char *header;
    const char *footer;
} PEM_HDR_FOOTERS;

// We only have a small subset of potential PEM encodings
const PEM_HDR_FOOTERS pem_hf[LAST_CERT_TYPE] = {
	{28, 26, "-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n"},
	{27, 25, "-----BEGIN PUBLIC KEY-----\n", "-----END PUBLIC KEY-----\n\0"},
	{31, 29, "-----BEGIN EC PRIVATE KEY-----\n", "-----END EC PRIVATE KEY-----\n"},
	{36, 34, "-----BEGIN CERTIFICATE REQUEST-----\n", "-----END CERTIFICATE REQUEST-----\n"}
};

void x509_generate_guid(uint8_t *guid, uint32_t *guid_len, uint8_t *seed, uint32_t seed_len)
{
	uint8_t digest[SHA384_HASH_LENGTH];
	uint32_t olen;

	hash_engine_sha_calculate(HASH_SHA384, seed, sizeof(seed_len),
			digest, sizeof(digest));
	base64_encode(guid, *guid_len, &olen, digest, 16);
	*guid_len = olen;
}

void x509_der_init_context(PFR_DER_CTX *ctx, uint8_t *buffer, uint32_t length)
{
	ctx->buffer = buffer;
	ctx->length = length;
	ctx->position = 0;
	memset(buffer, 0, length);
	for (int i = 0; i < DER_MAX_NESTED; i++) {
		ctx->collection_start[i] = -1;
	}
	ctx->collection_position = 0;
}

int x509_start_seq_or_set(PFR_DER_CTX *ctx, bool sequence)
{
	uint8_t tp = sequence ? 0x30 : 0x31;

	if (ctx->collection_position >= DER_MAX_NESTED)
		return -1;

	ctx->buffer[ctx->position++] = tp;
	ctx->collection_start[ctx->collection_position++] = ctx->position;
	return 0;
}

int x509_add_int_from_array(PFR_DER_CTX *ctx, uint8_t *val, uint32_t bytes)
{
	uint32_t i, num_leading_zeros = 0;
	bool negative;

	for (i = 0; i < bytes; i++) {
		if (val[i] != 0)
			break;
		num_leading_zeros++;
	}

	negative = val[num_leading_zeros] >= 128;
	ctx->buffer[ctx->position++] = 0x02;

	if (bytes == num_leading_zeros) {
		ctx->buffer[ctx->position++] = 1;
		ctx->buffer[ctx->position++] = 0;
	} else {
		if (negative) {
			ctx->buffer[ctx->position++] = (uint8_t)(bytes - num_leading_zeros + 1);
			ctx->buffer[ctx->position++] = 0;
		} else {
			ctx->buffer[ctx->position++] = (uint8_t)(bytes - num_leading_zeros);
		}

		for (i = num_leading_zeros; i < bytes; i++)
			ctx->buffer[ctx->position++] = val[i];
	}

	return 0;
}

int x509_add_short_explicit_int(PFR_DER_CTX *ctx, int val)
{
	long valx;

	ctx->buffer[ctx->position++] = 0xA0;
	ctx->buffer[ctx->position++] = 3;

	valx = htonl(val);

	return (x509_add_int_from_array(ctx, (uint8_t *)&valx, 4));
}

int x509_add_int(PFR_DER_CTX *ctx, int val)
{
	long valx = htonl(val);

	return (x509_add_int_from_array(ctx, (uint8_t *)&valx, 4));
}

int x509_add_bool(PFR_DER_CTX *ctx, bool val)
{
	ctx->buffer[ctx->position++] = 0x01;
	ctx->buffer[ctx->position++] = 0x01;
	ctx->buffer[ctx->position++] = (val == true) ? 0xFF : 0x00;

	return 0;
}

int x509_add_oid(PFR_DER_CTX *ctx, int *values)
{
	int     j, k;
	int     lenPos, digitPos = 0;
	int     val, digit;
	int     num_values = 0;

	for (j = 0; j < 16; j++) {
		if (values[j] < 0)
			break;
		num_values++;
	}

	ctx->buffer[ctx->position++] = 6;

	// Save space for length (only <128 supported)
	lenPos = ctx->position;
	ctx->position++;

	// DER-encode the OID, first octet is special
	val = num_values == 1 ? 0 : values[1];
	ctx->buffer[ctx->position++] = (uint8_t)(values[0] * 40 + val);

	// Others are base-128 encoded with the most significant bit of each byte,
	// apart from the least significant byte, set to 1.
	if (num_values >= 2) {
		uint8_t digits[5] = { 0 };

		for (j = 2; j < num_values; j++) {
			digitPos = 0;
			val = values[j];

			// Convert to B128
			while (true) {
				digit = val % 128;
				digits[digitPos++] = (uint8_t)digit;
				val = val / 128;
				if (val == 0) {
					break;
				}
			}

			// Reverse into the buffer, setting the MSB as needed.
			for (k = digitPos - 1; k >= 0; k--) {
				val = digits[k];
				if (k != 0) {
					val += 128;
				}
				ctx->buffer[ctx->position++] = (uint8_t)val;
			}
		}
	}

	ctx->buffer[lenPos] = (uint8_t)(ctx->position - 1 - lenPos);
	return 0;
}

int x509_get_int_encoded_num_bytes(int val)
{
	if (val < 128) {
		return 1;
	}
	if (val < 256) {
		return 2;
	}
	return 3;
}

int x509_encode_int(uint8_t *buf, int val)
{
	if (val <128) {
		buf[0] = (uint8_t)val;
		return 0;
	}
	if (val < 256) {
		buf[0] = 0x81;
		buf[1] = (uint8_t)val;
		return 0;
	}
	buf[0] = 0x82;
	buf[1] = (uint8_t)(val / 256);
	buf[2] = val % 256;

	return 0;
}

int x509_pop_nesting(PFR_DER_CTX *ctx)
{
	int start_pos, num_bytes, encoded_len_size;

	start_pos = ctx->collection_start[--ctx->collection_position];
	num_bytes = ctx->position - start_pos;

	encoded_len_size = x509_get_int_encoded_num_bytes(num_bytes);

	memmove(ctx->buffer + start_pos + encoded_len_size,
			ctx->buffer + start_pos,
			num_bytes);

	x509_encode_int(ctx->buffer + start_pos, num_bytes);

	ctx->position += encoded_len_size;

	return 0;
}

int x509_add_utf8_str(PFR_DER_CTX *ctx, uint8_t *str)
{
	uint32_t i, num_char = (uint32_t)strlen(str);

	ctx->buffer[ctx->position++] = 0x0c;
	ctx->buffer[ctx->position++] = (uint8_t)num_char;

	for (i = 0; i < num_char; i++) {
		ctx->buffer[ctx->position++] = str[i];
	}
	return 0;
}

int x509_add_x501_name(PFR_DER_CTX *ctx, uint8_t *common, uint8_t *org, uint8_t *country)
{
	x509_start_seq_or_set(ctx, true);
	x509_start_seq_or_set(ctx, false);
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_common_name);
	x509_add_utf8_str(ctx, common);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	x509_start_seq_or_set(ctx, false);
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_country_name);
	x509_add_utf8_str(ctx, country);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	x509_start_seq_or_set(ctx, false);
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_org_name);
	x509_add_utf8_str(ctx, org);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	return 0;
}

int x509_add_utc_time(PFR_DER_CTX *ctx, uint8_t *str)
{
	uint32_t i, num_char = (uint32_t)strlen(str);

	ctx->buffer[ctx->position++] = 0x17;
	ctx->buffer[ctx->position++] = (uint8_t)num_char;

	for (i = 0; i < num_char; i++) {
		ctx->buffer[ctx->position++] = str[i];
	}

	return 0;
}

int x509_add_bit_str(PFR_DER_CTX *ctx, uint8_t *bit_str, uint32_t bit_str_num_bytes)
{
	int len = bit_str_num_bytes + 1;

	ctx->buffer[ctx->position++] = 0x03;
	x509_encode_int(ctx->buffer + ctx->position, len);
	ctx->position += x509_get_int_encoded_num_bytes(len);
	ctx->buffer[ctx->position++] = 0;
	memcpy(ctx->buffer + ctx->position, bit_str, bit_str_num_bytes);
	ctx->position += bit_str_num_bytes;

	return 0;
}

int x509_add_oct_str(PFR_DER_CTX *ctx, uint8_t *oct_str, uint32_t oct_str_len)
{
	ctx->buffer[ctx->position++] = 0x04;
	x509_encode_int(ctx->buffer + ctx->position, oct_str_len);
	ctx->position += x509_get_int_encoded_num_bytes(oct_str_len);
	memcpy(ctx->buffer + ctx->position, oct_str, oct_str_len);
	ctx->position += oct_str_len;

	return 0;
}

int x509_start_explicit(PFR_DER_CTX *ctx, uint32_t num)
{
    ctx->buffer[ctx->position++] = 0xA0 + (uint8_t)num;
    ctx->collection_start[ctx->collection_position++] = ctx->position;

    return 0;
}

int x509_envelop_oct_str(PFR_DER_CTX *ctx)
{
	ctx->buffer[ctx->position++] = 0x04;
	ctx->collection_start[ctx->collection_position++] = ctx->position;

	return 0;
}

int x509_envelop_bit_str(PFR_DER_CTX *ctx)
{
	ctx->buffer[ctx->position++] = 0x03;
	ctx->collection_start[ctx->collection_position++] = ctx->position;
	ctx->buffer[ctx->position++] = 0;

	return 0;
}

int x509_tbs_to_cert(PFR_DER_CTX *ctx)
{
	memmove(ctx->buffer + 1, ctx->buffer, ctx->position);
	ctx->position++;

	// sequence tag
	ctx->buffer[0] = 0x30;
	ctx->collection_start[ctx->collection_position++] = 1;

	return 0;
}

int x509_der_to_pem(PFR_DER_CTX *ctx, uint32_t type, uint8_t *pem, uint32_t *length)
{
	uint32_t req_len, olen;
	uint32_t base64_len = BASE64_LEN(ctx->position);

	req_len = base64_len + pem_hf[type].hLen + pem_hf[type].fLen;

	if (length && (*length < req_len)) {
		*length = req_len;
		return -1;
	}

	memcpy(pem, pem_hf[type].header, pem_hf[type].hLen);
	pem += pem_hf[type].hLen;

	base64_encode(pem, DER_MAX_PEM, &olen, ctx->buffer, ctx->position);
	pem += base64_len;
	memcpy(pem, pem_hf[type].footer, pem_hf[type].fLen);
	pem += pem_hf[type].fLen;

	if (length)
		*length = req_len;

	return 0;
}

int x509_add_extentions(PFR_DER_CTX *ctx, uint8_t *devid_pub_key, uint32_t devid_pub_key_len,
		uint8_t *dev_fwid, uint32_t fwid_len)
{
	uint8_t auth_key_identifier[SHA1_HASH_LENGTH];
	uint8_t key_usage = RIOT_X509_KEY_USAGE;
	uint8_t ext_len = 1;

	hash_engine_sha_calculate(HASH_SHA1, devid_pub_key, devid_pub_key_len,
			auth_key_identifier, sizeof(auth_key_identifier));

	x509_start_explicit(ctx, 3);
	x509_start_seq_or_set(ctx, true);

	// key usage
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_key_usage);
	x509_envelop_oct_str(ctx);
	x509_add_bit_str(ctx, &key_usage, ext_len);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	// extended key usage
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_ext_key_usage);
	x509_envelop_oct_str(ctx);
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_client_auth);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	// authority key identifier
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_auth_key_identifier);
	x509_envelop_oct_str(ctx);
	x509_start_seq_or_set(ctx, true);
	x509_start_explicit(ctx, 0);
	x509_add_oct_str(ctx, auth_key_identifier, SHA1_HASH_LENGTH);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	// basic constraints
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_basic_constraints);
	// is critical
	x509_add_bool(ctx, true);
	x509_envelop_oct_str(ctx);
	x509_start_seq_or_set(ctx, true);
	// cA = false
	x509_add_bool(ctx, false);
	x509_add_int(ctx, 1);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	return 0;
}

int x509_get_alias_cert_tbs(PFR_DER_CTX *ctx, PFR_X509_TBS *tbs_data,
		uint8_t *alias_pub_key, uint8_t *devid_pub_key,
		uint8_t *dev_fwid, uint32_t fwid_len)
{
	uint8_t guid_buf[64] = {0};
	uint32_t guid_buf_len = sizeof(guid_buf);

	if (strncmp(tbs_data->subject_common, "*", 1) == 0) {
		x509_generate_guid(guid_buf, &guid_buf_len, devid_pub_key, ECDSA384_PUBLIC_KEY_SIZE);
		guid_buf[guid_buf_len - 1] = 0;
		tbs_data->subject_common = guid_buf;
	}

	x509_start_seq_or_set(ctx, true);
	x509_add_short_explicit_int(ctx, 2);
	x509_add_int_from_array(ctx, tbs_data->serial_num, X509_SERIAL_NUM_LENGTH);
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_ecdsa_with_sha384);
	x509_pop_nesting(ctx);

	x509_add_x501_name(ctx, tbs_data->issuer_common, tbs_data->issuer_org,
			tbs_data->issuer_country);
	x509_start_seq_or_set(ctx, true);
	x509_add_utc_time(ctx, tbs_data->valid_from);
	x509_add_utc_time(ctx, tbs_data->valid_to);
	x509_pop_nesting(ctx);

	x509_add_x501_name(ctx, tbs_data->subject_common, tbs_data->subject_org,
			tbs_data->subject_country);
	x509_start_seq_or_set(ctx, true);
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_ec_pubkey);
	x509_add_oid(ctx, oid_curve_ecdsa384);
	x509_pop_nesting(ctx);

	x509_add_bit_str(ctx, alias_pub_key, ECDSA384_PUBLIC_KEY_SIZE);
	x509_pop_nesting(ctx);
	x509_add_extentions(ctx, devid_pub_key, ECDSA384_PUBLIC_KEY_SIZE, dev_fwid, fwid_len);
	x509_pop_nesting(ctx);

	return 0;
}

int x509_get_device_cert_tbs(PFR_DER_CTX *ctx, PFR_X509_TBS *tbs_data,
		uint8_t *devid_pub_key)
{
	uint8_t key_usage = RIOT_X509_KEY_USAGE;
	x509_start_seq_or_set(ctx, true);
	x509_add_short_explicit_int(ctx, 2);
	x509_add_int_from_array(ctx, tbs_data->serial_num, X509_SERIAL_NUM_LENGTH);
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_ecdsa_with_sha384);
	x509_pop_nesting(ctx);

	x509_add_x501_name(ctx, tbs_data->issuer_common, tbs_data->issuer_org,
			tbs_data->issuer_country);
	x509_start_seq_or_set(ctx, true);
	x509_add_utc_time(ctx, tbs_data->valid_from);
	x509_add_utc_time(ctx, tbs_data->valid_to);
	x509_pop_nesting(ctx);

	x509_add_x501_name(ctx, tbs_data->subject_common, tbs_data->subject_org,
			tbs_data->subject_country);
	x509_start_seq_or_set(ctx, true);
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_ec_pubkey);
	x509_add_oid(ctx, oid_curve_ecdsa384);
	x509_pop_nesting(ctx);

	x509_add_bit_str(ctx, devid_pub_key, ECDSA384_PUBLIC_KEY_SIZE);
	x509_pop_nesting(ctx);
	x509_start_explicit(ctx, 3);
	x509_start_seq_or_set(ctx, true);

	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_key_usage);
	x509_envelop_oct_str(ctx);
	x509_add_bit_str(ctx, &key_usage, 1);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_basic_constraints);
	x509_add_bool(ctx, true);
	x509_envelop_oct_str(ctx);
	x509_start_seq_or_set(ctx, true);
	x509_add_bool(ctx, true);
	x509_add_int(ctx, 1);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	return 0;
}

int x509_get_csr_tbs(PFR_DER_CTX *ctx, PFR_X509_TBS *tbs_data, uint8_t *devid_pub_key)
{
	x509_start_seq_or_set(ctx, true);
	x509_add_int(ctx, 0);
	x509_add_x501_name(ctx, tbs_data->issuer_common, tbs_data->issuer_org,
			tbs_data->issuer_country);

	x509_start_seq_or_set(ctx, true);
	x509_start_seq_or_set(ctx, true);
	x509_add_oid(ctx, oid_ec_pubkey);
	x509_add_oid(ctx, oid_curve_ecdsa384);
	x509_pop_nesting(ctx);
	x509_add_bit_str(ctx, devid_pub_key, ECDSA384_PUBLIC_KEY_SIZE);
	x509_pop_nesting(ctx);
	x509_start_explicit(ctx, 0);
	x509_pop_nesting(ctx);
	x509_pop_nesting(ctx);

	return 0;
}

void x509_set_serial_number(PFR_X509_TBS *tbs_data, uint8_t *digest, uint8_t digest_len)
{
	uint8_t dice_seed[9] = "DICE_SEED";
	uint8_t dice_seed_digest[SHA384_HASH_LENGTH];
	uint8_t final_digest[SHA384_HASH_LENGTH];
	hash_engine_sha_calculate(HASH_SHA384, dice_seed, sizeof(dice_seed),
			dice_seed_digest, sizeof(dice_seed_digest));
	hash_engine_start(HASH_SHA384);
	hash_engine_update(dice_seed_digest, sizeof(dice_seed_digest));
	hash_engine_update(digest, digest_len);
	hash_engine_finish(final_digest, sizeof(final_digest));
	memcpy(tbs_data->serial_num, final_digest, X509_SERIAL_NUM_LENGTH);

	// DER encoded serial number must be positive and the first byte must not be zero
	tbs_data->serial_num[0] &= 0x7f;
	tbs_data->serial_num[0] |= 0x01;
}

int hash_device_firmware(uint32_t addr, uint32_t fw_size, uint8_t *hash, uint32_t hash_len,
		enum hash_algo algo)
{
	const struct device *flash_dev;
	uint32_t read_len;
	flash_dev = device_get_binding("fmc_cs0");
	hash_engine_start(algo);
	while (fw_size > 0) {
		read_len = (fw_size < PAGE_SIZE) ? fw_size : PAGE_SIZE;
		flash_read(flash_dev, addr, buffer, read_len);
		hash_engine_update(buffer, read_len);
		addr += read_len;
		fw_size -= read_len;
	}

	hash_engine_finish(hash, hash_len);

	return 0;
}

// TODO:
// Since srand() is not supported in current zephyr, we use the hash of cdi digest
// as the seed of mbedtls random number generator.
#if 0
int get_rand_bytes( void *rngState, uint8_t *output, size_t length)
{
	ARG_UNUSED(rngState);
	for (; length; length--)
		*output++ = (uint8_t)rand();

	return 0;
}

int seed_drbg(uint8_t *digest, uint32_t digest_len)
{
	uint32_t i, seed;
	mbedtls_md_info_t *md_sha384;
	int ret = -1;

	for (i = 0; i < digest_len; i++) {
		seed += ~(digest[i]);
	}
	srand(~seed);

	mbedtls_hmac_drbg_init(&hmac_drbg_ctx);

	if (!(md_sha384 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384)))
		goto free_drbg;

	if (mbedtls_hmac_drbg_seed(&hmac_drbg_ctx, md_sha384, get_rand_bytes, NULL, NULL, 0))
		goto free_drbg;

	ret = 0;

free_drbg:
	if (ret)
		mbedtls_hmac_drbg_free(&hmac_drbg_ctx);

	return ret;
}
#else

// Temporary solution
int get_rand_bytes_by_cdi(void *rngState, uint8_t *output, size_t length)
{
	uint8_t cdi_digest_digest[SHA384_HASH_LENGTH];
	ARG_UNUSED(rngState);
	hash_engine_sha_calculate(HASH_SHA384, (uint8_t *)cdi_digest, SHA384_HASH_LENGTH,
			cdi_digest_digest, sizeof(cdi_digest_digest));
	memset(output, 0, length);
	memcpy(output, cdi_digest_digest,
			(length <= SHA384_HASH_LENGTH) ? length : SHA384_HASH_LENGTH);


	return 0;
}

int get_rand_bytes_by_cdi_fwid(void *rngState, uint8_t *output, size_t length)
{
	ARG_UNUSED(rngState);


	// Combine CDI and FWID for deriving alias key
	hash_engine_start(HASH_SHA384);
	hash_engine_update(cdi_digest, SHA384_HASH_LENGTH);
	hash_engine_update(dev_fwid, SHA384_HASH_LENGTH);
	hash_engine_finish(alias_digest, sizeof(alias_digest));
	memset(output, 0, length);
	memcpy(output, alias_digest,
			(length <= SHA384_HASH_LENGTH) ? length : SHA384_HASH_LENGTH);

	return 0;
}

int seed_drbg(int (*f_entropy)(void *, unsigned char *, size_t), void *p_entropy)
{
	mbedtls_md_info_t *md_sha384;
	int ret = -1;

	if (hmac_drbg_ctx.MBEDTLS_PRIVATE(entropy_len))
		mbedtls_hmac_drbg_free(&hmac_drbg_ctx);

	mbedtls_hmac_drbg_init(&hmac_drbg_ctx);

	if (!(md_sha384 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384)))
		goto free_drbg;

	if (mbedtls_hmac_drbg_seed(&hmac_drbg_ctx, md_sha384, f_entropy,
				p_entropy, NULL, 0))
		goto free_drbg;

	ret = 0;

free_drbg:
	if (ret)
		mbedtls_hmac_drbg_free(&hmac_drbg_ctx);

	return ret;
}

#endif


void derive_key_pair(mbedtls_ecdsa_context *ctx_sign, uint8_t *privkey_buf, uint8_t *pubkey_buf,
		int (*f_entropy)(void *, unsigned char *, size_t), void *p_entropy)
{
	size_t len;
	// Seed drbg with cdi digest
	seed_drbg(f_entropy, p_entropy);

	mbedtls_ecdsa_init(ctx_sign);

	if (mbedtls_ecdsa_genkey(ctx_sign, MBEDTLS_ECP_DP_SECP384R1, mbedtls_hmac_drbg_random,
				&hmac_drbg_ctx)) {
		return;
	}

	if (mbedtls_ecp_point_write_binary(&ctx_sign->MBEDTLS_PRIVATE(grp),
			&ctx_sign->MBEDTLS_PRIVATE(d),
			MBEDTLS_ECP_PF_UNCOMPRESSED, &len, privkey_buf, 128)) {
		LOG_ERR("Failed to get ecdsa privkey");
		return;
	}

	if (mbedtls_ecp_point_write_binary(&ctx_sign->MBEDTLS_PRIVATE(grp),
			&ctx_sign->MBEDTLS_PRIVATE(Q),
			MBEDTLS_ECP_PF_UNCOMPRESSED, &len, pubkey_buf, 128)) {
		LOG_ERR("Failed to get ecdsa pubkey");
		return;
	}
}

int x509_digest_sign(PFR_ECC_SIG *sig, uint8_t *digest, uint32_t digest_len,
		mbedtls_ecdsa_context *ctx)
{

	return (mbedtls_ecdsa_sign(&ctx->MBEDTLS_PRIVATE(grp), &sig->r, &sig->s,
				&ctx->MBEDTLS_PRIVATE(d), digest, digest_len,
				mbedtls_hmac_drbg_random, &hmac_drbg_ctx));
}

int x509_cert_sign(PFR_ECC_SIG *sig, void *data, uint32_t size, mbedtls_ecdsa_context *ctx)
{
	uint8_t digest[SHA384_HASH_LENGTH];

	hash_engine_sha_calculate(HASH_SHA384, data, size, digest, sizeof(digest));

	return (x509_digest_sign(sig, digest, sizeof(digest), ctx));
}

int x509_mpi_to_int(mbedtls_mpi *mpi, uint8_t *buf, uint32_t buf_len)
{
	return (mbedtls_mpi_write_binary(mpi, buf, SHA384_HASH_LENGTH));
}

int x509_gen_cert(PFR_DER_CTX *cert, PFR_ECC_SIG *tbs_sig)
{
	uint8_t enc_buf[SHA384_HASH_LENGTH] = {0};
	uint32_t enc_buf_len = sizeof(enc_buf);

	x509_tbs_to_cert(cert);
	x509_start_seq_or_set(cert, true);
	x509_add_oid(cert, oid_ecdsa_with_sha384);
	x509_pop_nesting(cert);
	x509_envelop_bit_str(cert);
	x509_start_seq_or_set(cert, true);
	x509_mpi_to_int(&tbs_sig->r, enc_buf, enc_buf_len);
	x509_add_int_from_array(cert, enc_buf, enc_buf_len);
	x509_mpi_to_int(&tbs_sig->s, enc_buf, enc_buf_len);
	x509_add_int_from_array(cert, enc_buf, enc_buf_len);
	x509_pop_nesting(cert);
	x509_pop_nesting(cert);
	x509_pop_nesting(cert);

	return 0;
}

void dice_start(size_t cert_type)
{
	// x509 TBS(to be signed) region
	PFR_X509_TBS x509_alias_tbs = {{0x55, 0x66, 0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd},
		"Aspeed PFR Core",
		"AST_TEST",
		"TW",
		"221010000000Z",
		"421010000000Z",
		"*",
		"AST_TEST",
		"TW"};

	PFR_X509_TBS x509_device_tbs = {{0x55, 0x66, 0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd},
		"Aspeed PFR R00t",
		"AST_TEST",
		"TW",
		"221010000000Z",
		"421010000000Z",
		"*",
		"AST_TEST",
		"TW"};

	mbedtls_ecdsa_context ctx_devid;
	mbedtls_ecdsa_context ctx_alias;
	PFR_DER_CTX der_ctx;
	PFR_ECC_SIG tbs_sig;
	uint32_t len;

	uint8_t der_buf[DER_MAX_TBS];
	// Hash CDI
	hash_engine_sha_calculate(HASH_SHA384, (uint8_t *)CDI_ADDRESS, CDI_LENGTH,
			cdi_digest, sizeof(cdi_digest));
	//LOG_HEXDUMP_INF((uint8_t *)CDI_ADDRESS, CDI_LENGTH, "CDI :");
	//LOG_HEXDUMP_INF(cdi_digest, SHA384_HASH_LENGTH, "CDI digest :");

	// Derive DeviceID key pair from CDI
	derive_key_pair(&ctx_devid, devid_priv_key_buf, devid_pub_key_buf,
			get_rand_bytes_by_cdi, NULL);
	//LOG_HEXDUMP_INF(devid_priv_key_buf, ECDSA384_PRIVATE_KEY_SIZE, "DEVID PRIKEY :");
	//LOG_HEXDUMP_INF(devid_pub_key_buf, ECDSA384_PUBLIC_KEY_SIZE, "DEVID PUBKEY :");

	// Set serial number of DeviceID certificate
	x509_set_serial_number(&x509_device_tbs, cdi_digest, sizeof(cdi_digest));

	mbedtls_mpi_write_string(&ctx_devid.MBEDTLS_PRIVATE(d), 16, keybuf, sizeof(keybuf), &len);
	mbedtls_mpi_write_string(&ctx_devid.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), 16, keybuf,
			sizeof(keybuf), &len);
	mbedtls_mpi_write_string(&ctx_devid.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), 16, keybuf,
			sizeof(keybuf), &len);

	// Hash device firmware as FWID
	hash_device_firmware(DEVICE_FIRMWARE_START_ADDRESS, DEVICE_FIRMWARE_SIZE, dev_fwid,
			SHA384_HASH_LENGTH, HASH_SHA384);

	// Derive Alias key pair from CDI and FWID
	derive_key_pair(&ctx_alias, alias_priv_key_buf, alias_pub_key_buf,
			get_rand_bytes_by_cdi_fwid, NULL);
	//LOG_HEXDUMP_INF(alias_priv_key_buf, ECDSA384_PRIVATE_KEY_SIZE, "Alias PRIKEY :");
	//LOG_HEXDUMP_INF(alias_pub_key_buf, ECDSA384_PUBLIC_KEY_SIZE, "Alias PUBKEY :");

	// Set serial number of Alias certificate
	x509_set_serial_number(&x509_alias_tbs, alias_digest, sizeof(alias_digest));

	mbedtls_mpi_write_string(&ctx_alias.MBEDTLS_PRIVATE(d), 16, keybuf, sizeof(keybuf), &len);
	mbedtls_mpi_write_string(&ctx_alias.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), 16, keybuf,
			sizeof(keybuf), &len);
	mbedtls_mpi_write_string(&ctx_alias.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), 16, keybuf,
			sizeof(keybuf), &len);

	x509_der_init_context(&der_ctx, der_buf, DER_MAX_TBS);
	x509_get_alias_cert_tbs(&der_ctx, &x509_alias_tbs, alias_pub_key_buf,
			devid_pub_key_buf, dev_fwid, SHA384_HASH_LENGTH);

	mbedtls_mpi_init(&tbs_sig.r);
	mbedtls_mpi_init(&tbs_sig.s);
	x509_cert_sign(&tbs_sig, der_ctx.buffer, der_ctx.position, &ctx_devid);

	x509_gen_cert(&der_ctx, &tbs_sig);
	len = sizeof(alias_cert);
	//LOG_HEXDUMP_INF(der_ctx.buffer, der_ctx.position, "Alias Cert DER :");
	x509_der_to_pem(&der_ctx, CERT_TYPE, alias_cert, &len);
	alias_cert[len] = 0;

	//LOG_HEXDUMP_INF(alias_cert, sizeof(alias_cert), "Alias Cert PEM :");

	if(cert_type) {
		// Self-Signed
		x509_device_tbs.issuer_common = x509_device_tbs.subject_common;
		x509_device_tbs.issuer_org = x509_device_tbs.subject_org;
		x509_device_tbs.issuer_country = x509_device_tbs.subject_country;
		x509_der_init_context(&der_ctx, der_buf, DER_MAX_TBS);
		x509_get_device_cert_tbs(&der_ctx, &x509_device_tbs, devid_pub_key_buf);
		x509_cert_sign(&tbs_sig, der_ctx.buffer, der_ctx.position, &ctx_devid);
		x509_gen_cert(&der_ctx, &tbs_sig);
		x509_der_to_pem(&der_ctx, CERT_TYPE, devid_cert, &len);
		devid_cert[len] = 0;
		//LOG_HEXDUMP_INF(der_ctx.buffer, der_ctx.position, "DevID Cert DER :");
		//LOG_HEXDUMP_INF(devid_cert, sizeof(devid_cert), "DevID Cert PEM :");
	} else {
		// CSR
		x509_der_init_context(&der_ctx, der_buf, DER_MAX_TBS);
		x509_get_csr_tbs(&der_ctx, &x509_alias_tbs, devid_pub_key_buf);
		x509_cert_sign(&tbs_sig, der_ctx.buffer, der_ctx.position, &ctx_devid);
		x509_gen_cert(&der_ctx, &tbs_sig);
		x509_der_to_pem(&der_ctx, CERT_REQ_TYPE, devid_cert, &len);
		devid_cert[len] = 0;
		//LOG_HEXDUMP_INF(der_ctx.buffer, der_ctx.position, "DevID CSR DER :");
		//LOG_HEXDUMP_INF(devid_cert, sizeof(devid_cert), "DevID CSR PEM :");
	}

	mbedtls_ecdsa_free(&ctx_devid);
	mbedtls_ecdsa_free(&ctx_alias);
}

void dump_cert(const struct shell *shell, uint8_t *cert, uint32_t cert_size)
{
	uint32_t remaining = cert_size;
	int i = 0, len, start = 0;
	uint8_t buf[65] = {0};

	while(remaining) {
		if (i - start == 63 || cert[i] == 0x0a) {
			len = (cert[i] == 0x0a) ? i - start : i - start + 1;
			memcpy(buf, &cert[start], len);
			shell_print(shell, "%s", buf);
			remaining -= (i - start) + 1;
			start = ++i;
		} else if (cert[i] == 0) {
			if (i > start) {
				memcpy(buf, &cert[start], i - start + 1);
				shell_print(shell, "%s", buf);
			}

			// print footer
			shell_print(shell, "%s", &cert[i + 1]);

			break;
		} else {
			++i;
		}
	}
}

static int cmd_dice(const struct shell *shell, size_t argc, char **argv)
{
	int i;
	uint8_t buf[65] = {0};

	if (argc != 2) {
		shell_print(shell, "asm dice <0/1> for generating device id CSR(0) or CERT(1)");
		return 0;
	}

	size_t cert_type = strtol(argv[1], NULL, 16);
	memset(devid_cert, 0, sizeof(devid_cert));
	memset(alias_cert, 0, sizeof(alias_cert));

	dice_start(cert_type);

	shell_print(shell, "DeviceID PRIV KEY :");
	shell_hexdump(shell, devid_priv_key_buf, ECDSA384_PRIVATE_KEY_SIZE);
	shell_print(shell, "DeviceID PUB KEY :");
	shell_hexdump(shell, devid_pub_key_buf, ECDSA384_PUBLIC_KEY_SIZE);
	shell_print(shell, "Alias PRIV KEY :");
	shell_hexdump(shell, alias_priv_key_buf, ECDSA384_PUBLIC_KEY_SIZE);
	shell_print(shell, "Alias PUB KEY :");
	shell_hexdump(shell, alias_pub_key_buf, ECDSA384_PUBLIC_KEY_SIZE);
	shell_print(shell, "DevID %s PEM :", (cert_type) ? "CERT" : "CSR");
	dump_cert(shell, devid_cert, sizeof(devid_cert));

	shell_print(shell, "Alias CERT PEM :");
	dump_cert(shell, alias_cert, sizeof(alias_cert));

	return 0;
}
#endif // CONFIG_ASPEED_DICE_SHELL

SHELL_STATIC_SUBCMD_SET_CREATE(sub_asm,
	SHELL_CMD(log, NULL, "Show state machine event log", cmd_asm_log),
	SHELL_CMD(event, &sub_event, "State Machine Event", NULL),
	SHELL_CMD(abr, NULL, "Control FMCWDT2 timer manually: enable or disable", cmd_asm_abr),
	SHELL_CMD(rot_rc, NULL, "ROT firmware recoery", cmd_asm_rot_recovery),
	SHELL_CMD(ufm_status, NULL, "Dump UFM status flag for update flow", cmd_asm_ufm_status),
	SHELL_CMD(spi_error_inject, &sub_spi_error, "Inject error to SPI for testing", NULL),
	SHELL_CMD(flash_cmp, NULL, "Flash content compairson", cmd_asm_flash_cmp),
	SHELL_CMD(flash_copy, NULL, "Copy data between Flash", cmd_asm_flash_copy),
	SHELL_CMD(flash_rebind, NULL, "Rebind SPI Flash", cmd_asm_flash_rebind),
	SHELL_CMD(pstate, NULL, "Test Platform State LED", cmd_test_plat_state_led),
#if defined(CONFIG_INTEL_PFR)
	SHELL_CMD(afm, NULL, "Dump AFM Structure: DEVICE OFFSET", cmd_afm),
#endif
#if defined(CONFIG_ASPEED_DICE_SHELL)
	SHELL_CMD(dice, NULL, "Generate Cert Chain", cmd_dice),
#endif
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(asm, &sub_asm, "Aspeed PFR State Machine Commands", NULL);
#endif
