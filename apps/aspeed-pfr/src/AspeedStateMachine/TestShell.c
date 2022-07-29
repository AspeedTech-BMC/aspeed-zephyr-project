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
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "flash/flash_aspeed.h"
#include "flash/flash_wrapper.h"
#include "gpio/gpio_aspeed.h"
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_util.h"

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

SHELL_STATIC_SUBCMD_SET_CREATE(sub_asm,
	SHELL_CMD(log, NULL, "Show state machine event log", cmd_asm_log),
	SHELL_CMD(event, &sub_event, "State Machine Event", NULL),
	SHELL_CMD(abr, NULL, "Control FMCWDT2 timer manually: enable or disable", cmd_asm_abr),
	SHELL_CMD(rot_rc, NULL, "ROT firmware recoery", cmd_asm_rot_recovery),
	SHELL_CMD(ufm_status, NULL, "Dump UFM status flag for update flow", cmd_asm_ufm_status),
	SHELL_CMD(spi_error_inject, &sub_spi_error, "Inject error to SPI for testing", NULL),
	SHELL_CMD(flash_cmp, NULL, "Flash content compairson", cmd_asm_flash_cmp),
	SHELL_CMD(flash_copy, NULL, "Copy data between Flash", cmd_asm_flash_copy),
	SHELL_CMD(pstate, NULL, "Test Platform State LED", cmd_test_plat_state_led),
	SHELL_CMD(afm, NULL, "Dump AFM Structure: DEVICE OFFSET", cmd_afm),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(asm, &sub_asm, "Aspeed PFR State Machine Commands", NULL);
#endif
