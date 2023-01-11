/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>
#include <shell/shell.h>
#include <stdlib.h>
#include "pfr/pfr_common.h"
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_util.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_pfm_manifest.h"
#include "intel_pfr_svn.h"
#include "intel_pfr_key_cancellation.h"

// key cancellation
static int cmd_cancel_csk_key_id(const struct shell *shell, size_t argc, char **argv)
{
	struct pfr_manifest test_manifest;
	uint8_t key_id;

	test_manifest.pc_type = strtoul(argv[1], NULL, 16);
	key_id = strtoul(argv[2], NULL, 10);

	cancel_csk_key_id(&test_manifest, key_id);

	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	return 0;
}

static int cmd_verify_csk_key_id(const struct shell *shell, size_t argc, char **argv)
{
	struct pfr_manifest test_manifest;
	uint8_t key_id;

	test_manifest.pc_type = strtoul(argv[1], NULL, 16);
	key_id = strtoul(argv[2], NULL, 10);

	if (!verify_csk_key_id(&test_manifest, key_id))
		shell_print(shell, "This CSK key is not cancelled.., PC type = 0x%x, Key Id = %d", test_manifest.pc_type, key_id);

	ARG_UNUSED(argc);
	return 0;
}

static int cmd_dump_key_cancellation_policy(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t buffer[4] = { 0 };
	uint32_t offset = 0;
	uint32_t pc_type;

	pc_type = strtoul(argv[1], NULL, 16);
	offset = get_cancellation_policy_offset(pc_type);

	if (!offset) {
		shell_error(shell, "Invalid provisioned UFM offset for key cancellation");
		return 0;
	}

	shell_print(shell, "UFM Offeset = %x", offset);
	ufm_read(PROVISION_UFM, offset, (uint8_t *)buffer, sizeof(buffer));
	shell_hexdump(shell, (uint8_t *)buffer, sizeof(buffer));

	ARG_UNUSED(argc);
	return 0;
}

// svn
static int cmd_get_svn(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t svn_policy[2];
	uint32_t offset;
	uint8_t svn;

	if (strncmp(argv[1], "rot", strlen("rot")) == 0)
		offset = SVN_POLICY_FOR_CPLD_UPDATE;
	else if (strncmp(argv[1], "pch", strlen("pch")) == 0)
		offset = SVN_POLICY_FOR_PCH_FW_UPDATE;
	else if (strncmp(argv[1], "bmc", strlen("bmc")) == 0)
		offset = SVN_POLICY_FOR_BMC_FW_UPDATE;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (strncmp(argv[1], "afm", strlen("afm")) == 0)
		offset = SVN_POLICY_FOR_AFM;
#endif
	else {
		shell_error(shell, "unsupported svn policy");
		return 0;
	}

	shell_print(shell, "svn policy offset = 0x%x", offset);
	ufm_read(PROVISION_UFM, offset, (uint8_t *)svn_policy, sizeof(svn_policy));
	shell_hexdump(shell, (uint8_t *)svn_policy, sizeof(svn_policy));
	svn = get_ufm_svn(offset);
	shell_print(shell, "svn policy for %s is %d", argv[1], svn);

	ARG_UNUSED(argc);
	return 0;
}

static int cmd_set_svn(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t offset;
	uint8_t svn;

	if (strncmp(argv[1], "rot", strlen("rot")) == 0)
		offset = SVN_POLICY_FOR_CPLD_UPDATE;
	else if (strncmp(argv[1], "pch", strlen("pch")) == 0)
		offset = SVN_POLICY_FOR_PCH_FW_UPDATE;
	else if (strncmp(argv[1], "bmc", strlen("bmc")) == 0)
		offset = SVN_POLICY_FOR_BMC_FW_UPDATE;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (strncmp(argv[1], "afm", strlen("afm")) == 0)
		offset = SVN_POLICY_FOR_AFM;
#endif
	else {
		shell_error(shell, "unsupported svn policy");
		return 0;
	}

	svn = strtoul(argv[2], NULL, 10);

	if (set_ufm_svn(offset, svn) != 0)
		shell_error(shell, "set svn policy for %s to %d failed", argv[1], svn);

	ARG_UNUSED(argc);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_kc_cmds,
	SHELL_CMD_ARG(verify, NULL, "<pc_type> <key_id>", cmd_verify_csk_key_id, 3, 0),
	SHELL_CMD_ARG(cancel, NULL, "<pc_type> <key_id>", cmd_cancel_csk_key_id, 3, 0),
	SHELL_CMD_ARG(dump, NULL, "<pc_type>", cmd_dump_key_cancellation_policy, 2, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_svn_cmds,
	SHELL_CMD_ARG(get, NULL, "<svn policy>: rot, pch, bmc, afm", cmd_get_svn, 2, 0),
	SHELL_CMD_ARG(set, NULL, "<svn policy>: rot, pch, bmc, afm", cmd_set_svn, 3, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_intel_pfr_cmds,
	SHELL_CMD(kc, &sub_kc_cmds, "Key Cancellation Commands", NULL),
	SHELL_CMD(svn, &sub_svn_cmds, "SVN Commands", NULL),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(intel_pfr, &sub_intel_pfr_cmds, "Intel PFR Commands", NULL);

