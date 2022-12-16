/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_CERBERUS_PFR)
#if defined(CONFIG_SHELL)

#include <zephyr.h>
#include <shell/shell.h>
#include <stdlib.h>

#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "pfr/pfr_ufm.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_key_cancellation.h"
#include "AspeedStateMachine/common_smc.h"

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

SHELL_STATIC_SUBCMD_SET_CREATE(sub_kc_cmds,
	SHELL_CMD_ARG(verify, NULL, "<pc_type> <key_id>", cmd_verify_csk_key_id, 3, 0),
	SHELL_CMD_ARG(cancel, NULL, "<pc_type> <key_id>", cmd_cancel_csk_key_id, 3, 0),
	SHELL_CMD_ARG(dump, NULL, "<pc_type>", cmd_dump_key_cancellation_policy, 2, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_cerberus_pfr_cmds,
	SHELL_CMD(kc, &sub_kc_cmds, "Key Cancellation Commands", NULL),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(cerberus_pfr, &sub_cerberus_pfr_cmds, "Cerberus PFR Commands", NULL);

#endif // CONFIG_SHELL
#endif // CONFIG_CERBERUS_PFR