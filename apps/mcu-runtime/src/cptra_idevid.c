/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 ASPEED Technology Inc.
 */

#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/misc/aspeed/otp_ast27xx.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>
#include <platform.h>
#include <chip.h>
#include <scu.h>
#include <manifest.h>

LOG_MODULE_REGISTER(cptra_idevid, CONFIG_SOC_LOG_LEVEL);

#if defined(CONFIG_CPTRA_DICE)
#define CPTRA_DICE_DRV_NAME			DEVICE_DT_NAME(DT_INST(0, aspeed_cptra_dice))
#else
#define CPTRA_DICE_DRV_NAME			"aspeed_cptra_dice"
#endif

#define CPTRA_MISC_DRV_NAME			DEVICE_DT_NAME(DT_INST(0, aspeed_cptra_misc))

/*
 * FMC/RT release tag lookup table, keyed on runtime_sha384_digest[0..1]
 * (first 8 bytes of the 48-byte RT firmware SHA384).
 *
 * To add a new entry: run cptra_dump_fw_info() on real hardware, copy the
 * "RT sha384" hex dump first 8 bytes, and add a row here.
 *
 * Release list: https://github.com/chipsalliance/caliptra-sw#fmcruntime-fw-releases
 */
struct cptra_fw_tag_entry {
	uint32_t rt_sha384[2]; /* runtime_sha384_digest[0..1], little-endian */
	const char *tag;
};

static const struct cptra_fw_tag_entry cptra_fw_tag_table[] = {
	/*
	 * Keys: runtime_sha384_digest[0..1] as little-endian uint32.
	 * Source: first 16 hex chars of runtime SHA384 per release at
	 * https://github.com/chipsalliance/caliptra-sw#fmcruntime-fw-releases
	 * Verify with "Caliptra RT  sha384:" hex dump logged at boot.
	 */
	{ .rt_sha384 = { 0x002809d7, 0x387f0bc6 }, .tag = "rt-1.2.0" }, /* d7092800c60b7f38 */
	{ .rt_sha384 = { 0xb6838fd4, 0x328d3729 }, .tag = "rt-1.2.1" }, /* d48f83b629378d32 */
	{ .rt_sha384 = { 0x09ce915a, 0x76c9e8d7 }, .tag = "rt-1.2.2" }, /* 5a91ce09d7e8c976 */
	{ .rt_sha384 = { 0x89865e07, 0x491547ec }, .tag = "rt-1.2.3" }, /* 075e8689ec471549 */
	{ .rt_sha384 = { 0x4aac73bf, 0xe46d0999 }, .tag = "rt-1.2.4" }, /* bf73ac4a99096de4 */
	{ .rt_sha384 = { 0x67406db5, 0x1e0a2315 }, .tag = "rt-1.2.5" }, /* b56d406715230a1e */
};

static const char *cptra_lookup_fw_tag(const uint32_t *rt_sha384)
{
	for (int i = 0; i < ARRAY_SIZE(cptra_fw_tag_table); i++) {
		if (cptra_fw_tag_table[i].rt_sha384[0] == rt_sha384[0] &&
		    cptra_fw_tag_table[i].rt_sha384[1] == rt_sha384[1])
			return cptra_fw_tag_table[i].tag;
	}
	return NULL;
}

static void cptra_dump_fw_info(void)
{
	const struct device *dev = device_get_binding(CPTRA_MISC_DRV_NAME);
	struct cptra_fw_info_ia in = {};
	struct cptra_fw_info_oa out = {};
	char sha_str[41]; /* 20 bytes → 40 hex chars + NUL */
	const char *tag;
	int ret;

	if (!dev) {
		LOG_WRN("cptra fw_info: misc device not found");
		return;
	}

	ret = caliptra_fw_info(dev, &in, &out);
	if (ret) {
		LOG_WRN("cptra fw_info: mailbox failed, ret:%d", ret);
		return;
	}

	bin2hex(out.runtime_revision, sizeof(out.runtime_revision), sha_str, sizeof(sha_str));
	tag = cptra_lookup_fw_tag(out.runtime_sha384_digest);
	if (tag)
		LOG_INF("Caliptra RT revision: %s (%s)", sha_str, tag);
	else
		LOG_INF("Caliptra RT revision: %s", sha_str);
}

#define OTPCAL_IDEVID_TBS_OFFSET		0x62
#define OTPCAL_IDEVID_SIGN_OFFSET		0x262

static int cptra_get_idevid_cert(struct cptra_get_idev_cert_ia *input,
				 struct cptra_get_idev_cert_oa *output)
{
#if defined(CONFIG_CPTRA_DICE)
	const struct device *dev = device_get_binding(CPTRA_DICE_DRV_NAME);
#else
	const struct device *dev = NULL;
#endif
	uint32_t cert_offset = OTPCAL_IDEVID_SIGN_OFFSET;
	uint32_t tbs_offset = OTPCAL_IDEVID_TBS_OFFSET;
	uint16_t *p16 = (uint16_t *)input->tbs;
	uint16_t data;
	int tbs_size = 0;
	int ret;

	if (!dev) {
		LOG_ERR("Device %s not found", CPTRA_DICE_DRV_NAME);
		return -ENODEV;
	}

	LOG_INF("Get IDEVID Certificate");
	memset(input, 0, sizeof(struct cptra_get_idev_cert_ia));
	memset(output, 0, sizeof(struct cptra_get_idev_cert_oa));

	LOG_INF("Get tbs from OTP");

	/* Check TBS tag */
	ret = otp_read_cptra(tbs_offset, &data);
	if (ret) {
		LOG_ERR("otp_read_cptra failed, ret:0x%x", ret);
		goto end;
	}

	if (data == 0x0) {
		LOG_WRN("tbs is empty");
		ret = -EIO;
		goto end;

	} else if (data != 0x8230) {
		LOG_ERR("Invalid tbs tag, expected 0x8230, got 0x%x", data);
		ret = -EIO;
		goto end;
	}

	/* Check TBS length */
	ret = otp_read_cptra(tbs_offset + 1, &data);
	if (ret) {
		LOG_ERR("otp_read_cptra failed, ret:0x%x", ret);
		goto end;
	}

	tbs_size = sys_cpu_to_be16(data);
	LOG_INF("tbs size: 0x%x", tbs_size);
	if (tbs_size >= sizeof(input->tbs)) {
		LOG_ERR("Invalid tbs length, expected less than 0x%x, got 0x%x",
			sizeof(input->tbs), data);
		ret = -EIO;
		goto end;
	}

	// TBS includes ASN.1 tag
	for (int i = 0; i < ((tbs_size + 1) / 2) + 2; i++) {
		ret = otp_read_cptra(tbs_offset + i, p16++);
		if (ret) {
			LOG_ERR("otp_read_cptra failed, ret:0x%x", ret);
			goto end;
		}
	}

	input->tbs_size = tbs_size + 0x4; /* 4 bytes for DER TAG & LENGTH */
	/* LOG_HEXDUMP_INF(input->tbs, input->tbs_size, "tbs"); */

	LOG_INF("Get signature_r from OTP");
	p16 = (uint16_t *)input->signature_r;
	for (int i = 0; i < sizeof(input->signature_r) / 2; i++) {
		ret = otp_read_cptra(cert_offset + i, p16++);
		if (ret) {
			LOG_ERR("otp_read_cptra failed, ret:0x%x", ret);
			goto end;
		}
	}

	cert_offset += 0x18; /* 48 bytes for r */
	LOG_INF("Get signature_s from OTP");
	p16 = (uint16_t *)input->signature_s;
	for (int i = 0; i < sizeof(input->signature_s) / 2; i++) {
		ret = otp_read_cptra(cert_offset + i, p16++);
		if (ret) {
			LOG_ERR("otp_read_cptra failed, ret:0x%x", ret);
			goto end;
		}
	}

	/* LOG_HEXDUMP_INF(input->signature_r, sizeof(input->signature_r), "r:"); */
	/* LOG_HEXDUMP_INF(input->signature_s, sizeof(input->signature_s), "s:"); */

	LOG_INF("Get IDEVID Certificate from Cptra");
	ret = caliptra_get_idev_cert(dev, input, output);
	if (ret) {
		LOG_ERR("caliptra_get_idev_cert is failure, ret:0x%x", ret);
		goto end;
	} else
		LOG_DBG("caliptra_get_idev_cert is successful");

	LOG_DBG("output: chksum:0x%x, fips_status:0x%x",
		output->chksum, output->fips_status);
	LOG_HEXDUMP_DBG(output->cert, output->cert_size, "cert:");

	return 0;

end:
	return ret;
}

static int cptra_populate_idevid(void)
{

	const struct device *dev = device_get_binding(CPTRA_DICE_DRV_NAME);
	struct cptra_get_idev_cert_ia input;
	struct cptra_get_idev_cert_oa output;
	struct cptra_populate_idev_cert_ia in_buff;
	struct cptra_populate_idev_cert_oa out_buff;
	int ret;

#if !defined(CONFIG_CPTRA_DICE)
	return -ENODEV;
#endif

	if (!dev) {
		LOG_ERR("Device %s not found", CPTRA_DICE_DRV_NAME);
		return -ENODEV;
	}

	/* Get IDEVID Certificate */
	ret = cptra_get_idevid_cert(&input, &output);
	if (ret)
		return ret;

	/* Populate IDEVID Certificate */
	LOG_INF("Populate IDEVID Certificate...");

	memset(&in_buff, 0, sizeof(struct cptra_populate_idev_cert_ia));
	memset(&out_buff, 0, sizeof(struct cptra_populate_idev_cert_oa));

	/* Initial idevid cert */
	in_buff.cert_size = output.cert_size;
	memcpy(in_buff.cert, output.cert, output.cert_size);

	ret = caliptra_populate_idev_cert(dev, &in_buff, &out_buff);
	if (ret) {
		LOG_ERR("caliptra_populate_idev_cert is failure, ret:0x%x", ret);
		goto end;
	} else
		LOG_DBG("caliptra_populate_idev_cert is successful");

	LOG_DBG("output: chksum:0x%x, fips_status:0x%x",
		out_buff.chksum, out_buff.fips_status);

	if (out_buff.fips_status) {
		LOG_ERR("FIPS status is not zero, fips_status:0x%x",
			out_buff.fips_status);
		ret = -EIO;
		goto end;
	}

	LOG_INF("%s: Pass", __func__);
	return 0;

end:
	LOG_ERR("%s: Failed", __func__);
	return ret;
}

#define CPTRA_IFC_BASE			DT_REG_ADDR(DT_NODELABEL(cptra_ifc))


static void cptra_check_error(void)
{
	uint32_t hw_fatal    = sys_read32(CPTRA_IFC_BASE + CPTRA_HW_ERROR_FATAL);
	uint32_t hw_nonfatal = sys_read32(CPTRA_IFC_BASE + CPTRA_HW_ERROR_NONFATAL);
	uint32_t fw_fatal    = sys_read32(CPTRA_IFC_BASE + CPTRA_FW_ERROR_FATAL);
	uint32_t fw_nonfatal = sys_read32(CPTRA_IFC_BASE + CPTRA_FW_ERROR_NONFATAL);

	if (hw_fatal || hw_nonfatal || fw_fatal || fw_nonfatal)
		LOG_WRN("CPTRA errors: hw_fatal=0x%08x hw_nonfatal=0x%08x fw_fatal=0x%08x fw_nonfatal=0x%08x",
			hw_fatal, hw_nonfatal, fw_fatal, fw_nonfatal);
	else
		LOG_INF("CPTRA: no errors detected");
}

int cptra_otp_init(struct ast_chip *chip)
{
	if (sys_read32(SCU1_HWSTRAP1) & SCU1_HWSTRAP1_DIS_CPTRA) {
		LOG_WRN("Caliptra is disabled");
		return 0;
	}

	cptra_check_error();

	if (!(sys_read32(SCU1_CPTRA_CTRL) & SCU1_CPTRA_RDY_FOR_RT)) {
		LOG_WRN("Caliptra is unavailable");
		return 0;
	}

	cptra_dump_fw_info();

#if !defined(CONFIG_CPTRA_DICE)
	return 0;
#else
	const struct device *dev = device_get_binding(CPTRA_DICE_DRV_NAME);
	struct cptra_reallocate_dpe_context_limits_ia input;
	struct cptra_reallocate_dpe_context_limits_oa output;
	int ret;

	ret = cptra_populate_idevid();
	if (ret)
		LOG_WRN("populate idevid skipped, ret:%d", ret);

	if (!dev) {
		LOG_ERR("Device %s not found", CPTRA_DICE_DRV_NAME);
		return -ENODEV;
	}

	memset(&input, 0, sizeof(input));
	memset(&output, 0, sizeof(output));
	input.pl0_context_limit = 32;

	if (!is_ast2700_a1()) {
		ret = caliptra_reallocate_dpe_context_limits(dev, &input, &output);
		if (ret) {
			LOG_ERR("caliptra_reallocate_dpe_context_limits failed, ret:0x%x", ret);
			return 0;
		}

		LOG_INF("DPE context limits reallocated: pl0=%u, pl1=%u",
			output.new_pl0_context_limit, output.new_pl1_context_limit);
	}

	return 0;
#endif
}
