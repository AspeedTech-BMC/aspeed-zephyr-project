/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 ASPEED Technology Inc.
 */

#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/misc/aspeed/otp_ast27xx.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(cptra_idevid, CONFIG_SOC_LOG_LEVEL);

#if defined(CONFIG_CPTRA_DICE)
#define CPTRA_DICE_DRV_NAME			DEVICE_DT_NAME(DT_INST(0, aspeed_cptra_dice))
#else
#define CPTRA_DICE_DRV_NAME			"aspeed_cptra_dice"
#endif

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

int cptra_populate_idevid(void)
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
