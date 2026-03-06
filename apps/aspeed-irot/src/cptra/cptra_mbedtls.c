#include <mbedtls/ecdsa.h>

#include <zephyr/drivers/cptra.h>
#include <zephyr/drivers/ipm.h>
#include <zephyr/drivers/misc/aspeed/cptra_ipc.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(cptra_mbedtls, LOG_LEVEL_DBG);

int mbedtls_ecdsa_verify_cptra(mbedtls_ecp_group *grp,
			     const unsigned char *buf, size_t blen,
			     const mbedtls_ecp_point *Q,
			     const mbedtls_mpi *r, const mbedtls_mpi *s)
{
	ARG_UNUSED(grp);
	uint8_t *p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	uint8_t *p8_ssp_in = (uint8_t *)IPC_CHANNEL_1_SSP_IN_ADDR;
	int ipccmd = CPTRA_IPCCMD_ECDSA384_SIGNATURE_VERIFY;
	struct cptra_ecdsa_ctx ctx;
	uint32_t data[2];
	int ret;

	/* Prepare tx data to bootmcu */
	p8_bmcu_in = (uint8_t *)IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	p8_bmcu_in += sizeof(struct cptra_ecdsa_ctx);

	/* Public Key X */
	ctx.qx = p8_bmcu_in;
	p8_bmcu_in += 48;
	/* Public Key Y */
	ctx.qy = p8_bmcu_in;
	p8_bmcu_in += 48;
	/* Signature R */
	ctx.r = p8_bmcu_in;
	p8_bmcu_in += 48;
	/* Signature S */
	ctx.s = p8_bmcu_in;
	p8_bmcu_in += 48;
	/* Message Hash */
	ctx.m = p8_bmcu_in;
	p8_bmcu_in += blen;

	ctx.qx_len = 48;
	ctx.qy_len = 48;
	ctx.r_len = 48;
	ctx.s_len = 48;
	ctx.m_len = blen;

	p8_ssp_in = (uint8_t *)IPC_CHANNEL_1_SSP_IN_ADDR;
	memcpy(p8_ssp_in, &ctx, sizeof(struct cptra_ecdsa_ctx));
	p8_ssp_in += sizeof(struct cptra_ecdsa_ctx);

	// Read data from mbedtls structures and copy to SSP input buffer
	uint8_t qx_buf[48], qy_buf[48], r_buf[48], s_buf[48];
	mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(X), qx_buf, 48);
	mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(Y), qy_buf, 48);
	mbedtls_mpi_write_binary(r, r_buf, 48);
	mbedtls_mpi_write_binary(s, s_buf, 48);
	memcpy(p8_ssp_in, qx_buf, 48);
	p8_ssp_in += 48;
	memcpy(p8_ssp_in, qy_buf, 48);
	p8_ssp_in += 48;
	memcpy(p8_ssp_in, r_buf, 48);
	p8_ssp_in += 48;
	memcpy(p8_ssp_in, s_buf, 48);
	p8_ssp_in += 48;
	memcpy(p8_ssp_in, buf, blen);
	p8_ssp_in += blen;

	data[0] = IPC_CHANNEL_1_BOOTMCU_IN_ADDR;
	data[1] = IPC_CHANNEL_1_BOOTMCU_OUT_ADDR;

	LOG_HEXDUMP_INF(qx_buf, 48, "Public Key QX");
	LOG_HEXDUMP_INF(qy_buf, 48, "Public Key QY");
	LOG_HEXDUMP_INF(r_buf, 48, "Signature R");
	LOG_HEXDUMP_INF(s_buf, 48, "Signature S");
	LOG_HEXDUMP_INF(buf, blen, "Message Hash");

	LOG_INF("BMCU_IN_ADDR:0x%x, BMCU_OUT_ADDR:0x%x", data[0], data[1]);

	ret = cptra_ipc_trigger(ipccmd, data, sizeof(data));
	if (ret) {
		LOG_ERR("cptra_ipc_trigger:0x%x is failure, ret:0x%x", ipccmd, ret);
		return -1;
	}

	LOG_DBG("cptra_ipc_trigger:%x is successful", ipccmd);

	cptra_ipc_receive(CPTRA_IPC_RX_TYPE_INTERNAL, &ret, sizeof(ret));

	if (ret == 0) {
		LOG_DBG(" result expected (pass), Pass");
	} else {
		LOG_ERR(" result unexpected (ret=%d), Failed", ret);
		return -1;
	}

	return 0;
}
