/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/sys/byteorder.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <platform.h>
#include <ufs.h>
#include <unipro.h>
#include <ast_loader.h>
#include <abr.h>

#define UFSHCI_TOP_ADDRESS 0x12C08000
#define UFSHCI_BASE_ADDRESS 0x12C08200

#define UFS_SECTOR_LENGTH	(0x1000)

#define SG_ID	(0)

LOG_MODULE_REGISTER(aspeed_ufs, CONFIG_SOC_FMC_LOG_LEVEL);

struct utp_transfer_cmd_desc ucd[1] __aligned(128);
struct utp_transfer_req_desc utr[1] __aligned(1024);

#define TEST_TAG 0
#define UFS_UIC_CMD_TIMEOUT 1000

struct ufs_hba g_hba = {.mmio_base = UFSHCI_BASE_ADDRESS};

static void ufshcd_prepare_utp_nop_upiu(struct ufs_hba *hba, uint8_t task_tag)
{
	struct utp_upiu_req *ucd_req = (struct utp_upiu_req *)hba->ucdl_base_addr[task_tag].command_upiu;
	struct utp_upiu_rsp *ucd_rsp = (struct utp_upiu_rsp *)hba->ucdl_base_addr[task_tag].response_upiu;

	memset(ucd_req, 0, sizeof(struct utp_upiu_req));
	memset(ucd_rsp, 0, sizeof(struct utp_upiu_rsp));
}

static inline bool ufshcd_ready_for_uic_cmd(struct ufs_hba *hba)
{
	if (ufshcd_readl(hba, REG_CONTROLLER_STATUS) & UIC_COMMAND_READY)
		return true;
	else
		return false;
}

static void ufshcd_dispatch_uic_cmd(struct ufs_hba *hba, struct uic_command *uic_cmd)
{
	hba->active_uic_cmd = uic_cmd;
	hba->active_uic_cmd->done = 0;

	/* Write Args */
	ufshcd_writel(hba, uic_cmd->argument1, REG_UIC_COMMAND_ARG_1);
	ufshcd_writel(hba, uic_cmd->argument2, REG_UIC_COMMAND_ARG_2);
	ufshcd_writel(hba, uic_cmd->argument3, REG_UIC_COMMAND_ARG_3);

	/* Write UIC Cmd */
	ufshcd_writel(hba, uic_cmd->command & COMMAND_OPCODE_MASK,
		      REG_UIC_COMMAND);
}

static int ufshcd_wait_for_uic_cmd(struct ufs_hba *hba, struct uic_command *uic_cmd)
{
	uint32_t val;

	while (!((val = ufshcd_readl(hba, REG_INTERRUPT_STATUS)) & UIC_COMMAND_COMPL))
		;

	ufshcd_writel(hba, UIC_COMMAND_COMPL, REG_INTERRUPT_STATUS);

	uic_cmd->argument2 = ufshcd_readl(hba, REG_UIC_COMMAND_ARG_2);
	uic_cmd->argument3 = ufshcd_readl(hba, REG_UIC_COMMAND_ARG_3);

	hba->errors |= (UFSHCD_ERROR_MASK & val);

	if (hba->errors & UIC_ERROR) {
		ufshcd_writel(hba, UIC_ERROR, REG_INTERRUPT_STATUS);
		hba->uic_error = 0;
	}

	return (uic_cmd->argument2 & MASK_UIC_COMMAND_RESULT);
}

static int ufshcd_send_uic_cmd(struct ufs_hba *hba, struct uic_command *uic_cmd)
{
	int ret = 0;

	if (!ufshcd_ready_for_uic_cmd(hba)) {
		LOG_ERR("Controller not ready to accept UIC commands\n");
		return UFS_ERROR;
	}

	uic_cmd->cmd_active = 1;
	ufshcd_dispatch_uic_cmd(hba, uic_cmd);

	ret = ufshcd_wait_for_uic_cmd(hba, uic_cmd);

	return ret;
}

static int ufshcd_dme_get_attr(struct ufs_hba *hba, uint32_t attr_sel,
			       uint32_t *mib_val, uint8_t peer)
{
	struct uic_command uic_cmd;
	int ret;
	int retries = UFS_UIC_COMMAND_RETRIES;

	memset(&uic_cmd, 0, sizeof(struct uic_command));

	uic_cmd.command = peer ?
		UIC_CMD_DME_PEER_GET : UIC_CMD_DME_GET;
	uic_cmd.argument1 = attr_sel;

	do {
		/* for peer attributes we retry upon failure */
		ret = ufshcd_send_uic_cmd(hba, &uic_cmd);
		if (ret)
			LOG_ERR("ufshcd send uic cmd error\n");

	} while (ret && peer && --retries);

	if (ret)
		LOG_ERR("ufshcd send uic cmd timeout\n");

	if (mib_val && !ret)
		*mib_val = uic_cmd.argument3;

	return ret;
}

static int ufshcd_dme_get(struct ufs_hba *hba,
			  uint32_t attr_sel, uint32_t *mib_val)
{
	return ufshcd_dme_get_attr(hba, attr_sel, mib_val, DME_LOCAL);
}

static inline int ufshcd_dme_peer_get(struct ufs_hba *hba,
				      uint32_t attr_sel, uint32_t *mib_val)
{
	return ufshcd_dme_get_attr(hba, attr_sel, mib_val, DME_PEER);
}

static int ufshcd_dme_set_attr(struct ufs_hba *hba, uint32_t attr_sel,
			       uint8_t attr_set, uint32_t mib_val, uint8_t peer)
{
	struct uic_command uic_cmd;
	int ret;
	int retries = UFS_UIC_COMMAND_RETRIES;

	memset(&uic_cmd, 0, sizeof(struct uic_command));
	uic_cmd.command = peer ?
		UIC_CMD_DME_PEER_SET : UIC_CMD_DME_SET;
	uic_cmd.argument1 = attr_sel;
	uic_cmd.argument2 = UIC_ARG_ATTR_TYPE(attr_set);
	uic_cmd.argument3 = mib_val;

	do {
		/* for peer attributes we retry upon failure */
		ret = ufshcd_send_uic_cmd(hba, &uic_cmd);
	} while (ret && peer && --retries);

	if (ret)
		LOG_ERR("dme set attr error\n");

	return ret;
}

static int ufshcd_dwc_dme_set_attrs(struct ufs_hba *hba,
				    const struct ufshcd_dme_attr_val *v, int n)
{
	int ret = 0;
	int attr_node = 0;

	for (attr_node = 0; attr_node < n; attr_node++) {
		ret = ufshcd_dme_set_attr(hba, v[attr_node].attr_sel,
					  ATTR_SET_NOR, v[attr_node].mib_val, v[attr_node].peer);

		if (ret)
			return ret;
	}

	return 0;
}

static int ufshcd_dme_set(struct ufs_hba *hba, uint32_t attr_sel,
			  uint32_t mib_val)
{
	return ufshcd_dme_set_attr(hba, attr_sel, ATTR_SET_NOR,
				   mib_val, DME_LOCAL);
}

static int ufshcd_dme_link_startup(struct ufs_hba *hba)
{
	struct uic_command uic_cmd;
	int ret;

	memset(&uic_cmd, 0, sizeof(struct uic_command));
	uic_cmd.command = UIC_CMD_DME_LINK_STARTUP;

	ret = ufshcd_send_uic_cmd(hba, &uic_cmd);
	if (ret)
		LOG_ERR("dme-link-startup: error code %d\n", ret);

	return ret;
}

static int ufshcd_dwc_link_is_up(struct ufs_hba *hba)
{
	int dme_result = 0;

	ufshcd_dme_get(hba, UIC_ARG_MIB(VS_POWERSTATE), &dme_result);

	if (dme_result == UFSHCD_LINK_IS_UP)
		return 0;

	return UFS_LINK_NOT_UP;
}

static int ufshcd_dwc_connection_setup(struct ufs_hba *hba)
{
	static const struct ufshcd_dme_attr_val setup_attrs[] = {
		{ UIC_ARG_MIB(T_CONNECTIONSTATE), 0, DME_LOCAL },
		{ UIC_ARG_MIB(N_DEVICEID), 0, DME_LOCAL },
		{ UIC_ARG_MIB(N_DEVICEID_VALID), 0, DME_LOCAL },
		{ UIC_ARG_MIB(T_PEERDEVICEID), 1, DME_LOCAL },
		{ UIC_ARG_MIB(T_PEERCPORTID), 0, DME_LOCAL },
		{ UIC_ARG_MIB(T_TRAFFICCLASS), 0, DME_LOCAL },
		{ UIC_ARG_MIB(T_CPORTFLAGS), 0x6, DME_LOCAL },
		{ UIC_ARG_MIB(T_CPORTMODE), 1, DME_LOCAL },
		{ UIC_ARG_MIB(T_CONNECTIONSTATE), 1, DME_LOCAL },
		{ UIC_ARG_MIB(T_CONNECTIONSTATE), 0, DME_PEER },
		{ UIC_ARG_MIB(N_DEVICEID), 1, DME_PEER },
		{ UIC_ARG_MIB(N_DEVICEID_VALID), 1, DME_PEER },
		{ UIC_ARG_MIB(T_PEERDEVICEID), 1, DME_PEER },
		{ UIC_ARG_MIB(T_PEERCPORTID), 0, DME_PEER },
		{ UIC_ARG_MIB(T_TRAFFICCLASS), 0, DME_PEER },
		{ UIC_ARG_MIB(T_CPORTFLAGS), 0x6, DME_PEER },
		{ UIC_ARG_MIB(T_CPORTMODE), 1, DME_PEER },
		{ UIC_ARG_MIB(T_CONNECTIONSTATE), 1, DME_PEER }
	};

	return ufshcd_dwc_dme_set_attrs(hba, setup_attrs, ARRAY_SIZE(setup_attrs));
}

static int ufshcd_dme_reset(struct ufs_hba *hba)
{
	struct uic_command uic_cmd;
	int ret;

	memset(&uic_cmd, 0, sizeof(struct uic_command));

	uic_cmd.command = UIC_CMD_DME_RESET;

	ret = ufshcd_send_uic_cmd(hba, &uic_cmd);

	return ret;
}

static int ufshcd_dme_enable(struct ufs_hba *hba)
{
	struct uic_command uic_cmd;
	int ret;

	memset(&uic_cmd, 0, sizeof(struct uic_command));

	uic_cmd.command = UIC_CMD_DME_ENABLE;

	ret = ufshcd_send_uic_cmd(hba, &uic_cmd);

	return ret;
}

static void ufshcd_memory_construct(struct ufs_hba *hba)
{
	int i;
	struct utp_transfer_req_desc *utrdlp;
	uintptr_t cmd_desc_element_addr;
	uintptr_t cmd_desc_dma_addr;
	uint32_t cmd_desc_size;

	/* Allocate memory for UTP command descriptors */
	hba->ucdl_base_addr = (struct utp_transfer_cmd_desc *)ucd;

	/* Allocate memory for UTP Transfer descriptors */
	hba->utrdl_base_addr = (struct utp_transfer_req_desc *)utr;

	/* Initialize each descriptor entries */
	utrdlp = hba->utrdl_base_addr;
	cmd_desc_dma_addr = (uintptr_t)hba->ucdl_base_addr;
	cmd_desc_size = sizeof(struct utp_transfer_cmd_desc);

	for (i = 0; i < hba->nutrs; i++) {
		/* Configure UTRD with command descriptor base address */
		cmd_desc_element_addr = (cmd_desc_dma_addr + (cmd_desc_size * i));
		utrdlp[i].command_desc_base_addr_lo = (cmd_desc_element_addr & 0xFFFFFFFF);
		utrdlp[i].command_desc_base_addr_hi = 0;

		/* Response upiu and prdt offset should be in double words */
		utrdlp[i].response_upiu_length = (ALIGNED_UPIU_SIZE >> 2);
		utrdlp[i].response_upiu_offset = (ALIGNED_UPIU_SIZE >> 2);
		utrdlp[i].prd_table_offset = (ALIGNED_UPIU_SIZE >> 1);
	}
}

/**
 * ufshcd_get_ufs_version - Get the UFS version supported by the HBA
 */
static inline uint32_t ufshcd_get_ufs_version(struct ufs_hba *hba)
{
	return ufshcd_readl(hba, REG_UFS_VERSION);
}

static void ufshcd_hba_capabilities(struct ufs_hba *hba)
{
	hba->caps = ufshcd_readl(hba, REG_CONTROLLER_CAPABILITIES);
#if defined(AHB_PATH)
	/* number of utp transfer request slots maximum is 32 */
	hba->nutrs = 1;
	/* number of utp task management request slots maximum is 8 */
	hba->nutmrs = 1;
#else
	hba->nutrs = (hba->caps & MASK_TRANSFER_REQUESTS_SLOTS) + 1;
	hba->nutmrs = ((hba->caps & MASK_TASK_MANAGEMENT_REQUEST_SLOTS) >> 16) + 1;
#endif
	hba->reserved_slot = hba->nutrs - 1;

	hba->version = ufshcd_get_ufs_version(hba);
}

static inline int ufshcd_get_lists_status(uint32_t reg)
{
	return !((reg & UFSHCD_STATUS_READY) == UFSHCD_STATUS_READY);
}

static void ufshcd_enable_run_stop_reg(struct ufs_hba *hba)
{
	ufshcd_writel(hba, UTP_TASK_REQ_LIST_RUN_STOP_BIT,
		      REG_UTP_TASK_REQ_LIST_RUN_STOP);
	ufshcd_writel(hba, UTP_TRANSFER_REQ_LIST_RUN_STOP_BIT,
		      REG_UTP_TRANSFER_REQ_LIST_RUN_STOP);
}

static int ufshcd_make_hba_operational(struct ufs_hba *hba)
{
	uint32_t reg;

	/* Configure UTRL and UTMRL base address registers */
	ufshcd_writel(hba, ((uintptr_t)hba->utrdl_base_addr & 0xFFFFFFFF),
		      REG_UTP_TRANSFER_REQ_LIST_BASE_L);
	ufshcd_writel(hba, 0,
		      REG_UTP_TRANSFER_REQ_LIST_BASE_H);

	ufshcd_writel(hba, 0,
		      REG_UTP_TASK_REQ_LIST_BASE_L);
	ufshcd_writel(hba, 0,
		      REG_UTP_TASK_REQ_LIST_BASE_H);

	/*
	 * UCRDY, UTMRLDY and UTRLRDY bits must be 1
	 */
	reg = ufshcd_readl(hba, REG_CONTROLLER_STATUS);
	if (!(ufshcd_get_lists_status(reg))) {
		ufshcd_enable_run_stop_reg(hba);
	} else {
		LOG_ERR("Host controller not ready to process requests");
		return UFS_ERROR;
	}

	return 0;
}

static void ufshcd_hba_start(struct ufs_hba *hba)
{
	uint32_t val = CONTROLLER_ENABLE;

	ufshcd_writel(hba, val, REG_CONTROLLER_ENABLE);
}

static bool ufshcd_is_hba_active(struct ufs_hba *hba)
{
	return (ufshcd_readl(hba, REG_CONTROLLER_ENABLE) & CONTROLLER_ENABLE)
		? false : true;
}

static void ufshcd_hba_stop(struct ufs_hba *hba)
{
	ufshcd_writel(hba, CONTROLLER_DISABLE,	REG_CONTROLLER_ENABLE);
	while (ufshcd_readl(hba, REG_CONTROLLER_ENABLE) & CONTROLLER_ENABLE)
		;
}

/**
 * ufshcd_get_req_rsp - returns the TR response transaction type
 */
static inline int ufshcd_get_req_rsp(struct utp_upiu_rsp *ucd_rsp_ptr)
{
	return (ucd_rsp_ptr->header.dword_0) & 0xff;
}

/**
 * ufshcd_get_tr_ocs - Get the UTRD Overall Command Status
 *
 */
static inline int ufshcd_get_tr_ocs(struct utp_transfer_req_desc *utrdlp)
{
	return sys_le32_to_cpu(utrdlp->header.dword_2) & MASK_OCS;
}

static inline int ufshcd_get_rsp_upiu_result(struct utp_upiu_rsp *ucd_rsp_ptr)
{
	return BSWAP_32(ucd_rsp_ptr->header.dword_1) & MASK_RSP_UPIU_RESULT;
}

/**
 * ufshcd_get_upmcrs - Get the power mode change request status
 */
static inline uint8_t ufshcd_get_upmcrs(struct ufs_hba *hba)
{
	return (ufshcd_readl(hba, REG_CONTROLLER_STATUS) >> 8) & 0x7;
}

/**
 * ufshcd_get_uic_cmd_result - Get the UIC command result
 * @hba: Pointer to adapter instance
 *
 * This function gets the result of UIC command completion
 * Returns 0 on success, non zero value on error
 */
static inline int ufshcd_get_uic_cmd_result(struct ufs_hba *hba)
{
	return ufshcd_readl(hba, REG_UIC_COMMAND_ARG_2) &
		   MASK_UIC_COMMAND_RESULT;
}

/**
 * ufshcd_get_dme_attr_val - Get the value of attribute returned by UIC command
 * @hba: Pointer to adapter instance
 *
 * This function gets UIC command argument3
 * Returns 0 on success, non zero value on error
 */
static inline uint32_t ufshcd_get_dme_attr_val(struct ufs_hba *hba)
{
	return ufshcd_readl(hba, REG_UIC_COMMAND_ARG_3);
}

static int ufshcd_check_query_response(struct ufs_hba *hba)
{
	struct ufs_query_res *query_res = &hba->dev_cmd.query.response;

	/* Get the UPIU response */
	query_res->response = ufshcd_get_rsp_upiu_result(hba->ucd_rsp_ptr) >>
				UPIU_RSP_CODE_OFFSET;
	return query_res->response;
}

/**
 * ufshcd_copy_query_response() - Copy the Query Response and the data
 * descriptor
 */
static int ufshcd_copy_query_response(struct ufs_hba *hba)
{
	struct ufs_query_res *query_res = &hba->dev_cmd.query.response;
	struct utp_upiu_rsp *ucd_rsp_ptr = (struct utp_upiu_rsp *)hba->ucdl_base_addr[TEST_TAG].response_upiu;

	memcpy(&query_res->upiu_res, &ucd_rsp_ptr->qr, QUERY_OSF_SIZE);

	/* Get the descriptor */
	if (hba->dev_cmd.query.descriptor && ucd_rsp_ptr->qr.opcode == UPIU_QUERY_OPCODE_READ_DESC) {
		uint8_t *descp = (uint8_t *)ucd_rsp_ptr +
				GENERAL_UPIU_REQUEST_SIZE;
		uint16_t resp_len;
		uint16_t buf_len;

		/* data segment length */
		resp_len = BSWAP_32(ucd_rsp_ptr->header.dword_2) & MASK_QUERY_DATA_SEG_LEN;
		buf_len = (hba->dev_cmd.query.request.upiu_req.length);

		if (buf_len >= resp_len) {
			memcpy(hba->dev_cmd.query.descriptor, descp, resp_len);
		} else {
			LOG_ERR("%s: Response size is bigger than buffer", __func__);
			return UFS_ERROR;
		}
	}

	return 0;
}

static int ufshcd_hba_enable(struct ufs_hba *hba)
{
	int retry = 10;

	if (!ufshcd_is_hba_active(hba))
		/* change controller state to "reset state" */
		ufshcd_hba_stop(hba);

	ufshcd_hba_start(hba);

	while (ufshcd_is_hba_active(hba)) {
		if (retry) {
			retry--;
		} else {
			LOG_ERR("Controller enable failed\n");
			return UFS_ERROR;
		}
	}

	return 0;
}

static int ufshcd_disable_host_tx_lcc(struct ufs_hba *hba)
{
	return ufshcd_dme_set(hba, UIC_ARG_MIB(PA_LOCAL_TX_LCC_ENABLE), 0);
}

static int ufshcd_init(struct ufs_hba *hba)
{
	int ret = 0;
	uint32_t tmp = 0;
	uint32_t cnt = 100;

	/* construct descriptor memory for following test */
	ufshcd_hba_capabilities(hba);
	ufshcd_memory_construct(hba);

	/* program HCLK=axiclk=400mhz for ast2700 */
#ifdef CONFIG_FPGA_ASPEED
	ufshcd_writel(hba, 24, DWC_UFS_REG_HCLKDIV);
#else
	ufshcd_writel(hba, 400, DWC_UFS_REG_HCLKDIV);
#endif

	/* enable dme layer */
	ret = ufshcd_hba_enable(hba);
	if (ret) {
		LOG_ERR("ufshcd dme enable failed!!!\n");
		return ret;
	}

	while (1) {
		ret = ufshcd_dme_get(hba, UIC_ARG_MIB(0x0041), &tmp);
		if (ret) {
			LOG_ERR("get 0x0041 failed\n");
			return UFS_MPHY_TX_NOT_READY;
		}

		if (tmp)
			break;
	};

	while (cnt--) {
		ret = ufshcd_dme_get(hba, UIC_ARG_MIB_SEL(0x00c1, 4), &tmp);
		if (ret) {
			LOG_ERR("get 0x00c1 failed\n");
			return UFS_MPHY_RX_NOT_READY;
		}

		if (tmp)
			break;
	};

	ret = ufshcd_dme_reset(hba);
	if (ret) {
		LOG_ERR("ufshcd_dme_reset failed\n");
		return ret;
	}

	ret = ufshcd_dme_enable(hba);
	if (ret) {
		LOG_ERR("ufshcd_dme_enable failed\n");
		return ret;
	}

	ret = ufshcd_disable_host_tx_lcc(hba);
	if (ret) {
		LOG_ERR("ufshcd_disable_host_tx_lcc failed!!!\n");
		return ret;
	}

	/* To write Shadow register bank to effective configuration block */
	ret = ufshcd_dme_set(hba, UIC_ARG_MIB(VS_MPHYCFGUPDT), 0x01);
	if (ret) {
		LOG_ERR("ufshcd dme set VS_MPHYCFGUPDT failed!!!\n");
		return ret;
	}

	/* start link up process */
	ret = ufshcd_dme_link_startup(hba);
	if (ret) {
		LOG_ERR("ufshcd start link failed\n");
		return ret;
	}

	/* check link status */
	ret = ufshcd_dwc_link_is_up(hba);
	if (ret) {
		LOG_ERR("ufshcd link is not up!!!\n");
		return ret;
	}

	/* dwc specific configuration */
	ret = ufshcd_dwc_connection_setup(hba);
	if (ret) {
		LOG_ERR("ufshcd connection setup failed\n");
		return ret;
	}

	ret = ufshcd_make_hba_operational(hba);

	return ret;
}

static void ufshcd_prepare_req_desc_hdr(struct ufs_hba *hba,
					uint8_t *upiu_flags,
					enum dma_data_direction cmd_dir,
					uint32_t tag)
{
	struct utp_transfer_req_desc *req_desc = &hba->utrdl_base_addr[tag];
	uint32_t data_direction;
	uint32_t dword_0;
	uint32_t dword_1 = 0;
	uint32_t dword_3 = 0;

	if (cmd_dir == DMA_FROM_DEVICE) {
		data_direction = UTP_DEVICE_TO_HOST;
		*upiu_flags = UPIU_CMD_FLAGS_READ;
	} else if (cmd_dir == DMA_TO_DEVICE) {
		data_direction = UTP_HOST_TO_DEVICE;
		*upiu_flags = UPIU_CMD_FLAGS_WRITE;
	} else {
		data_direction = UTP_NO_DATA_TRANSFER;
		*upiu_flags = UPIU_CMD_FLAGS_NONE;
	}

	dword_0 = data_direction | (UTP_CMD_TYPE_UFS_STORAGE
				<< UPIU_COMMAND_TYPE_OFFSET);
	dword_0 |= UTP_REQ_DESC_INT_CMD;

	/* Transfer request descriptor header fields */
	req_desc->header.dword_0 = dword_0;
	req_desc->header.dword_1 = dword_1;
	/*
	 * assigning invalid value for command status. Controller
	 * updates OCS on command completion, with the command
	 * status
	 */
	req_desc->header.dword_2 = OCS_INVALID_COMMAND_STATUS;
	req_desc->header.dword_3 = dword_3;

	req_desc->prd_table_length = 0;
}

static void ufshcd_prepare_utp_query_req_upiu(struct ufs_hba *hba,
					      uint32_t upiu_flags, uint32_t task_tag)
{
	struct utp_upiu_req *ucd_req_ptr = (struct utp_upiu_req *)hba->ucdl_base_addr[task_tag].command_upiu;
	struct utp_upiu_rsp *ucd_rsp_ptr = (struct utp_upiu_rsp *)hba->ucdl_base_addr[task_tag].response_upiu;

	struct ufs_query *query = &hba->dev_cmd.query;

	/* Query request header */
	ucd_req_ptr->header.dword_0 =
				UPIU_HEADER_DWORD(UPIU_TRANSACTION_QUERY_REQ,
						  upiu_flags, 0, TEST_TAG);
	ucd_req_ptr->header.dword_1 =
				UPIU_HEADER_DWORD(0, query->request.query_func,
						  0, 0);

	ucd_req_ptr->header.dword_2 = 0;

	/* Copy the Query Request buffer as is */
	memcpy(&ucd_req_ptr->qr, &query->request.upiu_req, QUERY_OSF_SIZE);

	memset(ucd_rsp_ptr, 0, sizeof(struct utp_upiu_rsp));
}

static int ufshcd_compose_dev_cmd(struct ufs_hba *hba, enum dev_cmd_type cmd_type, int tag)
{
	int err = 0;
	uint8_t upiu_flags;

	ufshcd_prepare_req_desc_hdr(hba, &upiu_flags, DMA_NONE, tag);
	if (cmd_type == DEV_CMD_TYPE_QUERY)
		ufshcd_prepare_utp_query_req_upiu(hba, upiu_flags, tag);
	else if (cmd_type == DEV_CMD_TYPE_NOP)
		ufshcd_prepare_utp_nop_upiu(hba, tag);
	else
		err = UFS_ERROR;

	return err;
}

static int ufshcd_wait_for_dev_cmd(struct ufs_hba *hba, uint32_t task_tag)
{
	struct utp_upiu_rsp *ucd_rsp_ptr = (struct utp_upiu_rsp *)hba->ucdl_base_addr[task_tag].response_upiu;
	struct utp_transfer_req_desc *utrdlp = &hba->utrdl_base_addr[task_tag];
	int err = 0, resp, result;

	hba->ucd_rsp_ptr = ucd_rsp_ptr;
	hba->errors = 0;

	while (!(ufshcd_readl(hba, REG_INTERRUPT_STATUS) & UTP_TRANSFER_REQ_COMPL))
		;
	ufshcd_writel(hba, UTP_TRANSFER_REQ_COMPL, REG_INTERRUPT_STATUS);

	while (ufshcd_readl(hba, REG_UTP_TRANSFER_REQ_DOOR_BELL) & (1 << task_tag))
		;
	ufshcd_writel(hba, (1 << task_tag), REG_UTP_TRANSFER_REQ_LIST_COMPL);

	err = ufshcd_get_tr_ocs(utrdlp);
	if (err) {
		LOG_ERR("Error in OCS:%d\n", err);
		return UFS_ERROR;
	}

	resp = ufshcd_get_req_rsp(ucd_rsp_ptr);
	switch (resp) {
	case UPIU_TRANSACTION_NOP_IN:
		break;
	case UPIU_TRANSACTION_QUERY_RSP:
		err = ufshcd_check_query_response(hba);
		if (!err)
			err = ufshcd_copy_query_response(hba);
		break;
	case UPIU_TRANSACTION_RESPONSE:
		result = ufshcd_get_rsp_upiu_result(ucd_rsp_ptr);

		err = result & MASK_SCSI_STATUS;
		if (err)
			LOG_ERR("SCSI error!!!\n");

		break;
	case UPIU_TRANSACTION_REJECT_UPIU:
		/* TODO: handle Reject UPIU Response */
		err = UFS_ERROR;
		LOG_ERR("%s: Reject UPIU not fully implemented\n", __func__);
		break;
	default:
		err = UFS_ERROR;
		LOG_ERR("%s: Invalid device management cmd response: %x\n", __func__, resp);
	}

	hba->errors = err;

	return hba->errors;
}

static void ufshcd_send_command(struct ufs_hba *hba, uint32_t tag)
{
	ufshcd_writel(hba, 1 << tag, REG_UTP_TRANSFER_REQ_DOOR_BELL);
}

static int ufshcd_exec_dev_cmd(struct ufs_hba *hba,
			       enum dev_cmd_type cmd_type, int timeout)
{
	int err = 0;
	uint32_t tag = TEST_TAG;

	err = ufshcd_compose_dev_cmd(hba, cmd_type, tag);
	if (err)
		return err;

	ufshcd_send_command(hba, tag);
	err = ufshcd_wait_for_dev_cmd(hba, tag);

	return err;
}

static int ufshcd_verify_dev_init(struct ufs_hba *hba)
{
	int retries, ret;

	for (retries = NOP_OUT_RETRIES; retries > 0; retries--) {
		ret = ufshcd_exec_dev_cmd(hba, DEV_CMD_TYPE_NOP, NOP_OUT_TIMEOUT);
		if (!ret)
			break;

		LOG_DBG("ufshcd verify retry cnt = %d\n", retries);
	}

	return ret;
}

static void ufshcd_prepare_utp_scsi_cmd_upiu(struct ufs_hba *hba, struct scsi_cmd *cmd, uint8_t upiu_flags, uint32_t task_tag)
{
	struct utp_upiu_req *ucd_req_ptr = (struct utp_upiu_req *)hba->ucdl_base_addr[task_tag].command_upiu;
	struct utp_upiu_rsp *ucd_rsp_ptr = (struct utp_upiu_rsp *)hba->ucdl_base_addr[task_tag].response_upiu;
	unsigned short cdb_len;

	/* command descriptor fields */
	ucd_req_ptr->header.dword_0 = UPIU_HEADER_DWORD(UPIU_TRANSACTION_COMMAND,
							upiu_flags,
							hba->lun, task_tag);
	ucd_req_ptr->header.dword_1 = UPIU_HEADER_DWORD(UPIU_COMMAND_SET_TYPE_SCSI,
							0, 0, 0);

	/* Total EHS length and Data segment length will be zero */
	ucd_req_ptr->header.dword_2 = 0;

	ucd_req_ptr->sc.exp_data_transfer_len = ((cmd->length & 0xff) << 24) |
						(((cmd->length & 0xff00) >> 8) << 16) |
						(((cmd->length & 0xff0000) >> 16) << 8) |
						((cmd->length & 0xff000000) >> 24);

	cdb_len = UFS_CDB_SIZE;
	memset(ucd_req_ptr->sc.cdb, 0, UFS_CDB_SIZE);
	memcpy(ucd_req_ptr->sc.cdb, cmd->cdb, cdb_len);

	memset(ucd_rsp_ptr, 0, sizeof(struct utp_upiu_rsp));
}

static int ufshcd_comp_scsi_upiu(struct ufs_hba *hba, struct scsi_cmd *cmd, int tag)
{
	uint8_t upiu_flags;

	ufshcd_prepare_req_desc_hdr(hba, &upiu_flags, cmd->sc_data_direction, tag);
	ufshcd_prepare_utp_scsi_cmd_upiu(hba, cmd, upiu_flags, tag);

	return 0;
}

static void ufshcd_map_sg(struct ufs_hba *hba, struct scsi_cmd *cmd, int tag)
{
	struct ufshcd_sg_entry *prd_table;
	struct scatterlist *sg = cmd->sdb.sg;
	struct utp_transfer_req_desc *req_desc = &hba->utrdl_base_addr[tag];
	uint32_t i;

	prd_table = (struct ufshcd_sg_entry *)hba->ucdl_base_addr[tag].prd_table;
	req_desc->prd_table_length = cmd->num_sg;

	for (i = 0; i < cmd->num_sg; i++, sg++) {
		prd_table[i].size = sg->length - 1;
		prd_table[i].base_addr = sg->dma_address & 0xffffffff;
		prd_table[i].upper_addr = 0;
		prd_table[i].reserved = 0;
		LOG_DBG("%s: prd_tbl[%d].size=%x\n", __func__, i, prd_table[i].size);
		LOG_DBG("%s: prd_tbl[%d].base_addr=%x\n", __func__, i, prd_table[i].base_addr);
		LOG_DBG("%s: prd_tbl[%d].upper_addr=%x\n", __func__, i, prd_table[i].upper_addr);
	}
}

static int wait_for_transfer_complete(struct ufs_hba *hba, uint32_t slot)
{
	struct utp_upiu_rsp *ucd_rsp_ptr = (struct utp_upiu_rsp *)hba->ucdl_base_addr[slot].response_upiu;
	struct utp_transfer_req_desc *utrdlp = &hba->utrdl_base_addr[slot];
	int ocs, result = 0;
	uint8_t scsi_status;

	hba->errors = 0;
	while (ufshcd_readl(hba, REG_UTP_TRANSFER_REQ_DOOR_BELL) & (1 << slot))
		;
	ufshcd_writel(hba, (1 << slot), REG_UTP_TRANSFER_REQ_LIST_COMPL);

	while (!(ufshcd_readl(hba, REG_INTERRUPT_STATUS) & UTP_TRANSFER_REQ_COMPL))
		;

	ufshcd_writel(hba, UTP_TRANSFER_REQ_COMPL, REG_INTERRUPT_STATUS);

	k_busy_wait(10);

	ocs = ufshcd_get_tr_ocs(utrdlp);
	switch (ocs) {
	case OCS_SUCCESS:
		result = ufshcd_get_req_rsp(ucd_rsp_ptr);
		switch (result) {
		case UPIU_TRANSACTION_RESPONSE:
			result = ufshcd_get_rsp_upiu_result(ucd_rsp_ptr);

			scsi_status = result & MASK_SCSI_STATUS;
			if (scsi_status) {
				hba->errors = UFS_ERROR;
				LOG_ERR("SCSI error!!!\n");
			}

			break;
		case UPIU_TRANSACTION_REJECT_UPIU:
			/* TODO: handle Reject UPIU Response */
			LOG_ERR("Reject UPIU not fully implemented\n");
			hba->errors = UFS_ERROR;
			break;
		default:
			LOG_ERR("Unexpected request response code = %x\n", result);
			hba->errors = UFS_ERROR;
		}
		break;
	default:
		LOG_ERR("OCS error from controller = %x\n", ocs);
		hba->errors = UFS_ERROR;
	}

	return hba->errors;
}

uint32_t num_sg_arry[] = {1, 2, 64, 128, 256, 512, 1024};
static int ufs_scsi_read10(uint32_t lba, uint32_t length, uintptr_t *data_buf, int sync)
{
	int ret = 0;
	struct ufs_hba *hba = &g_hba;
	struct scsi_cmd cmd = {
		.sc_data_direction = DMA_FROM_DEVICE,
		.cdb = {READ_10,	/* command */
			0,  /* lun/reserved */
			(lba & 0xFF000000) >> 24,  /* lba */
			(lba & 0xFF0000) >> 16,  /* lba */
			(lba & 0xFF00) >> 8,	/* lba */
			(lba & 0xFF),  /* lba */
			0,  /* reserved */
			0,  /* transfer length */
			0,  /* transfer length */
			0
		},/* reserved/flag/link */
	};
	int i;

	uint32_t lbs = length / 4096;

	cmd.cdb[7] = (lbs & 0xff00) >> 8;
	cmd.cdb[8] = lbs & 0xff;
	cmd.length = length;
	cmd.num_sg = num_sg_arry[SG_ID];

	LOG_DBG("%s: lba = 0x%x, num_sg = %d, length = 0x%x, *buf=0x%x\n", __func__, lba, cmd.num_sg, length, (uint32_t)data_buf);

	for (i = 0; i < cmd.num_sg; i++) {
		cmd.sdb.sg[i].dma_address = ((unsigned long)data_buf) + length / cmd.num_sg * i;
		cmd.sdb.sg[i].length = length / cmd.num_sg;
	}

	ret = ufshcd_comp_scsi_upiu(hba, &cmd, TEST_TAG);
	ufshcd_map_sg(hba, &cmd, TEST_TAG);

	ufshcd_send_command(hba, TEST_TAG);

	// wait for transfer complete.
	if (sync)
		ret = wait_for_transfer_complete(hba, TEST_TAG);

	LOG_DBG("%s: *buf[0]=0x%x\n", __func__, *((uint32_t *)data_buf));
	LOG_DBG("%s: *buf[1]=0x%x\n", __func__, *((uint32_t *)data_buf + 1));
	LOG_DBG("%s: *buf[2]=0x%x\n", __func__, *((uint32_t *)data_buf + 2));
	LOG_DBG("%s: *buf[3]=0x%x\n", __func__, *((uint32_t *)data_buf + 3));

	return ret;
}

static int ufs_test_unit_ready(void)
{
	int ret = 0;
	struct ufs_hba *hba = &g_hba;
	struct scsi_cmd cmd = {
		.sc_data_direction = DMA_NONE,
		.cdb = {TEST_UNIT_READY,	/* command */
			0,  /* reserved */
			0,  /* reserved */
			0,  /* reserved */
			0,  /* reserved */
			0,  /* control */
		},/* reserved/flag/link */
	};

	LOG_DBG("%s\n", __func__);

	ret = ufshcd_comp_scsi_upiu(hba, &cmd, TEST_TAG);

	ufshcd_send_command(hba, TEST_TAG);

	ret = wait_for_transfer_complete(hba, TEST_TAG);

	return ret;
}

static inline void ufshcd_init_query(struct ufs_hba *hba,
				     struct ufs_query_req **request,
				     struct ufs_query_res **response,
				     enum query_opcode opcode,
				     uint8_t idn, uint8_t index, uint8_t selector)
{
	*request = &hba->dev_cmd.query.request;
	*response = &hba->dev_cmd.query.response;
	memset(*request, 0, sizeof(struct ufs_query_req));
	memset(*response, 0, sizeof(struct ufs_query_res));
	(*request)->upiu_req.opcode = opcode;
	(*request)->upiu_req.idn = idn;
	(*request)->upiu_req.index = index;
	(*request)->upiu_req.selector = selector;
}

int ufshcd_query_flag(struct ufs_hba *hba, enum query_opcode opcode,
		      enum flag_idn idn, bool *flag_res)
{
	struct ufs_query_req *request = NULL;
	struct ufs_query_res *response = NULL;
	int err, index = 0, selector = 0;
	int timeout = QUERY_REQ_TIMEOUT;

	ufshcd_init_query(hba, &request, &response, opcode, idn, index,
			  selector);

	switch (opcode) {
	case UPIU_QUERY_OPCODE_SET_FLAG:
		request->query_func = UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST;
		break;
	case UPIU_QUERY_OPCODE_READ_FLAG:
		request->query_func = UPIU_QUERY_FUNC_STANDARD_READ_REQUEST;
		if (!flag_res) {
			/* No dummy reads */
			LOG_ERR("%s: Invalid argument for read request\n",
			      __func__);
			err = UFS_ERROR;
			goto out;
		}
		break;
	default:
		LOG_ERR("%s: Expected query flag opcode but got = %d\n",
		      __func__, opcode);
		err = UFS_ERROR;
		goto out;
	}

	err = ufshcd_exec_dev_cmd(hba, DEV_CMD_TYPE_QUERY, timeout);

	if (err) {
		LOG_ERR("%s: Sending flag query for idn %d failed, err = %d\n",
		      __func__, idn, err);
		goto out;
	}

	if (flag_res)
		*flag_res = (BSWAP_32(response->upiu_res.value) &
				MASK_QUERY_UPIU_FLAG_LOC) & 0x1;

out:
	return err;
}

static int ufshcd_query_flag_retry(struct ufs_hba *hba,
				   enum query_opcode opcode,
				   enum flag_idn idn, bool *flag_res)
{
	int ret;
	int retries;

	LOG_DBG("%s\n", __func__);

	for (retries = 0; retries < QUERY_REQ_RETRIES; retries++) {
		ret = ufshcd_query_flag(hba, opcode, idn, flag_res);
		if (ret)
			LOG_ERR("%s: failed with error %d, retries %d\n",
			      __func__, ret, retries);
		else
			break;
	}

	if (ret)
		LOG_DBG("%s: query attribute, opcode %d, idn %d, failed with error %d after %d retires\n",
		      __func__, opcode, idn, ret, retries);
	return ret;
}

static int ufshcd_complete_dev_init(struct ufs_hba *hba)
{
	int i;
	int err;
	bool flag_res = 1;

	LOG_DBG("%s\n", __func__);

	err = ufshcd_query_flag_retry(hba, UPIU_QUERY_OPCODE_SET_FLAG,
				      QUERY_FLAG_IDN_FDEVICEINIT, NULL);
	if (err) {
		LOG_ERR("%s setting fDeviceInit flag failed with error %d\n",
		      __func__, err);
		goto out;
	}

	/* poll for max. 1000 iterations for fDeviceInit flag to clear */
	for (i = 0; i < 1000 && !err && flag_res; i++) {
		err = ufshcd_query_flag_retry(hba, UPIU_QUERY_OPCODE_READ_FLAG,
					      QUERY_FLAG_IDN_FDEVICEINIT,
					      &flag_res);
		LOG_DBG("flag_res=%d\n", flag_res);
	}

	if (err)
		LOG_ERR("%s reading fDeviceInit flag failed with error %d\n",
		      __func__, err);
	else if (flag_res)
		LOG_ERR("%s fDeviceInit was not cleared by the device\n",
		      __func__);

out:
	return err;
}

/**
 * ufshcd_uic_pwr_ctrl - executes UIC commands (which affects the link power
 * state) and waits for it to take effect.
 *
 */
static int ufshcd_uic_pwr_ctrl(struct ufs_hba *hba, struct uic_command *cmd)
{
	uint32_t timer = 0;
	uint8_t status;
	int ret;

	ret = ufshcd_send_uic_cmd(hba, cmd);
	if (ret) {
		LOG_ERR("pwr ctrl cmd 0x%x with mode 0x%x uic error %d\n",
		      cmd->command, cmd->argument3, ret);

		return ret;
	}

	do {
		status = ufshcd_get_upmcrs(hba);
		if (timer++ > UFS_UIC_CMD_TIMEOUT) {
			LOG_ERR("pwr ctrl cmd 0x%x failed, host upmcrs:0x%x\n",
			      cmd->command, status);
			ret = (status != PWR_OK) ? status : -1;
			break;
		}
		k_busy_wait(1000);
	} while (status != PWR_LOCAL);

	return ret;
}

/**
 * ufshcd_uic_change_pwr_mode - Perform the UIC power mode change
 *				using DME_SET primitives.
 */
static int ufshcd_uic_change_pwr_mode(struct ufs_hba *hba, uint8_t mode)
{
	struct uic_command uic_cmd = {0};
	int ret;

	uic_cmd.command = UIC_CMD_DME_SET;
	uic_cmd.argument1 = UIC_ARG_MIB(PA_PWRMODE);
	uic_cmd.argument3 = mode;
	ret = ufshcd_uic_pwr_ctrl(hba, &uic_cmd);

	return ret;
}

static int ufshcd_change_power_mode(struct ufs_hba *hba)
{
	int ret, rx_lane, tx_lane;

	LOG_DBG("%s\n", __func__);

	/* Get the connected lane count */
	ufshcd_dme_get(hba, UIC_ARG_MIB(PA_CONNECTEDRXDATALANES),
		       &rx_lane);
	ufshcd_dme_get(hba, UIC_ARG_MIB(PA_CONNECTEDTXDATALANES),
		       &tx_lane);

	if (!rx_lane || !tx_lane) {
		LOG_ERR("%s, invalid connected lanes\n", __func__);
		return 0xfe;
	}

	LOG_DBG("%s, connected_rx_lane=%d, connected_tx_lane=%d\n", __func__, rx_lane, tx_lane);

	/* set lane number */
	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_ACTIVERXDATALANES), rx_lane);
	ufshcd_dme_set(hba, UIC_ARG_MIB(PA_ACTIVETXDATALANES), tx_lane);

	/* set SLOW_AUTO on both tx/rx */
	ret = ufshcd_uic_change_pwr_mode(hba, 0x55);

	return ret;
}

static int ufs_connection_test(int lun)
{
	int ret = 0, retry = 10;
	struct ufs_hba *hba = &g_hba;
	uint32_t ahit;

	hba->lun = lun;

	/* clock enable */
	sys_write32(0x4000000, 0x12c02244);

	/* ufs top reset assert*/
	sys_write32(0x10000, 0x12c02200);
	k_busy_wait(1000);
	/* ufs top reset deassert*/
	sys_write32(0x10000, 0x12c02204);
	k_busy_wait(1000);

	//writel(0x20, 0x12c08018);
	sys_write32(0x05ffff00, 0x12c0808c);
	sys_write32(0xd0707, 0x12c08090);

	/* mphy reset assert */
	sys_write32(0x00, UFSHCI_TOP_ADDRESS);
	k_busy_wait(1000);
	/* mphy reset deassert */
	sys_write32(0x11, UFSHCI_TOP_ADDRESS);

	k_busy_wait(1000);

	/* set to ahb mode to access io sram */
	sys_write32(0, 0x12c080e4);

	/* configure platform and start phy link up */
	ret = ufshcd_init(hba);
	if (ret)
		return ret;

	/* send NOP to verify the connection */
	ret = ufshcd_verify_dev_init(hba);
	if (ret)
		return UFS_NOP_ERROR;

	ahit = FIELD_PREP(UFSHCI_AHIBERN8_TIMER_MASK, 150) |
			FIELD_PREP(UFSHCI_AHIBERN8_SCALE_MASK, 3);
	ufshcd_writel(hba, 0, REG_AUTO_HIBERNATE_IDLE_TIMER);

	ret = ufshcd_complete_dev_init(hba);
	if (ret)
		return UFS_COMPL_INIT_ERROR;

	while (retry-- && (ret = ufs_test_unit_ready()))
		;

	if (ret)
		return UFS_TEST_UNIT_RDY_ERROR;

	/* change 2 lane */
	ret = ufshcd_change_power_mode(hba);
	if (ret)
		return UFS_CHANGE_LANE_ERROR;

	return ret;
}

static int ufs_read(struct device *dev, uint32_t *dst, uint32_t src, uint32_t len)
{
	uint32_t *base;
	int ret;
	uint32_t blks;
	uint32_t offset, lba, trans, extra;
	uint8_t blk_buf[UFS_SECTOR_LENGTH], *out = (uint8_t *)dst, *in = (uint8_t *)src;

	lba = (uint32_t)src / UFS_SECTOR_LENGTH;
	offset = (uint32_t)src % UFS_SECTOR_LENGTH;

	/* Handle the case where the source address is not aligned to block size */
	if (offset) {
		if (len < (UFS_SECTOR_LENGTH - offset))
			trans = len;
		else
			trans = UFS_SECTOR_LENGTH - offset;

		/* Read the first block to get the offset */
		ret = ufs_scsi_read10(lba, UFS_SECTOR_LENGTH, (uintptr_t *)blk_buf, SYNC);
		if (ret) {
			LOG_ERR("blk read is incomplete!!!\n");
			return -1;
		}

		base = (uint32_t *)(blk_buf + offset);
		memcpy(dst, base, trans);

		out += trans;
		in  += trans;
		len -= trans;
	}

	/* Read the rest of the blocks */
	while (len)  {
		blks = len / UFS_SECTOR_LENGTH;
		extra = len % UFS_SECTOR_LENGTH;

		lba = (uint32_t)in / UFS_SECTOR_LENGTH;
		offset = (uint32_t)in % UFS_SECTOR_LENGTH;

		if (len == extra) {
			/* Read out the last block */
			ret = ufs_scsi_read10(lba, UFS_SECTOR_LENGTH, (uintptr_t *)blk_buf, SYNC);
			if (ret) {
				LOG_ERR("blk read is incomplete!!!\n");
				return -1;
			}

			memcpy(out, blk_buf + offset, extra);

			out += extra;
			in += extra;
			len -= extra;
		} else {
			if (blks > 0x20)
				blks = 0x20;

			/* Read out the whole block */
			ret = ufs_scsi_read10(lba, blks * UFS_SECTOR_LENGTH, (uintptr_t *)out, SYNC);
			if (ret) {
				LOG_ERR("blk read is incomplete!!!\n");
				return -1;
			}

			out += (UFS_SECTOR_LENGTH * blks);
			in += (UFS_SECTOR_LENGTH * blks);
			len -= (UFS_SECTOR_LENGTH * blks);
		}
	}

	return 0;
}

static int ufs_init(struct device *dev)
{
	int lun = (1 << abr_get_ind());
	int err = 0;

	err = ufs_connection_test(lun);

	return err;
}

static struct ast_loader_ops bootufs_ops = {
	.init = ufs_init,
	.copy = ufs_read,
};

int ufs_register(struct ast_loader *loader)
{
	struct device *dev;

	dev = (struct device *)device_get_binding("ufshc@12c08000");
	if (!dev) {
		LOG_ERR("No device named ufs");
		return -1;
	}

	loader->ops = &bootufs_ops;
	loader->dev = dev;

	LOG_DBG("UFS loader registered");

	return 0;
}

DEVICE_DEFINE(ufs, "ufshc@12c08000", NULL, NULL,
		&g_hba, NULL,
		POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
		NULL);
