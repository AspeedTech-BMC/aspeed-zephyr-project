#ifndef _UFS_H
#define _UFS_H

//#include <bootdev.h>

#define AHB_PATH

#define UFS_IRQ 118
#ifndef CONFIG_IRQ
#define POLLING_MODE
#endif
//#define POLLING_MODE

#define UFS_CDB_SIZE	16
#define UPIU_TRANSACTION_UIC_CMD 0x1F

#define ufshcd_writel(hba, val, reg)	\
	sys_write32((val), (hba)->mmio_base + (reg))
#define ufshcd_readl(hba, reg)	\
	sys_read32((hba)->mmio_base + (reg))

enum {
	IRQ_NONE = (0 << 0),
	IRQ_HANDLED = (1 << 0),
};

enum {
	ASYNC = 0,
	SYNC
};

enum {
	UFS_SUCCESS = 0,
	UFS_ERROR,
	UFS_LINK_NOT_UP,
	UFS_NOP_ERROR,
	UFS_COMPL_INIT_ERROR,
	UFS_TEST_UNIT_RDY_ERROR,
	UFS_CHANGE_LANE_ERROR,
	UFS_MPHY_TX_NOT_READY,
	UFS_MPHY_RX_NOT_READY,
	UFS_INVALID,
	UFS_TIMEOUT,
};

enum ufshcd_caps {
	/* Allow dynamic clk gating */
	UFSHCD_CAP_CLK_GATING				= 1 << 0,

	/* Allow hiberb8 with clk gating */
	UFSHCD_CAP_HIBERN8_WITH_CLK_GATING		= 1 << 1,

	/* Allow dynamic clk scaling */
	UFSHCD_CAP_CLK_SCALING				= 1 << 2,

	/* Allow auto bkops to enabled during runtime suspend */
	UFSHCD_CAP_AUTO_BKOPS_SUSPEND			= 1 << 3,

	/*
	 * This capability allows host controller driver to use the UFS HCI's
	 * interrupt aggregation capability.
	 * CAUTION: Enabling this might reduce overall UFS throughput.
	 */
	UFSHCD_CAP_INTR_AGGR				= 1 << 4,

	/*
	 * This capability allows the device auto-bkops to be always enabled
	 * except during suspend (both runtime and suspend).
	 * Enabling this capability means that device will always be allowed
	 * to do background operation when it's active but it might degrade
	 * the performance of ongoing read/write operations.
	 */
	UFSHCD_CAP_KEEP_AUTO_BKOPS_ENABLED_EXCEPT_SUSPEND = 1 << 5,

	/*
	 * This capability allows host controller driver to automatically
	 * enable runtime power management by itself instead of waiting
	 * for userspace to control the power management.
	 */
	UFSHCD_CAP_RPM_AUTOSUSPEND			= 1 << 6,

	/*
	 * This capability allows the host controller driver to turn-on
	 * WriteBooster, if the underlying device supports it and is
	 * provisioned to be used. This would increase the write performance.
	 */
	UFSHCD_CAP_WB_EN				= 1 << 7,

	/*
	 * This capability allows the host controller driver to use the
	 * inline crypto engine, if it is present
	 */
	UFSHCD_CAP_CRYPTO				= 1 << 8,

	/*
	 * This capability allows the controller regulators to be put into
	 * lpm mode aggressively during clock gating.
	 * This would increase power savings.
	 */
	UFSHCD_CAP_AGGR_POWER_COLLAPSE			= 1 << 9,

	/*
	 * This capability allows the host controller driver to use DeepSleep,
	 * if it is supported by the UFS device. The host controller driver must
	 * support device hardware reset via the hba->device_reset() callback,
	 * in order to exit DeepSleep state.
	 */
	UFSHCD_CAP_DEEPSLEEP				= 1 << 10,
};

enum ufshcd_quirks {
	/* Interrupt aggregation support is broken */
	UFSHCD_QUIRK_BROKEN_INTR_AGGR			= 1 << 0,

	/*
	 * delay before each dme command is required as the unipro
	 * layer has shown instabilities
	 */
	UFSHCD_QUIRK_DELAY_BEFORE_DME_CMDS		= 1 << 1,

	/*
	 * If UFS host controller is having issue in processing LCC (Line
	 * Control Command) coming from device then enable this quirk.
	 * When this quirk is enabled, host controller driver should disable
	 * the LCC transmission on UFS device (by clearing TX_LCC_ENABLE
	 * attribute of device to 0).
	 */
	UFSHCD_QUIRK_BROKEN_LCC				= 1 << 2,

	/*
	 * The attribute PA_RXHSUNTERMCAP specifies whether or not the
	 * inbound Link supports unterminated line in HS mode. Setting this
	 * attribute to 1 fixes moving to HS gear.
	 */
	UFSHCD_QUIRK_BROKEN_PA_RXHSUNTERMCAP		= 1 << 3,

	/*
	 * This quirk needs to be enabled if the host controller only allows
	 * accessing the peer dme attributes in AUTO mode (FAST AUTO or
	 * SLOW AUTO).
	 */
	UFSHCD_QUIRK_DME_PEER_ACCESS_AUTO_MODE		= 1 << 4,

	/*
	 * This quirk needs to be enabled if the host controller doesn't
	 * advertise the correct version in UFS_VER register. If this quirk
	 * is enabled, standard UFS host driver will call the vendor specific
	 * ops (get_ufs_hci_version) to get the correct version.
	 */
	UFSHCD_QUIRK_BROKEN_UFS_HCI_VERSION		= 1 << 5,

	/*
	 * Clear handling for transfer/task request list is just opposite.
	 */
	UFSHCI_QUIRK_BROKEN_REQ_LIST_CLR		= 1 << 6,

	/*
	 * This quirk needs to be enabled if host controller doesn't allow
	 * that the interrupt aggregation timer and counter are reset by s/w.
	 */
	UFSHCI_QUIRK_SKIP_RESET_INTR_AGGR		= 1 << 7,

	/*
	 * This quirks needs to be enabled if host controller cannot be
	 * enabled via HCE register.
	 */
	UFSHCI_QUIRK_BROKEN_HCE				= 1 << 8,

	/*
	 * This quirk needs to be enabled if the host controller regards
	 * resolution of the values of PRDTO and PRDTL in UTRD as byte.
	 */
	UFSHCD_QUIRK_PRDT_BYTE_GRAN			= 1 << 9,

	/*
	 * This quirk needs to be enabled if the host controller reports
	 * OCS FATAL ERROR with device error through sense data
	 */
	UFSHCD_QUIRK_BROKEN_OCS_FATAL_ERROR		= 1 << 10,

	/*
	 * This quirk needs to be enabled if the host controller has
	 * auto-hibernate capability but it doesn't work.
	 */
	UFSHCD_QUIRK_BROKEN_AUTO_HIBERN8		= 1 << 11,

	/*
	 * This quirk needs to disable manual flush for write booster
	 */
	UFSHCI_QUIRK_SKIP_MANUAL_WB_FLUSH_CTRL		= 1 << 12,

	/*
	 * This quirk needs to disable unipro timeout values
	 * before power mode change
	 */
	UFSHCD_QUIRK_SKIP_DEF_UNIPRO_TIMEOUT_SETTING = 1 << 13,

	/*
	 * This quirk allows only sg entries aligned with page size.
	 */
	UFSHCD_QUIRK_ALIGN_SG_WITH_PAGE_SIZE		= 1 << 14,
};

enum dev_cmd_type {
	DEV_CMD_TYPE_NOP		= 0x0,
	DEV_CMD_TYPE_QUERY		= 0x1,
};

/* DWC HC UFSHCI specific Registers */
enum dwc_specific_registers {
	DWC_UFS_REG_HCLKDIV = 0xFC,
};

/* Clock Divider Values: Hex equivalent of frequency in MHz */
enum clk_div_values {
	DWC_UFS_REG_HCLKDIV_DIV_62_5	= 0x3e,
	DWC_UFS_REG_HCLKDIV_DIV_125 = 0x7d,
	DWC_UFS_REG_HCLKDIV_DIV_200 = 0xc8,
};

/* Selector Index */
enum selector_index {
	SELIND_LN0_TX		= 0x00,
	SELIND_LN1_TX		= 0x01,
	SELIND_LN0_RX		= 0x04,
	SELIND_LN1_RX		= 0x05,
};

/* UFSHCD UIC layer error flags */
enum {
	UFSHCD_UIC_DL_PA_INIT_ERROR = (1 << 0), /* Data link layer error */
	UFSHCD_UIC_DL_NAC_RECEIVED_ERROR = (1 << 1), /* Data link layer error */
	UFSHCD_UIC_DL_TCx_REPLAY_ERROR = (1 << 2), /* Data link layer error */
	UFSHCD_UIC_NL_ERROR = (1 << 3), /* Network layer error */
	UFSHCD_UIC_TL_ERROR = (1 << 4), /* Transport Layer error */
	UFSHCD_UIC_DME_ERROR = (1 << 5), /* DME error */
	UFSHCD_UIC_PA_GENERIC_ERROR = (1 << 6), /* Generic PA error */
};

/*
 * UFS Protocol Information Unit related definitions
 */

/* Task management functions */
enum {
	UFS_ABORT_TASK		= 0x01,
	UFS_ABORT_TASK_SET	= 0x02,
	UFS_CLEAR_TASK_SET	= 0x04,
	UFS_LOGICAL_RESET	= 0x08,
	UFS_QUERY_TASK		= 0x80,
	UFS_QUERY_TASK_SET	= 0x81,
};

/* UTP UPIU Transaction Codes Initiator to Target */
enum {
	UPIU_TRANSACTION_NOP_OUT	= 0x00,
	UPIU_TRANSACTION_COMMAND	= 0x01,
	UPIU_TRANSACTION_DATA_OUT	= 0x02,
	UPIU_TRANSACTION_TASK_REQ	= 0x04,
	UPIU_TRANSACTION_QUERY_REQ	= 0x16,
};

/* UTP UPIU Transaction Codes Target to Initiator */
enum {
	UPIU_TRANSACTION_NOP_IN		= 0x20,
	UPIU_TRANSACTION_RESPONSE	= 0x21,
	UPIU_TRANSACTION_DATA_IN	= 0x22,
	UPIU_TRANSACTION_TASK_RSP	= 0x24,
	UPIU_TRANSACTION_READY_XFER = 0x31,
	UPIU_TRANSACTION_QUERY_RSP	= 0x36,
	UPIU_TRANSACTION_REJECT_UPIU	= 0x3F,
};

/* UPIU Read/Write flags */
enum {
	UPIU_CMD_FLAGS_NONE = 0x00,
	UPIU_CMD_FLAGS_WRITE	= 0x20,
	UPIU_CMD_FLAGS_READ = 0x40,
};

struct utp_upiu_header {
	uint32_t dword_0;
	uint32_t dword_1;
	uint32_t dword_2;
};

struct utp_upiu_query {
	uint8_t opcode;
	uint8_t idn;
	uint8_t index;
	uint8_t selector;
	uint16_t reserved_osf;
	uint16_t length;
	uint32_t value;
	uint32_t reserved[2];
};

struct utp_upiu_cmd {
	uint32_t exp_data_transfer_len;
	uint8_t cdb[UFS_CDB_SIZE];
};

/**
 * struct utp_upiu_req - general upiu request structure
 * @header:UPIU header structure DW-0 to DW-2
 * @sc: fields structure for scsi command DW-3 to DW-7
 * @qr: fields structure for query request DW-3 to DW-7
 * @uc: use utp_upiu_query to host the 4 dwords of uic command
 */
struct utp_upiu_req {
	struct utp_upiu_header header;
	union {
		struct utp_upiu_cmd		sc;
		struct utp_upiu_query	qr;
		struct utp_upiu_query	uc;
	};
};

#define UFS_SENSE_SIZE	18

struct utp_cmd_rsp {
	uint32_t residual_transfer_count;
	uint32_t reserved[4];
	uint16_t sense_data_len;
	uint8_t sense_data[UFS_SENSE_SIZE];
};

struct ufshpb_active_field {
	uint16_t active_rgn;
	uint16_t active_srgn;
};

struct utp_hpb_rsp {
	uint32_t residual_transfer_count;
	uint32_t reserved1[4];
	uint16_t sense_data_len;
	uint8_t desc_type;
	uint8_t additional_len;
	uint8_t hpb_op;
	uint8_t lun;
	uint8_t active_rgn_cnt;
	uint8_t inactive_rgn_cnt;
	struct ufshpb_active_field hpb_active_field[2];
	uint16_t hpb_inactive_field[2];
};

#define UTP_HPB_RSP_SIZE 40

struct utp_upiu_rsp {
	struct utp_upiu_header header;
	union {
		struct utp_cmd_rsp sr;
		struct utp_hpb_rsp hr;
		struct utp_upiu_query qr;
	};
};

/**
 * struct ufs_query_req - parameters for building a query request
 * @query_func: UPIU header query function
 * @upiu_req: the query request data
 */
struct ufs_query_req {
	uint8_t query_func;
	struct utp_upiu_query upiu_req;
};

/**
 * struct ufs_query_resp - UPIU QUERY
 * @response: device response code
 * @upiu_res: query response data
 */
struct ufs_query_res {
	uint8_t response;
	struct utp_upiu_query upiu_res;
};

/**
 * struct ufs_query - holds relevant data structures for query request
 * @request: request upiu and function
 * @descriptor: buffer for sending/receiving descriptor
 * @response: response upiu and response
 */
struct ufs_query {
	struct ufs_query_req request;
	uint8_t *descriptor;
	struct ufs_query_res response;
};

/**
 * struct ufs_dev_cmd - all assosiated fields with device management commands
 * @type: device management command type - Query, NOP OUT
 * @tag_wq: wait queue until free command slot is available
 */
struct ufs_dev_cmd {
	enum dev_cmd_type type;
	struct ufs_query query;
	int complete;
};

/* GenSelectorIndex calculation macros for M-PHY attributes */
#define UIC_ARG_MPHY_TX_GEN_SEL_INDEX(lane) (lane)
#define UIC_ARG_MPHY_RX_GEN_SEL_INDEX(lane) (PA_MAXDATALANES + (lane))

#define UIC_ARG_MIB_SEL(attr, sel)	((((attr) & 0xFFFF) << 16) |\
					 ((sel) & 0xFFFF))
#define UIC_ARG_MIB(attr)		UIC_ARG_MIB_SEL(attr, 0)
#define UIC_ARG_ATTR_TYPE(t)		(((t) & 0xFF) << 16)
#define UIC_GET_ATTR_ID(v)		(((v) >> 16) & 0xFFFF)

struct ufshcd_dme_attr_val {
	uint32_t attr_sel;
	uint32_t mib_val;
	uint8_t peer;
};

/*
 * Common Block Attributes
 */
#define TX_GLOBALHIBERNATE			UNIPRO_CB_OFFSET(0x002B)
#define REFCLKMODE				UNIPRO_CB_OFFSET(0x00BF)
#define DIRECTCTRL19				UNIPRO_CB_OFFSET(0x00CD)
#define DIRECTCTRL10				UNIPRO_CB_OFFSET(0x00E6)
#define CDIRECTCTRL6				UNIPRO_CB_OFFSET(0x00EA)
#define RTOBSERVESELECT				UNIPRO_CB_OFFSET(0x00F0)
#define CBDIVFACTOR				UNIPRO_CB_OFFSET(0x00F1)
#define CBDCOCTRL5				UNIPRO_CB_OFFSET(0x00F3)
#define CBPRGPLL2				UNIPRO_CB_OFFSET(0x00F8)
#define CBPRGTUNING				UNIPRO_CB_OFFSET(0x00FB)

#define UNIPRO_CB_OFFSET(x)			(0x8000 | (x))

/* UIC command interfaces for DME primitives */
#define DME_LOCAL	0
#define DME_PEER	1
#define ATTR_SET_NOR	0	/* NORMAL */
#define ATTR_SET_ST 1	/* STATIC */

/**
 * struct uic_command - UIC command structure
 * @command: UIC command
 * @argument1: UIC command argument 1
 * @argument2: UIC command argument 2
 * @argument3: UIC command argument 3
 * @cmd_active: Indicate if UIC command is outstanding
 * @done: UIC command completion
 */
struct uic_command {
	uint32_t command;
	uint32_t argument1;
	uint32_t argument2;
	uint32_t argument3;
	uint32_t cmd_active;
	int done;
};

#define UFS_UIC_COMMAND_RETRIES 10
#define UIC_CMD_TIMEOUT 500
#define NOP_OUT_RETRIES    10
#define NOP_OUT_TIMEOUT    50 /* msecs */

#define QUERY_REQ_RETRIES 3
#define QUERY_REQ_TIMEOUT 1500

#define MASK_QUERY_UPIU_FLAG_LOC 0xFF

#define GENERAL_UPIU_REQUEST_SIZE (sizeof(struct utp_upiu_req))
#define QUERY_DESC_MAX_SIZE		  255
#define QUERY_DESC_MIN_SIZE		  2
#define QUERY_DESC_HDR_SIZE		  2
#define QUERY_OSF_SIZE			  (GENERAL_UPIU_REQUEST_SIZE - \
					(sizeof(struct utp_upiu_header)))

#define RESPONSE_UPIU_SENSE_DATA_LENGTH 18
#define UPIU_HEADER_DWORD(byte3, byte2, byte1, byte0)\
			(((byte0) << 24) | ((byte1) << 16) |\
			 ((byte2) << 8) | (byte3))

/* Link Status*/
enum link_status {
	UFSHCD_LINK_IS_DOWN = 1,
	UFSHCD_LINK_IS_UP	= 2,
};

/* UIC Commands */
enum uic_cmd_dme {
	UIC_CMD_DME_GET			= 0x01,
	UIC_CMD_DME_SET			= 0x02,
	UIC_CMD_DME_PEER_GET	= 0x03,
	UIC_CMD_DME_PEER_SET	= 0x04,
	UIC_CMD_DME_POWERON		= 0x10,
	UIC_CMD_DME_POWEROFF	= 0x11,
	UIC_CMD_DME_ENABLE		= 0x12,
	UIC_CMD_DME_RESET		= 0x14,
	UIC_CMD_DME_END_PT_RST		= 0x15,
	UIC_CMD_DME_LINK_STARTUP	= 0x16,
	UIC_CMD_DME_HIBER_ENTER		= 0x17,
	UIC_CMD_DME_HIBER_EXIT		= 0x18,
	UIC_CMD_DME_TEST_MODE		= 0x1A,
};

#define MASK_UIC_COMMAND_RESULT			0xFF

/* Controller UFSHCI version */
enum {
	UFSHCI_VERSION_10 = 0x00010000, /* 1.0 */
	UFSHCI_VERSION_11 = 0x00010100, /* 1.1 */
	UFSHCI_VERSION_20 = 0x00000200, /* 2.0 */
	UFSHCI_VERSION_21 = 0x00000210, /* 2.1 */
};

/* Interrupt disable masks */
enum {
	/* Interrupt disable mask for UFSHCI v1.0 */
	INTERRUPT_MASK_ALL_VER_10	= 0x30FFF,
	INTERRUPT_MASK_RW_VER_10	= 0x30000,

	/* Interrupt disable mask for UFSHCI v1.1 */
	INTERRUPT_MASK_ALL_VER_11	= 0x31FFF,

	/* Interrupt disable mask for UFSHCI v2.1 */
	INTERRUPT_MASK_ALL_VER_21	= 0x71FFF,
};

/* UFSHCI Registers */
enum {
	REG_CONTROLLER_CAPABILITIES		= 0x00,
	REG_UFS_VERSION				= 0x08,
	REG_CONTROLLER_DEV_ID			= 0x10,
	REG_CONTROLLER_PROD_ID			= 0x14,
	REG_AUTO_HIBERNATE_IDLE_TIMER		= 0x18,
	REG_INTERRUPT_STATUS			= 0x20,
	REG_INTERRUPT_ENABLE			= 0x24,
	REG_CONTROLLER_STATUS			= 0x30,
	REG_CONTROLLER_ENABLE			= 0x34,
	REG_UIC_ERROR_CODE_PHY_ADAPTER_LAYER	= 0x38,
	REG_UIC_ERROR_CODE_DATA_LINK_LAYER	= 0x3C,
	REG_UIC_ERROR_CODE_NETWORK_LAYER	= 0x40,
	REG_UIC_ERROR_CODE_TRANSPORT_LAYER	= 0x44,
	REG_UIC_ERROR_CODE_DME			= 0x48,
	REG_UTP_TRANSFER_REQ_INT_AGG_CONTROL	= 0x4C,
	REG_UTP_TRANSFER_REQ_LIST_BASE_L	= 0x50,
	REG_UTP_TRANSFER_REQ_LIST_BASE_H	= 0x54,
	REG_UTP_TRANSFER_REQ_DOOR_BELL		= 0x58,
	REG_UTP_TRANSFER_REQ_LIST_CLEAR		= 0x5C,
	REG_UTP_TRANSFER_REQ_LIST_RUN_STOP	= 0x60,
	REG_UTP_TRANSFER_REQ_LIST_COMPL		= 0x64,
	REG_UTP_TASK_REQ_LIST_BASE_L		= 0x70,
	REG_UTP_TASK_REQ_LIST_BASE_H		= 0x74,
	REG_UTP_TASK_REQ_DOOR_BELL		= 0x78,
	REG_UTP_TASK_REQ_LIST_CLEAR		= 0x7C,
	REG_UTP_TASK_REQ_LIST_RUN_STOP		= 0x80,
	REG_UIC_COMMAND				= 0x90,
	REG_UIC_COMMAND_ARG_1			= 0x94,
	REG_UIC_COMMAND_ARG_2			= 0x98,
	REG_UIC_COMMAND_ARG_3			= 0x9C,

	UFSHCI_REG_SPACE_SIZE			= 0xA0,

	REG_UFS_CCAP				= 0x100,
	REG_UFS_CRYPTOCAP			= 0x104,

	UFSHCI_CRYPTO_REG_SPACE_SIZE		= 0x400,
};

/* Controller capability masks */
enum {
	MASK_TRANSFER_REQUESTS_SLOTS		= 0x0000001F,
	MASK_TASK_MANAGEMENT_REQUEST_SLOTS	= 0x00070000,
	MASK_AUTO_HIBERN8_SUPPORT		= 0x00800000,
	MASK_64_ADDRESSING_SUPPORT		= 0x01000000,
	MASK_OUT_OF_ORDER_DATA_DELIVERY_SUPPORT = 0x02000000,
	MASK_UIC_DME_TEST_MODE_SUPPORT		= 0x04000000,
	MASK_CRYPTO_SUPPORT			= 0x10000000,
};

#define UFSHCI_AHIBERN8_TIMER_MASK              GENMASK(9, 0)
#define UFSHCI_AHIBERN8_SCALE_MASK              GENMASK(12, 10)
#define UFSHCI_AHIBERN8_SCALE_FACTOR            10
#define UFSHCI_AHIBERN8_MAX                     (1023 * 100000)

/* HCS - Host Controller Status 30h */
#define DEVICE_PRESENT				0x1
#define UTP_TRANSFER_REQ_LIST_READY		0x2
#define UTP_TASK_REQ_LIST_READY			0x4
#define UIC_COMMAND_READY			0x8
#define HOST_ERROR_INDICATOR			0x10
#define DEVICE_ERROR_INDICATOR			0x20
#define UIC_POWER_MODE_CHANGE_REQ_STATUS_MASK	UFS_MASK(0x7, 8)

/* HCE - Host Controller Enable 34h */
#define CONTROLLER_ENABLE	0x1
#define CONTROLLER_DISABLE	0x0
#define CRYPTO_GENERAL_ENABLE	0x2

/* UECPA - Host UIC Error Code PHY Adapter Layer 38h */
#define UIC_PHY_ADAPTER_LAYER_ERROR			0x80000000
#define UIC_PHY_ADAPTER_LAYER_ERROR_CODE_MASK		0x1F
#define UIC_PHY_ADAPTER_LAYER_LANE_ERR_MASK		0xF
#define UIC_PHY_ADAPTER_LAYER_GENERIC_ERROR		0x10

/* UECDL - Host UIC Error Code Data Link Layer 3Ch */
#define UIC_DATA_LINK_LAYER_ERROR		0x80000000
#define UIC_DATA_LINK_LAYER_ERROR_CODE_MASK 0xFFFF
#define UIC_DATA_LINK_LAYER_ERROR_TCX_REP_TIMER_EXP 0x2
#define UIC_DATA_LINK_LAYER_ERROR_AFCX_REQ_TIMER_EXP	0x4
#define UIC_DATA_LINK_LAYER_ERROR_FCX_PRO_TIMER_EXP 0x8
#define UIC_DATA_LINK_LAYER_ERROR_RX_BUF_OF 0x20
#define UIC_DATA_LINK_LAYER_ERROR_PA_INIT	0x2000
#define UIC_DATA_LINK_LAYER_ERROR_NAC_RECEIVED	0x0001
#define UIC_DATA_LINK_LAYER_ERROR_TCx_REPLAY_TIMEOUT 0x0002

/* UECN - Host UIC Error Code Network Layer 40h */
#define UIC_NETWORK_LAYER_ERROR			0x80000000
#define UIC_NETWORK_LAYER_ERROR_CODE_MASK	0x7
#define UIC_NETWORK_UNSUPPORTED_HEADER_TYPE 0x1
#define UIC_NETWORK_BAD_DEVICEID_ENC		0x2
#define UIC_NETWORK_LHDR_TRAP_PACKET_DROPPING	0x4

/* UECT - Host UIC Error Code Transport Layer 44h */
#define UIC_TRANSPORT_LAYER_ERROR		0x80000000
#define UIC_TRANSPORT_LAYER_ERROR_CODE_MASK	0x7F
#define UIC_TRANSPORT_UNSUPPORTED_HEADER_TYPE	0x1
#define UIC_TRANSPORT_UNKNOWN_CPORTID		0x2
#define UIC_TRANSPORT_NO_CONNECTION_RX		0x4
#define UIC_TRANSPORT_CONTROLLED_SEGMENT_DROPPING	0x8
#define UIC_TRANSPORT_BAD_TC			0x10
#define UIC_TRANSPORT_E2E_CREDIT_OVERFOW	0x20
#define UIC_TRANSPORT_SAFETY_VALUE_DROPPING	0x40

/* UECDME - Host UIC Error Code DME 48h */
#define UIC_DME_ERROR			0x80000000
#define UIC_DME_ERROR_CODE_MASK		0x1

/* UTRIACR - Interrupt Aggregation control register - 0x4Ch */
#define INT_AGGR_TIMEOUT_VAL_MASK		0xFF
#define INT_AGGR_COUNTER_THRESHOLD_MASK		UFS_MASK(0x1F, 8)
#define INT_AGGR_COUNTER_AND_TIMER_RESET	0x10000
#define INT_AGGR_STATUS_BIT			0x100000
#define INT_AGGR_PARAM_WRITE			0x1000000
#define INT_AGGR_ENABLE				0x80000000

/* UTRLRSR - UTP Transfer Request Run-Stop Register 60h */
#define UTP_TRANSFER_REQ_LIST_RUN_STOP_BIT	0x1

/* UTMRLRSR - UTP Task Management Request Run-Stop Register 80h */
#define UTP_TASK_REQ_LIST_RUN_STOP_BIT		0x1

#define UFSHCD_STATUS_READY (UTP_TRANSFER_REQ_LIST_READY |\
				UTP_TASK_REQ_LIST_READY |\
				UIC_COMMAND_READY)

/* UTRLRSR - UTP Transfer Request Run-Stop Register 60h */
#define UTP_TRANSFER_REQ_LIST_RUN_STOP_BIT	0x1

/* UTMRLRSR - UTP Task Management Request Run-Stop Register 80h */
#define UTP_TASK_REQ_LIST_RUN_STOP_BIT		0x1

enum {
	PWR_OK		= 0x0,
	PWR_LOCAL	= 0x01,
	PWR_REMOTE	= 0x02,
	PWR_BUSY	= 0x03,
	PWR_ERROR_CAP	= 0x04,
	PWR_FATAL_ERROR = 0x05,
};

/* UICCMD - UIC Command */
#define COMMAND_OPCODE_MASK		0xFF
#define GEN_SELECTOR_INDEX_MASK		0xFFFF

/*
 * PHY Adpater attributes
 */
#define PA_ACTIVETXDATALANES	0x1560
#define PA_ACTIVERXDATALANES	0x1580
#define PA_TXTRAILINGCLOCKS 0x1564
#define PA_PHY_TYPE		0x1500
#define PA_AVAILTXDATALANES 0x1520
#define PA_AVAILRXDATALANES 0x1540
#define PA_MINRXTRAILINGCLOCKS	0x1543
#define PA_TXPWRSTATUS		0x1567
#define PA_RXPWRSTATUS		0x1582
#define PA_TXFORCECLOCK		0x1562
#define PA_TXPWRMODE		0x1563
#define PA_LEGACYDPHYESCDL	0x1570
#define PA_MAXTXSPEEDFAST	0x1521
#define PA_MAXTXSPEEDSLOW	0x1522
#define PA_MAXRXSPEEDFAST	0x1541
#define PA_MAXRXSPEEDSLOW	0x1542
#define PA_TXLINKSTARTUPHS	0x1544
#define PA_LOCAL_TX_LCC_ENABLE	0x155E
#define PA_TXSPEEDFAST		0x1565
#define PA_TXSPEEDSLOW		0x1566
#define PA_REMOTEVERINFO	0x15A0
#define PA_TXGEAR		0x1568
#define PA_TXTERMINATION	0x1569
#define PA_HSSERIES		0x156A
#define PA_PWRMODE		0x1571
#define PA_RXGEAR		0x1583
#define PA_RXTERMINATION	0x1584
#define PA_MAXRXPWMGEAR		0x1586
#define PA_MAXRXHSGEAR		0x1587
#define PA_RXHSUNTERMCAP	0x15A5
#define PA_RXLSTERMCAP		0x15A6
#define PA_GRANULARITY		0x15AA
#define PA_PACPREQTIMEOUT	0x1590
#define PA_PACPREQEOBTIMEOUT	0x1591
#define PA_HIBERN8TIME		0x15A7
#define PA_LOCALVERINFO		0x15A9
#define PA_GRANULARITY		0x15AA
#define PA_TACTIVATE		0x15A8
#define PA_PACPFRAMECOUNT	0x15C0
#define PA_PACPERRORCOUNT	0x15C1
#define PA_PHYTESTCONTROL	0x15C2
#define PA_PWRMODEUSERDATA0 0x15B0
#define PA_PWRMODEUSERDATA1 0x15B1
#define PA_PWRMODEUSERDATA2 0x15B2
#define PA_PWRMODEUSERDATA3 0x15B3
#define PA_PWRMODEUSERDATA4 0x15B4
#define PA_PWRMODEUSERDATA5 0x15B5
#define PA_PWRMODEUSERDATA6 0x15B6
#define PA_PWRMODEUSERDATA7 0x15B7
#define PA_PWRMODEUSERDATA8 0x15B8
#define PA_PWRMODEUSERDATA9 0x15B9
#define PA_PWRMODEUSERDATA10	0x15BA
#define PA_PWRMODEUSERDATA11	0x15BB
#define PA_CONNECTEDTXDATALANES 0x1561
#define PA_CONNECTEDRXDATALANES 0x1581
#define PA_LOGICALLANEMAP	0x15A1
#define PA_SLEEPNOCONFIGTIME	0x15A2
#define PA_STALLNOCONFIGTIME	0x15A3
#define PA_SAVECONFIGTIME	0x15A4
#define PA_TXHSADAPTTYPE	   0x15D4

/*
 * M-TX Configuration Attributes
 */
#define TX_HIBERN8TIME_CAPABILITY		0x000F
#define TX_MODE					0x0021
#define TX_HSRATE_SERIES			0x0022
#define TX_HSGEAR				0x0023
#define TX_PWMGEAR				0x0024
#define TX_AMPLITUDE				0x0025
#define TX_HS_SLEWRATE				0x0026
#define TX_SYNC_SOURCE				0x0027
#define TX_HS_SYNC_LENGTH			0x0028
#define TX_HS_PREPARE_LENGTH			0x0029
#define TX_LS_PREPARE_LENGTH			0x002A
#define TX_HIBERN8_CONTROL			0x002B
#define TX_LCC_ENABLE				0x002C
#define TX_PWM_BURST_CLOSURE_EXTENSION		0x002D
#define TX_BYPASS_8B10B_ENABLE			0x002E
#define TX_DRIVER_POLARITY			0x002F
#define TX_HS_UNTERMINATED_LINE_DRIVE_ENABLE	0x0030
#define TX_LS_TERMINATED_LINE_DRIVE_ENABLE	0x0031
#define TX_LCC_SEQUENCER			0x0032
#define TX_MIN_ACTIVATETIME			0x0033
#define TX_PWM_G6_G7_SYNC_LENGTH		0x0034
#define TX_REFCLKFREQ				0x00EB
#define TX_CFGCLKFREQVAL			0x00EC
#define CFGEXTRATTR				0x00F0
#define DITHERCTRL2				0x00F1

/*
 * IS - Interrupt Status - 20h
 */
#define UTP_TRANSFER_REQ_COMPL			0x1
#define UIC_DME_END_PT_RESET			0x2
#define UIC_ERROR				0x4
#define UIC_TEST_MODE				0x8
#define UIC_POWER_MODE				0x10
#define UIC_HIBERNATE_EXIT			0x20
#define UIC_HIBERNATE_ENTER			0x40
#define UIC_LINK_LOST				0x80
#define UIC_LINK_STARTUP			0x100
#define UTP_TASK_REQ_COMPL			0x200
#define UIC_COMMAND_COMPL			0x400
#define DEVICE_FATAL_ERROR			0x800
#define CONTROLLER_FATAL_ERROR			0x10000
#define SYSTEM_BUS_FATAL_ERROR			0x20000
#define CRYPTO_ENGINE_FATAL_ERROR		0x40000

#define UFSHCD_UIC_HIBERN8_MASK (UIC_HIBERNATE_ENTER |\
				UIC_HIBERNATE_EXIT)

#define UFSHCD_UIC_PWR_MASK (UFSHCD_UIC_HIBERN8_MASK |\
				UIC_POWER_MODE)

#define UFSHCD_UIC_MASK		(UIC_COMMAND_COMPL | UFSHCD_UIC_PWR_MASK)

#define UFSHCD_ERROR_MASK	(UIC_ERROR |\
				DEVICE_FATAL_ERROR |\
				CONTROLLER_FATAL_ERROR |\
				SYSTEM_BUS_FATAL_ERROR |\
				CRYPTO_ENGINE_FATAL_ERROR)

#define INT_FATAL_ERRORS	(DEVICE_FATAL_ERROR |\
				CONTROLLER_FATAL_ERROR |\
				SYSTEM_BUS_FATAL_ERROR |\
				CRYPTO_ENGINE_FATAL_ERROR |\
				UIC_LINK_LOST)

#define UFSHCD_ENABLE_INTRS (UTP_TRANSFER_REQ_COMPL |\
					UTP_TASK_REQ_COMPL |\
					UFSHCD_ERROR_MASK)

/*Other attributes*/
#define VS_MPHYCFGUPDT		0xD085
#define VS_DEBUGOMC		0xD09E
#define VS_POWERSTATE		0xD083

/*
 * Data Link Layer Attributes
 */
#define DL_TC0TXFCTHRESHOLD 0x2040
#define DL_FC0PROTTIMEOUTVAL	0x2041
#define DL_TC0REPLAYTIMEOUTVAL	0x2042
#define DL_AFC0REQTIMEOUTVAL	0x2043
#define DL_AFC0CREDITTHRESHOLD	0x2044
#define DL_TC0OUTACKTHRESHOLD	0x2045
#define DL_TC1TXFCTHRESHOLD 0x2060
#define DL_FC1PROTTIMEOUTVAL	0x2061
#define DL_TC1REPLAYTIMEOUTVAL	0x2062
#define DL_AFC1REQTIMEOUTVAL	0x2063
#define DL_AFC1CREDITTHRESHOLD	0x2064
#define DL_TC1OUTACKTHRESHOLD	0x2065
#define DL_TXPREEMPTIONCAP	0x2000
#define DL_TC0TXMAXSDUSIZE	0x2001
#define DL_TC0RXINITCREDITVAL	0x2002
#define DL_TC0TXBUFFERSIZE	0x2005
#define DL_PEERTC0PRESENT	0x2046
#define DL_PEERTC0RXINITCREVAL	0x2047
#define DL_TC1TXMAXSDUSIZE	0x2003
#define DL_TC1RXINITCREDITVAL	0x2004
#define DL_TC1TXBUFFERSIZE	0x2006
#define DL_PEERTC1PRESENT	0x2066
#define DL_PEERTC1RXINITCREVAL	0x2067

#define DL_FC0ProtectionTimeOutVal_Default      8191
#define DL_TC0ReplayTimeOutVal_Default          65535
#define DL_AFC0ReqTimeOutVal_Default            32767
#define DL_FC1ProtectionTimeOutVal_Default      8191
#define DL_TC1ReplayTimeOutVal_Default          65535
#define DL_AFC1ReqTimeOutVal_Default            32767

#define DME_LocalFC0ProtectionTimeOutVal        0xD041
#define DME_LocalTC0ReplayTimeOutVal            0xD042
#define DME_LocalAFC0ReqTimeOutVal              0xD043

/*
 * Network Layer Attributes
 */
#define N_DEVICEID		0x3000
#define N_DEVICEID_VALID	0x3001
#define N_TC0TXMAXSDUSIZE	0x3020
#define N_TC1TXMAXSDUSIZE	0x3021

/*
 * Transport Layer Attributes
 */
#define T_NUMCPORTS		0x4000
#define T_NUMTESTFEATURES	0x4001
#define T_CONNECTIONSTATE	0x4020
#define T_PEERDEVICEID		0x4021
#define T_PEERCPORTID		0x4022
#define T_TRAFFICCLASS		0x4023
#define T_PROTOCOLID		0x4024
#define T_CPORTFLAGS		0x4025
#define T_TXTOKENVALUE		0x4026
#define T_RXTOKENVALUE		0x4027
#define T_LOCALBUFFERSPACE	0x4028
#define T_PEERBUFFERSPACE	0x4029
#define T_CREDITSTOSEND		0x402A
#define T_CPORTMODE		0x402B
#define T_TC0TXMAXSDUSIZE	0x4060
#define T_TC1TXMAXSDUSIZE	0x4061

enum {
	TASK_REQ_UPIU_SIZE_DWORDS	= 8,
	TASK_RSP_UPIU_SIZE_DWORDS	= 8,
	ALIGNED_UPIU_SIZE		= 128,
};

struct ufshcd_sg_entry {
	uint32_t	base_addr;
	uint32_t	upper_addr;
	uint32_t	reserved;
	uint32_t	size;
};

/**
 * struct utp_transfer_cmd_desc - UFS Command Descriptor structure
 * @command_upiu: Command UPIU Frame address
 * @response_upiu: Response UPIU Frame address
 * @prd_table: Physical Region Descriptor
 */
#if defined(AHB_PATH)
#define SG_ALL 1
#else
#define SG_ALL 1024
#endif
struct utp_transfer_cmd_desc {
	uint8_t command_upiu[ALIGNED_UPIU_SIZE];
	uint8_t response_upiu[ALIGNED_UPIU_SIZE];
	struct ufshcd_sg_entry	  prd_table[SG_ALL];
};

struct request_desc_header {
	uint32_t dword_0;
	uint32_t dword_1;
	uint32_t dword_2;
	uint32_t dword_3;
};

/**
 * struct utp_transfer_req_desc - UTRD structure
 * @header: UTRD header DW-0 to DW-3
 * @command_desc_base_addr_lo: UCD base address low DW-4
 * @command_desc_base_addr_hi: UCD base address high DW-5
 * @response_upiu_length: response UPIU length DW-6
 * @response_upiu_offset: response UPIU offset DW-6
 * @prd_table_length: Physical region descriptor length DW-7
 * @prd_table_offset: Physical region descriptor offset DW-7
 */
struct utp_transfer_req_desc {
	/* DW 0-3 */
	struct request_desc_header header;

	/* DW 4-5*/
	uint32_t  command_desc_base_addr_lo;
	uint32_t  command_desc_base_addr_hi;

	/* DW 6 */
	uint16_t  response_upiu_length;
	uint16_t  response_upiu_offset;

	/* DW 7 */
	uint16_t  prd_table_length;
	uint16_t  prd_table_offset;
};

struct utp_task_req_desc {
	/* DW 0-3 */
	struct request_desc_header header;

	/* DW 4-11 - Task request UPIU structure */
	struct {
		struct utp_upiu_header	req_header;
		uint32_t		  input_param1;
		uint32_t		  input_param2;
		uint32_t		  input_param3;
		uint32_t		  __reserved1[2];
	} upiu_req;

	/* DW 12-19 - Task Management Response UPIU structure */
	struct {
		struct utp_upiu_header	rsp_header;
		uint32_t		  output_param1;
		uint32_t		  output_param2;
		uint32_t		  __reserved2[3];
	} upiu_rsp;
};

/* UPIU Query request function */
enum {
	UPIU_QUERY_FUNC_STANDARD_READ_REQUEST			= 0x01,
	UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST			= 0x81,
};

/* Offset of the response code in the UPIU header */
#define UPIU_RSP_CODE_OFFSET		8

enum {
	MASK_SCSI_STATUS		= 0xFF,
	MASK_TASK_RESPONSE				= 0xFF00,
	MASK_RSP_UPIU_RESULT			= 0xFFFF,
	MASK_QUERY_DATA_SEG_LEN			= 0xFFFF,
	MASK_RSP_UPIU_DATA_SEG_LEN	= 0xFFFF,
	MASK_RSP_EXCEPTION_EVENT		= 0x10000,
	MASK_TM_SERVICE_RESP		= 0xFF,
	MASK_TM_FUNC			= 0xFF,
};

enum flag_idn {
	QUERY_FLAG_IDN_FDEVICEINIT			= 0x01,
	QUERY_FLAG_IDN_PERMANENT_WPE			= 0x02,
	QUERY_FLAG_IDN_PWR_ON_WPE			= 0x03,
	QUERY_FLAG_IDN_BKOPS_EN				= 0x04,
	QUERY_FLAG_IDN_LIFE_SPAN_MODE_ENABLE		= 0x05,
	QUERY_FLAG_IDN_PURGE_ENABLE			= 0x06,
	QUERY_FLAG_IDN_RESERVED2			= 0x07,
	QUERY_FLAG_IDN_FPHYRESOURCEREMOVAL		= 0x08,
	QUERY_FLAG_IDN_BUSY_RTC				= 0x09,
	QUERY_FLAG_IDN_RESERVED3			= 0x0A,
	QUERY_FLAG_IDN_PERMANENTLY_DISABLE_FW_UPDATE	= 0x0B,
};

/* Attribute idn for Query requests */
enum attr_idn {
	QUERY_ATTR_IDN_BOOT_LU_EN		= 0x00,
	QUERY_ATTR_IDN_RESERVED			= 0x01,
	QUERY_ATTR_IDN_POWER_MODE		= 0x02,
	QUERY_ATTR_IDN_ACTIVE_ICC_LVL		= 0x03,
	QUERY_ATTR_IDN_OOO_DATA_EN		= 0x04,
	QUERY_ATTR_IDN_BKOPS_STATUS		= 0x05,
	QUERY_ATTR_IDN_PURGE_STATUS		= 0x06,
	QUERY_ATTR_IDN_MAX_DATA_IN		= 0x07,
	QUERY_ATTR_IDN_MAX_DATA_OUT		= 0x08,
	QUERY_ATTR_IDN_DYN_CAP_NEEDED		= 0x09,
	QUERY_ATTR_IDN_REF_CLK_FREQ		= 0x0A,
	QUERY_ATTR_IDN_CONF_DESC_LOCK		= 0x0B,
	QUERY_ATTR_IDN_MAX_NUM_OF_RTT		= 0x0C,
	QUERY_ATTR_IDN_EE_CONTROL		= 0x0D,
	QUERY_ATTR_IDN_EE_STATUS		= 0x0E,
	QUERY_ATTR_IDN_SECONDS_PASSED		= 0x0F,
	QUERY_ATTR_IDN_CNTX_CONF		= 0x10,
	QUERY_ATTR_IDN_CORR_PRG_BLK_NUM		= 0x11,
	QUERY_ATTR_IDN_RESERVED2		= 0x12,
	QUERY_ATTR_IDN_RESERVED3		= 0x13,
	QUERY_ATTR_IDN_FFU_STATUS		= 0x14,
	QUERY_ATTR_IDN_PSA_STATE		= 0x15,
	QUERY_ATTR_IDN_PSA_DATA_SIZE		= 0x16,
};

/* Descriptor idn for Query requests */
enum desc_idn {
	QUERY_DESC_IDN_DEVICE		= 0x0,
	QUERY_DESC_IDN_CONFIGURATION	= 0x1,
	QUERY_DESC_IDN_UNIT		= 0x2,
	QUERY_DESC_IDN_RFU_0		= 0x3,
	QUERY_DESC_IDN_INTERCONNECT = 0x4,
	QUERY_DESC_IDN_STRING		= 0x5,
	QUERY_DESC_IDN_RFU_1		= 0x6,
	QUERY_DESC_IDN_GEOMETRY		= 0x7,
	QUERY_DESC_IDN_POWER		= 0x8,
	QUERY_DESC_IDN_HEALTH			= 0x9,
	QUERY_DESC_IDN_MAX,
};

enum desc_header_offset {
	QUERY_DESC_LENGTH_OFFSET	= 0x00,
	QUERY_DESC_DESC_TYPE_OFFSET = 0x01,
};

/* UTP QUERY Transaction Specific Fields OpCode */
enum query_opcode {
	UPIU_QUERY_OPCODE_NOP		= 0x0,
	UPIU_QUERY_OPCODE_READ_DESC = 0x1,
	UPIU_QUERY_OPCODE_WRITE_DESC	= 0x2,
	UPIU_QUERY_OPCODE_READ_ATTR = 0x3,
	UPIU_QUERY_OPCODE_WRITE_ATTR	= 0x4,
	UPIU_QUERY_OPCODE_READ_FLAG = 0x5,
	UPIU_QUERY_OPCODE_SET_FLAG	= 0x6,
	UPIU_QUERY_OPCODE_CLEAR_FLAG	= 0x7,
	UPIU_QUERY_OPCODE_TOGGLE_FLAG	= 0x8,
};

/* Query response result code */
enum {
	QUERY_RESULT_SUCCESS					= 0x00,
	QUERY_RESULT_NOT_READABLE				= 0xF6,
	QUERY_RESULT_NOT_WRITEABLE				= 0xF7,
	QUERY_RESULT_ALREADY_WRITTEN			= 0xF8,
	QUERY_RESULT_INVALID_LENGTH				= 0xF9,
	QUERY_RESULT_INVALID_VALUE				= 0xFA,
	QUERY_RESULT_INVALID_SELECTOR			= 0xFB,
	QUERY_RESULT_INVALID_INDEX				= 0xFC,
	QUERY_RESULT_INVALID_IDN				= 0xFD,
	QUERY_RESULT_INVALID_OPCODE				= 0xFE,
	QUERY_RESULT_GENERAL_FAILURE			= 0xFF,
};

struct ufs_pa_layer_attr {
	uint32_t gear_rx;
	uint32_t gear_tx;
	uint32_t lane_rx;
	uint32_t lane_tx;
	uint32_t pwr_rx;
	uint32_t pwr_tx;
	uint32_t hs_rate;
};

struct ufs_pwr_mode_info {
	bool is_valid;
	struct ufs_pa_layer_attr info;
};

enum ufs_desc_def_size {
	QUERY_DESC_DEVICE_DEF_SIZE		= 0x40,
	QUERY_DESC_CONFIGURATION_DEF_SIZE	= 0x90,
	QUERY_DESC_UNIT_DEF_SIZE		= 0x23,
	QUERY_DESC_INTERCONNECT_DEF_SIZE	= 0x06,
	QUERY_DESC_GEOMETRY_DEF_SIZE		= 0x48,
	QUERY_DESC_POWER_DEF_SIZE		= 0x62,
	QUERY_DESC_HEALTH_DEF_SIZE		= 0x25,
};

struct ufs_desc_size {
	int dev_desc;
	int pwr_desc;
	int geom_desc;
	int interc_desc;
	int unit_desc;
	int conf_desc;
	int hlth_desc;
};

/* Transfer request command type */
enum {
	UTP_CMD_TYPE_SCSI		= 0x0,
	UTP_CMD_TYPE_UFS		= 0x1,
	UTP_CMD_TYPE_DEV_MANAGE		= 0x2,
};

/* To accommodate UFS2.0 required Command type */
enum {
	UTP_CMD_TYPE_UFS_STORAGE	= 0x1,
};

enum {
	UTP_SCSI_COMMAND		= 0x00000000,
	UTP_NATIVE_UFS_COMMAND		= 0x10000000,
	UTP_DEVICE_MANAGEMENT_FUNCTION	= 0x20000000,
	UTP_REQ_DESC_INT_CMD		= 0x01000000,
	UTP_REQ_DESC_CRYPTO_ENABLE_CMD	= 0x00800000,
};

/* UTP Transfer Request Data Direction (DD) */
enum {
	UTP_NO_DATA_TRANSFER	= 0x00000000,
	UTP_HOST_TO_DEVICE	= 0x02000000,
	UTP_DEVICE_TO_HOST	= 0x04000000,
};

/* Overall command status values */
enum {
	OCS_SUCCESS			= 0x0,
	OCS_INVALID_CMD_TABLE_ATTR	= 0x1,
	OCS_INVALID_PRDT_ATTR		= 0x2,
	OCS_MISMATCH_DATA_BUF_SIZE	= 0x3,
	OCS_MISMATCH_RESP_UPIU_SIZE = 0x4,
	OCS_PEER_COMM_FAILURE		= 0x5,
	OCS_ABORTED			= 0x6,
	OCS_FATAL_ERROR			= 0x7,
	OCS_DEVICE_FATAL_ERROR		= 0x8,
	OCS_INVALID_CRYPTO_CONFIG	= 0x9,
	OCS_GENERAL_CRYPTO_ERROR	= 0xA,
	OCS_INVALID_COMMAND_STATUS	= 0x0F,
	MASK_OCS			= 0x0F,
};

enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

/* UTP Transfer Request Command Type (CT) */
enum {
	UPIU_COMMAND_SET_TYPE_SCSI	= 0x0,
	UPIU_COMMAND_SET_TYPE_UFS	= 0x1,
	UPIU_COMMAND_SET_TYPE_QUERY = 0x2,
};

/* UTP Transfer Request Command Offset */
#define UPIU_COMMAND_TYPE_OFFSET	28

/* Offset of the response code in the UPIU header */
#define UPIU_RSP_CODE_OFFSET		8

#define UFS_CDB_SIZE	16

struct scatterlist {
	unsigned long	page_link;
	unsigned int	offset;
	unsigned int	length;
	unsigned long	dma_address;
#ifdef CONFIG_NEED_SG_DMA_LENGTH
	unsigned int	dma_length;
#endif
};

struct scsi_data_buffer {
	struct scatterlist sg[SG_ALL];
	uint32_t length;
};

struct scsi_device {
	uint64_t lun;
};

struct scsi_cmd {
	int sc_data_direction;
	struct scsi_device *device;

	struct scsi_data_buffer sdb;
	uint32_t length;
	//struct ufshcd_sg_entry *sg;
	uint32_t num_sg;

	uint8_t *cmnd;
	uint8_t cdb[UFS_CDB_SIZE];
};

/*
 *		SCSI opcodes
 */

#define TEST_UNIT_READY		  0x00
#define REZERO_UNIT			  0x01
#define REQUEST_SENSE		  0x03
#define FORMAT_UNIT			  0x04
#define READ_BLOCK_LIMITS	  0x05
#define REASSIGN_BLOCKS		  0x07
#define INITIALIZE_ELEMENT_STATUS 0x07
#define READ_6				  0x08
#define WRITE_6				  0x0a
#define SEEK_6				  0x0b
#define READ_REVERSE		  0x0f
#define WRITE_FILEMARKS		  0x10
#define SPACE				  0x11
#define INQUIRY				  0x12
#define RECOVER_BUFFERED_DATA 0x14
#define MODE_SELECT			  0x15
#define RESERVE				  0x16
#define RELEASE				  0x17
#define COPY				  0x18
#define ERASE				  0x19
#define MODE_SENSE			  0x1a
#define START_STOP			  0x1b
#define RECEIVE_DIAGNOSTIC	  0x1c
#define SEND_DIAGNOSTIC		  0x1d
#define ALLOW_MEDIUM_REMOVAL  0x1e

#define READ_FORMAT_CAPACITIES 0x23
#define SET_WINDOW			  0x24
#define READ_CAPACITY		  0x25
#define READ_10				  0x28
#define WRITE_10			  0x2a
#define SEEK_10				  0x2b
#define POSITION_TO_ELEMENT   0x2b
#define WRITE_VERIFY		  0x2e
#define VERIFY				  0x2f
#define SEARCH_HIGH			  0x30
#define SEARCH_EQUAL		  0x31
#define SEARCH_LOW			  0x32
#define SET_LIMITS			  0x33
#define PRE_FETCH			  0x34
#define READ_POSITION		  0x34
#define SYNCHRONIZE_CACHE	  0x35
#define LOCK_UNLOCK_CACHE	  0x36

#define REPORT_LUNS			  0xa0

/* Well known logical unit id in LUN field of UPIU */
enum {
	UFS_UPIU_REPORT_LUNS_WLUN	= 0x81,
	UFS_UPIU_UFS_DEVICE_WLUN	= 0xD0,
	UFS_UPIU_BOOT_WLUN		= 0xB0,
	UFS_UPIU_RPMB_WLUN		= 0xC4,
};

/* Device descriptor parameters offsets in bytes*/
enum device_desc_param {
	DEVICE_DESC_PARAM_LEN			= 0x0,
	DEVICE_DESC_PARAM_TYPE			= 0x1,
	DEVICE_DESC_PARAM_DEVICE_TYPE		= 0x2,
	DEVICE_DESC_PARAM_DEVICE_CLASS		= 0x3,
	DEVICE_DESC_PARAM_DEVICE_SUB_CLASS	= 0x4,
	DEVICE_DESC_PARAM_PRTCL			= 0x5,
	DEVICE_DESC_PARAM_NUM_LU		= 0x6,
	DEVICE_DESC_PARAM_NUM_WLU		= 0x7,
	DEVICE_DESC_PARAM_BOOT_ENBL		= 0x8,
	DEVICE_DESC_PARAM_DESC_ACCSS_ENBL	= 0x9,
	DEVICE_DESC_PARAM_INIT_PWR_MODE		= 0xA,
	DEVICE_DESC_PARAM_HIGH_PR_LUN		= 0xB,
	DEVICE_DESC_PARAM_SEC_RMV_TYPE		= 0xC,
	DEVICE_DESC_PARAM_SEC_LU		= 0xD,
	DEVICE_DESC_PARAM_BKOP_TERM_LT		= 0xE,
	DEVICE_DESC_PARAM_ACTVE_ICC_LVL		= 0xF,
	DEVICE_DESC_PARAM_SPEC_VER		= 0x10,
	DEVICE_DESC_PARAM_MANF_DATE		= 0x12,
	DEVICE_DESC_PARAM_MANF_NAME		= 0x14,
	DEVICE_DESC_PARAM_PRDCT_NAME		= 0x15,
	DEVICE_DESC_PARAM_SN			= 0x16,
	DEVICE_DESC_PARAM_OEM_ID		= 0x17,
	DEVICE_DESC_PARAM_MANF_ID		= 0x18,
	DEVICE_DESC_PARAM_UD_OFFSET		= 0x1A,
	DEVICE_DESC_PARAM_UD_LEN		= 0x1B,
	DEVICE_DESC_PARAM_RTT_CAP		= 0x1C,
	DEVICE_DESC_PARAM_FRQ_RTC		= 0x1D,
	DEVICE_DESC_PARAM_UFS_FEAT		= 0x1F,
	DEVICE_DESC_PARAM_FFU_TMT		= 0x20,
	DEVICE_DESC_PARAM_Q_DPTH		= 0x21,
	DEVICE_DESC_PARAM_DEV_VER		= 0x22,
	DEVICE_DESC_PARAM_NUM_SEC_WPA		= 0x24,
	DEVICE_DESC_PARAM_PSA_MAX_DATA		= 0x25,
	DEVICE_DESC_PARAM_PSA_TMT		= 0x29,
	DEVICE_DESC_PARAM_PRDCT_REV		= 0x2A,
};

/* Unit descriptor parameters offsets in bytes*/
enum unit_desc_param {
	UNIT_DESC_PARAM_LEN			= 0x0,
	UNIT_DESC_PARAM_TYPE			= 0x1,
	UNIT_DESC_PARAM_UNIT_INDEX		= 0x2,
	UNIT_DESC_PARAM_LU_ENABLE		= 0x3,
	UNIT_DESC_PARAM_BOOT_LUN_ID		= 0x4,
	UNIT_DESC_PARAM_LU_WR_PROTECT		= 0x5,
	UNIT_DESC_PARAM_LU_Q_DEPTH		= 0x6,
	UNIT_DESC_PARAM_PSA_SENSITIVE		= 0x7,
	UNIT_DESC_PARAM_MEM_TYPE		= 0x8,
	UNIT_DESC_PARAM_DATA_RELIABILITY	= 0x9,
	UNIT_DESC_PARAM_LOGICAL_BLK_SIZE	= 0xA,
	UNIT_DESC_PARAM_LOGICAL_BLK_COUNT	= 0xB,
	UNIT_DESC_PARAM_ERASE_BLK_SIZE		= 0x13,
	UNIT_DESC_PARAM_PROVISIONING_TYPE	= 0x17,
	UNIT_DESC_PARAM_PHY_MEM_RSRC_CNT	= 0x18,
	UNIT_DESC_PARAM_CTX_CAPABILITIES	= 0x20,
	UNIT_DESC_PARAM_LARGE_UNIT_SIZE_M1	= 0x22,
	UNIT_DESC_PARAM_HPB_LU_MAX_ACTIVE_RGNS	= 0x23,
	UNIT_DESC_PARAM_HPB_PIN_RGN_START_OFF	= 0x25,
	UNIT_DESC_PARAM_HPB_NUM_PIN_RGNS	= 0x27,
	UNIT_DESC_PARAM_WB_BUF_ALLOC_UNITS	= 0x29,
};

#define MAX_MODEL_LEN 16

/**
 * ufs_dev_desc - ufs device details from the device descriptor
 *
 * @wmanufacturerid: card details
 * @model: card model
 */
struct ufs_dev_desc {
	uint16_t wmanufacturerid;
	char model[MAX_MODEL_LEN + 1];
};

struct completion {
	int done;
	int wait;
};

struct ufs_hba {
	uint32_t mmio_base;
	struct uic_command *active_uic_cmd;
	uint32_t reserved_slot;
	uint32_t task_tag[32];

	uint32_t caps;
	uint32_t version;
	int nutrs;
	int nutmrs;
	int lun;

	uint32_t errors;
	uint32_t uic_error;

	struct utp_transfer_cmd_desc *ucdl_base_addr;
	struct utp_transfer_req_desc *utrdl_base_addr;
	struct utp_task_req_desc *utmrdl_base_addr;

	struct utp_upiu_req *ucd_req_ptr;
	struct utp_upiu_rsp *ucd_rsp_ptr;
	struct ufshcd_sg_entry *ucd_prdt_ptr;

	struct ufs_dev_cmd dev_cmd;

	struct ufs_desc_size	desc_size;
	struct ufs_pa_layer_attr pwr_info;
	struct ufs_pwr_mode_info max_pwr_info;

	int transfer_complete;
	//struct completion *uic_async_done;
	int uic_async_done;
	unsigned long outstanding_reqs;

	unsigned int quirks;	/* Deviations from standard UFSHCI spec. */
};

static inline bool ufshcd_is_intr_aggr_allowed(struct ufs_hba *hba)
{
	return (hba->caps & UFSHCD_CAP_INTR_AGGR) &&
		!(hba->quirks & UFSHCD_QUIRK_BROKEN_INTR_AGGR);
}

int ufs_init(int id);
int ufs_read(uint32_t *dst, uint32_t src, uint32_t len);
uint32_t fit_scsi_load_read(struct fit_load_info *load, uint32_t sector,
			       uint32_t count, void *buf);
#endif
