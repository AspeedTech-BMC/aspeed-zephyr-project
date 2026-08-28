#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <mctp_vdm_pci.h>

LOG_MODULE_REGISTER(mctp_vdm_pci);


uint8_t mctp_vdm_pci_cmd_handler(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_params ext_params)
{
	if (!buf || len < sizeof(struct mctp_vdm_pci_req)) {

		return MCTP_ERROR;
	}
	struct mctp_vdm_pci_req *req = (struct mctp_vdm_pci_req *)buf;
	uint16_t pci_vnd_id = sys_get_be16(req->pci_vnd_id);

	LOG_HEXDUMP_INF(buf, len, "MCTP VDM PCI REQ");
	if (req->msg_type != MCTP_MSG_TYPE_VEN_DEF_PCI)
	{
		LOG_ERR("Unexpected MCTP message type 0x%02x", req->msg_type);
		return MCTP_ERROR;
	}


	if (pci_vnd_id != ASPEED_PCI_VENDOR_ID) {
		LOG_ERR("Unexpected PCI vendor ID 0x%04x", pci_vnd_id);
		return MCTP_ERROR;
	}

	return mctp_vdm_pci_generate_eat_handle(mctp_p, buf, len, ext_params);
}

