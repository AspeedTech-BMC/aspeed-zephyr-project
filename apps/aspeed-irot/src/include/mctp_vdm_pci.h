#pragma once
#include <stdint.h>
#include <mctp.h>

/* ASPEED Technology PCI vendor ID, transmitted big-endian in the MCTP VDM-PCI header */
#define ASPEED_PCI_VENDOR_ID 0x1A03

struct mctp_vdm_pci_req {
	uint8_t msg_type;
	uint8_t pci_vnd_id[2];
	uint8_t vdm[0];
};

#if defined(CONFIG_COMPOSITE_EAT)
uint8_t mctp_vdm_pci_cmd_handler(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_params ext_params);
uint8_t mctp_vdm_pci_generate_eat_handle(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_params ext_params);
#endif
