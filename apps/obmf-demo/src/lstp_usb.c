/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/usb_ch9.h>
#include <string.h>

#include "lstp_usb.h"
#include "lstp_router.h"

LOG_MODULE_REGISTER(lstp_usb, LOG_LEVEL_DBG);

#define LSTP_USB_CLASS_SUBCLASS 0x00
#define LSTP_USB_CLASS_PROTOCOL 0x00
/* Base vendor specific class */
#define LSTP_USB_BCC_VENDOR 0xFF

struct usb_lstp_config {
	struct usb_if_descriptor if0;
	struct usb_ep_descriptor if0_in_ep;
	struct usb_ep_descriptor if0_out_ep;
} __packed;

USBD_CLASS_DESCR_DEFINE(primary, 0) struct usb_lstp_config lstp_cfg = {
	.if0 = {
		.bLength = sizeof(struct usb_if_descriptor),
		.bDescriptorType = USB_DESC_INTERFACE,
		.bInterfaceNumber = 0,
		.bAlternateSetting = 0,
		.bNumEndpoints = 2,
		.bInterfaceClass = LSTP_USB_BCC_VENDOR,
		.bInterfaceSubClass = 0x3f, // for nv lstp driver
		.bInterfaceProtocol = 0x01, // for nv lstp driver
		.iInterface = 0,
	},
	.if0_in_ep = {
		.bLength = sizeof(struct usb_ep_descriptor),
		.bDescriptorType = USB_DESC_ENDPOINT,
		.bEndpointAddress = LSTP_IN_EP_ADDR,
		.bmAttributes = USB_DC_EP_BULK,
		.wMaxPacketSize = LSTP_USB_MAX_EP_BUFFER_SIZE,
		.bInterval = 0x00,
	},
	.if0_out_ep = {
		.bLength = sizeof(struct usb_ep_descriptor),
		.bDescriptorType = USB_DESC_ENDPOINT,
		.bEndpointAddress = LSTP_OUT_EP_ADDR,
		.bmAttributes = USB_DC_EP_BULK,
		.wMaxPacketSize = LSTP_USB_MAX_EP_BUFFER_SIZE,
		.bInterval = 0x00,
	},
};

static struct {
	uint8_t rx_buf[1024]; /* Sufficient for LSTP_MSG_SIZE */
	size_t rx_len;
} usb_dev_data;

static void lstp_usb_bulk_out(uint8_t ep, enum usb_dc_ep_cb_status_code ep_status)
{
	uint32_t bytes_read;

	usb_ep_read_wait(ep, usb_dev_data.rx_buf, sizeof(usb_dev_data.rx_buf), &bytes_read);
	usb_ep_read_continue(ep);

	LOG_HEXDUMP_DBG(usb_dev_data.rx_buf, (bytes_read > 64 ? 64 : bytes_read), "USB RX Packets");

	if (bytes_read > 0) {
		/* Route directly to LSTP core */
		lstp_router_receive(usb_dev_data.rx_buf, bytes_read);
	}
}

static void lstp_usb_bulk_in(uint8_t ep, enum usb_dc_ep_cb_status_code ep_status)
{
	LOG_DBG("Bulk IN transaction complete on EP 0x%02x", ep);
}

/* Endpoint configuration */
static struct usb_ep_cfg_data lstp_ep_data[] = {
	{
		.ep_cb = lstp_usb_bulk_out,
		.ep_addr = LSTP_OUT_EP_ADDR
	},
	{
		.ep_cb = lstp_usb_bulk_in,
		.ep_addr = LSTP_IN_EP_ADDR
	}
};

static void lstp_interface_config(struct usb_desc_header *head, uint8_t bInterfaceNumber)
{
	ARG_UNUSED(head);
	lstp_cfg.if0.bInterfaceNumber = bInterfaceNumber;
}

static void lstp_usb_status_cb(struct usb_cfg_data *cfg,
		enum usb_dc_status_code status,
		const uint8_t *param)
{
	ARG_UNUSED(param);
	ARG_UNUSED(cfg);

	switch (status) {
		case USB_DC_ERROR:
			LOG_ERR("USB device error");
			break;
		case USB_DC_RESET:
			LOG_INF("USB device reset");
			break;
		case USB_DC_CONNECTED:
			LOG_INF("USB device connected");
			break;
		case USB_DC_CONFIGURED:
			LOG_INF("USB device configured");
			break;
		case USB_DC_DISCONNECTED:
			LOG_INF("USB device disconnected");
			break;
		default:
			break;
	}
}

static int lstp_usb_class_handle_req(struct usb_setup_packet *pSetup, int32_t *len, uint8_t **data)
{
	/* Let the USB stack handle standard/vendor requests we don't care about */
	return -ENOTSUP;
}

static int lstp_usb_vendor_handle_req(struct usb_setup_packet *pSetup, int32_t *len, uint8_t **data)
{
	/* Let the USB stack handle standard/vendor requests we don't care about */
	return -ENOTSUP;
}

/* Configuration of the USB Device send to the USB Driver */
USBD_DEFINE_CFG_DATA(lstp_usb_config) = {
	.usb_device_description = NULL,
	.interface_config = lstp_interface_config,
	.interface_descriptor = &lstp_cfg.if0,
	.cb_usb_status = lstp_usb_status_cb,
	.interface = {
		.class_handler = lstp_usb_class_handle_req,
		.custom_handler = NULL,
		.vendor_handler = lstp_usb_vendor_handle_req,
	},
	.num_endpoints = ARRAY_SIZE(lstp_ep_data),
	.endpoint = lstp_ep_data
};

int lstp_usb_init(void)
{
	LOG_INF("Initializing LSTP USB Transport");
	int ret = usb_enable(NULL);
	if (ret < 0) {
		LOG_ERR("Failed to enable USB: %d", ret);
		return ret;
	}
	return 0;
}

int lstp_usb_send(const uint8_t *data, size_t len)
{
	uint32_t bytes_written;
	int ret;

	LOG_HEXDUMP_DBG(data, (len > 64 ? 64 : len), "USB TX Packets");

	ret = usb_write(LSTP_IN_EP_ADDR, data, len, &bytes_written);
	if (ret < 0) {
		LOG_ERR("USB write failed: %d", ret);
		return ret;
	}

	if (bytes_written != len) {
		LOG_WRN("USB short write: %u of %zu", bytes_written, len);
	}

	return 0;
}
