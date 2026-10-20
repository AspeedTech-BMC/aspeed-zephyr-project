/*
 * Copyright (c) 2024 Intel Corporation
 * Copyright 2025 NXP
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * libmctp binding for MCTP over USB (DMTF DSP0283), a USB device class on
 * the new USB device stack. Ported from Zephyr 4.x
 * include/zephyr/pmci/mctp/mctp_usb.h for this Zephyr 3.7 tree.
 */

#ifndef MCTP_MCTP_USB_H_
#define MCTP_MCTP_USB_H_

#include <zephyr/kernel.h>
#include <zephyr/sys/iterable_sections.h>
#include <libmctp.h>

/* MCTP class subclass options */
#define USBD_MCTP_SUBCLASS_MANAGEMENT_CONTROLLER   0
#define USBD_MCTP_SUBCLASS_MANAGED_DEVICE_ENDPOINT 0
#define USBD_MCTP_SUBCLASS_HOST_INTERFACE_ENDPOINT 1

/* MCTP class protocol options */
#define USBD_MCTP_PROTOCOL_1_X 1
#define USBD_MCTP_PROTOCOL_2_X 2

/* DSP0283 transfer header: DMTF ID (2 bytes), reserved, length */
#define MCTP_USB_HEADER_SIZE       4
/* The header's length byte counts the header too, so a transfer is <= 255 bytes */
#define MCTP_USB_MAX_PACKET_LENGTH 255
/* Largest MCTP packet (MCTP header included) one transfer can carry */
#define MCTP_USB_MAX_MCTP_PACKET   (MCTP_USB_MAX_PACKET_LENGTH - MCTP_USB_HEADER_SIZE)

struct mctp_usb_stats {
	/** MCTP packets received and handed to libmctp */
	uint32_t rx_pkts;
	/** Received packets dropped: bad length byte, or no packet buffer */
	uint32_t rx_drops;
	/**
	 * Times OUT was left unarmed (host NAKed) because the buffer pool ran
	 * dry. Updated outside the binding's lock, so read it with atomic_get().
	 */
	atomic_t rx_out_starved;
	/** MCTP packets queued on IN */
	uint32_t tx_pkts;
	/** Packets that could not be sent, and were dropped */
	uint32_t tx_errors;
};

struct mctp_binding_usb {
	/** @cond INTERNAL_HIDDEN */
	struct mctp_binding binding;
	struct usbd_class_data *usb_class_data;
	uint8_t tx_buf[MCTP_USB_HEADER_SIZE + MCTP_USB_MAX_PACKET_LENGTH];
	struct k_sem tx_lock;
	struct mctp_pktbuf *rx_pkt;
	uint8_t rx_data_idx;
	enum {
		STATE_WAIT_HDR_DMTF0,
		STATE_WAIT_HDR_DMTF1,
		STATE_WAIT_HDR_RSVD0,
		STATE_WAIT_HDR_LEN,
		STATE_DATA
	} rx_state;
	uint8_t tx_storage[MCTP_PKTBUF_SIZE(MCTP_USB_MAX_MCTP_PACKET)] PKTBUF_STORAGE_ALIGN;
	/* A packet failed: drop the rest of its message unsent */
	bool tx_drop;
	/** @endcond INTERNAL_HIDDEN */
	/**
	 * Held while received packets are handed to libmctp (in the system
	 * workqueue). libmctp is not thread-safe: hold it around every other
	 * call into the struct mctp this binding is registered with.
	 */
	struct k_mutex lock;
	/** Packet counters, maintained by the binding */
	struct mctp_usb_stats stats;
};

struct mctp_usb_class_inst {
	/** MCTP subclass used in the USB interface descriptor */
	uint8_t subclass;
	/** MCTP protocol version used in the USB interface descriptor */
	uint8_t mctp_protocol;
	/** Pointer to the associated MCTP USB bus binding */
	struct mctp_binding_usb *mctp_binding;
};

int mctp_usb_start(struct mctp_binding *binding);
int mctp_usb_tx(struct mctp_binding *binding, struct mctp_pktbuf *pkt);

/**
 * @brief Define an MCTP USB binding and its USB class instance.
 *
 * The number of instances must match CONFIG_MCTP_USB_CLASS_INSTANCES_COUNT.
 */
#define MCTP_USB_DEFINE(_name, _subclass, _protocol)						\
	struct mctp_binding_usb _name = {							\
		.binding = {									\
			.name = STRINGIFY(_name),						\
			.version = 1,								\
			.pkt_size = MCTP_USB_MAX_MCTP_PACKET,					\
			.pkt_header = 0,							\
			.pkt_trailer = 0,							\
			.tx_storage = _name.tx_storage,						\
			.start = mctp_usb_start,						\
			.tx = mctp_usb_tx							\
		},										\
		.usb_class_data = NULL,								\
		/* Static, so they are valid even if the binding never starts */		\
		.tx_lock = Z_SEM_INITIALIZER(_name.tx_lock, 1, 1),				\
		.lock = Z_MUTEX_INITIALIZER(_name.lock),					\
		.rx_pkt = NULL,									\
		.rx_data_idx = 0,								\
		.rx_state = STATE_WAIT_HDR_DMTF0						\
	};											\
												\
	const STRUCT_SECTION_ITERABLE(mctp_usb_class_inst, mctp_usb_class_inst_##_name) = {	\
		.subclass = _subclass,								\
		.mctp_protocol = _protocol,							\
		.mctp_binding = &_name,								\
	};

#endif /* MCTP_MCTP_USB_H_ */
