/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"
#include "SPDM/RequestCmd/SPDMRequestCmd.h"

#define SPDM_REQUESTER_STACK_SIZE 1024
#define SPDM_REQUESTER_PRIO 3

LOG_MODULE_REGISTER(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_send_request(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	int ret;

	if (context->send_recv != NULL) {
		ret = context->send_recv(ctx, req_msg, rsp_msg);
	} else {
		// TODO: timeout required!
		context->send(ctx, req_msg, sizeof(req_msg->header) + req_msg->buffer.size);

		size_t length;
		context->recv(ctx, rsp_msg, &length);
		ret = 0;
	}
	return ret;
}

K_FIFO_DEFINE(spdm_req_fifo);
void spdm_requester_main(void *a, void *b, void *c)
{
	struct spdm_context *target_list[8] = {0};

	do {
		struct spdm_req_fifo_data *attest_task = NULL;

		attest_task = k_fifo_get(&spdm_req_fifo, K_SECONDS(5));
		if (attest_task != NULL) {
			switch (attest_task->command) {
			case SPDM_REQ_ADD:
				for (size_t i = 0; i<8; ++i) {
					if (target_list[i] == NULL) {
#if 1
						target_list[i] = spdm_context_create();
						init_requester_context(target_list[i]);
#else
						target_list[i] = attest_task->spdm_ctx;
#endif
						break;
					}
				}
				break;
			case SPDM_REQ_REMOVE:
				for (size_t i = 0; i<8; ++i) {
					if (target_list[i] != NULL) {
#if 1
						spdm_context_release(target_list[i]);
#endif
						target_list[i] = NULL;
						break;
					}
				}
				break;
			default:
				LOG_ERR("Incorrect Requester Command=%d ctx=%p",
						attest_task->command, attest_task->spdm_ctx);
				break;
			}
			k_free(attest_task);
		} else {
			for (size_t i=0; i<8; ++i) {
				int ret;
				struct spdm_context *context = target_list[i];
				if (context == NULL)
					continue;

				// TODO: Get from context->connetion_data
				uint8_t bus=0, eid=0;

				/* VCA: Initiate Connection */
				ret = spdm_get_version(context);
				if (ret < 0) {
					LOG_ERR("SPDM[%d,%02x] GET_VERSION Failed", bus, eid);
					continue;
				}
				ret = spdm_get_capabilities(context);
				if (ret < 0) {
					LOG_ERR("SPDM[%d,%02x] GET_CAPABILITIES Failed", bus, eid);
					continue;
				}
				ret = spdm_negotiate_algorithms(context);
				if (ret < 0) {
					LOG_ERR("SPDM[%d,%02x] NEGOTIATE_ALGORITHMS Failed", bus, eid);
					continue;
				}

				/* Device identities */
				if (context->remote.capabilities.flags & SPDM_CERT_CAP) {
					ret = spdm_get_digests(context);

					for (uint8_t slot_id = 0; slot_id < 8; ++slot_id) {
						if (context->remote.certificate.slot_mask & (1 << slot_id)) {
							LOG_INF("Getting Certificate Slot[%d]", slot_id);
							ret = spdm_get_certificate(context, slot_id);
							if (ret != 0) {
								LOG_ERR("SPDM[%d,%02x] GET_CERTIFICATE Failed", bus, eid);
								break;
							}
						}
					}
					if (ret != 0) {
						continue;
					}
				} else {
					LOG_ERR("SPDM[%d,%02x] Device doesn't support GET_CERTIFICATE", bus, eid);
					continue;
				}

				/* Device Authentication */
				ret = spdm_challenge(context, 0x01, 0x00);
				if (ret < 0) {
					LOG_ERR("SPDM[%d,%02x] CHALLENGE Failed", bus, eid);
					continue;
				}

				/* Device Attestation */
				uint8_t number_of_blocks = 0, measurement_block, received_blocks = 0;
				bool signature_verified = false;

				spdm_context_reset_l1l2_hash(context);
				ret = spdm_get_measurements(context, 0,
						SPDM_MEASUREMENT_OPERATION_TOTAL_NUMBER, &number_of_blocks);
				/* Get 0x01 - 0xFE block */
				/* TODO: The block_id and measurement should comparing from AFM. Now we just scan it */
				ret = spdm_get_measurements(context, 0, 0x01, &measurement_block);
				ret = spdm_get_measurements(context, 0, 0x02, &measurement_block);
				ret = spdm_get_measurements(context, 0, 0x03, &measurement_block);
				ret = spdm_get_measurements(context, 0, 0x04, &measurement_block);
				ret = spdm_get_measurements(context, 0, 0x05, &measurement_block);
				ret = spdm_get_measurements(context, 0, 0xfd, &measurement_block);
				ret = spdm_get_measurements(context, SPDM_MEASUREMENT_REQ_ATTR_GEN_SIGNATURE,
						0xfe, &measurement_block);
				if (ret == 0) {
					signature_verified = true;
				}
				if (signature_verified == false) {
					/* Recovery the firmware ?? */
				}
			}
		}
#if 0
		LOG_HEXDUMP_INF(context->message_a.data, context->message_a.size, "Message A:");
		LOG_HEXDUMP_INF(context->message_b.data, context->message_b.size, "Message B:");
		LOG_HEXDUMP_INF(context->message_c.data, context->message_c.size, "Message C:");
#endif
	} while (1);
}
