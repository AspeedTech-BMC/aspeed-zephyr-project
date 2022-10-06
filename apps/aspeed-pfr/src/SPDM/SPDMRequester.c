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
						target_list[i] = attest_task->spdm_ctx;
						break;
					}
				}
				break;
			case SPDM_REQ_REMOVE:
				for (size_t i = 0; i<8; ++i) {
					if (target_list[i] == attest_task->spdm_ctx) {
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
				struct spdm_context *context = target_list[i];
				if (context == NULL)
					continue;

				spdm_get_version(context);
				spdm_get_capabilities(context);
				spdm_negotiate_algorithms(context);
				if (context->remote.capabilities.flags & SPDM_CERT_CAP) {
					spdm_get_digests(context);

					for (uint8_t slot_id = 0; slot_id < 8; ++slot_id) {
						if (context->remote.certificate.slot_mask & (1 << slot_id)) {
							LOG_ERR("Getting Certificate Slot[%d]", slot_id);
							spdm_get_certificate(context, slot_id);
							k_msleep(1000);
						}
					}
				}

				spdm_challenge(context, 0x01, 0x00);

				uint8_t number_of_blocks = 0, measurement_block;
				spdm_get_measurements(context, 0, SPDM_MEASUREMENT_OPERATION_TOTAL_NUMBER, &number_of_blocks);
				for (uint8_t block_id = 1; block_id <= number_of_blocks; ++block_id) {
					spdm_get_measurements(context, 0, block_id, &measurement_block);
				}
				spdm_get_measurements(context,
						SPDM_MEASUREMENT_REQ_ATTR_GEN_SIGNATURE,
						SPDM_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
						&measurement_block);
			}
		}
#if 0
		LOG_HEXDUMP_INF(context->message_a.data, context->message_a.size, "Message A:");
		LOG_HEXDUMP_INF(context->message_b.data, context->message_b.size, "Message B:");
		LOG_HEXDUMP_INF(context->message_c.data, context->message_c.size, "Message C:");
#endif
	} while (1);
}
