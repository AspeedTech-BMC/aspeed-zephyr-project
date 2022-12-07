/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <portability/cmsis_os2.h>

#include "SPDM/SPDMCommon.h"
#include "SPDM/RequestCmd/SPDMRequestCmd.h"

#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "include/SmbusMailBoxCom.h"
#include "mctp/mctp_base_protocol.h"
#include "AspeedStateMachine/AspeedStateMachine.h"

#define SPDM_REQUESTER_STACK_SIZE 1024
#define SPDM_REQUESTER_PRIO 3

LOG_MODULE_REGISTER(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

static void spdm_attester_tick(struct k_timer *timeer);

osEventFlagsId_t spdm_attester_event;
K_TIMER_DEFINE(spdm_attester_timer, spdm_attester_tick, NULL);

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

enum ATTEST_RESULT {
	ATTEST_SUCCEEDED,
	ATTEST_FAILED_VCA = -1,
	ATTEST_FAILED_DIGEST = -2,
	ATTEST_FAILED_CERTIFICATE = -3,
	ATTEST_FAILED_CHALLENGE_AUTH = -4,
	ATTEST_FAILED_MEASUREMENTS_MISMATCH = -5,
};

int spdm_attest_device(void *ctx, AFM_DEVICE_STRUCTURE *afm_body) {
	int ret = 0;
	struct spdm_context *context = (struct spdm_context *)ctx;

	do {
		if (context == NULL)
			break;

		// TODO: Get from context->connetion_data
		uint8_t bus=0, eid=0;

		/* VCA: Initiate Connection */
		ret = spdm_get_version(context);
		if (ret < 0) {
			LOG_ERR("SPDM[%d,%02x] GET_VERSION Failed", bus, eid);
			ret = ATTEST_FAILED_VCA;
			break;
		}
		ret = spdm_get_capabilities(context);
		if (ret < 0) {
			LOG_ERR("SPDM[%d,%02x] GET_CAPABILITIES Failed", bus, eid);
			ret = ATTEST_FAILED_VCA;
			break;
		}
		ret = spdm_negotiate_algorithms(context);
		if (ret < 0) {
			LOG_ERR("SPDM[%d,%02x] NEGOTIATE_ALGORITHMS Failed", bus, eid);
			ret = ATTEST_FAILED_VCA;
			break;
		}

		/* Device identities */
		if (context->remote.capabilities.flags & SPDM_CERT_CAP) {
			ret = spdm_get_digests(context);
			if (ret != 0) {
				ret = ATTEST_FAILED_DIGEST;
				break;
			}

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
				ret = ATTEST_FAILED_CERTIFICATE;
				break;
			}
		} else {
			LOG_ERR("SPDM[%d,%02x] Device doesn't support GET_CERTIFICATE", bus, eid);
			break;
		}

		/* Device Authentication */
		ret = spdm_challenge(context, 0x01, 0x00);
		if (ret < 0) {
			LOG_ERR("SPDM[%d,%02x] CHALLENGE Failed", bus, eid);
			ret = ATTEST_FAILED_CHALLENGE_AUTH;
			break;
		}

		/* Device Attestation */
		uint8_t number_of_blocks = 0, measurement_block, received_blocks = 0;
		bool signature_verified = false;

		spdm_context_reset_l1l2_hash(context);
		ret = spdm_get_measurements(context, 0,
				SPDM_MEASUREMENT_OPERATION_TOTAL_NUMBER, &number_of_blocks, NULL);

		if (ret != 0 || number_of_blocks != afm_body->TotalMeasurements) {
			LOG_ERR("AFM expecting %d but got %d measurements",
					afm_body->TotalMeasurements, number_of_blocks);

			ret = ATTEST_FAILED_MEASUREMENTS_MISMATCH;
			break;
		}

		uint8_t afm_index = 0;
		uint8_t meas_index = 0;
		AFM_DEVICE_MEASUREMENT_VALUE *possible_measure = afm_body->Measurements;
		uint8_t request_attribute = 0;
		if (context->remote.capabilities.flags & SPDM_MEAS_CAP_SIG) {
			request_attribute = SPDM_MEASUREMENT_REQ_ATTR_GEN_SIGNATURE;
		}

		/* This is Intel EGS style of measurement attestation, the AFM device structure
		 * doesn't contain measurement block index, so we need to scan through it.
		 *
		 * TODO: In Intel BHS, the AFM device structure has extended to include 
		 * measurement block index, so we could directly ask for it.
		 */
		while (afm_body->TotalMeasurements != afm_index) {
			if (++meas_index == SPDM_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
				/* Reach the end of measurement */
				LOG_ERR("Measurement block reach to the end");
				break;
			}

			ret = spdm_get_measurements(context, request_attribute, meas_index,
					&measurement_block, possible_measure);
			if (ret == 0) {
				/* Measurement and signature matched */
				LOG_INF("AFM[%02x] measured at measurement block [%02x]", afm_index, meas_index);
				afm_index++;
				if (afm_index == afm_body->TotalMeasurements) {
					signature_verified = true;
					break;
				} else {
					possible_measure =
						(uint8_t *)possible_measure + 4 +
						possible_measure->ValueSize * possible_measure->PossibleMeasurements;
				}
			} else if (ret == -1) {
				/* Measurement not found check next one */
				LOG_DBG("AFM[%02x] measurement block [%02x] not exist", afm_index, meas_index);
			} else if (ret == -2) {
				/* Signature invalid */
				signature_verified = false;
				break;
			} else {
				LOG_ERR("AFM[%02x] measurement block [%02x] failed", afm_index, meas_index);
				break;
			}

		}

		if (signature_verified == false) {
			/* Recovery the firmware ?? */
			ret = ATTEST_FAILED_MEASUREMENTS_MISMATCH;
			break;
		}
	} while (0);

	return ret;
}

static void spdm_attester_tick(struct k_timer *timeer)
{
	osEventFlagsSet(spdm_attester_event, SPDM_REQ_EVT_TICK);
}

struct spdm_context *target_list[8] = {0};
AFM_DEVICE_STRUCTURE *afm_list[8] = {0};

void spdm_attester_main(void *a, void *b, void *c)
{
	uint32_t events;
	osEventFlagsWait(spdm_attester_event, SPDM_REQ_EVT_ENABLE, osFlagsNoClear, osWaitForever);
	LOG_INF("SPDM Attester Thread Enabled");

	uint32_t RUNNING_COUNT = 0;
	while(1) {

		// Schedule the next tick
		// k_timer_start(&spdm_attester_timer, K_SECONDS(60), K_NO_WAIT);
		// Tick event will be cleared.
		events = osEventFlagsWait(spdm_attester_event,
				SPDM_REQ_EVT_TICK | SPDM_REQ_EVT_T0 | SPDM_REQ_EVT_ENABLE,
				osFlagsWaitAll | osFlagsNoClear,
				osWaitForever);
		LOG_INF("Start SPDM attestation events=%08x count=%lu", events, ++RUNNING_COUNT);

		for (size_t device = 0; device < 8; ++device) {
			// Make sure current state can run attestation
			events = osEventFlagsGet(spdm_attester_event);
			if (!(events & SPDM_REQ_EVT_T0)) {
				// Attestation is stopped by Aspeed State Machine
				LOG_ERR("T0 FLAG is cleared. Stop attestation at device[%d]", device);
				break;
			}
#if 1
			if (afm_list[device]) {
				LOG_INF("Attestation device[%d] events=%08x SPDM_REQ_EVT_T0=%08x", device, events, SPDM_REQ_EVT_T0);
				LOG_INF("UUID=%04x, BusId=%02x, DeviceAddress=%02x, BindingSped=%02x, Policy=%02x",
						afm_list[device]->UUID,
						afm_list[device]->BusID,
						afm_list[device]->DeviceAddress,
						afm_list[device]->BindingSpec,
						afm_list[device]->Policy);


				/* Create context */
				struct spdm_context *context = spdm_context_create();

				// DEST_EID using NULL EID due to AFM device structure design
				init_requester_context(context,
						afm_list[device]->BusID,
						afm_list[device]->DeviceAddress,
						MCTP_BASE_PROTOCOL_NULL_EID);

				/* Attested the device */
				int ret = spdm_attest_device(/* target_list[device] */ context, afm_list[device]);

				/* Check Policy */
				switch (ret) {
				case ATTEST_SUCCEEDED:
					LOG_INF("ATTEST UUID[%04x] Succeeded", afm_list[device]->UUID);
					break;
				case ATTEST_FAILED_VCA:
					/* Protocol Error */
					LOG_ERR("ATTEST UUID[%04x] Protocol Error", afm_list[device]->UUID);
					LogErrorCodes(SPDM_PROTOCOL_ERROR_FAIL, SPDM_CONNECTION_FAIL);
					if (afm_list[device]->Policy & BIT(2)) {
						/* Lock down in reset */
						GenerateStateMachineEvent(ATTESTATION_FAILED, 0);
					}	
					break;
				case ATTEST_FAILED_DIGEST:
					LOG_ERR("ATTEST UUID[%04x] Challenge Error", afm_list[device]->UUID);
					LogErrorCodes(ATTESTATION_CHALLENGE_FAIL, SPDM_DIGEST_FAIL);
					if (afm_list[device]->Policy & BIT(1)) {
						/* Lock down in reset */
						GenerateStateMachineEvent(ATTESTATION_FAILED, 0);
					}
					break;
				case ATTEST_FAILED_CERTIFICATE:
					LOG_ERR("ATTEST UUID[%04x] Challenge Error", afm_list[device]->UUID);
					LogErrorCodes(ATTESTATION_CHALLENGE_FAIL, SPDM_CERTIFICATE_FAIL);
					if (afm_list[device]->Policy & BIT(1)) {
						/* Lock down in reset */
						GenerateStateMachineEvent(ATTESTATION_FAILED, 0);
					}
					break;
				case ATTEST_FAILED_CHALLENGE_AUTH:
					/* Challenge Error */
					LOG_ERR("ATTEST UUID[%04x] Challenge Error", afm_list[device]->UUID);
					LogErrorCodes(ATTESTATION_CHALLENGE_FAIL, SPDM_CHALLENGE_FAIL);
					if (afm_list[device]->Policy & BIT(1)) {
						/* Lock down in reset */
						GenerateStateMachineEvent(ATTESTATION_FAILED, 0);
					}
					break;
				case ATTEST_FAILED_MEASUREMENTS_MISMATCH:
					/* Measurement unexpected or mismatch */
					LOG_ERR("ATTEST UUID[%04x] Measurement Error", afm_list[device]->UUID);
					LogErrorCodes(ATTESTATION_MEASUREMENT_FAIL, SPDM_MEASUREMENT_FAIL);
					if (afm_list[device]->Policy & BIT(0)) {
						/* Lock down in reset */
						GenerateStateMachineEvent(ATTESTATION_FAILED, 0);
					} 	
					break;	
				default:
					break;
				}

				spdm_context_release(context);
			}
#else
			if (target_list[device])
				spdm_attest_device(target_list[device]);
#endif
			// k_sleep(K_SECONDS(3));
		}
		osEventFlagsClear(spdm_attester_event, SPDM_REQ_EVT_TICK);
	}
}

void spdm_enable_attester()
{
	osEventFlagsSet(spdm_attester_event, SPDM_REQ_EVT_ENABLE);
}

void spdm_run_attester()
{
	afm_list[0] = (uint8_t *)0x80000000 + 0xf1400;
	afm_list[1] = (uint8_t *)0x80000000 + 0xf2400;

	osEventFlagsSet(spdm_attester_event, SPDM_REQ_EVT_T0);
	k_timer_start(&spdm_attester_timer, K_MINUTES(1), K_SECONDS(3));
}

void spdm_stop_attester()
{
	k_timer_stop(&spdm_attester_timer);
	osEventFlagsClear(spdm_attester_event, SPDM_REQ_EVT_T0);
}

#if defined(CONFIG_SHELL)
void spdm_get_attester()
{
	uint32_t events = osEventFlagsGet(spdm_attester_event);
	LOG_WRN("Attester Event Flag = 0x%08x", events);
}

void spdm_add_device(uint16_t uuid)
{
#if 1
	afm_list[0] = (uint8_t *)0x80000000 + 0xf1400;
	afm_list[1] = (uint8_t *)0x80000000 + 0xf2400;
#else
	// Only for testing. This should be in critical section
	for (size_t i = 0; i < 8; ++i) {
		if (target_list[i] == NULL) {
			target_list[i] = spdm_context_create();
			init_requester_context(target_list[i]);
			break;
		}
	}
#endif
}

void spdm_remove_device(uint16_t uuid)
{
	// Only for testing. This should be in critical section
	for (size_t i = 0; i < 8; ++i) {
		if (afm_list[i] != NULL) {
			//spdm_context_release(target_list[i]);
			afm_list[i] = NULL;
			break;
		}
	}
}
#endif
