/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <random/rand32.h>

#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_handle_get_measurements(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	int ret;
	/* Deserialize */
	/* Measurement operation:
	 * - A value of 0x0 shall query the Responder for the total number of measurements available.
	 * - A value of 0xFF shall request all measurements.
	 * - A value between 0x1 and 0xFE, inclusively, shall request the measurement at the index
	 *   corresponding to that value.
	 */
	uint8_t req_signature = req_msg->header.param1 & 0x01;
	uint8_t req_measurement = req_msg->header.param2;

	LOG_ERR("GET_MEASUREMENTS[%02x,%02x]", req_msg->header.param1, req_msg->header.param2);
	// uint8_t req_nonce[32];
	// spdm_buffer_get_array(&req_msg->buffer, req_nonce, 32);

	rsp_msg->header.request_response_code = SPDM_RSP_MEASUREMENTS;
	rsp_msg->header.param2 = 0;
	if (req_measurement == 0) {
		uint8_t measurement_count;
		context->get_measurement(context, req_measurement, &measurement_count, NULL, NULL);
		rsp_msg->header.param1 = measurement_count; // Total number of measurements

		spdm_buffer_init(&rsp_msg->buffer, 1 + 3 + 0 + 32 + 2 + 0);

		/* Number of Blocks (1):
		 * If Param2 in the requested measurement operation is 0 , this field shall be 0.
		 */
		spdm_buffer_append_u8(&rsp_msg->buffer, 0);

		/* MeasurementRecordLength (3):
		 * If Param2 in the requested measurement operation is 0 , this field shall be 0.
		 */
		spdm_buffer_append_u8(&rsp_msg->buffer, 0);
		spdm_buffer_append_u8(&rsp_msg->buffer, 0);
		spdm_buffer_append_u8(&rsp_msg->buffer, 0);

		/* Nonce (32) */
		spdm_buffer_append_nonce(&rsp_msg->buffer);

		/* OpaqueLength + Opaque Data */
		spdm_buffer_append_u16(&rsp_msg->buffer, 0);

	} else {
		/* TODO: Calculate the requested measurements,
		 *       perhaps a call back for context? 
		 */

		/* Serialize the result */
		uint8_t measurement[(48 + 4 + 3) * 3];
		uint8_t measurement_count;
		size_t measurement_size = sizeof(measurement);
		uint32_t L = measurement_size, OL = 0;

		spdm_buffer_init(&rsp_msg->buffer, 1 + 3 + L + SPDM_NONCE_SIZE + 2 + OL);


		context->get_measurement(context, req_measurement, &measurement_count, measurement, &measurement_size);
		rsp_msg->header.param1 = measurement_count; // Total number of measurements

		/* Number of Blocks (1) */
		spdm_buffer_append_u8(&rsp_msg->buffer, measurement_count);

		/* MeasurementRecordLength (3): TODO: Support u24? */
		spdm_buffer_append_u8(&rsp_msg->buffer, (measurement_size >>  0) & 0xFF);
		spdm_buffer_append_u8(&rsp_msg->buffer, (measurement_size >>  8) & 0xFF);
		spdm_buffer_append_u8(&rsp_msg->buffer, (measurement_size >> 16) & 0xFF);

		/* MeasurementRecord (L) */
		spdm_buffer_append_array(&rsp_msg->buffer, measurement, measurement_size);

		/* Nonce (32) */
		spdm_buffer_append_nonce(&rsp_msg->buffer);

		/* OpaqueLength + Opaque Data */
		spdm_buffer_append_u16(&rsp_msg->buffer, 0);
	}

	/* Signature */
	// Alias ID Key is in context->key_pair
	// Signature = Sign(SK, Hash(L1))
	// - Sign(): Algorithm selected in ALGORITHMS (SECP384R1)
	// - SK: private key associated with the leaf ceritficate of
	//       the responder in slot=Param1 of the CHALLENGE request message
	// - Hash(): Algorithm selected in ALGORITHMS (SHA384)
	// - L1/L2: Concatenate(GET_MEASUREMENTS_REQUEST1, MEASUREMENTS_RESPONSE1, ...,
	//          GET_MEASUREMENTS_REQUESTn-1, MEASUREMENTS_RESPONSEn-1,
	//          GET_MEASUREMENTS_REQUESTn, MEASUREMENTS_RESPONSEn)

	/* Append Req/Rsp to L1L2 hash */
	spdm_context_update_l1l2_hash(context, req_msg, rsp_msg);

	if (req_signature == 0x01) {
		/* GET_MEASUREMENTS_REQUESTn
		 * Entire first GET_MEASUREMENTS request message under consideration, where the Requester has
		 * requested a signature on that specific GET_MEASUREMENTS request.
		 */
		uint8_t hash[48];

		mbedtls_sha512_finish(&context->l1l2_context, hash);
		spdm_context_reset_l1l2_hash(context);

		/* Sign the message */
		uint8_t sig[MBEDTLS_ECDSA_MAX_LEN];
		size_t sig_len = 0;

		mbedtls_mpi r, s;
		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);

		ret = mbedtls_ecdsa_sign(&context->key_pair.MBEDTLS_PRIVATE(grp),
				&r, &s, &context->key_pair.MBEDTLS_PRIVATE(d),
				hash, sizeof(hash), context->random_callback, context);
		LOG_INF("mbedtls_ecdsa_sign ret=%x", -ret);
		LOG_HEXDUMP_INF(hash, sizeof(hash), "Responder L1 HASH");

		size_t r_size = mbedtls_mpi_size(&r), s_size = mbedtls_mpi_size(&s);
		mbedtls_mpi_write_binary(&r, sig, r_size);
		mbedtls_mpi_write_binary(&s, sig + r_size, s_size);
		sig_len = r_size + s_size;

		mbedtls_mpi_free(&s);
		mbedtls_mpi_free(&r);
		spdm_buffer_resize(&rsp_msg->buffer, rsp_msg->buffer.write_ptr + sig_len);
		spdm_buffer_append_array(&rsp_msg->buffer, sig, sig_len);
		if (ret) {
			LOG_ERR("GET_MEASUREMENTS Failed to sign message");
			rsp_msg->header.request_response_code = SPDM_RSP_ERROR;
			rsp_msg->header.param1 = SPDM_ERROR_CODE_UNSPECIFIED;
			rsp_msg->header.param2 = 0;
			spdm_buffer_release(&rsp_msg->buffer);
			ret = -1;
			goto cleanup;
		}
	}

	ret = 0;

cleanup:
	return ret;
}
