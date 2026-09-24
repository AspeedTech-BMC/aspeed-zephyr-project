/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h> 

#include <stdlib.h>
#include <string.h>

#include <zephyr/drivers/cptra.h>
#include <zephyr/drivers/misc/aspeed/cptra_ipc.h>
#include <zephyr/drivers/misc/aspeed/otp_ast27xx.h>

#include <qcbor/qcbor_encode.h>

LOG_MODULE_DECLARE(composite_eat);

#include "evidence_provider_irot.h"

/* CoAP Content-Format for the encoded local evidence: application/cbor. */
/*
 * EAT UEID (claim 256), per RFC 9711: a type byte followed by the identifier.
 * The identifier is the 16 bytes at byte offset 0x70 of the OTP Caliptra
 * region. otp_read_cptra() adds the region base (CAL_REGION_START_ADDR,
 * 0x1c00) itself and indexes in 16-bit words, so byte 0x70 is word 0x38.
 */
#define IROT_UEID_TYPE_RAND			0x01u
#define IROT_UEID_OTP_WORD_OFFSET		(0x70u / 2u)
#define IROT_UEID_OTP_WORDS			(16u / 2u)
#define IROT_UEID_LENGTH			(1u + 16u)

#define IROT_LOCAL_EVIDENCE_CONTENT_FORMAT	60u

/* Encoded quote is ~1830 bytes; stays below COMPOSITE_EAT_MAX_LOCAL_EVIDENCE_LENGTH. */
#define IROT_LOCAL_EVIDENCE_MAX			2048u

/* Profile-defined map keys of the encoded Caliptra PCR quote. */
#define IROT_MEAS_KEY_PCRS			1
#define IROT_MEAS_KEY_RESET_COUNTERS		2
#define IROT_MEAS_KEY_NONCE			3
#define IROT_MEAS_KEY_DIGEST			4
#define IROT_MEAS_KEY_SIGNATURE			5

/*
 * One allocation backing a pinned snapshot. The local evidence descriptor and
 * the encoded bytes it borrows must stay valid until end_snapshot.
 */
struct irot_evidence_snapshot {
	struct composite_eat_local_evidence local[1];
	uint8_t ueid[IROT_UEID_LENGTH];
	uint8_t encoded[IROT_LOCAL_EVIDENCE_MAX];
};

/*
 * Build the UEID from OTP. The OTP byte stream is the little-endian
 * serialization of each 16-bit word, so the words are staged in an aligned
 * buffer and copied out without swapping; this matches how the IDevID TBS is
 * read in cptra_idevid.c. Staging also avoids an unaligned 16-bit access,
 * since the type byte puts the identifier at an odd offset.
 */
static int irot_read_ueid(uint8_t *ueid)
{
	uint16_t words[IROT_UEID_OTP_WORDS];
	bool provisioned = false;
	int ret;

	for (uint32_t i = 0; i < IROT_UEID_OTP_WORDS; i++) {
		ret = otp_read_cptra(IROT_UEID_OTP_WORD_OFFSET + i, &words[i]);
		if (ret) {
			LOG_ERR("otp_read_cptra failed (word %u, ret:0x%x)",
				IROT_UEID_OTP_WORD_OFFSET + i, ret);
			return -1;
		}

		if (words[i] != 0)
			provisioned = true;
	}

	/* An all-zero field means the UEID was never fused. Fail rather than
	 * attest under an identifier that is not ours.
	 */
	if (!provisioned) {
		LOG_ERR("UEID is not provisioned in OTP");
		return -1;
	}

	ueid[0] = IROT_UEID_TYPE_RAND;
	memcpy(&ueid[1], words, sizeof(words));

	return 0;
}

static int irot_get_pcr_quote(struct cptra_quote_pcrs_oa *output)
{
	struct cptra_quote_pcrs_ia input;
	int ret;

	memset(&input, 0, sizeof(input));
	memset(output, 0, sizeof(*output));

	ret = cptra_ipc_transfer(CPTRA_IPCCMD_QUOTE_PCRS, &input, sizeof(input),
				 CPTRA_IPC_RX_TYPE_EXTERNAL, output, sizeof(*output));
	if (ret) {
		LOG_ERR("caliptra_quote_pcrs is failure, ret:0x%x", ret);
		return -1;
	}

	if (output->fips_status != 0) {
		LOG_ERR("FIPS error from caliptra, status:0x%x", output->fips_status);
		return -1;
	}

	return 0;
}

static int irot_encode_measurement(const struct cptra_quote_pcrs_oa *quote, uint8_t *buffer,
				   size_t capacity, size_t *length)
{
	uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH];
	QCBOREncodeContext encoder;
	QCBORError error;
	UsefulBufC encoded;
	size_t index;

	memcpy(signature, quote->signature_r, sizeof(quote->signature_r));
	memcpy(signature + sizeof(quote->signature_r), quote->signature_s,
	       sizeof(quote->signature_s));

	QCBOREncode_Init(&encoder, (UsefulBuf){buffer, capacity});

	QCBOREncode_OpenMap(&encoder);

	QCBOREncode_OpenArrayInMapN(&encoder, IROT_MEAS_KEY_PCRS);
	for (index = 0; index < ARRAY_SIZE(quote->PCRs); ++index) {
		QCBOREncode_AddBytes(&encoder,
				     (UsefulBufC){quote->PCRs[index], sizeof(quote->PCRs[index])});
	}
	QCBOREncode_CloseArray(&encoder);

	QCBOREncode_OpenArrayInMapN(&encoder, IROT_MEAS_KEY_RESET_COUNTERS);
	for (index = 0; index < ARRAY_SIZE(quote->reset_ctrs); ++index) {
		QCBOREncode_AddUInt64(&encoder, quote->reset_ctrs[index]);
	}
	QCBOREncode_CloseArray(&encoder);

	QCBOREncode_AddBytesToMapN(&encoder, IROT_MEAS_KEY_NONCE,
				   (UsefulBufC){quote->nonce, sizeof(quote->nonce)});
	QCBOREncode_AddBytesToMapN(&encoder, IROT_MEAS_KEY_DIGEST,
				   (UsefulBufC){quote->digest, sizeof(quote->digest)});
	QCBOREncode_AddBytesToMapN(&encoder, IROT_MEAS_KEY_SIGNATURE,
				   (UsefulBufC){signature, sizeof(signature)});

	QCBOREncode_CloseMap(&encoder);

	error = QCBOREncode_Finish(&encoder, &encoded);
	if (error != QCBOR_SUCCESS) {
		LOG_ERR("Failed to encode local evidence: %d", error);
		return -1;
	}

	*length = encoded.len;
	return 0;
}

int begin_snapshot(void *context, void **snapshot_handle,
                          struct composite_eat_evidence_snapshot *evidence) {
	/* EAT profile URI (claim 265) the reference integration expects. */
	static uint8_t profile[] =
		"https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/";

	struct irot_evidence_snapshot *snapshot;
	struct cptra_quote_pcrs_oa *quote;
	size_t encoded_length = 0;

	if (!snapshot_handle || !evidence) {
		LOG_ERR("begin_snapshot snapshot_handle=%p evidence=%p", snapshot_handle, evidence);
		return -1;
	}

	evidence->profile.data = profile;
	evidence->profile.length = sizeof(profile) - 1;

	snapshot = (struct irot_evidence_snapshot *)malloc(sizeof(struct irot_evidence_snapshot));
	quote = (struct cptra_quote_pcrs_oa *)malloc(sizeof(struct cptra_quote_pcrs_oa));
	if (!snapshot || !quote) {
		LOG_ERR("Failed to allocate evidence snapshot");
		goto error;
	}

	if (irot_read_ueid(snapshot->ueid)) {
		goto error;
	}

	evidence->ueid.data = snapshot->ueid;
	evidence->ueid.length = sizeof(snapshot->ueid);

	if (irot_get_pcr_quote(quote)) {
		goto error;
	}

	if (irot_encode_measurement(quote, snapshot->encoded, sizeof(snapshot->encoded),
				    &encoded_length)) {
		goto error;
	}

	free(quote);

	snapshot->local[0].content_format = IROT_LOCAL_EVIDENCE_CONTENT_FORMAT;
	snapshot->local[0].encoded.data = snapshot->encoded;
	snapshot->local[0].encoded.length = encoded_length;

	evidence->local_evidence = snapshot->local;
	evidence->local_evidence_count = 1;

	*snapshot_handle = snapshot;
	return 0;

error:
	free(quote);
	free(snapshot);
	return -1;
}

void end_snapshot(void *context, void *snapshot_handle) {
	if (!snapshot_handle) {
		LOG_WRN("end_snapshot context=%p snapshot_handle=%p", context, snapshot_handle);
		return;
	}

	free(snapshot_handle);
}
