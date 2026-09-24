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

/* CoAP Content-Format application/tcg-dice-concise-evidence+cbor. */
#define IROT_LOCAL_EVIDENCE_CONTENT_FORMAT	10571u

/* Encoded evidence is ~120 bytes; stays below COMPOSITE_EAT_MAX_LOCAL_EVIDENCE_LENGTH. */
#define IROT_LOCAL_EVIDENCE_MAX			2048u

/*
 * TCG DICE Concise Evidence map keys, which follow the CoRIM/CoMID data model:
 *
 *   concise-evidence = { ev-triples => { evidence => [ + ev-triple-record ] } }
 *   ev-triple-record = [ environment-map, [ + measurement-map ] ]
 *
 * One measurement-map per PCR, keyed by the register index, with the value in
 * digests. The verifier appraises digests entries and has no comparison for
 * integrity-registers, so that key is not used here:
 *
 *   { 0: <index>, 1: { 2: [ [ 7, h'<48-byte digest>' ] ] } }
 *
 * These are draft-tracking assignments; they track the revision the reference
 * integration consumes.
 */
#define COEV_KEY_EV_TRIPLES			0
#define COEV_EV_TRIPLES_KEY_EVIDENCE		0
#define COEV_ENVIRONMENT_KEY_CLASS		0
#define COEV_CLASS_KEY_VENDOR			1
#define COEV_CLASS_KEY_MODEL			2
#define COEV_MEASUREMENT_KEY_MKEY		0
#define COEV_MEASUREMENT_KEY_MVAL		1
#define COEV_MVAL_KEY_DIGESTS			2

/* sha-384 in the IANA Named Information Hash Algorithm registry. */
#define COEV_HASH_ALG_SHA_384			7

/* Only this PCR is reported as an integrity register. */
#define IROT_REPORTED_PCR_INDEX			31

#define IROT_EVIDENCE_VENDOR			"ASPEED Technology Inc."
#define IROT_EVIDENCE_MODEL			"AST2700"

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

/* Emit one measurement-map: the PCR index as mkey, its digest under digests. */
static void irot_encode_pcr_measurement(QCBOREncodeContext *encoder,
					const struct cptra_quote_pcrs_oa *quote, size_t index)
{
	QCBOREncode_OpenMap(encoder);					/* measurement-map */
	QCBOREncode_AddUInt64ToMapN(encoder, COEV_MEASUREMENT_KEY_MKEY, index);
	QCBOREncode_OpenMapInMapN(encoder, COEV_MEASUREMENT_KEY_MVAL);
	QCBOREncode_OpenArrayInMapN(encoder, COEV_MVAL_KEY_DIGESTS);	/* digests-type */
	QCBOREncode_OpenArray(encoder);					/* digest */
	QCBOREncode_AddUInt64(encoder, COEV_HASH_ALG_SHA_384);
	QCBOREncode_AddBytes(encoder,
			     (UsefulBufC){quote->PCRs[index], sizeof(quote->PCRs[index])});
	QCBOREncode_CloseArray(encoder);				/* digest */
	QCBOREncode_CloseArray(encoder);				/* digests */
	QCBOREncode_CloseMap(encoder);					/* mval */
	QCBOREncode_CloseMap(encoder);					/* measurement-map */
}

/*
 * Serialize the reported Caliptra PCR as TCG DICE Concise Evidence: one
 * integrity register, keyed by its PCR index, holding a [alg, digest] pair.
 *
 * The quote nonce, composite digest and signature are deliberately not carried:
 * Concise Evidence states measurements, and the token's own COSE_Sign1 over the
 * DPE leaf key is what signs them. Freshness comes from EAT claim 10.
 */
static int irot_encode_measurement(const struct cptra_quote_pcrs_oa *quote, uint8_t *buffer,
				   size_t capacity, size_t *length)
{
	QCBOREncodeContext encoder;
	QCBORError error;
	UsefulBufC encoded;
	const size_t index = IROT_REPORTED_PCR_INDEX;

	if (index >= ARRAY_SIZE(quote->PCRs)) {
		LOG_ERR("PCR index %u is outside the quote", (uint32_t)index);
		return -1;
	}

	QCBOREncode_Init(&encoder, (UsefulBuf){buffer, capacity});

	QCBOREncode_OpenMap(&encoder);					/* concise-evidence */
	QCBOREncode_OpenMapInMapN(&encoder, COEV_KEY_EV_TRIPLES);
	QCBOREncode_OpenArrayInMapN(&encoder, COEV_EV_TRIPLES_KEY_EVIDENCE);

	QCBOREncode_OpenArray(&encoder);				/* ev-triple-record */

	QCBOREncode_OpenMap(&encoder);					/* environment-map */
	QCBOREncode_OpenMapInMapN(&encoder, COEV_ENVIRONMENT_KEY_CLASS);
	QCBOREncode_AddTextToMapN(&encoder, COEV_CLASS_KEY_VENDOR,
				  UsefulBuf_FROM_SZ_LITERAL(IROT_EVIDENCE_VENDOR));
	QCBOREncode_AddTextToMapN(&encoder, COEV_CLASS_KEY_MODEL,
				  UsefulBuf_FROM_SZ_LITERAL(IROT_EVIDENCE_MODEL));
	QCBOREncode_CloseMap(&encoder);					/* class-map */
	QCBOREncode_CloseMap(&encoder);					/* environment-map */

	QCBOREncode_OpenArray(&encoder);				/* [ + measurement-map ] */
	irot_encode_pcr_measurement(&encoder, quote, index);
	QCBOREncode_CloseArray(&encoder);				/* measurement list */

	QCBOREncode_CloseArray(&encoder);				/* ev-triple-record */

	QCBOREncode_CloseArray(&encoder);				/* evidence */
	QCBOREncode_CloseMap(&encoder);					/* ev-triples */
	QCBOREncode_CloseMap(&encoder);					/* concise-evidence */

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
