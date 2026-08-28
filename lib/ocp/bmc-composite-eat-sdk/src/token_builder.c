/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <string.h>

#include <qcbor/qcbor_encode.h>

#include "composite_eat/token_builder.h"

#define EAT_CLAIM_NONCE 10
#define EAT_CLAIM_UEID 256
#define EAT_CLAIM_PROFILE 265
#define EAT_CLAIM_SUBMODULES 266
#define EAT_CLAIM_MEASUREMENTS 273
#define COSE_HEADER_ALGORITHM 1
#define COSE_HEADER_CONTENT_TYPE 3
#define COSE_HEADER_X5CHAIN 33
#define COSE_HEADER_X5T 34
#define CONTENT_TYPE_EAT_CWT "application/eat+cwt"

static void clear_bytes(void *data, size_t length) {
    volatile uint8_t *cursor = data;

    while (length-- > 0u) {
        *cursor++ = 0u;
    }
}

static bool buffer_valid(const struct composite_eat_buffer *buffer) {
    return (buffer != NULL) && (buffer->data != NULL) && (buffer->length != 0u);
}

static bool utf8_valid(const uint8_t *text, size_t length) {
    size_t offset = 0u;

    while (offset < length) {
        uint8_t first = text[offset++];
        uint32_t codepoint;
        size_t continuation;
        size_t index;

        if (first < 0x80u) {
            continue;
        }
        if ((first >= 0xc2u) && (first <= 0xdfu)) {
            codepoint = first & 0x1fu;
            continuation = 1u;
        } else if ((first >= 0xe0u) && (first <= 0xefu)) {
            codepoint = first & 0x0fu;
            continuation = 2u;
        } else if ((first >= 0xf0u) && (first <= 0xf4u)) {
            codepoint = first & 0x07u;
            continuation = 3u;
        } else {
            return false;
        }

        if ((length - offset) < continuation) {
            return false;
        }
        for (index = 0u; index < continuation; ++index) {
            uint8_t next = text[offset++];

            if ((next & 0xc0u) != 0x80u) {
                return false;
            }
            codepoint = (codepoint << 6) | (next & 0x3fu);
        }

        if (((continuation == 1u) && (codepoint < 0x80u)) ||
            ((continuation == 2u) && (codepoint < 0x800u)) ||
            ((continuation == 3u) && (codepoint < 0x10000u)) ||
            ((codepoint >= 0xd800u) && (codepoint <= 0xdfffu)) || (codepoint > 0x10ffffu)) {
            return false;
        }
    }

    return true;
}

enum composite_eat_status
composite_eat_validate_evidence_snapshot(const struct composite_eat_evidence_snapshot *evidence) {
    size_t index;

    if ((evidence == NULL) || !buffer_valid(&evidence->ueid) || (evidence->ueid.length < 7u) ||
        (evidence->ueid.length > 33u) || !buffer_valid(&evidence->profile) ||
        (evidence->profile.length > COMPOSITE_EAT_MAX_PROFILE_LENGTH) ||
        !utf8_valid(evidence->profile.data, evidence->profile.length) ||
        (memchr(evidence->profile.data, '\0', evidence->profile.length) != NULL) ||
        (evidence->local_evidence == NULL) || (evidence->local_evidence_count == 0u) ||
        (evidence->local_evidence_count > COMPOSITE_EAT_MAX_LOCAL_EVIDENCE)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }
    for (index = 0; index < evidence->local_evidence_count; ++index) {
        if (!buffer_valid(&evidence->local_evidence[index].encoded) ||
            (evidence->local_evidence[index].encoded.length >
             COMPOSITE_EAT_MAX_LOCAL_EVIDENCE_LENGTH)) {
            return COMPOSITE_EAT_BAD_ARGUMENT;
        }
    }
    return COMPOSITE_EAT_OK;
}

enum composite_eat_status composite_eat_validate_attestation_identity(
    const struct composite_eat_attestation_identity *identity) {
    size_t index;

    if ((identity == NULL) || (identity->certificates == NULL) ||
        (identity->certificate_count == 0u) ||
        (identity->certificate_count > COMPOSITE_EAT_MAX_CERTIFICATES)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }
    for (index = 0; index < identity->certificate_count; ++index) {
        if ((identity->certificates[index].data == NULL) ||
            (identity->certificates[index].length == 0u) ||
            (identity->certificates[index].length > COMPOSITE_EAT_MAX_CERTIFICATE_LENGTH)) {
            return COMPOSITE_EAT_BAD_ARGUMENT;
        }
    }
    return COMPOSITE_EAT_OK;
}

static int compare_records(const struct composite_eat_device_record *left,
                           const struct composite_eat_device_record *right) {
    if (left->environment_length != right->environment_length) {
        return (left->environment_length < right->environment_length) ? -1 : 1;
    }
    return memcmp(left->environment, right->environment, left->environment_length);
}

static void add_payload(QCBOREncodeContext *encoder,
                        const struct composite_eat_generation_request *request,
                        const struct composite_eat_evidence_snapshot *evidence) {
    uint8_t order[COMPOSITE_EAT_MAX_DEVICE_RECORDS];
    char environment[COMPOSITE_EAT_MAX_ENVIRONMENT_LENGTH + 1u];
    size_t index;
    size_t position;

    for (index = 0; index < request->record_count; ++index) {
        order[index] = (uint8_t)index;
        for (position = index; position > 0u; --position) {
            const struct composite_eat_device_record *left =
                &request->records[order[position - 1u]];
            const struct composite_eat_device_record *right = &request->records[order[position]];

            if (compare_records(left, right) <= 0) {
                break;
            }
            order[position] = order[position - 1u];
            order[position - 1u] = (uint8_t)index;
        }
    }

    QCBOREncode_OpenMap(encoder);
    QCBOREncode_AddBytesToMapN(encoder, EAT_CLAIM_NONCE,
                               (UsefulBufC){request->nonce, request->nonce_length});
    QCBOREncode_AddBytesToMapN(encoder, EAT_CLAIM_UEID,
                               (UsefulBufC){evidence->ueid.data, evidence->ueid.length});
    QCBOREncode_AddTextToMapN(encoder, EAT_CLAIM_PROFILE,
                              (UsefulBufC){evidence->profile.data, evidence->profile.length});

    QCBOREncode_OpenMapInMapN(encoder, EAT_CLAIM_SUBMODULES);
    for (index = 0; index < request->record_count; ++index) {
        const struct composite_eat_device_record *record = &request->records[order[index]];

        memcpy(environment, record->environment, record->environment_length);
        environment[record->environment_length] = '\0';
        QCBOREncode_OpenArrayInMap(encoder, environment);
        QCBOREncode_AddInt64(encoder, COMPOSITE_EAT_COSE_ALGORITHM_SHA384);
        QCBOREncode_AddBytes(encoder, (UsefulBufC){record->digest, sizeof(record->digest)});
        QCBOREncode_CloseArray(encoder);
    }
    QCBOREncode_CloseMap(encoder);

    QCBOREncode_OpenArrayInMapN(encoder, EAT_CLAIM_MEASUREMENTS);
    for (index = 0; index < evidence->local_evidence_count; ++index) {
        QCBOREncode_OpenArray(encoder);
        QCBOREncode_AddUInt64(encoder, evidence->local_evidence[index].content_format);
        QCBOREncode_AddBytes(encoder, (UsefulBufC){evidence->local_evidence[index].encoded.data,
                                                   evidence->local_evidence[index].encoded.length});
        QCBOREncode_CloseArray(encoder);
    }
    QCBOREncode_CloseArray(encoder);
    QCBOREncode_CloseMap(encoder);
}

static void
add_protected_headers(QCBOREncodeContext *encoder,
                      const uint8_t leaf_thumbprint_sha384[COMPOSITE_EAT_SHA384_LENGTH]) {
    QCBOREncode_OpenMap(encoder);
    QCBOREncode_AddInt64ToMapN(encoder, COSE_HEADER_ALGORITHM, COMPOSITE_EAT_COSE_ALGORITHM_ES384);
    QCBOREncode_AddTextToMapN(encoder, COSE_HEADER_CONTENT_TYPE,
                              UsefulBuf_FROM_SZ_LITERAL(CONTENT_TYPE_EAT_CWT));
    QCBOREncode_OpenArrayInMapN(encoder, COSE_HEADER_X5T);
    QCBOREncode_AddInt64(encoder, COMPOSITE_EAT_COSE_ALGORITHM_SHA384);
    QCBOREncode_AddBytes(encoder,
                         (UsefulBufC){leaf_thumbprint_sha384, COMPOSITE_EAT_SHA384_LENGTH});
    QCBOREncode_CloseArray(encoder);
    QCBOREncode_CloseMap(encoder);
}

static enum composite_eat_status finish_encoding(QCBOREncodeContext *encoder, size_t *length) {
    UsefulBufC output;

    if (QCBOREncode_Finish(encoder, &output) != QCBOR_SUCCESS) {
        return COMPOSITE_EAT_ENCODING_ERROR;
    }
    *length = output.len;
    return COMPOSITE_EAT_OK;
}

enum composite_eat_status
composite_eat_prepare(const struct composite_eat_generation_request *request,
                      const struct composite_eat_evidence_snapshot *evidence,
                      const struct composite_eat_attestation_identity *identity,
                      const uint8_t leaf_thumbprint_sha384[COMPOSITE_EAT_SHA384_LENGTH],
                      struct composite_eat_workspace *workspace,
                      struct composite_eat_prepared *prepared) {
    QCBOREncodeContext encoder;

    if ((workspace == NULL) || (prepared == NULL)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    clear_bytes(workspace, sizeof(*workspace));
    clear_bytes(prepared, sizeof(*prepared));
    if ((composite_eat_validate_generation_request(request) != COMPOSITE_EAT_OK) ||
        (composite_eat_validate_evidence_snapshot(evidence) != COMPOSITE_EAT_OK) ||
        (composite_eat_validate_attestation_identity(identity) != COMPOSITE_EAT_OK) ||
        (leaf_thumbprint_sha384 == NULL)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    QCBOREncode_Init(
        &encoder, (UsefulBuf){workspace->protected_headers, sizeof(workspace->protected_headers)});
    add_protected_headers(&encoder, leaf_thumbprint_sha384);
    if (finish_encoding(&encoder, &workspace->protected_headers_length) != COMPOSITE_EAT_OK) {
        clear_bytes(workspace, sizeof(*workspace));
        clear_bytes(prepared, sizeof(*prepared));
        return COMPOSITE_EAT_ENCODING_ERROR;
    }

    QCBOREncode_Init(&encoder, (UsefulBuf){workspace->payload, sizeof(workspace->payload)});
    add_payload(&encoder, request, evidence);
    if (finish_encoding(&encoder, &workspace->payload_length) != COMPOSITE_EAT_OK) {
        clear_bytes(workspace, sizeof(*workspace));
        clear_bytes(prepared, sizeof(*prepared));
        return COMPOSITE_EAT_ENCODING_ERROR;
    }

    prepared->workspace = workspace;
    prepared->identity = identity;
    prepared->ready = true;
    return COMPOSITE_EAT_OK;
}

static size_t bstr_header(size_t length, uint8_t header[5]) {
    if (length < 24u) {
        header[0] = (uint8_t)(0x40u | length);
        return 1u;
    }
    if (length < 0x100u) {
        header[0] = 0x58u;
        header[1] = (uint8_t)length;
        return 2u;
    }
    if (length < 0x10000u) {
        header[0] = 0x59u;
        header[1] = (uint8_t)(length >> 8);
        header[2] = (uint8_t)length;
        return 3u;
    }
    header[0] = 0x5au;
    header[1] = (uint8_t)(length >> 24);
    header[2] = (uint8_t)(length >> 16);
    header[3] = (uint8_t)(length >> 8);
    header[4] = (uint8_t)length;
    return 5u;
}

enum composite_eat_status composite_eat_signing_input_next(struct composite_eat_prepared *prepared,
                                                           const uint8_t **data, size_t *length) {
    static const uint8_t prefix[] = {0x84u, 0x6au, 'S', 'i', 'g', 'n',
                                     'a',   't',   'u', 'r', 'e', '1'};
    static const uint8_t empty_external_aad = 0x40u;

    if ((data == NULL) || (length == NULL)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    *data = NULL;
    *length = 0u;
    if ((prepared == NULL) || !prepared->ready || (prepared->workspace == NULL)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }
    if (prepared->signing_part >= 6u) {
        return COMPOSITE_EAT_DONE;
    }

    switch (prepared->signing_part) {
    case 0u:
        *data = prefix;
        *length = sizeof(prefix);
        break;
    case 1u:
        *data = prepared->header;
        *length = bstr_header(prepared->workspace->protected_headers_length, prepared->header);
        break;
    case 2u:
        *data = prepared->workspace->protected_headers;
        *length = prepared->workspace->protected_headers_length;
        break;
    case 3u:
        *data = &empty_external_aad;
        *length = 1u;
        break;
    case 4u:
        *data = prepared->header;
        *length = bstr_header(prepared->workspace->payload_length, prepared->header);
        break;
    case 5u:
        *data = prepared->workspace->payload;
        *length = prepared->workspace->payload_length;
        break;
    default:
        return COMPOSITE_EAT_STATE_ERROR;
    }
    ++prepared->signing_part;

    return COMPOSITE_EAT_OK;
}

static void add_token(QCBOREncodeContext *encoder, const struct composite_eat_prepared *prepared,
                      const uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH]) {
    size_t index;

    QCBOREncode_AddTag(encoder, CBOR_TAG_CWT);
    QCBOREncode_AddTag(encoder, CBOR_TAG_COSE_SIGN1);
    QCBOREncode_OpenArray(encoder);
    QCBOREncode_AddBytes(encoder, (UsefulBufC){prepared->workspace->protected_headers,
                                               prepared->workspace->protected_headers_length});
    QCBOREncode_OpenMap(encoder);
    if (prepared->identity->certificate_count == 1u) {
        QCBOREncode_AddBytesToMapN(encoder, COSE_HEADER_X5CHAIN,
                                   (UsefulBufC){prepared->identity->certificates[0].data,
                                                prepared->identity->certificates[0].length});
    } else {
        QCBOREncode_OpenArrayInMapN(encoder, COSE_HEADER_X5CHAIN);
        for (index = 0; index < prepared->identity->certificate_count; ++index) {
            QCBOREncode_AddBytes(encoder,
                                 (UsefulBufC){prepared->identity->certificates[index].data,
                                              prepared->identity->certificates[index].length});
        }
        QCBOREncode_CloseArray(encoder);
    }
    QCBOREncode_CloseMap(encoder);
    QCBOREncode_AddBytes(
        encoder, (UsefulBufC){prepared->workspace->payload, prepared->workspace->payload_length});
    QCBOREncode_AddBytes(encoder, (UsefulBufC){signature, COMPOSITE_EAT_ES384_SIGNATURE_LENGTH});
    QCBOREncode_CloseArray(encoder);
}

enum composite_eat_status
composite_eat_finish(const struct composite_eat_prepared *prepared,
                     const uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH],
                     uint8_t *response, size_t response_capacity, size_t *response_length) {
    QCBOREncodeContext encoder;
    UsefulBufC output;

    if (response_length == NULL) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }
    *response_length = 0u;
    if ((prepared == NULL) || !prepared->ready || (prepared->workspace == NULL) ||
        (composite_eat_validate_attestation_identity(prepared->identity) != COMPOSITE_EAT_OK) ||
        (signature == NULL) || ((response == NULL) && (response_capacity != 0u))) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }
    if (prepared->signing_part < 6u) {
        return COMPOSITE_EAT_STATE_ERROR;
    }

    QCBOREncode_Init(&encoder, SizeCalculateUsefulBuf);
    add_token(&encoder, prepared, signature);
    if (QCBOREncode_FinishGetSize(&encoder, response_length) != QCBOR_SUCCESS) {
        *response_length = 0u;
        return COMPOSITE_EAT_ENCODING_ERROR;
    }
    if (*response_length > COMPOSITE_EAT_MAX_RESPONSE_LENGTH) {
        *response_length = 0u;
        return COMPOSITE_EAT_ENCODING_ERROR;
    }
    if (response_capacity < *response_length) {
        return COMPOSITE_EAT_BUFFER_TOO_SMALL;
    }

    QCBOREncode_Init(&encoder, (UsefulBuf){response, response_capacity});
    add_token(&encoder, prepared, signature);
    if ((QCBOREncode_Finish(&encoder, &output) != QCBOR_SUCCESS) ||
        (output.len != *response_length)) {
        memset(response, 0, response_capacity);
        *response_length = 0u;
        return COMPOSITE_EAT_ENCODING_ERROR;
    }

    return COMPOSITE_EAT_OK;
}

void composite_eat_clear(struct composite_eat_workspace *workspace,
                         struct composite_eat_prepared *prepared) {
    if (workspace != NULL) {
        clear_bytes(workspace, sizeof(*workspace));
    }
    if (prepared != NULL) {
        clear_bytes(prepared, sizeof(*prepared));
    }
}
