/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <string.h>

#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_encode.h>

#include "composite_eat/generation_request.h"

#define REQUEST_KEY_VERSION 1
#define REQUEST_KEY_NONCE 2
#define REQUEST_KEY_RECORDS 3
#define RECORD_KEY_ENVIRONMENT 1
#define RECORD_KEY_DIGEST 2
#define REQUEST_FIELD_COUNT 3u
#define RECORD_FIELD_COUNT 2u

static enum composite_eat_status get_next(QCBORDecodeContext *decoder, QCBORItem *item) {
    size_t tag;

    if (QCBORDecode_GetNext(decoder, item) != QCBOR_SUCCESS) {
        return COMPOSITE_EAT_MALFORMED_REQUEST;
    }
    for (tag = 0; tag < QCBOR_MAX_TAGS_PER_ITEM; ++tag) {
        if (item->uTags[tag] != CBOR_TAG_INVALID16) {
            return COMPOSITE_EAT_MALFORMED_REQUEST;
        }
    }
    return COMPOSITE_EAT_OK;
}

static bool definite_count(const QCBORItem *item, uint16_t expected) {
    return (item->val.uCount != QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH) &&
           (item->val.uCount == expected);
}

static bool integer_label(const QCBORItem *item, int64_t expected) {
    return (item->uLabelType == QCBOR_TYPE_INT64) && (item->label.int64 == expected);
}

static enum composite_eat_status decode_digest(QCBORDecodeContext *decoder,
                                               const QCBORItem *container,
                                               struct composite_eat_device_record *record) {
    QCBORItem item;

    if ((container->uDataType != QCBOR_TYPE_ARRAY) || !definite_count(container, 2u) ||
        (container->uNestingLevel != 3u)) {
        return COMPOSITE_EAT_MALFORMED_REQUEST;
    }
    if ((get_next(decoder, &item) != COMPOSITE_EAT_OK) || (item.uNestingLevel != 4u) ||
        (item.uLabelType != QCBOR_TYPE_NONE) || (item.uDataType != QCBOR_TYPE_INT64) ||
        (item.val.int64 != COMPOSITE_EAT_COSE_ALGORITHM_SHA384)) {
        return COMPOSITE_EAT_MALFORMED_REQUEST;
    }
    if ((get_next(decoder, &item) != COMPOSITE_EAT_OK) || (item.uNestingLevel != 4u) ||
        (item.uLabelType != QCBOR_TYPE_NONE) || (item.uDataType != QCBOR_TYPE_BYTE_STRING) ||
        (item.val.string.len != COMPOSITE_EAT_SHA384_LENGTH)) {
        return COMPOSITE_EAT_MALFORMED_REQUEST;
    }

    memcpy(record->digest, item.val.string.ptr, sizeof(record->digest));
    return COMPOSITE_EAT_OK;
}

static enum composite_eat_status decode_record(QCBORDecodeContext *decoder,
                                               struct composite_eat_generation_request *request,
                                               size_t record_index) {
    struct composite_eat_device_record *record = &request->records[record_index];
    QCBORItem item;
    bool environment_seen = false;
    bool digest_seen = false;
    size_t field;

    if ((get_next(decoder, &item) != COMPOSITE_EAT_OK) || (item.uNestingLevel != 2u) ||
        (item.uLabelType != QCBOR_TYPE_NONE) || (item.uDataType != QCBOR_TYPE_MAP) ||
        !definite_count(&item, RECORD_FIELD_COUNT)) {
        return COMPOSITE_EAT_MALFORMED_REQUEST;
    }

    for (field = 0; field < RECORD_FIELD_COUNT; ++field) {
        if ((get_next(decoder, &item) != COMPOSITE_EAT_OK) || (item.uNestingLevel != 3u)) {
            return COMPOSITE_EAT_MALFORMED_REQUEST;
        }

        if (integer_label(&item, RECORD_KEY_ENVIRONMENT)) {
            if (environment_seen || (item.uDataType != QCBOR_TYPE_TEXT_STRING) ||
                (item.val.string.len == 0u) ||
                (item.val.string.len > COMPOSITE_EAT_MAX_ENVIRONMENT_LENGTH) ||
                (memchr(item.val.string.ptr, '\0', item.val.string.len) != NULL)) {
                return COMPOSITE_EAT_MALFORMED_REQUEST;
            }
            memcpy(record->environment, item.val.string.ptr, item.val.string.len);
            record->environment_length = item.val.string.len;
            environment_seen = true;
        } else if (integer_label(&item, RECORD_KEY_DIGEST)) {
            if (digest_seen || (decode_digest(decoder, &item, record) != COMPOSITE_EAT_OK)) {
                return COMPOSITE_EAT_MALFORMED_REQUEST;
            }
            digest_seen = true;
        } else {
            return COMPOSITE_EAT_MALFORMED_REQUEST;
        }
    }

    return (environment_seen && digest_seen) ? COMPOSITE_EAT_OK : COMPOSITE_EAT_MALFORMED_REQUEST;
}

enum composite_eat_status
composite_eat_generation_request_decode(const uint8_t *encoded, size_t encoded_length,
                                        struct composite_eat_generation_request *request) {
    QCBORDecodeContext decoder;
    QCBORItem item;
    bool version_seen = false;
    bool nonce_seen = false;
    bool records_seen = false;
    size_t field;
    enum composite_eat_status result = COMPOSITE_EAT_MALFORMED_REQUEST;

    if (request == NULL) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    if ((encoded == NULL) || (encoded_length == 0u) ||
        (encoded_length > COMPOSITE_EAT_MAX_GENERATION_REQUEST_LENGTH)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    QCBORDecode_Init(&decoder, (UsefulBufC){encoded, encoded_length}, QCBOR_DECODE_MODE_NORMAL);

    if ((get_next(&decoder, &item) != COMPOSITE_EAT_OK) || (item.uNestingLevel != 0u) ||
        (item.uLabelType != QCBOR_TYPE_NONE) || (item.uDataType != QCBOR_TYPE_MAP) ||
        !definite_count(&item, REQUEST_FIELD_COUNT)) {
        goto error;
    }

    for (field = 0; field < REQUEST_FIELD_COUNT; ++field) {
        if ((get_next(&decoder, &item) != COMPOSITE_EAT_OK) || (item.uNestingLevel != 1u)) {
            goto error;
        }

        if (integer_label(&item, REQUEST_KEY_VERSION)) {
            if (version_seen || (item.uDataType != QCBOR_TYPE_INT64)) {
                goto error;
            }
            if (item.val.int64 != COMPOSITE_EAT_GENERATION_REQUEST_VERSION) {
                result = COMPOSITE_EAT_BAD_VERSION;
                goto error;
            }
            request->version = (uint32_t)item.val.int64;
            version_seen = true;
        } else if (integer_label(&item, REQUEST_KEY_NONCE)) {
            if (nonce_seen || (item.uDataType != QCBOR_TYPE_BYTE_STRING) ||
                (item.val.string.len < COMPOSITE_EAT_MIN_NONCE_LENGTH) ||
                (item.val.string.len > COMPOSITE_EAT_MAX_NONCE_LENGTH)) {
                goto error;
            }
            memcpy(request->nonce, item.val.string.ptr, item.val.string.len);
            request->nonce_length = item.val.string.len;
            nonce_seen = true;
        } else if (integer_label(&item, REQUEST_KEY_RECORDS)) {
            size_t record;

            if (records_seen || (item.uDataType != QCBOR_TYPE_ARRAY) ||
                (item.uNestingLevel != 1u) ||
                (item.val.uCount == QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH)) {
                goto error;
            }
            if (item.val.uCount > COMPOSITE_EAT_MAX_DEVICE_RECORDS) {
                result = COMPOSITE_EAT_TOO_MANY_RECORDS;
                goto error;
            }
            request->record_count = item.val.uCount;
            for (record = 0; record < request->record_count; ++record) {
                if (decode_record(&decoder, request, record) != COMPOSITE_EAT_OK) {
                    goto error;
                }
            }
            records_seen = true;
        } else {
            goto error;
        }
    }

    if (!version_seen || !nonce_seen || !records_seen ||
        (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS) ||
        (composite_eat_validate_generation_request(request) != COMPOSITE_EAT_OK)) {
        goto error;
    }

    return COMPOSITE_EAT_OK;

error:
    memset(request, 0, sizeof(*request));
    return result;
}

static void add_request(QCBOREncodeContext *encoder,
                        const struct composite_eat_generation_request *request) {
    size_t record;

    QCBOREncode_OpenMap(encoder);
    QCBOREncode_AddInt64ToMapN(encoder, REQUEST_KEY_VERSION, request->version);
    QCBOREncode_AddBytesToMapN(encoder, REQUEST_KEY_NONCE,
                               (UsefulBufC){request->nonce, request->nonce_length});
    QCBOREncode_OpenArrayInMapN(encoder, REQUEST_KEY_RECORDS);
    for (record = 0; record < request->record_count; ++record) {
        QCBOREncode_OpenMap(encoder);
        QCBOREncode_AddTextToMapN(encoder, RECORD_KEY_ENVIRONMENT,
                                  (UsefulBufC){request->records[record].environment,
                                               request->records[record].environment_length});
        QCBOREncode_OpenArrayInMapN(encoder, RECORD_KEY_DIGEST);
        QCBOREncode_AddInt64(encoder, COMPOSITE_EAT_COSE_ALGORITHM_SHA384);
        QCBOREncode_AddBytes(encoder, (UsefulBufC){request->records[record].digest,
                                                   sizeof(request->records[record].digest)});
        QCBOREncode_CloseArray(encoder);
        QCBOREncode_CloseMap(encoder);
    }
    QCBOREncode_CloseArray(encoder);
    QCBOREncode_CloseMap(encoder);
}

enum composite_eat_status
composite_eat_generation_request_encode(const struct composite_eat_generation_request *request,
                                        uint8_t *encoded, size_t encoded_capacity,
                                        size_t *encoded_length) {
    QCBOREncodeContext encoder;
    UsefulBufC output;

    if (encoded_length == NULL) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }
    *encoded_length = 0u;
    if (((encoded == NULL) && (encoded_capacity != 0u)) ||
        (composite_eat_validate_generation_request(request) != COMPOSITE_EAT_OK)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    QCBOREncode_Init(&encoder, SizeCalculateUsefulBuf);
    add_request(&encoder, request);
    if (QCBOREncode_FinishGetSize(&encoder, encoded_length) != QCBOR_SUCCESS) {
        *encoded_length = 0;
        return COMPOSITE_EAT_ENCODING_ERROR;
    }
    if (*encoded_length > COMPOSITE_EAT_MAX_GENERATION_REQUEST_LENGTH) {
        *encoded_length = 0;
        return COMPOSITE_EAT_ENCODING_ERROR;
    }
    if (encoded_capacity < *encoded_length) {
        return COMPOSITE_EAT_BUFFER_TOO_SMALL;
    }

    QCBOREncode_Init(&encoder, (UsefulBuf){encoded, encoded_capacity});
    add_request(&encoder, request);
    if ((QCBOREncode_Finish(&encoder, &output) != QCBOR_SUCCESS) ||
        (output.len != *encoded_length)) {
        *encoded_length = 0;
        return COMPOSITE_EAT_ENCODING_ERROR;
    }

    return COMPOSITE_EAT_OK;
}
