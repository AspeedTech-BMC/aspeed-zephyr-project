/* SPDX-License-Identifier: Apache-2.0 */

#ifndef COMPOSITE_EAT_TYPES_H
#define COMPOSITE_EAT_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "composite_eat/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Generation-request wire-schema version and bounded input capacities. */
#define COMPOSITE_EAT_GENERATION_REQUEST_VERSION 1u
#define COMPOSITE_EAT_MAX_DEVICE_RECORDS 64u
#define COMPOSITE_EAT_MIN_NONCE_LENGTH 8u
#define COMPOSITE_EAT_MAX_NONCE_LENGTH 64u
#define COMPOSITE_EAT_MAX_ENVIRONMENT_LENGTH 64u
#define COMPOSITE_EAT_SHA384_LENGTH 48u
#define COMPOSITE_EAT_ES384_SIGNATURE_LENGTH 96u
#define COMPOSITE_EAT_MAX_CERTIFICATES 7u
#define COMPOSITE_EAT_MAX_CERTIFICATE_LENGTH 4096u
#define COMPOSITE_EAT_MAX_LOCAL_EVIDENCE 4u
#define COMPOSITE_EAT_MAX_LOCAL_EVIDENCE_LENGTH 4096u
#define COMPOSITE_EAT_MAX_PROFILE_LENGTH 128u
#define COMPOSITE_EAT_MAX_GENERATION_REQUEST_LENGTH 8192u

/* Fixed token-builder workspace and signed main-token output capacities. */
#define COMPOSITE_EAT_PAYLOAD_MAX 9216u
#define COMPOSITE_EAT_PROTECTED_MAX 160u
#define COMPOSITE_EAT_MAX_RESPONSE_LENGTH 26624u

#define COMPOSITE_EAT_COSE_ALGORITHM_ES384 (-35)
#define COMPOSITE_EAT_COSE_ALGORITHM_SHA384 (-43)

struct composite_eat_buffer {
    /* Borrowed immutable bytes; data must be non-NULL when length is nonzero. */
    const uint8_t *data;
    size_t length;
};

struct composite_eat_device_record {
    /* Non-NUL-terminated env.* identifier; unused bytes have no meaning. */
    uint8_t environment[COMPOSITE_EAT_MAX_ENVIRONMENT_LENGTH];
    size_t environment_length;
    /* SHA-384 over the encoded detached Claims-Set for this environment. */
    uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH];
};

/* Typed form of the private Composite EAT generation request. */
struct composite_eat_generation_request {
    /* Must equal COMPOSITE_EAT_GENERATION_REQUEST_VERSION. */
    uint32_t version;
    /* Verifier nonce bytes; only the first nonce_length bytes are consumed. */
    uint8_t nonce[COMPOSITE_EAT_MAX_NONCE_LENGTH];
    size_t nonce_length;
    /* Device digest records; only the first record_count entries are consumed. */
    struct composite_eat_device_record records[COMPOSITE_EAT_MAX_DEVICE_RECORDS];
    size_t record_count;
};

struct composite_eat_local_evidence {
    /* CoAP Content-Format identifying the opaque encoded evidence. */
    uint16_t content_format;
    struct composite_eat_buffer encoded;
};

/* One coherent, platform-authorized evidence snapshot consumed by prepare. */
struct composite_eat_evidence_snapshot {
    /* EAT UEID bytes, including the UEID type byte; length must be 7..33. */
    struct composite_eat_buffer ueid;
    /* UTF-8 EAT profile URI with no embedded NUL; semantics are platform policy. */
    struct composite_eat_buffer profile;
    /* Borrowed array containing 1..COMPOSITE_EAT_MAX_LOCAL_EVIDENCE entries. */
    const struct composite_eat_local_evidence *local_evidence;
    size_t local_evidence_count;
};

struct composite_eat_der_certificate {
    /* Borrowed immutable canonical DER bytes. */
    const uint8_t *data;
    size_t length;
};

struct composite_eat_attestation_identity {
    /* Borrowed canonical DER certificates, leaf first and issuer-by-issuer. */
    const struct composite_eat_der_certificate *certificates;
    size_t certificate_count;
};

/*
 * Caller-owned fixed storage. Treat fields as opaque outside SDK calls; no
 * caller initialization is required before prepare.
 */
struct composite_eat_workspace {
    uint8_t protected_headers[COMPOSITE_EAT_PROTECTED_MAX];
    size_t protected_headers_length;
    uint8_t payload[COMPOSITE_EAT_PAYLOAD_MAX];
    size_t payload_length;
};

/*
 * Caller-owned operation state. Treat fields as opaque outside SDK calls; no
 * caller initialization is required before prepare.
 */
struct composite_eat_prepared {
    struct composite_eat_workspace *workspace;
    const struct composite_eat_attestation_identity *identity;
    size_t signing_part;
    uint8_t header[5];
    bool ready;
};

/* Validate the typed request without modifying it; returns OK or BAD_ARGUMENT. */
enum composite_eat_status
composite_eat_validate_generation_request(const struct composite_eat_generation_request *request);

/*
 * Validate evidence buffer presence, encoding bounds, UEID length, and profile
 * text structure. This does not authenticate evidence, parse local evidence,
 * validate URI syntax, or authorize a profile. Returns OK or BAD_ARGUMENT.
 */
enum composite_eat_status
composite_eat_validate_evidence_snapshot(const struct composite_eat_evidence_snapshot *evidence);

/*
 * Validate certificate-view presence and bounds. This does not parse X.509,
 * validate a path, check order, or bind the leaf to a signing key. Returns OK
 * or BAD_ARGUMENT.
 */
enum composite_eat_status composite_eat_validate_attestation_identity(
    const struct composite_eat_attestation_identity *identity);

#ifdef __cplusplus
}
#endif

#endif
