/* SPDX-License-Identifier: Apache-2.0 */

#ifndef COMPOSITE_EAT_STATUS_H
#define COMPOSITE_EAT_STATUS_H

enum composite_eat_status {
    /* The operation succeeded; signing_input_next returned one segment. */
    COMPOSITE_EAT_OK = 0,
    /* signing_input_next has no more segments; the caller may call finish. */
    COMPOSITE_EAT_DONE = 1,
    /* A pointer, length, typed field, or combination of arguments is invalid. */
    COMPOSITE_EAT_BAD_ARGUMENT = -1,
    /* Encoded generation-request CBOR violates the versioned wire schema. */
    COMPOSITE_EAT_MALFORMED_REQUEST = -2,
    /* The generation-request schema version is unsupported. */
    COMPOSITE_EAT_BAD_VERSION = -3,
    /* Encoded generation-request CBOR contains too many device records. */
    COMPOSITE_EAT_TOO_MANY_RECORDS = -4,
    /* Output capacity is insufficient; the output length reports the requirement. */
    COMPOSITE_EAT_BUFFER_TOO_SMALL = -5,
    /* Valid inputs cannot be encoded within the SDK's fixed workspace or output limit. */
    COMPOSITE_EAT_ENCODING_ERROR = -6,
    /* A split-phase builder function was called out of sequence. */
    COMPOSITE_EAT_STATE_ERROR = -7,
};

#endif
