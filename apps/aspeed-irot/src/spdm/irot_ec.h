/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 * SPDX-License-Identifier: MIT
 */

#pragma once

/*
 * libspdm EC context that stands for the responder identity key held by
 * Caliptra. libspdm_responder_data_sign() passes &irot_caliptra_identity_key as
 * the signing context and ec.c's libspdm_ecdsa_sign() routes only that context
 * to Caliptra DPE SIGN. A NULL context is rejected, so a failed key load can
 * never fall back to signing with the device identity key.
 */
extern char irot_caliptra_identity_key;
