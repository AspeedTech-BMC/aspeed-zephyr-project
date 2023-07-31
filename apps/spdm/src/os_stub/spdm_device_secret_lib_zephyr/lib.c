/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/
#include <logging/log.h>

LOG_MODULE_REGISTER(spdm_secret, CONFIG_LOG_DEFAULT_LEVEL);
#include <base.h>
#include <library/spdm_crypt_lib.h>
#include "hal/library/responder/asymsignlib.h"
#include "hal/library/responder/csrlib.h"
#include "hal/library/responder/measlib.h"
#include "hal/library/responder/psklib.h"
#include "hal/library/responder/setcertlib.h"
#include "hal/library/requester/reqasymsignlib.h"
#include "hal/library/requester/psklib.h"
#include "hal/library/debuglib.h"

#include "spdm_device_secret_lib_internal.h"
#include "ecp256/end_responder.key.der.h"
#include "ecp384/end_responder.key.der.h"

#include "raw_data_key.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
/**
 * Fill image hash measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_image_hash_block (
    bool use_bit_stream,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    size_t hash_size;
    uint8_t data[LIBSPDM_MEASUREMENT_RAW_DATA_SIZE];
    bool result;

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);

    measurement_block->measurement_block_common_header
    .index = measurements_index;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_set_mem(data, sizeof(data), (uint8_t)(measurements_index));

    if (!use_bit_stream) {
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_type =
            (measurements_index - 1);
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_size =
            (uint16_t)hash_size;

        measurement_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       (uint16_t)hash_size);

        result = libspdm_measurement_hash_all(
            measurement_hash_algo, data,
            sizeof(data),
            (void *)(measurement_block + 1));
        if (!result) {
            return 0;
        }

        return sizeof(spdm_measurement_block_dmtf_t) + hash_size;

    } else {
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_type =
            (measurements_index - 1) |
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
        measurement_block->measurement_block_dmtf_header
        .dmtf_spec_measurement_value_size =
            (uint16_t)sizeof(data);

        measurement_block->measurement_block_common_header
        .measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       (uint16_t)sizeof(data));

        libspdm_copy_mem((void *)(measurement_block + 1), sizeof(data), data, sizeof(data));

        return sizeof(spdm_measurement_block_dmtf_t) + sizeof(data);
    }
}

/**
 * Fill svn measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_svn_block (
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    spdm_measurements_secure_version_number_t svn;

    measurement_block->measurement_block_common_header
    .index = LIBSPDM_MEASUREMENT_INDEX_SVN;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    svn = 0x7;

    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_size =
        (uint16_t)sizeof(svn);

    measurement_block->measurement_block_common_header
    .measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)sizeof(svn));

    libspdm_copy_mem((void *)(measurement_block + 1), sizeof(svn), (void *)&svn, sizeof(svn));

    return sizeof(spdm_measurement_block_dmtf_t) + sizeof(svn);
}

/**
 * Fill manifest measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_manifest_block (
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    uint8_t data[LIBSPDM_MEASUREMENT_MANIFEST_SIZE];

    measurement_block->measurement_block_common_header
    .index = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_set_mem(data, sizeof(data),
                    (uint8_t)SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST);

    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_size =
        (uint16_t)sizeof(data);

    measurement_block->measurement_block_common_header
    .measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)sizeof(data));

    libspdm_copy_mem((void *)(measurement_block + 1), sizeof(data), data, sizeof(data));

    return sizeof(spdm_measurement_block_dmtf_t) + sizeof(data);
}

/**
 * Fill device mode measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_device_mode_block (
    spdm_measurement_block_dmtf_t *measurement_block
    )
{
    spdm_measurements_device_mode_t device_mode;

    measurement_block->measurement_block_common_header
    .index = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_DEVICE_MODE;
    measurement_block->measurement_block_common_header
    .measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    device_mode.operational_mode_capabilities =
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_MANUFACTURING_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_VALIDATION_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_NORMAL_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_RECOVERY_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_RMA_MODE |
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_DECOMMISSIONED_MODE;
    device_mode.operational_mode_state =
        SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_NORMAL_MODE;
    device_mode.device_mode_capabilities =
        SPDM_MEASUREMENT_DEVICE_MODE_NON_INVASIVE_DEBUG_MODE_IS_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_IS_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_NON_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE_AFTER_MFG;
    device_mode.device_mode_state =
        SPDM_MEASUREMENT_DEVICE_MODE_NON_INVASIVE_DEBUG_MODE_IS_ACTIVE |
        SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE_AFTER_MFG;

    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_DEVICE_MODE |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header
    .dmtf_spec_measurement_value_size =
        (uint16_t)sizeof(device_mode);

    measurement_block->measurement_block_common_header
    .measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)sizeof(device_mode));

    libspdm_copy_mem((void *)(measurement_block + 1), sizeof(device_mode),
                     (void *)&device_mode, sizeof(device_mode));

    return sizeof(spdm_measurement_block_dmtf_t) + sizeof(device_mode);
}

libspdm_return_t libspdm_measurement_collection(
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    uint8_t request_attribute,
    uint8_t *content_changed,
    uint8_t *measurements_count,
    void *measurements,
    size_t *measurements_size)
{
    spdm_measurement_block_dmtf_t *measurement_block;
    size_t hash_size;
    uint8_t index;
    size_t total_size_needed;
    bool use_bit_stream;
    size_t measurement_block_size;

    if ((measurement_specification !=
         SPDM_MEASUREMENT_SPECIFICATION_DMTF) ||
        (measurement_hash_algo == 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);
    LIBSPDM_ASSERT(hash_size != 0);

    use_bit_stream = false;
    if ((measurement_hash_algo == SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY) ||
        ((request_attribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED) !=
         0)) {
        use_bit_stream = true;
    }

    if (measurements_index ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
        *measurements_count = LIBSPDM_MEASUREMENT_BLOCK_NUMBER;
        goto successful_return;
    } else if (measurements_index ==
               SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {

        /* Calculate total_size_needed based on hash algo selected.
         * If we have an hash algo, then the first HASH_NUMBER elements will be
         * hash values, otherwise HASH_NUMBER raw bitstream values.*/
        if (!use_bit_stream) {
            total_size_needed =
                LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                (sizeof(spdm_measurement_block_dmtf_t) + hash_size);
        } else {
            total_size_needed =
                LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                (sizeof(spdm_measurement_block_dmtf_t) + LIBSPDM_MEASUREMENT_RAW_DATA_SIZE);
        }
        /* Next one - SVN is always raw bitstream data.*/
        total_size_needed +=
            (sizeof(spdm_measurement_block_dmtf_t) +
             sizeof(spdm_measurements_secure_version_number_t));
        /* Next one - manifest is always raw bitstream data.*/
        total_size_needed +=
            (sizeof(spdm_measurement_block_dmtf_t) + LIBSPDM_MEASUREMENT_MANIFEST_SIZE);
        /* Next one - device_mode is always raw bitstream data.*/
        total_size_needed +=
            (sizeof(spdm_measurement_block_dmtf_t) + sizeof(spdm_measurements_device_mode_t));

        LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
        if (total_size_needed > *measurements_size) {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }

        *measurements_size = total_size_needed;
        *measurements_count = LIBSPDM_MEASUREMENT_BLOCK_NUMBER;
        measurement_block = measurements;

        /* The first HASH_NUMBER blocks may be hash values or raw bitstream*/
        for (index = 1; index <= LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER; index++) {
            measurement_block_size = libspdm_fill_measurement_image_hash_block (use_bit_stream,
                                                                                measurement_hash_algo,
                                                                                index,
                                                                                measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        /* Next one - SVN is always raw bitstream data.*/
        {
            measurement_block_size = libspdm_fill_measurement_svn_block (measurement_block);
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        /* Next one - manifest is always raw bitstream data.*/
        {
            measurement_block_size = libspdm_fill_measurement_manifest_block (measurement_block);
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        /* Next one - device_mode is always raw bitstream data.*/
        {
            measurement_block_size = libspdm_fill_measurement_device_mode_block (measurement_block);
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }

        goto successful_return;
    } else {
        /* One Index */
        if (measurements_index <= LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER) {
            if (!use_bit_stream) {
                total_size_needed =
                    sizeof(spdm_measurement_block_dmtf_t) +
                    hash_size;
            } else {
                total_size_needed =
                    sizeof(spdm_measurement_block_dmtf_t) +
                    LIBSPDM_MEASUREMENT_RAW_DATA_SIZE;
            }
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_image_hash_block (use_bit_stream,
                                                                                measurement_hash_algo,
                                                                                measurements_index,
                                                                                measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else if (measurements_index == LIBSPDM_MEASUREMENT_INDEX_SVN) {
            total_size_needed =
                sizeof(spdm_measurement_block_dmtf_t) +
                sizeof(spdm_measurements_secure_version_number_t);
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_svn_block (measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else if (measurements_index ==
                   SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST) {
            total_size_needed =
                sizeof(spdm_measurement_block_dmtf_t) +
                LIBSPDM_MEASUREMENT_MANIFEST_SIZE;
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_manifest_block (measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else if (measurements_index == SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_DEVICE_MODE) {
            total_size_needed =
                sizeof(spdm_measurement_block_dmtf_t) +
                sizeof(spdm_measurements_device_mode_t);
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_measurement_device_mode_block (measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else {
            *measurements_count = 0;
            return LIBSPDM_STATUS_MEAS_INVALID_INDEX;
        }
    }

successful_return:
    if ((content_changed != NULL) &&
        ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_12)) {
        /* return content change*/
        if ((request_attribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
            0) {
            *content_changed = SPDM_MEASUREMENTS_RESPONSE_CONTENT_NO_CHANGE_DETECTED;
        } else {
            *content_changed = SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_NO_DETECTION;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}


bool libspdm_measurement_opaque_data(
	spdm_version_number_t spdm_version,
	uint8_t measurement_specification,
	uint32_t measurement_hash_algo,
	uint8_t measurement_index,
	uint8_t request_attribute,
	void *opaque_data,
	size_t *opaque_data_size)
{
	*opaque_data_size = 0;
	return true;
}

bool libspdm_challenge_opaque_data(
	spdm_version_number_t spdm_version,
	uint8_t slot_id,
	uint8_t *measurement_summary_hash,
	size_t measurement_summary_hash_size,
	void *opaque_data,
	size_t *opaque_data_size)
{
	*opaque_data_size = 0;
	return true;
}

bool libspdm_encap_challenge_opaque_data(
	spdm_version_number_t spdm_version,
	uint8_t slot_id,
	uint8_t *measurement_summary_hash,
	size_t measurement_summary_hash_size,
	void *opaque_data,
	size_t *opaque_data_size)
{
	LOG_ERR("libspdm_encap_challenge_opaque_data");
	*opaque_data_size = 0;
	return true;
}

bool libspdm_generate_measurement_summary_hash(
	spdm_version_number_t spdm_version,
	uint32_t base_hash_algo,
	uint8_t measurement_specification,
	uint32_t measurement_hash_algo,
	uint8_t measurement_summary_hash_type,
	uint8_t  *measurement_summary_hash,
	uint32_t measurement_summary_hash_size)
{
    uint8_t measurement_data[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    size_t index;
    spdm_measurement_block_dmtf_t *cached_measurment_block;
    size_t measurment_data_size;
    size_t measurment_block_size;
    uint8_t device_measurement[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t device_measurement_count;
    size_t device_measurement_size;
    libspdm_return_t status;
    bool result;

    switch (measurement_summary_hash_type) {
    case SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
        break;

    case SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
    case SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH:
        if (measurement_summary_hash_size != libspdm_get_hash_size(base_hash_algo)) {
            return false;
        }

        /* get all measurement data*/
        device_measurement_size = sizeof(device_measurement);
        status = libspdm_measurement_collection(
            spdm_version, measurement_specification,
            measurement_hash_algo,
            0xFF, /* Get all measurements*/
            0,
            NULL,
            &device_measurement_count, device_measurement,
            &device_measurement_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return false;
        }

        /* double confirm that MeasurmentData internal size is correct*/
        measurment_data_size = 0;
        cached_measurment_block = (void *)device_measurement;
        for (index = 0; index < device_measurement_count; index++) {
            measurment_block_size =
                sizeof(spdm_measurement_block_common_header_t) +
                cached_measurment_block
                ->measurement_block_common_header
                .measurement_size;
            LIBSPDM_ASSERT(cached_measurment_block
                           ->measurement_block_common_header
                           .measurement_size ==
                           sizeof(spdm_measurement_block_dmtf_header_t) +
                           cached_measurment_block
                           ->measurement_block_dmtf_header
                           .dmtf_spec_measurement_value_size);
            measurment_data_size +=
                cached_measurment_block
                ->measurement_block_common_header
                .measurement_size;
            cached_measurment_block =
                (void *)((size_t)cached_measurment_block +
                         measurment_block_size);
        }

        LIBSPDM_ASSERT(measurment_data_size <=
                       LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE);

        /* get required data and hash them*/
        cached_measurment_block = (void *)device_measurement;
        measurment_data_size = 0;
        for (index = 0; index < device_measurement_count; index++) {
            measurment_block_size =
                sizeof(spdm_measurement_block_common_header_t) +
                cached_measurment_block
                ->measurement_block_common_header
                .measurement_size;
            /* filter unneeded data*/
            if ((measurement_summary_hash_type ==
                 SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH) ||
                ((cached_measurment_block
                  ->measurement_block_dmtf_header
                  .dmtf_spec_measurement_value_type &
                  SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK) ==
                 SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM)) {
                if (spdm_version < (SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT)) {
                    libspdm_copy_mem(&measurement_data[measurment_data_size],
                                     sizeof(measurement_data)
                                     - (&measurement_data[measurment_data_size] - measurement_data),
                                     &cached_measurment_block->measurement_block_dmtf_header,
                                     cached_measurment_block->measurement_block_common_header
                                     .measurement_size);

                    measurment_data_size +=
                        cached_measurment_block
                        ->measurement_block_common_header
                        .measurement_size;
                } else {
                    libspdm_copy_mem(&measurement_data[measurment_data_size],
                                     sizeof(measurement_data)
                                     - (&measurement_data[measurment_data_size] - measurement_data),
                                     cached_measurment_block,
                                     sizeof(cached_measurment_block->measurement_block_common_header) +
                                     cached_measurment_block->measurement_block_common_header
                                     .measurement_size);

                    measurment_data_size +=
                        sizeof(cached_measurment_block->measurement_block_common_header) +
                        cached_measurment_block
                        ->measurement_block_common_header
                        .measurement_size;
                }
            }
            cached_measurment_block =
                (void *)((size_t)cached_measurment_block +
                         measurment_block_size);
        }

        result = libspdm_hash_all(base_hash_algo, measurement_data,
                                  measurment_data_size, measurement_summary_hash);
        if (!result) {
            return false;
        }
        break;
    default:
        return false;
        break;
    }
    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
bool libspdm_requester_data_sign(
	spdm_version_number_t spdm_version, uint8_t op_code,
	uint16_t req_base_asym_alg,
	uint32_t base_hash_algo, bool is_data_hash,
	const uint8_t *message, size_t message_size,
	uint8_t *signature, size_t *sig_size)
{
	LOG_ERR("libspdm_requester_data_sign");
	return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

#if LIBSPDM_ECDSA_SUPPORT
uint8_t m_libspdm_ec256_responder_private_key[] = LIBSPDM_EC256_RESPONDER_PRIVATE_KEY;
uint8_t m_libspdm_ec256_responder_public_key[] = LIBSPDM_EC256_RESPONDER_PUBLIC_KEY;

uint8_t m_libspdm_ec384_responder_private_key[] = LIBSPDM_EC384_RESPONDER_PRIVATE_KEY;
uint8_t m_libspdm_ec384_responder_public_key[] = LIBSPDM_EC384_RESPONDER_PUBLIC_KEY;

uint8_t m_libspdm_ec521_responder_private_key[] = LIBSPDM_EC521_RESPONDER_PRIVATE_KEY;
uint8_t m_libspdm_ec521_responder_public_key[] = LIBSPDM_EC521_RESPONDER_PUBLIC_KEY;

uint8_t m_libspdm_ec256_requester_private_key[] = LIBSPDM_EC256_REQUESTER_PRIVATE_KEY;
uint8_t m_libspdm_ec256_requester_public_key[] = LIBSPDM_EC256_REQUESTER_PUBLIC_KEY;

uint8_t m_libspdm_ec384_requester_private_key[] = LIBSPDM_EC384_REQUESTER_PRIVATE_KEY;
uint8_t m_libspdm_ec384_requester_public_key[] = LIBSPDM_EC384_REQUESTER_PUBLIC_KEY;

uint8_t m_libspdm_ec521_requester_private_key[] = LIBSPDM_EC521_REQUESTER_PRIVATE_KEY;
uint8_t m_libspdm_ec521_requester_public_key[] = LIBSPDM_EC521_REQUESTER_PUBLIC_KEY;
#endif /*LIBSPDM_ECDSA_SUPPORT*/

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
uint8_t m_libspdm_rsa2048_res_n[] = LIBSPDM_RSA2048_RES_N;
uint8_t m_libspdm_rsa2048_res_e[] = LIBSPDM_RSA2048_RES_E;
uint8_t m_libspdm_rsa2048_res_d[] = LIBSPDM_RSA2048_RES_D;
uint8_t m_libspdm_rsa3072_res_n[] = LIBSPDM_RSA3072_RES_N;
uint8_t m_libspdm_rsa3072_res_e[] = LIBSPDM_RSA3072_RES_E;
uint8_t m_libspdm_rsa3072_res_d[] = LIBSPDM_RSA3072_RES_D;
uint8_t m_libspdm_rsa4096_res_n[] = LIBSPDM_RSA4096_RES_N;
uint8_t m_libspdm_rsa4096_res_e[] = LIBSPDM_RSA4096_RES_E;
uint8_t m_libspdm_rsa4096_res_d[] = LIBSPDM_RSA4096_RES_D;
uint8_t m_libspdm_rsa2048_req_n[] = LIBSPDM_RSA2048_REQ_N;
uint8_t m_libspdm_rsa2048_req_e[] = LIBSPDM_RSA2048_REQ_E;
uint8_t m_libspdm_rsa2048_req_d[] = LIBSPDM_RSA2048_REQ_D;
uint8_t m_libspdm_rsa3072_req_n[] = LIBSPDM_RSA3072_REQ_N;
uint8_t m_libspdm_rsa3072_req_e[] = LIBSPDM_RSA3072_REQ_E;
uint8_t m_libspdm_rsa3072_req_d[] = LIBSPDM_RSA3072_REQ_D;
uint8_t m_libspdm_rsa4096_req_n[] = LIBSPDM_RSA4096_REQ_N;
uint8_t m_libspdm_rsa4096_req_e[] = LIBSPDM_RSA4096_REQ_E;
uint8_t m_libspdm_rsa4096_req_d[] = LIBSPDM_RSA4096_REQ_D;
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

bool libspdm_get_responder_private_key_from_raw_data(uint32_t base_asym_algo, void **context)
{
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) || (LIBSPDM_ECDSA_SUPPORT)
    bool result;

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
    void *rsa_context;
    uint8_t *rsa_n;
    uint8_t *rsa_e;
    uint8_t *rsa_d;
    size_t rsa_n_size;
    size_t rsa_e_size;
    size_t rsa_d_size;
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_ECDSA_SUPPORT
    void *ec_context;
    size_t ec_nid;
    uint8_t *ec_public;
    uint8_t *ec_private;
    size_t ec_public_size;
    size_t ec_private_size;
#endif /*LIBSPDM_ECDSA_SUPPORT*/

    switch (base_asym_algo) {
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        rsa_n = m_libspdm_rsa2048_res_n;
        rsa_e = m_libspdm_rsa2048_res_e;
        rsa_d = m_libspdm_rsa2048_res_d;
        rsa_n_size = sizeof(m_libspdm_rsa2048_res_n);
        rsa_e_size = sizeof(m_libspdm_rsa2048_res_e);
        rsa_d_size = sizeof(m_libspdm_rsa2048_res_d);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        rsa_n = m_libspdm_rsa3072_res_n;
        rsa_e = m_libspdm_rsa3072_res_e;
        rsa_d = m_libspdm_rsa3072_res_d;
        rsa_n_size = sizeof(m_libspdm_rsa3072_res_n);
        rsa_e_size = sizeof(m_libspdm_rsa3072_res_e);
        rsa_d_size = sizeof(m_libspdm_rsa3072_res_d);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        rsa_n = m_libspdm_rsa4096_res_n;
        rsa_e = m_libspdm_rsa4096_res_e;
        rsa_d = m_libspdm_rsa4096_res_d;
        rsa_n_size = sizeof(m_libspdm_rsa4096_res_n);
        rsa_e_size = sizeof(m_libspdm_rsa4096_res_e);
        rsa_d_size = sizeof(m_libspdm_rsa4096_res_d);
        break;
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_ECDSA_SUPPORT
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        ec_nid = LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256;
        ec_public = m_libspdm_ec256_responder_public_key;
        ec_private = m_libspdm_ec256_responder_private_key;
        ec_public_size = sizeof(m_libspdm_ec256_responder_public_key);
        ec_private_size = sizeof(m_libspdm_ec256_responder_private_key);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        ec_nid = LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384;
        ec_public = m_libspdm_ec384_responder_public_key;
        ec_private = m_libspdm_ec384_responder_private_key;
        ec_public_size = sizeof(m_libspdm_ec384_responder_public_key);
        ec_private_size = sizeof(m_libspdm_ec384_responder_private_key);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        ec_nid = LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521;
        ec_public = m_libspdm_ec521_responder_public_key;
        ec_private = m_libspdm_ec521_responder_private_key;
        ec_public_size = sizeof(m_libspdm_ec521_responder_public_key);
        ec_private_size = sizeof(m_libspdm_ec521_responder_private_key);
        break;
#endif /*LIBSPDM_ECDSA_SUPPORT*/
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
        rsa_context = libspdm_rsa_new();
        if (rsa_context == NULL) {
            return false;
        }
        result = libspdm_rsa_set_key(rsa_context, LIBSPDM_RSA_KEY_N, rsa_n, rsa_n_size);
        if (!result) {
            libspdm_rsa_free(rsa_context);
            return false;
        }
        result = libspdm_rsa_set_key(rsa_context, LIBSPDM_RSA_KEY_E, rsa_e, rsa_e_size);
        if (!result) {
            libspdm_rsa_free(rsa_context);
            return false;
        }
        result = libspdm_rsa_set_key(rsa_context, LIBSPDM_RSA_KEY_D, rsa_d, rsa_d_size);
        if (!result) {
            libspdm_rsa_free(rsa_context);
            return false;
        }
        *context = rsa_context;
        return true;
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
        ec_context = libspdm_ec_new_by_nid(ec_nid);
        if (ec_context == NULL) {
            return false;
        }
        result = libspdm_ec_set_pub_key(ec_context, ec_public, ec_public_size);
        if (!result) {
            libspdm_ec_free(ec_context);
            return false;
        }
        result = libspdm_ec_set_priv_key(ec_context, ec_private, ec_private_size);
        if (!result) {
            libspdm_ec_free(ec_context);
            return false;
        }
        *context = ec_context;
        return true;
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif /*#LIBSPDM_ECDSA_SUPPORT*/
    }

#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) || (LIBSPDM_ECDSA_SUPPORT) */
    return false;
}

bool libspdm_responder_data_sign(
	spdm_version_number_t spdm_version, uint8_t op_code,
	uint32_t base_asym_algo,
	uint32_t base_hash_algo, bool is_data_hash,
	const uint8_t *message, size_t message_size,
	uint8_t *signature, size_t *sig_size)
{
	void *context;
	bool result;
	result = libspdm_get_responder_private_key_from_raw_data(base_asym_algo, &context);
	if (!result) {
		LOG_ERR("Failed to load responder private key");
		return false;
	}

	if (is_data_hash) {
		result = libspdm_asym_sign_hash(spdm_version, op_code, base_asym_algo, base_hash_algo,
				  context,
				  message, message_size, signature, sig_size);
		LOG_DBG("libspdm_asym_sign_hash result=%d", result);
	} else {
		result = libspdm_asym_sign(spdm_version, op_code, base_asym_algo,
			     base_hash_algo, context,
			     message, message_size,
			     signature, sig_size);
		LOG_DBG("libspdm_asym_sign result=%d", result);
	}
	libspdm_asym_free(base_asym_algo, context);

	return result;
}


#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
bool libspdm_psk_handshake_secret_hkdf_expand(
	spdm_version_number_t spdm_version,
	uint32_t base_hash_algo,
	const uint8_t *psk_hint,
	size_t psk_hint_size,
	const uint8_t *info,
	size_t info_size,
	uint8_t *out, size_t out_size)
{
	LOG_ERR("libspdm_psk_handshake_secret_hkdf_expand");
	return false;
}

bool libspdm_psk_master_secret_hkdf_expand(
	spdm_version_number_t spdm_version,
	uint32_t base_hash_algo,
	const uint8_t *psk_hint,
	size_t psk_hint_size,
	const uint8_t *info,
	size_t info_size, uint8_t *out,
	size_t out_size)
{
	LOG_ERR("libspdm_psk_master_secret_hkdf_expand");
	return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
bool libspdm_is_in_trusted_environment()
{
	LOG_ERR("libspdm_is_in_trusted_environment");
	return false;
}

bool libspdm_write_certificate_to_nvm(uint8_t slot_id, const void * cert_chain,
				      size_t cert_chain_size,
				      uint32_t base_hash_algo, uint32_t base_asym_algo)
{
	LOG_ERR("libspdm_write_certificate_to_nvm");
	return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
bool libspdm_gen_csr(uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
		     const void *request, size_t request_size,
		     uint8_t *requester_info, size_t requester_info_length,
		     uint8_t *opaque_data, uint16_t opaque_data_length,
		     size_t *csr_len, uint8_t *csr_pointer,
		     bool is_device_cert_model)
{
	LOG_ERR("libspdm_gen_csr");
	return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */

