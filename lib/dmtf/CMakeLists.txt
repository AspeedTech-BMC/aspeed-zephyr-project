# Copyright (c) 2023 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

if (CONFIG_DMTF_LIBSPDM)
zephyr_interface_library_named(dmtf_libspdm)

target_include_directories(dmtf_libspdm INTERFACE
	include
	libspdm/include
	libspdm/include/hal
	libspdm/os_stub
	libspdm/os_stub/include
	libspdm/os_stub/cryptlib_mbedtls
)

zephyr_library()
zephyr_library_link_libraries(mbedTLS)

if (CONFIG_DMTF_LIBSPDM_CONFIG_FILE)
	target_compile_definitions(dmtf_libspdm INTERFACE
		LIBSPDM_CONFIG="${CONFIG_DMTF_LIBSPDM_CONFIG_FILE}")
endif()

# os_stub
zephyr_library_sources(
	libspdm/os_stub/malloclib/malloclib.c
	libspdm/os_stub/debuglib/debuglib.c
	libspdm/os_stub/cryptlib_mbedtls/cipher/aead_aes_gcm.c
	libspdm/os_stub/cryptlib_mbedtls/cipher/aead_chacha20_poly1305.c
	libspdm/os_stub/cryptlib_mbedtls/cipher/aead_sm4_gcm.c
	libspdm/os_stub/cryptlib_mbedtls/der/der.c
	libspdm/os_stub/cryptlib_mbedtls/hash/sha.c
	libspdm/os_stub/cryptlib_mbedtls/hash/sha3.c
	libspdm/os_stub/cryptlib_mbedtls/hash/sm3.c
	libspdm/os_stub/cryptlib_mbedtls/hmac/hmac_sha.c
	libspdm/os_stub/cryptlib_mbedtls/hmac/hmac_sha3.c
	libspdm/os_stub/cryptlib_mbedtls/hmac/hmac_sm3.c
	libspdm/os_stub/cryptlib_mbedtls/kdf/hkdf_sha.c
	libspdm/os_stub/cryptlib_mbedtls/kdf/hkdf_sha3.c
	libspdm/os_stub/cryptlib_mbedtls/kdf/hkdf_sm3.c
	libspdm/os_stub/cryptlib_mbedtls/pem/pem.c
	libspdm/os_stub/cryptlib_mbedtls/pk/ec.c
	libspdm/os_stub/cryptlib_mbedtls/pk/ecd.c
	libspdm/os_stub/cryptlib_mbedtls/pk/dh.c
	libspdm/os_stub/cryptlib_mbedtls/pk/sm2.c
	libspdm/os_stub/cryptlib_mbedtls/pk/rsa_basic.c
	libspdm/os_stub/cryptlib_mbedtls/pk/rsa_ext.c
	libspdm/os_stub/cryptlib_mbedtls/pk/x509.c
	libspdm/os_stub/cryptlib_mbedtls/rand/rand.c
	libspdm/os_stub/cryptlib_mbedtls/sys_call/crt_wrapper_host.c
	libspdm/os_stub/cryptlib_mbedtls/sys_call/mem_allocation.c
)

# spdm common library
zephyr_library_sources(
	libspdm/library/spdm_common_lib/libspdm_com_context_data.c
	libspdm/library/spdm_common_lib/libspdm_com_crypto_service.c
	libspdm/library/spdm_common_lib/libspdm_com_msg_log.c
	libspdm/library/spdm_common_lib/libspdm_com_support.c
	libspdm/library/spdm_common_lib/libspdm_com_context_data_session.c
	libspdm/library/spdm_common_lib/libspdm_com_crypto_service_session.c
	libspdm/library/spdm_common_lib/libspdm_com_opaque_data.c

	libspdm/library/spdm_crypt_lib/libspdm_crypt_aead.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_asym.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_cert.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_dhe.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_hash.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_hkdf.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_hmac.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_rng.c

	libspdm/library/spdm_requester_lib/libspdm_req_challenge.c
	libspdm/library/spdm_requester_lib/libspdm_req_common.c
	libspdm/library/spdm_requester_lib/libspdm_req_communication.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_certificate.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_challenge_auth.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_digests.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_error.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_key_update.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_request.c
	libspdm/library/spdm_requester_lib/libspdm_req_end_session.c
	libspdm/library/spdm_requester_lib/libspdm_req_finish.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_capabilities.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_certificate.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_csr.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_digests.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_event_types.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_key_pair_info.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_measurement_extension_log.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_measurements.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_version.c
	libspdm/library/spdm_requester_lib/libspdm_req_handle_error_response.c
	libspdm/library/spdm_requester_lib/libspdm_req_heartbeat.c
	libspdm/library/spdm_requester_lib/libspdm_req_key_exchange.c
	libspdm/library/spdm_requester_lib/libspdm_req_key_update.c
	libspdm/library/spdm_requester_lib/libspdm_req_negotiate_algorithms.c
	libspdm/library/spdm_requester_lib/libspdm_req_psk_exchange.c
	libspdm/library/spdm_requester_lib/libspdm_req_psk_finish.c
	libspdm/library/spdm_requester_lib/libspdm_req_send_receive.c
	libspdm/library/spdm_requester_lib/libspdm_req_set_certificate.c
	libspdm/library/spdm_requester_lib/libspdm_req_set_key_pair_info.c
	libspdm/library/spdm_requester_lib/libspdm_req_subscribe_event_types.c
	libspdm/library/spdm_requester_lib/libspdm_req_vendor_request.c

	libspdm/library/spdm_responder_lib/libspdm_rsp_algorithms.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_capabilities.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_certificate.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_challenge_auth.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_chunk_get.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_chunk_send_ack.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_common.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_communication.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_csr.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_digests.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_encap_challenge.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_encap_get_certificate.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_encap_get_digests.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_encap_key_update.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_encap_response.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_end_session.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_error.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_finish.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_get_key_pair_info.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_handle_response_state.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_heartbeat.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_key_exchange.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_key_update.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_measurement_extension_log.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_measurements.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_psk_exchange.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_psk_finish.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_receive_send.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_respond_if_ready.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_set_certificate.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_set_key_pair_info_ack.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_subscribe_event_types_ack.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_supported_event_types.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_vendor_response.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_version.c

	libspdm/library/spdm_secured_message_lib/libspdm_secmes_context_data.c
	libspdm/library/spdm_secured_message_lib/libspdm_secmes_encode_decode.c
	libspdm/library/spdm_secured_message_lib/libspdm_secmes_key_exchange.c
	libspdm/library/spdm_secured_message_lib/libspdm_secmes_session.c

	libspdm/library/spdm_transport_mctp_lib/libspdm_mctp_common.c
	libspdm/library/spdm_transport_mctp_lib/libspdm_mctp_mctp.c


	libspdm/os_stub/memlib/compare_mem.c
	libspdm/os_stub/memlib/copy_mem.c
	libspdm/os_stub/memlib/set_mem.c
	libspdm/os_stub/memlib/zero_mem.c

	libspdm/os_stub/spdm_crypt_ext_lib/spdm_crypt_ext.c
)

zephyr_library_link_libraries(dmtf_libspdm)

endif()

