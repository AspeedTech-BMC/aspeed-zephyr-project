/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <stdint.h>
#include "state_machine/common_smc.h"
#include "pfr/pfr_common.h"
#include "intel_pfr_definitions.h"
#include "pfr/pfr_util.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_key_cancellation.h"
#include "intel_pfr_verification.h"
#include "Smbus_mailbox/Smbus_mailbox.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int intel_pfr_manifest_verify(struct manifest *manifest, struct hash_engine *hash,
			      struct signature_verification *verification, uint8_t *hash_out, uint32_t hash_length)
{
	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) manifest;
	uint32_t pc_type = 0;
	int status = 0;

	ARG_UNUSED(hash);
	ARG_UNUSED(verification);
	ARG_UNUSED(hash_out);
	ARG_UNUSED(hash_length);
	ARG_UNUSED(verification);

	init_pfr_authentication(pfr_manifest->pfr_authentication);

	status = pfr_spi_read(pfr_manifest->image_type, pfr_manifest->address + BLOCK0_PCTYPE_ADDRESS, sizeof(pc_type), (uint8_t *)&pc_type);
	if (status != Success) {
		LOG_ERR("Flash read PC type failed");
		return Failure;
	}

	// Validate PC type
	status = pfr_manifest->pfr_authentication->validate_pctye(pfr_manifest, pc_type);
	if (status != Success)
		return Failure;

	// Validate Key cancellation
	status = pfr_manifest->pfr_authentication->validate_kc(pfr_manifest);
	if (status != Success)
		return Failure;

	// Block1verifcation
	status = pfr_manifest->pfr_authentication->block1_verify(pfr_manifest);
	if (status != Success)
		return status;

	// Block0Verification
	status = pfr_manifest->pfr_authentication->block0_verify(pfr_manifest);
	if (status != Success)
		return Failure;

	return status;
}

int validate_pc_type(struct pfr_manifest *manifest, uint32_t pc_type)
{
	if (pc_type != manifest->pc_type && manifest->pc_type != PFR_PCH_CPU_Seamless_Update_Capsule) {
		LOG_ERR("Validation PC Type failed, block0_read_pc_type = %x, manifest_pc_type = %x", pc_type, manifest->pc_type);
		return Failure;
	}

	return Success;
}

// Block 1 Block 0 Entry
int intel_block1_block0_entry_verify(struct pfr_manifest *manifest)
{
	uint8_t buffer[sizeof(BLOCK0ENTRY)] = { 0 };
	uint8_t block0_signature_curve_magic = 0;
	uint32_t block0_entry_address = 0;
	BLOCK0ENTRY *block1_buffer;
	uint32_t hash_length = 0;
	int status = 0;

	// Adjusting Block Address in case of KeyCancellation
	if (manifest->kc_flag == 0)
		block0_entry_address = manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0) + CSK_START_ADDRESS + sizeof(CSKENTRY);
	else
		block0_entry_address = manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0) + CSK_START_ADDRESS;

	status = pfr_spi_read(manifest->image_type, block0_entry_address, sizeof(BLOCK0ENTRY), buffer);
	if (status != Success) {
		LOG_ERR("Block1 Block0 Entry: Flash read data failed");
		return Failure;
	}

	block1_buffer = (BLOCK0ENTRY *)&buffer;

	if (block1_buffer->TagBlock0Entry != BLOCK1_BLOCK0ENTRYTAG) {
		LOG_ERR("Block1 Block0 Entry: Magic/Tag not matched, %x", block1_buffer->TagBlock0Entry);
		return Failure;
	}

	if (block1_buffer->Block0SignatureMagic == SIGNATURE_SECP256_TAG) {
		block0_signature_curve_magic = secp256r1;
		manifest->pfr_hash->type = HASH_TYPE_SHA256;
		hash_length = SHA256_HASH_LENGTH;
	} else if (block1_buffer->Block0SignatureMagic == SIGNATURE_SECP384_TAG) {
		block0_signature_curve_magic = secp384r1;
		manifest->pfr_hash->type = HASH_TYPE_SHA384;
		hash_length = SHA384_HASH_LENGTH;
	} else {
		LOG_ERR("Block1 Block0 Entry: Unsupported signature magic, %x", block1_buffer->Block0SignatureMagic);
		return Failure;
	}

	// Key curve and Block 0 signature curve type should match
	if (block0_signature_curve_magic != manifest->hash_curve) {
		LOG_ERR("Block1 Block0 Entry: key curve magic and Block0 signature curve magic not matched, key_curve = %x, sig_curve = %x",
			manifest->hash_curve, block0_signature_curve_magic);
		return Failure;
	}

	manifest->pfr_hash->start_address = manifest->address;
	manifest->pfr_hash->length = sizeof(PFR_AUTHENTICATION_BLOCK0);

	status = manifest->base->get_hash((struct manifest *)manifest, manifest->hash, manifest->pfr_hash->hash_out, hash_length);
	if (status != Success) {
		LOG_ERR("Block1 Block0 Entry: Get hash failed");
		return Failure;
	}

	memcpy(manifest->verification->pubkey->signature_r, block1_buffer->Block0SignatureR, hash_length);
	memcpy(manifest->verification->pubkey->signature_s, block1_buffer->Block0SignatureS, hash_length);

	status = manifest->verification->base->verify_signature((struct signature_verification *)manifest, manifest->pfr_hash->hash_out, hash_length, NULL, (2 * hash_length));
	if (status != Success) {
		LOG_ERR("Block1 Block0 Entry: Verify signature failed");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->x, hash_length, "ECDSA X:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->y, hash_length, "ECDSA Y:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->signature_r, hash_length, "ECDSA R:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->signature_s, hash_length, "ECDSA S:");
		LOG_INF("Hash Info: address = %x, length = %x", manifest->pfr_hash->start_address, manifest->pfr_hash->length);
		LOG_HEXDUMP_INF(manifest->pfr_hash->hash_out, hash_length, "Calculated D:");
		return Failure;
	}

	return Success;
}

// Block 1 CSK Entry
int intel_block1_csk_block0_entry_verify(struct pfr_manifest *manifest)
{
	uint32_t block1_address = manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0);
	uint8_t buffer[sizeof(CSKENTRY)] = { 0 };
	uint8_t csk_sign_curve_magic = 0;
	uint8_t csk_key_curve_type = 0;
	uint32_t sign_bit_verify = 0;
	CSKENTRY *block1_buffer;
	uint32_t hash_length = 0;
	int status = 0;
	int i;

	status = pfr_spi_read(manifest->image_type, block1_address + CSK_START_ADDRESS, sizeof(CSKENTRY), buffer);
	if (status != Success) {
		LOG_ERR("Block1 CSK Entry: Flash read data failed");
		return Failure;
	}

	block1_buffer = (CSKENTRY *)&buffer;

	// validate CSK entry magic tag
	if (block1_buffer->CskEntryInitial.Tag != BLOCK1CSKTAG) {
		LOG_ERR("Block1 CSK Entry: Magic/Tag not matched, %x", block1_buffer->CskEntryInitial.Tag);
		return Failure;
	}

	if (block1_buffer->CskEntryInitial.PubCurveMagic == PUBLIC_SECP256_TAG) {
		csk_key_curve_type = secp256r1;
	} else if (block1_buffer->CskEntryInitial.PubCurveMagic == PUBLIC_SECP384_TAG) {
		csk_key_curve_type = secp384r1;
	} else {
		LOG_ERR("Block1 CSK Entry: Unsupported curve magic, %x", block1_buffer->CskEntryInitial.PubCurveMagic);
		return Failure;
	}

	// Root key curve and CSK curve should match
	if (csk_key_curve_type != manifest->hash_curve) {
		LOG_ERR("Block1 CSK Entry: Root key curve magic and CSK curve magic not matched, root_curve = %x, csk_curve = %x",
			manifest->hash_curve, csk_key_curve_type);
		return Failure;
	}

	if (block1_buffer->CskSignatureMagic == SIGNATURE_SECP256_TAG) {
		csk_sign_curve_magic = secp256r1;
		manifest->pfr_hash->type = HASH_TYPE_SHA256;
		hash_length = SHA256_DIGEST_LENGTH;
	} else if (block1_buffer->CskSignatureMagic == SIGNATURE_SECP384_TAG) {
		csk_sign_curve_magic = secp384r1;
		manifest->pfr_hash->type = HASH_TYPE_SHA384;
		hash_length = SHA384_DIGEST_LENGTH;
	} else {
		LOG_ERR("Block1 CSK Entry: Unsupported signature magic, %x", block1_buffer->CskSignatureMagic);
		return Failure;
	}

	if (csk_key_curve_type != csk_sign_curve_magic) {
		LOG_ERR("Block1 CSK Entry: curve magic type and signature magic type not matched, key_curve = %x, sig_curve = %x",
			csk_key_curve_type, csk_sign_curve_magic);
		return Failure;
	}

	// Key permission
	if (manifest->pc_type == PFR_BMC_UPDATE_CAPSULE) {// Bmc update
		sign_bit_verify = SIGN_BMC_UPDATE_BIT3;
	} else if (manifest->pc_type == PFR_PCH_UPDATE_CAPSULE) {       // PCH update
		sign_bit_verify = SIGN_PCH_UPDATE_BIT1;
	} else if (manifest->pc_type == PFR_BMC_PFM) {                  // BMC PFM
		sign_bit_verify = SIGN_BMC_PFM_BIT2;
	} else if (manifest->pc_type == PFR_PCH_PFM) {                  // PCH PFM
		sign_bit_verify = SIGN_PCH_PFM_BIT0;
	} else if (manifest->pc_type == PFR_CPLD_UPDATE_CAPSULE
		   || manifest->pc_type == PFR_CPLD_UPDATE_CAPSULE_DECOMMISSON) {
		// ROT update
		sign_bit_verify = SIGN_CPLD_UPDATE_BIT4;
	}

	if (!(block1_buffer->CskEntryInitial.KeyPermission & sign_bit_verify)) {
		LOG_ERR("Block1 CSK Entry: CSK key permission denied..., %x", block1_buffer->CskEntryInitial.KeyPermission);
		return Failure;
	}

	// Check for the 0s in the reserved field
	for (i = 0; i < BLOCK1_CSK_ENTRY_RESERVED_SIZE; i++) {
		if (block1_buffer->CskEntryInitial.Reserved[i] != 0) {
			LOG_ERR("Block1 CSK Entry: reserved data failed");
			return Failure;
		}
	}

	status = get_buffer_hash(manifest, (uint8_t *)&block1_buffer->CskEntryInitial.PubCurveMagic, CSK_ENTRY_PC_SIZE, manifest->pfr_hash->hash_out);
	if (status != Success) {
		LOG_ERR("Block1 CSK Entry: Get hash failed");
		return Failure;
	}

	memcpy(manifest->verification->pubkey->signature_r, block1_buffer->CskSignatureR, hash_length);
	memcpy(manifest->verification->pubkey->signature_s, block1_buffer->CskSignatureS, hash_length);

	status = manifest->verification->base->verify_signature((struct signature_verification *)manifest, manifest->pfr_hash->hash_out, hash_length, NULL, (2 * hash_length));
	if (status != Success) {
		LOG_ERR("Block1 CSK Entry: Verify signature failed");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->x, hash_length, "ECDSA X:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->y, hash_length, "ECDSA Y:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->signature_r, hash_length, "ECDSA R:");
		LOG_HEXDUMP_INF(manifest->verification->pubkey->signature_s, hash_length, "ECDSA S:");
		LOG_INF("Hash Info: address = %x, length = %x", manifest->pfr_hash->start_address, manifest->pfr_hash->length);
		LOG_HEXDUMP_INF(manifest->pfr_hash->hash_out, hash_length, "Calculated D:");
		return Failure;
	}

	// Update csk key to validate b0 entry
	memcpy(manifest->verification->pubkey->x, block1_buffer->CskEntryInitial.PubKeyX, hash_length);
	memcpy(manifest->verification->pubkey->y, block1_buffer->CskEntryInitial.PubKeyY, hash_length);

	status = manifest->pfr_authentication->block1_block0_entry_verify(manifest);
	if (status != Success)
		return Failure;

	return Success;
}

// Block 1
int intel_block1_verify(struct pfr_manifest *manifest)
{
	int status = 0;
	PFR_AUTHENTICATION_BLOCK1 *block1_buffer;
	uint8_t buffer[LENGTH] = { 0 };

	status = pfr_spi_read(manifest->image_type, manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0), sizeof(block1_buffer->TagBlock1) + sizeof(block1_buffer->ReservedBlock1) + sizeof(block1_buffer->RootEntry), buffer);
	if (status != Success) {
		LOG_ERR("Block1: Flash read data failed");
		return Failure;
	}

	block1_buffer = (PFR_AUTHENTICATION_BLOCK1 *)buffer;

	if (block1_buffer->TagBlock1 != BLOCK1TAG) {
		LOG_ERR("Block1: Tag Not Found, %x", block1_buffer->TagBlock1);
		return Failure;
	}

	status = verify_root_key_entry(manifest, block1_buffer);
	if (status != Success) {
		LOG_ERR("Block1 Root Entry: Validation failed");
		return Failure;
	}

	LOG_INF("Block1 Root Entry: Validation success");

	// Update root key to validate csk entry if csk entry exist or b0 entry if csk entry does not exist
	memcpy(manifest->verification->pubkey->x, block1_buffer->RootEntry.PubKeyX, sizeof(block1_buffer->RootEntry.PubKeyX));
	memcpy(manifest->verification->pubkey->y, block1_buffer->RootEntry.PubKeyY, sizeof(block1_buffer->RootEntry.PubKeyY));

	if (manifest->kc_flag == 0) {
		// CSK and Block 0 entry verification
		status = manifest->pfr_authentication->block1_csk_block0_entry_verify(manifest);
		if (status != Success) {
			LOG_ERR("Block1 CSK and Block0 Entry: Validation failed");
			return Failure;
		}
		LOG_INF("Block1 CSK and Block0 Entry: Validation success");
	} else  {
		status = manifest->pfr_authentication->block1_block0_entry_verify(manifest);
		if (status != Success) {
			LOG_ERR("Block1 Block0 Entry: Validation failed");
			return Failure;
		}
		LOG_INF("Block1 Block0 Entry: Validation success");
	}

	return Success;
}

// BLOCK 0
int intel_block0_verify(struct pfr_manifest *manifest)
{
	uint8_t buffer[sizeof(PFR_AUTHENTICATION_BLOCK0)] = { 0 };
	uint8_t sha_buffer[SHA384_DIGEST_LENGTH] = { 0 };
	PFR_AUTHENTICATION_BLOCK0 *block0_buffer;
	uint32_t hash_length = 0;
	uint8_t *ptr_sha;
	int status = 0;
	int i;

	status = pfr_spi_read(manifest->image_type, manifest->address, sizeof(PFR_AUTHENTICATION_BLOCK0), buffer);
	if (status != Success) {
		LOG_ERR("Block0: Flash read data failed");
		return Failure;
	}

	block0_buffer = (PFR_AUTHENTICATION_BLOCK0 *)buffer;

	if (block0_buffer->Block0Tag != BLOCK0TAG) {
		LOG_ERR("Block0: Tag Not Found, %x", block0_buffer->Block0Tag);
		return Failure;
	}

	if ((block0_buffer->PcLength < 128) || (block0_buffer->PcLength % 128 != 0)) {
		LOG_ERR("Block0: PC length failed, %x", block0_buffer->PcLength);
		return Failure;
	}

	// Both key cancellation certificate and decommission capsule have the same fixed size of 128 bytes.
	if (block0_buffer->PcType & DECOMMISSION_CAPSULE) {
		if (block0_buffer->PcLength != KCH_CAN_CERT_OR_DECOMM_CAP_PC_SIZE) {
			LOG_ERR("Block0: Invalid decommission capsule PC length, %x", block0_buffer->PcLength);
			return Failure;
		}
	}

	if (block0_buffer->PcType & KEY_CANCELLATION_CAPSULE) {
		if (block0_buffer->PcLength != KCH_CAN_CERT_OR_DECOMM_CAP_PC_SIZE) {
			LOG_ERR("Block0: Invalid key cancellation capsule PC length, %x", block0_buffer->PcLength);
			return Failure;
		}
	}

	// Check for the 0s in the reserved field
	for (i = 0; i < BLOCK0_SECOND_RESERVED_SIZE; i++) {
		if (block0_buffer->Reserved2[i] != 0) {
			LOG_ERR("Block0: Invalid reserved2 data");
			return Failure;
		}
	}

	// Protected content length
	manifest->pc_length = block0_buffer->PcLength;
	manifest->pfr_hash->start_address = manifest->address + PFM_SIG_BLOCK_SIZE;
	manifest->pfr_hash->length = block0_buffer->PcLength;

	if (manifest->hash_curve == secp256r1) {
		manifest->pfr_hash->type = HASH_TYPE_SHA256;
		hash_length = SHA256_DIGEST_LENGTH;
		ptr_sha = block0_buffer->Sha256Pc;
	} else if (manifest->hash_curve == secp384r1) {
		manifest->pfr_hash->type = HASH_TYPE_SHA384;
		hash_length = SHA384_DIGEST_LENGTH;
		ptr_sha = block0_buffer->Sha384Pc;
	} else  {
		LOG_ERR("Block0: Unsupported hash curve, %x", manifest->hash_curve);
		return Failure;
	}

	status = manifest->base->get_hash((struct manifest *)manifest, manifest->hash, sha_buffer, hash_length);
	if (status != Success) {
		LOG_ERR("Block0: Get hash failed");
		return Failure;
	}

	LOG_INF("Block0: Verification PC, address = %x, length = %x", manifest->pfr_hash->start_address, manifest->pfr_hash->length);
	status = compare_buffer(ptr_sha, sha_buffer, hash_length);
	if (status != Success) {
		LOG_ERR("Block0: Verification PC failed");
		LOG_HEXDUMP_INF(sha_buffer, hash_length, "Calculated hash:");
		LOG_HEXDUMP_INF(ptr_sha, hash_length, "Expected hash:");
		return Failure;
	}

	if (block0_buffer->PcType == PFR_CPLD_UPDATE_CAPSULE)
		SetCpldFpgaRotHash(&sha_buffer[0]);

	LOG_INF("Block0: Hash Matched");
	return Success;
}

void init_pfr_authentication(struct pfr_authentication *pfr_authentication)
{
	pfr_authentication->validate_pctye = validate_pc_type;
	pfr_authentication->validate_kc = validate_key_cancellation_flag;
	pfr_authentication->block1_verify = intel_block1_verify;
	pfr_authentication->block1_csk_block0_entry_verify = intel_block1_csk_block0_entry_verify;
	pfr_authentication->block1_block0_entry_verify = intel_block1_block0_entry_verify;
	pfr_authentication->block0_verify = intel_block0_verify;
}
