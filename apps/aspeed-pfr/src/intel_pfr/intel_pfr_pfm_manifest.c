/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include "intel_pfr_pfm_manifest.h"
#include "intel_pfr_definitions.h"
#include "AspeedStateMachine/common_smc.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_update.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "Smbus_mailbox/Smbus_mailbox.h"

LOG_MODULE_REGISTER(pfr, CONFIG_LOG_DEFAULT_LEVEL);

uint32_t g_pfm_manifest_length = 1;
uint32_t g_fvm_manifest_length = 1;

uint8_t g_active_pfm_svn;

ProtectLevelMask pch_protect_level_mask_count;
ProtectLevelMask bmc_protect_level_mask_count;

int pfm_spi_region_verification(struct pfr_manifest *manifest);

int pfm_version_set(struct pfr_manifest *manifest, uint32_t read_address)
{
	int status = 0;
	uint8_t active_svn;
	uint16_t active_major_version, active_minor_version;
	uint8_t ufm_svn = 0;
	uint8_t buffer[sizeof(PFM_STRUCTURE_1)];

	status = pfr_spi_read(manifest->image_type, read_address, sizeof(PFM_STRUCTURE_1), buffer);
	if (status != Success) {
		LOG_ERR("Pfm Version Set failed...");
		return Failure;
	}

	if (((PFM_STRUCTURE_1 *)buffer)->PfmTag == PFMTAG) {
		LOG_INF("PfmTag verification success...");
	} else {
		LOG_ERR("PfmTag verification failed...\n expected: %x\n actual: %x",
				PFMTAG, ((PFM_STRUCTURE_1 *)buffer)->PfmTag);
		return Failure;
	}

	active_svn = ((PFM_STRUCTURE_1 *)buffer)->SVN;
	active_major_version = ((PFM_STRUCTURE_1 *)buffer)->PfmRevision;
	active_major_version = active_major_version & 0xFF;
	active_minor_version = ((PFM_STRUCTURE_1 *)buffer)->PfmRevision;
	active_minor_version = active_minor_version >> 8;

	if (manifest->image_type == PCH_TYPE) {
		SetPchPfmActiveSvn(active_svn);
		SetPchPfmActiveMajorVersion(active_major_version);
		SetPchPfmActiveMinorVersion(active_minor_version);

		ufm_svn = get_ufm_svn(manifest, SVN_POLICY_FOR_PCH_FW_UPDATE);
		if (ufm_svn < active_svn)
			status = set_ufm_svn(manifest, SVN_POLICY_FOR_PCH_FW_UPDATE, active_svn);

	} else if (manifest->image_type == BMC_TYPE) {
		SetBmcPfmActiveSvn(active_svn);
		SetBmcPfmActiveMajorVersion(active_major_version);
		SetBmcPfmActiveMinorVersion(active_minor_version);

		ufm_svn = get_ufm_svn(manifest, SVN_POLICY_FOR_BMC_FW_UPDATE);
		if (ufm_svn < active_svn)
			status = set_ufm_svn(manifest, SVN_POLICY_FOR_BMC_FW_UPDATE, active_svn);
	}

	return Success;
}

int get_recover_pfm_version_details(struct pfr_manifest *manifest, uint32_t address)
{
	int status = 0;
	uint32_t pfm_data_address = 0;
	uint16_t recovery_major_version, recovery_minor_version;
	uint8_t recovery_svn;
	uint8_t ufm_svn;
	PFM_STRUCTURE_1 *pfm_data;
	uint8_t buffer[sizeof(PFM_STRUCTURE_1)];

	// PFM data start address after Recovery block and PFM block
	pfm_data_address = address + PFM_SIG_BLOCK_SIZE + PFM_SIG_BLOCK_SIZE;

	status = pfr_spi_read(manifest->image_type, pfm_data_address, sizeof(PFM_STRUCTURE_1),
			buffer);
	if (status != Success) {
		LOG_ERR("Get Recover Pfm Version Details failed...");
		return Failure;
	}

	pfm_data = (PFM_STRUCTURE_1 *)buffer;
	recovery_svn = pfm_data->SVN;
	recovery_major_version = pfm_data->PfmRevision;
	recovery_major_version = recovery_major_version & 0xFF;
	recovery_minor_version = pfm_data->PfmRevision;
	recovery_minor_version = recovery_minor_version >> 8;

	// MailBox Communication
	if (manifest->image_type == PCH_TYPE) {
		SetPchPfmRecoverSvn(recovery_svn);
		SetPchPfmRecoverMajorVersion(recovery_major_version);
		SetPchPfmRecoverMinorVersion(recovery_minor_version);

		ufm_svn = get_ufm_svn(manifest, SVN_POLICY_FOR_PCH_FW_UPDATE);
		if (ufm_svn < recovery_svn)
			status = set_ufm_svn(manifest, SVN_POLICY_FOR_PCH_FW_UPDATE, recovery_svn);
	} else if (manifest->image_type == BMC_TYPE) {
		SetBmcPfmRecoverSvn(recovery_svn);
		SetBmcPfmRecoverMajorVersion(recovery_major_version);
		SetBmcPfmRecoverMinorVersion(recovery_minor_version);

		ufm_svn = get_ufm_svn(manifest, SVN_POLICY_FOR_BMC_FW_UPDATE);
		if (ufm_svn < recovery_svn)
			status = set_ufm_svn(manifest, SVN_POLICY_FOR_BMC_FW_UPDATE, recovery_svn);
	}

	return status;
}

int read_statging_area_pfm(struct pfr_manifest *manifest, uint8_t *svn_version)
{
	int status = 0;
	uint32_t pfm_start_address = 0;
	uint8_t buffer[sizeof(PFM_STRUCTURE_1)];

	// PFM data start address after Staging block and PFM block
	pfm_start_address = manifest->address + PFM_SIG_BLOCK_SIZE + PFM_SIG_BLOCK_SIZE;

	status = pfr_spi_read(manifest->image_type, pfm_start_address, sizeof(PFM_STRUCTURE_1),
			buffer);
	if (status != Success) {
		LOG_ERR("Invalid Staging Area Pfm ");
		return Failure;
	}

	*svn_version = ((PFM_STRUCTURE_1 *)buffer)->SVN;

	return Success;
}

int spi_region_hash_verification(struct pfr_manifest *pfr_manifest,
		PFM_SPI_DEFINITION *PfmSpiDefinition, uint8_t *pfm_spi_Hash)
{

	int status = 0;
	uint32_t region_length;

	LOG_INF("RegionStartAddress: %x, RegionEndAddress: %x",
		     PfmSpiDefinition->RegionStartAddress, PfmSpiDefinition->RegionEndAddress);
	region_length = (PfmSpiDefinition->RegionEndAddress) - (PfmSpiDefinition->RegionStartAddress);

	if ((PfmSpiDefinition->HashAlgorithmInfo.SHA256HashPresent == 1) ||
	    (PfmSpiDefinition->HashAlgorithmInfo.SHA384HashPresent == 1)) {
		LOG_INF("Digest verification start");

		uint8_t sha_buffer[SHA384_DIGEST_LENGTH] = { 0 };
		uint32_t hash_length = 0;

		pfr_manifest->pfr_hash->start_address = PfmSpiDefinition->RegionStartAddress;
		pfr_manifest->pfr_hash->length = region_length;

		if (PfmSpiDefinition->HashAlgorithmInfo.SHA256HashPresent == 1) {
			pfr_manifest->pfr_hash->type = HASH_TYPE_SHA256;
			hash_length = SHA256_DIGEST_LENGTH;
		} else if (PfmSpiDefinition->HashAlgorithmInfo.SHA384HashPresent == 1) {
			pfr_manifest->pfr_hash->type = HASH_TYPE_SHA384;
			hash_length = SHA384_DIGEST_LENGTH;
		} else  {
			return Failure;
		}

		pfr_manifest->base->get_hash((struct manifest *)pfr_manifest, pfr_manifest->hash,
				sha_buffer, hash_length);

		status = compare_buffer(pfm_spi_Hash, sha_buffer, hash_length);
		if (status != Success) {
			LOG_ERR("Digest verification failed");
			return Failure;
		}
		LOG_INF("Digest verification succeeded");
	}


	return Success;
}

int get_spi_region_hash(struct pfr_manifest *manifest, uint32_t address,
		PFM_SPI_DEFINITION *p_spi_definition, uint8_t *pfm_spi_hash)
{
	if (p_spi_definition->HashAlgorithmInfo.SHA256HashPresent == 1) {
		pfr_spi_read(manifest->image_type, address, SHA256_SIZE,
				pfm_spi_hash);

		return SHA256_SIZE;
	} else if (p_spi_definition->HashAlgorithmInfo.SHA384HashPresent == 1) {
		pfr_spi_read(manifest->image_type, address, SHA384_SIZE,
				pfm_spi_hash);

		return SHA384_SIZE;
	}

	return 0;
}

#if defined(CONFIG_SEAMLESS_UPDATE)
int fvm_spi_region_verification(struct pfr_manifest *manifest)
{
	uint32_t read_address = manifest->address;
	FVM_STRUCTURE fvm_data;
	bool done = false;
	uint32_t fvm_addr = read_address + PFM_SIG_BLOCK_SIZE;
	uint32_t fvm_end_addr;
	PFM_SPI_DEFINITION spi_definition = { 0 };
	uint8_t pfm_spi_hash[SHA384_SIZE] = { 0 };

	LOG_INF("Verifying FVM...");
	if (manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length)) {
		LOG_ERR("Verify active FVM failed");
		return Failure;
	}

	if (pfr_spi_read(manifest->image_type, fvm_addr,
				sizeof(FVM_STRUCTURE), (uint8_t *)&fvm_data))
			return Failure;

	if (fvm_data.FvmTag != FVMTAG) {
		LOG_ERR("FVMTag verification failed...\n expected: %x\n actual: %x",
				FVMTAG, fvm_data.FvmTag);
		return Failure;
	}

	fvm_end_addr = fvm_addr + fvm_data.Length;
	fvm_addr += sizeof(FVM_STRUCTURE);

	while (!done) {
		if (pfr_spi_read(manifest->image_type, fvm_addr,
					sizeof(PFM_SPI_DEFINITION), &spi_definition))
			return Failure;

		switch(spi_definition.PFMDefinitionType){
			case SPI_REGION:
				fvm_addr += sizeof(PFM_SPI_DEFINITION);
				fvm_addr += get_spi_region_hash(manifest, fvm_addr, &spi_definition,
						&pfm_spi_hash);
				if (spi_region_hash_verification(manifest, &spi_definition,
							&pfm_spi_hash))
					return Failure;

				memset(&spi_definition, 0, sizeof(PFM_SPI_DEFINITION));
				memset(pfm_spi_hash, 0, SHA384_SIZE);
				break;
			case PCH_FVM_CAP:
				fvm_addr += sizeof(FVM_CAPABLITIES);
				break;
			default:
				done = true;
				break;
		}

		if (fvm_addr >= fvm_end_addr)
			break;
	}

	return Success;
}
#endif

int pfm_spi_region_verification(struct pfr_manifest *manifest)
{
	uint32_t read_address = manifest->address;
	PFM_STRUCTURE_1 pfm_data;
	bool done = false;
	uint32_t pfm_addr = read_address + PFM_SIG_BLOCK_SIZE;
	uint32_t pfm_end_addr;
#if defined(CONFIG_SEAMLESS_UPDATE)
	PFM_FVM_ADDRESS_DEFINITION *fvm_def;
#endif
	PFM_SPI_DEFINITION spi_definition = { 0 };
	uint8_t pfm_spi_hash[SHA384_SIZE] = { 0 };

	if (pfr_spi_read(manifest->image_type, pfm_addr,
				sizeof(PFM_STRUCTURE_1), (uint8_t *)&pfm_data))
			return Failure;
	pfm_end_addr = pfm_addr + pfm_data.Length;
	pfm_addr += sizeof(PFM_STRUCTURE_1);

	while (!done) {
		if (pfr_spi_read(manifest->image_type, pfm_addr,
					sizeof(PFM_SPI_DEFINITION), &spi_definition))
			return Failure;

		switch(spi_definition.PFMDefinitionType){
			case SPI_REGION:
				pfm_addr += sizeof(PFM_SPI_DEFINITION);
				pfm_addr += get_spi_region_hash(manifest, pfm_addr, &spi_definition,
						&pfm_spi_hash);
				if (spi_region_hash_verification(manifest, &spi_definition,
							&pfm_spi_hash))
					return Failure;

				memset(&spi_definition, 0, sizeof(PFM_SPI_DEFINITION));
				memset(pfm_spi_hash, 0, SHA384_SIZE);
				break;
			case SMBUS_RULE:
				pfm_addr += sizeof(PFM_SMBUS_RULE);
				break;
#if defined(CONFIG_SEAMLESS_UPDATE)
			case FVM_ADDR_DEF:
				fvm_def = &spi_definition;
				manifest->address = fvm_def->FVMAddress;
				if (fvm_spi_region_verification(manifest)) {
					manifest->address = read_address;
					LOG_ERR("FVM SPI region verification failed");
					return Failure;
				}
				pfm_addr += sizeof(PFM_FVM_ADDRESS_DEFINITION);
				break;
#endif
			default:
				done = true;
				break;
		}

		if (pfm_addr >= pfm_end_addr)
			break;
	}
	manifest->address = read_address;

	return Success;
}

