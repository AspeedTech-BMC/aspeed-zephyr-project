/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <flash/flash_aspeed.h>
#include <sys/types.h>
#include <zephyr/storage/flash_map.h>

#include "intel_pfr_pfm_manifest.h"
#include "intel_pfr_definitions.h"
#include "AspeedStateMachine/common_smc.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_update.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "intel_pfr_svn.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

bool validate_region_data(struct pfr_manifest *pfr_manifest, uint32_t address)
{
	int ret;
	uint32_t org_address;

	org_address = pfr_manifest->address;
	pfr_manifest->address = address;
	pfr_manifest->flash->state->device_id[0] = pfr_manifest->image_type;
	ret = pfr_manifest->base->verify((struct manifest *)pfr_manifest, pfr_manifest->hash,
			pfr_manifest->verification->base, pfr_manifest->pfr_hash->hash_out,
			pfr_manifest->pfr_hash->length);
	pfr_manifest->address = org_address;

	if (ret) {
		LOG_ERR("Verify image %d with offset %x failed",
			pfr_manifest->image_type, address);
		return false;
	}

	return true;
}

int get_active_pfm_version_details(struct pfr_manifest *manifest, uint32_t address)
{
	int status = 0;
	uint32_t pfm_data_address = 0;
	uint8_t active_svn;
	uint16_t active_major_version, active_minor_version;
	uint8_t buffer[sizeof(PFM_STRUCTURE)];

	// PFM data start address after signature
	if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256)
		pfm_data_address = address + LMS_PFM_SIG_BLOCK_SIZE;
	else
		pfm_data_address = address + PFM_SIG_BLOCK_SIZE;

	status = pfr_spi_read(manifest->image_type, pfm_data_address, sizeof(PFM_STRUCTURE), buffer);
	if (status != Success) {
		LOG_ERR("Get Pfm Version Details failed");
		return Failure;
	}

	if (((PFM_STRUCTURE *)buffer)->PfmTag == PFMTAG) {
		active_svn = ((PFM_STRUCTURE *)buffer)->SVN;
		active_major_version = ((PFM_STRUCTURE *)buffer)->PfmRevision & 0xFF;
		active_minor_version = ((PFM_STRUCTURE *)buffer)->PfmRevision >> 8;

		if (manifest->image_type == PCH_TYPE) {
			SetPchPfmActiveSvn(active_svn);
			SetPchPfmActiveMajorVersion(active_major_version);
			SetPchPfmActiveMinorVersion(active_minor_version);
		} else if (manifest->image_type == BMC_TYPE) {
			SetBmcPfmActiveSvn(active_svn);
			SetBmcPfmActiveMajorVersion(active_major_version);
			SetBmcPfmActiveMinorVersion(active_minor_version);
		}
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
		else if (manifest->image_type == ROT_EXT_CPLD_ACT) {
			SetIntelCpldActiveSvn(active_svn);
			SetIntelCpldActiveMajorVersion(active_major_version);
			SetIntelCpldActiveMinorVersion(active_minor_version);
		}
#endif
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (((PFM_STRUCTURE *)buffer)->PfmTag == AFM_TAG) {
		active_svn = ((PFM_STRUCTURE *)buffer)->SVN;
		active_major_version = ((PFM_STRUCTURE *)buffer)->PfmRevision & 0xFF;
		active_minor_version = ((PFM_STRUCTURE *)buffer)->PfmRevision >> 8;

		SetAfmActiveSvn(active_svn);
		SetAfmActiveMajorVersion(active_major_version);
		SetAfmActiveMinorVersion(active_minor_version);
	}
#endif
	else {
		LOG_ERR("PfmTag verification failed, expected: %x, actual: %x",
				PFMTAG, ((PFM_STRUCTURE *)buffer)->PfmTag);
		return Failure;
	}

	return Success;
}

int get_recover_pfm_version_details(struct pfr_manifest *manifest, uint32_t address)
{
	int status = 0;
	uint32_t pfm_data_address = 0;
	uint16_t recovery_major_version, recovery_minor_version;
	uint8_t recovery_svn;
	uint8_t policy_svn;
	PFM_STRUCTURE *pfm_data;
	uint8_t buffer[sizeof(PFM_STRUCTURE)];

	// PFM data start address after Recovery block and PFM block
	if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256)
		pfm_data_address = address + LMS_PFM_SIG_BLOCK_SIZE + LMS_PFM_SIG_BLOCK_SIZE;
	else
		pfm_data_address = address + PFM_SIG_BLOCK_SIZE + PFM_SIG_BLOCK_SIZE;

	status = pfr_spi_read(manifest->image_type, pfm_data_address, sizeof(PFM_STRUCTURE),
			buffer);
	if (status != Success) {
		LOG_ERR("Get Recover Pfm Version Details failed");
		return Failure;
	}

	pfm_data = (PFM_STRUCTURE *)buffer;

	if (pfm_data->PfmTag == PFMTAG) {
		recovery_svn = pfm_data->SVN;
		recovery_major_version = pfm_data->PfmRevision & 0xFF;
		recovery_minor_version = pfm_data->PfmRevision >> 8;

		// MailBox Communication
		if (manifest->image_type == PCH_TYPE) {
			SetPchPfmRecoverSvn(recovery_svn);
			SetPchPfmRecoverMajorVersion(recovery_major_version);
			SetPchPfmRecoverMinorVersion(recovery_minor_version);
			policy_svn = get_ufm_svn(SVN_POLICY_FOR_PCH_FW_UPDATE);
			if (recovery_svn > policy_svn)
				status = set_ufm_svn(SVN_POLICY_FOR_PCH_FW_UPDATE, recovery_svn);
		} else if (manifest->image_type == BMC_TYPE) {
			SetBmcPfmRecoverSvn(recovery_svn);
			SetBmcPfmRecoverMajorVersion(recovery_major_version);
			SetBmcPfmRecoverMinorVersion(recovery_minor_version);
			policy_svn = get_ufm_svn(SVN_POLICY_FOR_BMC_FW_UPDATE);
			if (recovery_svn > policy_svn)
				status = set_ufm_svn(SVN_POLICY_FOR_BMC_FW_UPDATE, recovery_svn);
		}
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
		else if (manifest->image_type == ROT_EXT_CPLD_RC) {
			// TODO: Recovery CPLD SVN is not defined in the specification.
			return Success;
		}
#endif
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (pfm_data->PfmTag == AFM_TAG) {
		recovery_svn = pfm_data->SVN;
		recovery_major_version = pfm_data->PfmRevision & 0xFF;
		recovery_minor_version = pfm_data->PfmRevision >> 8;

		SetAfmRecoverSvn(recovery_svn);
		SetAfmRecoverMajorVersion(recovery_major_version);
		SetAfmRecoverMinorVersion(recovery_minor_version);
		policy_svn = get_ufm_svn(SVN_POLICY_FOR_AFM);
		if (recovery_svn > policy_svn)
			status = set_ufm_svn(SVN_POLICY_FOR_AFM, recovery_svn);
	}
#endif
	else {
		LOG_ERR("PfmTag verification failed, expected: %x, actual: %x",
			PFMTAG, ((PFM_STRUCTURE *)buffer)->PfmTag);
		return Failure;
	}

	return status;
}

int spi_region_hash_verification(struct pfr_manifest *pfr_manifest,
		PFM_SPI_DEFINITION *PfmSpiDefinition, uint8_t *pfm_spi_Hash)
{

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

		pfr_manifest->flash->state->device_id[0] = pfr_manifest->image_type;
		pfr_manifest->base->get_hash((struct manifest *)pfr_manifest, pfr_manifest->hash,
				sha_buffer, hash_length);

		if (memcmp(pfm_spi_Hash, sha_buffer, hash_length)) {
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

	if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256) {
		fvm_addr = read_address + LMS_PFM_SIG_BLOCK_SIZE;
	}

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
				sizeof(PFM_SPI_DEFINITION), (uint8_t *)&spi_definition))
			return Failure;

		switch (spi_definition.PFMDefinitionType) {
		case SPI_REGION:
			fvm_addr += sizeof(PFM_SPI_DEFINITION);
			fvm_addr += get_spi_region_hash(manifest, fvm_addr, &spi_definition,
					pfm_spi_hash);
			if (spi_region_hash_verification(manifest, &spi_definition,
							pfm_spi_hash))
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

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
#if (CONFIG_AFM_SPEC_VERSION == 4)
#include <aspeed_util.h>
#include "SPDM/SPDMRequester.h"
int verify_internal_afm(struct pfr_manifest *pfr_manifest, uint32_t flash_type)
{
	uint32_t afm_body_offset;
	uint8_t sha_buffer[SHA384_DIGEST_LENGTH];
	uint8_t afm_body_sha[SHA384_DIGEST_LENGTH];
	int hash_length = SHA384_DIGEST_LENGTH;
	uint32_t org_type, afm_addr;
	off_t *afmlist = spdm_get_afm_list();
	bool ret;

	org_type = pfr_manifest->image_type;
	if (flash_type == BMC_SPI) {
		afm_body_offset = BMC_AFM_BODY_OFFSET;
		afm_addr = pfr_manifest->bmc_afm_address;
	} else {
		afm_body_offset = CPU0_AFM_BODY_OFFSET;
		afm_addr = pfr_manifest->cpu0_afm_address;
	}

	if (afm_addr == 0) {
		// PFM doesn't carry AFM, to check if internal afm is existed or not
		uint32_t block0_tag;

		pfr_spi_read(pfr_manifest->image_type, afm_body_offset,
				sizeof(uint32_t), (uint8_t *)&block0_tag);
		if (block0_tag == BLOCK0TAG) {
			ret = validate_region_data(pfr_manifest, afm_body_offset);
			if (ret == true) {
				LOG_ERR("Internal AFM (%x) has data, to erase it",
					afm_body_offset);
				return Failure;
			}
		}
		return Success;
	}

	pfr_manifest->image_type = flash_type;
	pfr_manifest->pfr_hash->start_address = afm_addr;
	pfr_manifest->pfr_hash->type = HASH_TYPE_SHA384;
	pfr_manifest->flash->state->device_id[0] = flash_type;
	pfr_manifest->pfr_hash->length = AFM_BODY_SIZE;
	pfr_manifest->base->get_hash((struct manifest *)pfr_manifest, pfr_manifest->hash,
			sha_buffer, hash_length);

	pfr_manifest->image_type = ROT_INTERNAL_AFM;
	pfr_manifest->pfr_hash->start_address = afm_body_offset;
	pfr_manifest->flash->state->device_id[0] = ROT_INTERNAL_AFM;
	pfr_manifest->base->get_hash((struct manifest *)pfr_manifest, pfr_manifest->hash,
			afm_body_sha, hash_length);
	pfr_manifest->image_type = org_type;

	if (memcmp(sha_buffer, afm_body_sha, hash_length)) {
		LOG_ERR("Internal AFM (%x) doesn't match PFM AFM", afm_body_offset);
		return Failure;
	} else
		LOG_INF("Internal AFM (%x) verification succeeded", afm_body_offset);

	if (flash_type == BMC_SPI)
		afmlist[afm_dev_idx_bmc] = BMC_AFM_BODY_OFFSET;
	else if (flash_type == PCH_SPI)
		afmlist[afm_dev_idx_cpu0] = CPU0_AFM_BODY_OFFSET;

	return Success;
}

void set_afm_address(struct pfr_manifest *manifest, uint32_t afm_addr)
{
	if (manifest->image_type == BMC_TYPE)
		manifest->bmc_afm_address = afm_addr;
	else if (manifest->image_type == PCH_TYPE)
		manifest->cpu0_afm_address = afm_addr;
	else
		LOG_WRN("Unknown image type : %x", manifest->image_type);
}

int verify_pfm_afm(struct pfr_manifest *manifest, uint32_t afm_addr, uint32_t afm_body_offset)
{
	PFR_AUTHENTICATION_BLOCK0 block0;
	uint8_t flash_type;

	LOG_INF("Get AFM addr info (%08x)", afm_addr);
	if (manifest->image_type == BMC_TYPE)
		flash_type = BMC_SPI;
	else
		flash_type = PCH_SPI;
	pfr_spi_read(manifest->image_type, afm_addr, sizeof(PFR_AUTHENTICATION_BLOCK0),
			(uint8_t *)&block0);
	if (block0.PcType == PFR_AFM) {
		/* if AFM data is an address defintion data, to find AFM device data */
		if (validate_region_data(manifest, afm_addr) == false) {
			set_afm_address(manifest, 0);
			LOG_ERR("AFM address defintion verification failed");
			return Failure;
		}
		pfr_spi_read(manifest->image_type, afm_addr + AFM_BODY_SIZE,
				sizeof(PFR_AUTHENTICATION_BLOCK0), (uint8_t *)&block0);
		if (block0.Block0Tag == BLOCK0TAG) {
			afm_addr += AFM_BODY_SIZE;
			/* Validate AFM device data */
			if (validate_region_data(manifest, afm_addr) == false) {
				set_afm_address(manifest, 0);
				LOG_ERR("%s AFM verification failed",
					(manifest->image_type == BMC_TYPE)?"BMC":"PCH");
				return Failure;
			}
			LOG_INF("%s AFM verification succeeded",
				(manifest->image_type == BMC_TYPE)?"BMC":"PCH");
			set_afm_address(manifest, afm_addr);
		} else {
			erase_afm_body(afm_body_offset);
			set_afm_address(manifest, 0);
			LOG_INF("No AFM device (%x, %x, %x)",
				block0.Block0Tag, block0.PcType, block0.PcLength);
			return Success;
		}
	} else if (block0.PcType == PFR_AFM_PER_DEV) {
		if (validate_region_data(manifest, afm_addr) == false) {
			set_afm_address(manifest, 0);
			LOG_ERR("%s AFM verification failed",
				(manifest->image_type == BMC_TYPE)?"BMC":"PCH");
			return Failure;
		}
		set_afm_address(manifest, afm_addr);
		LOG_INF("%s AFM verification succeeded",
			(manifest->image_type == BMC_TYPE)?"BMC":"PCH");
	} else {
		set_afm_address(manifest, 0);
		LOG_ERR("Invalid AFM type (%x, %x, %x)",
			block0.Block0Tag, block0.PcType, block0.PcLength);
		return Failure;
	}

	return Success;
}

int erase_afm_body(uint32_t afm_body_offset)
{
	uint32_t block0_tag;

	if (pfr_spi_read(ROT_INTERNAL_AFM, afm_body_offset, sizeof(uint32_t),
		(uint8_t *)&block0_tag)) {
		LOG_ERR("Failed to read flash (%x)", afm_body_offset);
		return Failure;
	}

	if (block0_tag == BLOCK0TAG) {
		if (pfr_spi_erase_region(ROT_INTERNAL_AFM, true, afm_body_offset, AFM_BODY_SIZE)) {
			LOG_ERR("Failed to erase AFM body Partition (%x)", afm_body_offset);
			return Failure;
		}
	}

	return Success;
}
#endif
int verify_afm_devices(struct pfr_manifest *manifest)
{
	int i, ret, count = 0;
	uint8_t *pData = NULL, *ptr;

#if (CONFIG_AFM_SPEC_VERSION == 4)
	if (manifest->image_type == ROT_EXT_AFM_ACT_1) {
#elif (CONFIG_AFM_SPEC_VERSION == 3)
	if (manifest->image_type == ROT_INTERNAL_AFM) {
#endif
		AFM_STRUCTURE afm_st;

		ret = validate_region_data(manifest, manifest->address);
		if (ret == false) {
			LOG_ERR("AFM address definition verification failed");
			return Failure;
		}
		count++;

		pfr_spi_read(manifest->image_type, manifest->address + PFM_SIG_BLOCK_SIZE,
				sizeof(afm_st), (uint8_t *)&afm_st);
		if (afm_st.AfmTag != AFM_TAG) {
			LOG_ERR("Invalid Tag found - %x", afm_st.AfmTag);
			return Failure;
		}
		pData = malloc(afm_st.Length);
		if (pData == NULL) {
			LOG_ERR("Failed to allocate memory (%d) for AFM data",
					afm_st.Length);
			return Failure;
		}
		pfr_spi_read(manifest->image_type, manifest->address + PFM_SIG_BLOCK_SIZE + sizeof(afm_st),
				afm_st.Length, pData);
		ptr = pData;
		// Get AFM address definition count
		while (ptr < pData + afm_st.Length) {
#if (CONFIG_AFM_SPEC_VERSION == 4)
			if (*ptr == AFM_ADDR_DEF) {
				count++;
				ptr += sizeof(AFM_ADDRESS_DEFINITION_v40);
			} else
				break;
#elif (CONFIG_AFM_SPEC_VERSION == 3)
			if (*ptr == AFM_ADDR_DEF_v3) {
				count++;
				ptr += sizeof(AFM_ADDRESS_DEFINITION);
			} else
				break;
#endif
		};
		free(pData);
		LOG_INF("Found %d AFM address definitions", count - 1);
	} else {
		PFR_AUTHENTICATION_BLOCK0 block0;

		// Get AFM device count
		for (i = 0; i < afm_dev_idx_addon_final - afm_dev_idx_onboard_final; i++) {
			pfr_spi_read(manifest->image_type, manifest->address + AFM_BODY_SIZE * i,
					sizeof(block0), (uint8_t *)&block0);
			if (block0.Block0Tag == BLOCK0TAG)
				count++;
			else
				break;
		}
		LOG_INF("Found %d AFM device", count);
	}

	for (i = 0; i < count; i++) {
		// AFM address defintion has been verified, don't need to verify it again.
		if (manifest->image_type == ROT_EXT_AFM_ACT_1 && i == 0)
			continue;
		ret = validate_region_data(manifest, manifest->address + AFM_BODY_SIZE * i);
		if (ret == false) {
			LOG_ERR("%s device %d verification is failed",
				(manifest->image_type == ROT_EXT_AFM_ACT_1)?"AFM1":"AFM2", i);
			return Failure;
		}
	}

	LOG_INF("%s verification succeeded", (manifest->image_type == ROT_EXT_AFM_ACT_1)?"AFM1":"AFM2");

	return Success;
}
#endif

int pfm_spi_region_verification(struct pfr_manifest *manifest)
{
	uint32_t read_address = manifest->address;
	PFM_STRUCTURE pfm_data;
	bool done = false;
	uint32_t pfm_addr = read_address + PFM_SIG_BLOCK_SIZE;
	uint32_t pfm_end_addr;
#if defined(CONFIG_SEAMLESS_UPDATE)
	PFM_FVM_ADDRESS_DEFINITION *fvm_def;
#endif
	PFM_SPI_DEFINITION spi_definition = { 0 };
	uint8_t pfm_spi_hash[SHA384_SIZE] = { 0 };
	bool new_format_found = false;
#if (CONFIG_AFM_SPEC_VERSION == 4)
	uint32_t afm_body_offset = 0xffffffff;

	if (manifest->image_type == BMC_TYPE) {
		afm_body_offset = BMC_AFM_BODY_OFFSET;
		set_afm_address(manifest, 0);
	} else if (manifest->image_type == PCH_TYPE) {
		afm_body_offset = CPU0_AFM_BODY_OFFSET;
		set_afm_address(manifest, 0);
	}
#endif

	if (manifest->hash_curve == hash_sign_algo384 || manifest->hash_curve == hash_sign_algo256)
		pfm_addr = read_address + LMS_PFM_SIG_BLOCK_SIZE;

	if (pfr_spi_read(manifest->image_type, pfm_addr,
			sizeof(PFM_STRUCTURE), (uint8_t *)&pfm_data))
		return Failure;

	/* there is no SPI region definition in the AFM region, to ignore the SPI region verification */
	if (pfm_data.PfmTag == AFM_TAG)
		return Success;

	pfm_end_addr = pfm_addr + pfm_data.Length;
	pfm_addr += sizeof(PFM_STRUCTURE);

	while (!done) {
		if (pfr_spi_read(manifest->image_type, pfm_addr,
				sizeof(PFM_SPI_DEFINITION), (uint8_t *)&spi_definition))
			return Failure;

		switch (spi_definition.PFMDefinitionType) {
		case SPI_REGION:
			pfm_addr += sizeof(PFM_SPI_DEFINITION);
			pfm_addr += get_spi_region_hash(manifest, pfm_addr, &spi_definition,
					pfm_spi_hash);
			if (spi_region_hash_verification(manifest, &spi_definition,
					pfm_spi_hash))
				return Failure;

			memset(&spi_definition, 0, sizeof(PFM_SPI_DEFINITION));
			memset(pfm_spi_hash, 0, SHA384_SIZE);
			break;
		case SMBUS_RULE:
			pfm_addr += sizeof(PFM_SMBUS_RULE);
			break;
#if defined(CONFIG_SEAMLESS_UPDATE)
		case FVM_ADDR_DEF:
			fvm_def = (PFM_FVM_ADDRESS_DEFINITION *)&spi_definition;
			manifest->address = fvm_def->FVMAddress;
			if (fvm_spi_region_verification(manifest)) {
				manifest->address = read_address;
				LOG_ERR("FVM SPI region verification failed");
				return Failure;
			}
			pfm_addr += sizeof(PFM_FVM_ADDRESS_DEFINITION);
			break;
		case FVM_CAP:
			pfm_addr += sizeof(FVM_CAPABLITIES);
			break;
#endif
#if (CONFIG_AFM_SPEC_VERSION == 4)
		case AFM_ADDR_DEF:
			AFM_ADDRESS_DEFINITION_v40 afm_def;

			if (pfr_spi_read(manifest->image_type, pfm_addr,
					sizeof(afm_def), (uint8_t *)&afm_def))
				return Failure;

			new_format_found = true;
			if (verify_pfm_afm(manifest,
					afm_def.AfmAddress, afm_body_offset))
				return Failure;
			pfm_addr += sizeof(AFM_ADDRESS_DEFINITION_v40);
			break;
#endif
		default:
			done = true;
			break;
		}

		if (pfm_addr >= pfm_end_addr)
			break;
	}

	LOG_INF("New PFM version is %sused", (new_format_found)?"":"not ");
#if (CONFIG_AFM_SPEC_VERSION == 4)
	if ((new_format_found == false) && (afm_body_offset != 0xffffffff))
		erase_afm_body(afm_body_offset);
#endif
	manifest->address = read_address;

	return Success;
}

