/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "pfr/pfr_common.h"
#pragma pack(1)

#define NUM_WHITESPACE 8

typedef struct PFMSPIDEFINITION {
	uint8_t PFMDefinitionType;
	struct {
		uint8_t ReadAllowed : 1;
		uint8_t WriteAllowed : 1;
		uint8_t RecoverOnFirstRecovery : 1;
		uint8_t RecoverOnSecondRecovery : 1;
		uint8_t RecoverOnThirdRecovery : 1;
		uint8_t Reserved : 3;
	} ProtectLevelMask;
	struct {
		uint16_t SHA256HashPresent : 1;
		uint16_t SHA384HashPresent : 1;
		uint16_t Reserved : 14;
	} HashAlgorithmInfo;
	uint32_t Reserved;
	uint32_t RegionStartAddress;
	uint32_t RegionEndAddress;
} PFM_SPI_DEFINITION;

typedef enum {
	manifest_success,
	manifest_failure,
	manifest_unsupported
} Manifest_Status;

typedef struct _PFM_SPI_REGION {
	uint8_t PfmDefType;
	uint8_t ProtectLevelMask;
	struct {
		uint16_t Sha256Present : 1;
		uint16_t Sha384Present : 1;
		uint16_t Reserved : 14;
	} HashAlgorithmInfo;
	uint32_t Reserved;
	uint32_t StartOffset;
	uint32_t EndOffset;
} PFM_SPI_REGION;



typedef struct _PFM_STRUCTURE_1 {
	uint32_t PfmTag;
	uint8_t SVN;
	uint8_t BkcVersion;
	uint16_t PfmRevision;
	uint32_t Reserved;
	uint8_t OemSpecificData[16];
	uint32_t Length;
} PFM_STRUCTURE_1;

typedef struct _FVM_STRUCTURE {
	uint32_t FvmTag;
	uint8_t SVN;
	uint8_t Reserved;
	uint16_t FvmRevision;
	uint16_t Reserved1;
	uint16_t FvType;
	uint8_t OemSpecificData[16];
	uint32_t Length;
} FVM_STRUCTURE;

typedef struct _PFM_SMBUS_RULE {
	uint8_t PFMDefinitionType;
	uint32_t Reserved;
	uint8_t BusId;
	uint8_t RuleID;
	uint8_t DeviceAddress;
	uint8_t CmdPasslist[32];
} PFM_SMBUS_RULE;

typedef struct _PFM_FVM_ADDRESS_DEFINITION {
	uint8_t PFMDefinitionType;
	uint16_t FVType;
	uint8_t Reserved[5];
	uint32_t FVMAddress;
} PFM_FVM_ADDRESS_DEFINITION;

typedef struct _FVM_CAPABILITIES {
	uint8_t FvmDefinition;
	uint16_t Reserved1;
	uint8_t Revision;
	uint16_t Size;
	uint32_t PckgVersion;
	uint32_t LayoutId;
	struct {
		uint32_t Reboot : 1;
		uint32_t Reserved : 31;
	} UpdateAction;
	uint8_t Reserved2[26];
	uint8_t Description[20];
} FVM_CAPABLITIES;

typedef struct _AFM_STRUCTURE {
	uint32_t AfmTag; /* Should be 0x8883CE1D */
	uint8_t SVN;
	uint8_t Reserved;
	uint16_t AfmRevision; /* Major:Minor */
	uint8_t OemSpecificData[16];
	uint32_t Length;
	uint8_t AfmBody[];
	/* Padding to nearest 128B bondary with 0xFF */
} AFM_STRUCTURE;

typedef struct _AFM_ADDRESS_DEFINITION {
	uint8_t AfmDefinitionType; /* 0x03 AFM SPI region address definitions */
	uint8_t DeviceAddress; /* 7-bit SMBus address of the device to be measured */
	uint16_t UUID; /* Universal Unique ID of the device */
	uint32_t Length; /* Length of the AFM in bytes */
	uint32_t AfmAddress; /* Address of AFM must be at least 4k aligned */
} AFM_ADDRESS_DEFINITION;

typedef struct _AFM_DEVICE_MEASUREMENT_VALUE {
	uint8_t PossibleMeasurements;
	uint8_t ValueType; /* Defined in DSP0274 1.0.0 spec section 4.10 */
	uint16_t ValueSize; /* Size of measurement value */
	uint8_t Values[];
} AFM_DEVICE_MEASUREMENT_VALUE;

typedef struct _AFM_DEVICE_STRUCTURE {
	uint16_t UUID;
	uint8_t BusID;
	uint8_t DeviceAddress; /* 7-bit SMBus address of the device to be measured */
	uint8_t BindingSpec; /* MCTP physical trasport binding (SMBus or I3C) */
	uint16_t BindingSpecVersion; /* Major:Minor */
	uint8_t Policy;
	uint8_t SVN;
	uint8_t Reserved1;
	uint16_t AfmVersion; /* Major:Minor */
	uint32_t CurveMagic; /* AFM_PUBLIC_SECP256_TAG, AFM_PUBLIC_SECP384_TAG, AFM_PUBLIC_RSA2K_TAG ... */
	uint16_t PlatformManufacturerStr;
	uint16_t PlatformManufacturerIDModel;
	uint8_t Reserved2[20];
	uint8_t PublicKeyModuleXY[512];
	uint32_t PublicKeyExponent;
	uint32_t TotalMeasurements;
	AFM_DEVICE_MEASUREMENT_VALUE Measurements[];
} AFM_DEVICE_STRUCTURE;

#define SHA384_SIZE 48
#define SHA256_SIZE 32

#define BIOS1_BIOS2 0x00
#define ME_SPS          0x01
#define Microcode1      0x02
#define Microcode2      0x03

#define SPI_REGION     0x1
#define SMBUS_RULE     0x2
#define FVM_ADDR_DEF   0x3
#define FVM_CAP        0x4

#define SIZE_OF_PCH_SMBUS_RULE 40
#define SPI_REGION_DEF_MIN_SIZE 16

#define PCH_FVM_SPI_REGION 0x01
#define PCH_FVM_CAP        0x04

typedef struct {
	uint8_t Calculated : 1;
	uint8_t Count : 2;
	uint8_t RecoveredCount : 2;
	uint8_t DynamicEraseTriggered : 1;
	uint8_t Reserved : 2;
} ProtectLevelMask;

extern uint32_t g_manifest_length;
extern uint32_t g_fvm_manifest_length;

extern ProtectLevelMask pch_protect_level_mask_count;
extern ProtectLevelMask bmc_protect_level_mask_count;

#pragma pack()

int read_statging_area_pfm(struct pfr_manifest *manifest, uint8_t *svn_version);
int get_recover_pfm_version_details(struct pfr_manifest *manifest, uint32_t address);
int pfm_version_set(struct pfr_manifest *manifest, uint32_t read_address);
int pfm_spi_region_verification(struct pfr_manifest *manifest);

