/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#define BMC_FLASH_ID                            0
#define PCH_FLASH_ID                            1

#define BMC_TYPE 0
#define PCH_TYPE 2

#define UFM0            4
#define UFM0_SIZE       256

#define UFM1            3

#define FALSE                            0
#define TRUE                             1
#define START                            2

#define PROVISION_UFM UFM0
#define PROVISION_UFM_SIZE UFM0_SIZE

#define UPDATE_STATUS_UFM UFM1
#define UPDATE_STATUS_ADDRESS 0x00

// Debug configuration token
#define PF_STATUS_DEBUG                 1
#define PF_UPDATE_DEBUG                 1
#define SMBUS_MAILBOX_DEBUG             1
#define INTEL_MANIFEST_DEBUG            1

#define BMC_SUPPORT                     1
#define EMULATION_SUPPORT               1
#define LOG_DEBUG                       1
#define LOG_ENABLE                      1
#define SMBUS_MAILBOX_SUPPORT           1
#define PFR_AUTO_PROVISION              1
#define UART_ENABLE                     1

#define CPLD_RELEASE_VERSION            1
#define CPLD_RoT_SVN                    1

// BIOS/BMC SPI Region information
#define PCH_ACTIVE_FW_UPDATE_ADDRESS    0x00000000
#define PCH_CAPSULE_STAGING_ADDRESS     0x007F0000
#define PCH_PFM_ADDRESS                 0x02FF0000
#define PCH_FVM_ADDRESS                 0x02FF1000
#define PCH_RECOVERY_AREA_ADDRESS       0x01BF0000

#define PBC_COMPRESSION_TAG             0x5F504243
#define PBC_VERSION                     2
#define PBC_PAGE_SIZE                   0x1000
#define PBC_PATTERN_SIZE                0x0001
#define PBC_PATTERN                     0xFF


#define BLOCK0TAG                       0xB6EAFD19
#define BLOCK0_RSA_TAG                  0x35C6B783
#define BLOCK1TAG                       0xF27F28D7
#define BLOCK1_RSA_TAG                  0xD1550984
#define BLOCK1_ROOTENTRY_TAG            0xA757A046
#define BLOCK1_ROOTENTRY_RSA_TAG        0x6CCDCAD7
#define BLOCK1CSKTAG                    0x14711C2F
#define BLOCK1_BLOCK0ENTRYTAG           0x15364367
#define SIGNATURE_SECP256_TAG           0xDE64437D
#define SIGNATURE_SECP384_TAG           0xEA2A50E9
#define SIGNATURE_RSA2K_256_TAG         0xee728a05
#define SIGNATURE_RSA3K_384_TAG         0x9432a93e
#define SIGNATURE_RSA4K_384_TAG         0xF61B70F3
#define SIGNATURE_RSA4K_512_TAG         0x383c5144
#define PUBLIC_SECP256_TAG              0xC7B88C74
#define PUBLIC_SECP384_TAG              0x08F07B47
#define PUBLIC_RSA2K_TAG                0x7FAD5E14
#define PUBLIC_RSA3K_TAG                0x684694E6
#define PUBLIC_RSA4K_TAG                0xB73AA717
#define PEM_TAG                         0x02B3CE1D
#define PFM_SIG_BLOCK_SIZE              1024
#define PFM_SIG_BLOCK_SIZE_3K           3072
#define PFMTAG                          0x02B3CE1D
#define FVMTAG                          0xA8E7C2D4
#define PFMTYPE                         0x01
#define UPDATE_CAPSULE                  1
#define ACTIVE_PFM                      2
#define ROT_TYPE                        3
#define LENGTH                          256

#define  SIGN_PCH_PFM_BIT0              0x00000001
#define  SIGN_PCH_UPDATE_BIT1           0x00000002
#define  SIGN_BMC_PFM_BIT2              0x00000004
#define  SIGN_BMC_UPDATE_BIT3           0x00000008
#define  SIGN_CPLD_UPDATE_BIT4          0x00000010
#define  SIGN_CPLD_UPDATE_BIT9          0x00000200

#define SHA384_SIZE 48
#define SHA256_SIZE 32

#define SHA256_DIGEST_LENGTH    32
#define SHA384_DIGEST_LENGTH    48
#define SHA512_DIGEST_LENGTH    64
#define FOUR_BYTE_ADDR_MODE     1
#define SVN_MAX                 63
#define MAX_READ_SIZE                   0x1000
#define MAX_WRITE_SIZE                  0x1000
#define PAGE_SIZE                       0x1000
#define BLOCK_SIZE                      0x10000
#define UFM_PAGE_SIZE                   16
#define ROOT_KEY_SIZE                   64
#define ROOT_KEY_X_Y_SIZE_256           32
#define ROOT_KEY_X_Y_SIZE_384           48

#define BLOCK_SUPPORT_1KB 1
#define BLOCK_SUPPORT_3KB 0

#define SMBUS_FILTER_IRQ_ENABLE                 0x20
#define SMBUS_FILTER_IRQ_DISABLE                0x00
#define SMBUS_FILTER_ENCRYPTED_DATA_SIZE        64
#define NOACK_FLAG                              0x3
#define ACTIVE_UFM PROVISION_UFM
#define ACTIVE_UFM_SIZE PROVISION_UFM_SIZE


#define  BIT0_SET                               0x00000001
#define  BIT1_SET                               0x00000002
#define  BIT2_SET                               0x00000004
#define  BIT3_SET                               0x00000008
#define  BIT4_SET                               0x00000010
#define  BIT5_SET                               0x00000020
#define  BIT6_SET                               0x00000040
#define  BIT7_SET                               0x00000080      // Smbus filter disable/enable Reuest key permission
#define  BIT8_SET                               0x00000100      // Debug Request key permission

enum Ecc_Curve {
	secp384r1 = 1,
	secp256r1,
};

typedef enum {
	DECOMPRESSION_STATIC_REGIONS_MASK             = 0b1,
	DECOMPRESSION_DYNAMIC_REGIONS_MASK            = 0b10,
	DECOMPRESSION_STATIC_AND_DYNAMIC_REGIONS_MASK = 0b11,
} DECOMPRESSION_TYPE_MASK_ENUM;

typedef struct {
	uint8_t ActiveRegion;
	uint8_t Recoveryregion;
} UPD_REGION;

typedef struct {
	uint8_t CpldStatus;
	uint8_t BmcStatus;
	uint8_t PchStatus;
	UPD_REGION Region[3];
	uint8_t DecommissionFlag;
	uint8_t CpldRecovery;
	uint8_t BmcToPchStatus;
	uint8_t Reserved[4];
} CPLD_STATUS;

