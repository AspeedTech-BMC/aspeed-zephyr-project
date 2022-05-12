/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include "state_machine/common_smc.h"
#include "intel_pfr_definitions.h"


#if PF_UPDATE_DEBUG
#define DEBUG_PRINTF printk
#else
#define DEBUG_PRINTF(...)
#endif

int is_compression_tag_matched(uint32_t image_type, uint32_t *compression_tag,uint32_t read_address,uint32_t AreaSize)
{
    uint32_t tag = 0;
    *compression_tag = *compression_tag + PFM_SIG_BLOCK_SIZE + PFM_SIG_BLOCK_SIZE;// Adding PFR Size
    
    //Loop To verify the Tag.
    while ((*compression_tag <= (read_address + AreaSize) - 4))
    {
    	if( pfr_spi_read(image_type, *compression_tag, sizeof(tag), (uint8_t *)&tag) )
    		return Failure;
        if (tag == COMPRESSION_TAG)
        {
            DEBUG_PRINTF("Tag Found\r\n"); 
            return Success;
        }
        *compression_tag += 1;
    }

    return Failure;
}

int decompression_erasing(uint32_t image_type, uint32_t N,uint32_t active_map_address)
{
	int status = 0;
    uint32_t index0 = 0;
	int8_t index1 = 0;
	uint8_t bit_map_data = 0;
	uint32_t erase_offset = 0;
	
    // Loop To Erase the data in destination chip based on the Active Buffer data
    DEBUG_PRINTF("Erasing...\r\n");
    for (index0 = 0; index0 < N/8; index0++)
    {
        status = pfr_spi_read(image_type, active_map_address, sizeof(uint8_t), (uint8_t *)&bit_map_data);
        if(status != Success){
    		DEBUG_PRINTF("Decompression Erase failed\r\n");
    		return Failure;
    	}
       
        active_map_address += 1;
        for (index1 = 7; index1 >= 0; index1--)
        {
            if ((bit_map_data >> index1) & 1)
            {
            	status = pfr_spi_erase_4k(image_type, erase_offset);
        		if(status != Success){
        			DEBUG_PRINTF("Decompression Erase failed\r\n");
        			return Failure;
        		}
            }
            erase_offset += PAGE_SIZE;
        }
    }
    DEBUG_PRINTF("Erase Successful\r\n");
    return Success;
}

int decompression_write(uint32_t image_type, uint32_t N,uint32_t compression_tag,uint32_t compression_map_address)
{
	int status = 0;
    uint8_t bit_map_data = 0;
	uint32_t index0 = 0;
	int8_t index1 = 0;
	uint32_t erase_offset = 0;
	
    //Loop to Write the Data in destination Chip Based on the Compression Buffer data
    DEBUG_PRINTF("Writing...\r\n");
    for (index0 = 0; index0 < N/8; index0++)
    {
    	status = pfr_spi_read(image_type, compression_map_address,sizeof(uint8_t), (uint8_t *)&bit_map_data);
    	if(status != Success)
    	   	return Failure;
    
    	compression_map_address += 1;
        for (index1 = 7; index1 >= 0; index1--)
        {
			if ((bit_map_data >> index1) & 1){
			    status = pfr_spi_page_read_write(image_type, &compression_tag,&erase_offset);
			    if(status != Success)
			    	return Failure;
			}
			else {
				erase_offset += PAGE_SIZE;
			}
        }
    }
    return Success;
}

int capsule_decompression(uint32_t image_type, uint32_t read_address,uint32_t area_size)
{
    int status = 0;
    uint32_t compression_tag = read_address;
    uint32_t N = 0;
    uint32_t bit_map_address = 0;
    
    if(is_compression_tag_matched(image_type, &compression_tag, read_address,area_size))
    {
        DEBUG_PRINTF("Tag Not Found\r\n");
        return Failure;
    }

    // Collecting the Active and Compression Buffer Values.
    compression_tag += 20;
    status = pfr_spi_read(image_type, compression_tag, sizeof(uint32_t), (uint8_t *)&N);
    if(status != Success){
		DEBUG_PRINTF("Decompression failed\r\n");
		return Failure;
	}

    compression_tag += 108;
    bit_map_address = compression_tag;

    status = decompression_erasing(image_type, N,bit_map_address);
    if(status != Success){
		return Failure;
	}

    compression_tag += N/8;
    bit_map_address = compression_tag;
    compression_tag += N/8;

	status = decompression_write(image_type, N,compression_tag,bit_map_address);
	if(status != Success){
		DEBUG_PRINTF("Decompression write failed\r\n");
		return Failure;
	}
    DEBUG_PRINTF("Decompression completed\r\n");
    return Success;
}



