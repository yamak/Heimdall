#ifndef HEIMDALL_CONFIG_H
#define HEIMDALL_CONFIG_H

/*****************************************************Current Configuration********************************************************
 *
 *                 39 38         30 29         21 20         12 11
 * +-----------------+-------------+-------------+-------------+-----------------+
 * |                 |             |             |             |                 |
 * |                 |             |             |             |                 |
 * +-----------------+-----+-------+------+------+------+------+--------+--------+
 *                         |              |             |               |
 *                         |              |             |               +------------ [11:0]  Physical frame offset
 *                         |              |             |
 *                         |              |             |
 *                         |              |             |
 *                         |              |             +---------------------------- [20:12] Index the level 3 page table
 *                         |              |
 *                         |              |
 *                         |              |
 *                         |              +------------------------------------------ [29:21] Index the level 2 page table
 *                         |
 *                         |
 *                         |
 *                         +--------------------------------------------------------- [30:38] Index the level 1 page table
 *
 *
 ********************************************************************************************************************************/

#define PAGE_SIZE 4096 									//4KB		
#define LINUX_LINEAR_MAPPING_MASK 0x3FFFFFFFFF			// Linux linear mapping mask
#define VA_BITS	39 										// Virtual address length 
#define KIMAGE_VOFFSET 0xFFFFFF8008000000 				// Kernel image Virtual address offset

#define NEXT_LEVEL_TABLE_ADDRESS_MASK 0xFFFFFFFFF000    // Every page table 4kb page aligned 
#define INIT_TASK_PHYSICAL_ADDRESS 0x1081500            // Init task physical address
#define LEVEL1_TABLE_SHIFT 30 							// Level 1 page table start bit
#define LEVEL2_TABLE_SHIFT 21							// Level 2 page table start bit
#define LEVEL3_TABLE_SHIFT 12							// Level 3 page table start bit
#define PAGE_TABLE_MASK 0x1FF							// Length of each page table is 9 bit
#define PAGE_MASK 0xFFFFFFFFF000						// Page number mask. Clear first 12 bit
#define PAGE_OFFSET_MASK 0xFFF 							// Page offset mask. Clear other than first 12 bit  		
#define TASK_COMM_LEN	16								// Linux task name length
#define DNAME_INLINE_LEN 32								// Linux executable and shared object name length
#define DIGEST_SIZE 32									// Digest size. Output length of SHA256 is 32 byte

#endif // HEIMDALL_CONFIG_H