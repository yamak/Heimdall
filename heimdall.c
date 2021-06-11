/* Copyright 2021 Yusuf YAMAK. All Rights Reserved.
   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
*/
#include <compiler.h>
#include <stdio.h>
#include <string.h>
#include <trace.h>
#include <kernel/pseudo_ta.h>
#include <kernel/panic.h>
#include <mm/tee_mm.h>
#include <mm/core_memprot.h>
#include <crypto/crypto.h>
#include "linux_access.h"
#include "heimdall.h"
#include "hash_table.h"


static TEE_Result calcutage_page_hash(paddr_t pageAddr);
static TEE_Result hash_init(void);
static void hash_deinit(void);

void* hash_ctx;                                       // global hash context
struct anomaly_info current_anomaly_info;             // Global anomaly info. heimdall_get_anomaly_info function returns address of this variable.
const unsigned char* current_expected_digest;         // Digest read from hash table is stored in this variable.
unsigned char current_calculated_digest[DIGEST_SIZE]; // Every calculated digest is stored in this array
const struct task_struct* init_task;

/**
 * @brief follow_page
 * This function perfoms page table walking operation. It behaves like MMU.
 * It converts linux's virtual address to physical address. This function
 * is relevant for 3 level page table configuration.
 * @param vma address of Linux vma struct which virtual address in
 * second parameter reside in
 * @param address Linux virtual address that wants to be converted to the physical address
 * @return Physical address
 */
static paddr_t follow_page(struct vm_area_struct *vma, unsigned long address)
{
	uint64_t* pageTablePtr;
	uint16_t pageTableIndex;
	paddr_t pageTablePhyscalAddr;
	paddr_t result;
	struct mm_struct* vm_mm_virt;

        vm_mm_virt   = (struct mm_struct*)linux_virt_to_optee_virt(vma->vm_mm); // Get vma's vm_mm attribute as optee virtual address
        pageTablePtr = (uint64_t*)linux_virt_to_optee_virt(vm_mm_virt->pgd);    // Get first level page table as optee virtual address

        pageTableIndex = (address>>LEVEL1_TABLE_SHIFT)&PAGE_TABLE_MASK; // Calculate first level page table index.
        pageTablePtr += pageTableIndex; // Add index to first level page table address
        pageTablePhyscalAddr = (*(pageTablePtr))&NEXT_LEVEL_TABLE_ADDRESS_MASK; // Read second level page table physical address
        pageTablePtr = phys_to_virt(pageTablePhyscalAddr,MEM_AREA_RAM_NSEC); // Convert physical address of second level page table to virtual address

        pageTableIndex = (address >> LEVEL2_TABLE_SHIFT)&PAGE_TABLE_MASK; // Calculate second level page table index.
        pageTablePtr += pageTableIndex; // Add index to second level page table address
        pageTablePhyscalAddr = (*(pageTablePtr))&NEXT_LEVEL_TABLE_ADDRESS_MASK; // Read third level page table physical address
        pageTablePtr = phys_to_virt(pageTablePhyscalAddr,MEM_AREA_RAM_NSEC); // Convert physical address of third level page table to virtual address

        pageTableIndex = (address >> LEVEL3_TABLE_SHIFT)&PAGE_TABLE_MASK; // Calculate third level page table index.
        pageTablePtr += pageTableIndex; // Add index to third level page table address

        result = ((*(pageTablePtr)))&PAGE_MASK; // Read physical frame number from third level page table

        result |= address&PAGE_OFFSET_MASK; // Add page offset to physical frame number.
	
        return result;

}

/**
 * @brief findDigestBoundry
 * This function find boundry in ELF_DIGEST_TABLE from EXEC_BOUNDRY array
 * @param filename Elf file name
 * @return Boundry struct of given elf file. If couldn't find, it returns NULL
 */
static const DigestBoundry* findDigestBoundry(const char* filename)
{
	const DigestBoundry* temp;
	int len;
        len = sizeof(EXEC_BOUNDRY)/sizeof(DigestBoundry); // Calculate length of EXEC_BOUNDRY array
        for (int i=0; i < len; i++) // Iterate over EXEC_BOUNDRY array
	{
		temp = &EXEC_BOUNDRY[i];
                if (!strcmp(filename, temp->filename)) // Compare current file name with given file name.
                    return temp; //Return result.
	}
	return NULL;
}

/**
 * @brief checkHashTable
 * This function compares current_calculated_digest with digest in given index.
 * @param boundry Boundry struct of digest that will be checked.
 * @param pageCount Page number of digest that will be checked.
 * @return If current_calculated_digest is found in given index, it returns TEE_SUCCESS.
 * Otherwise, it returns TEE_ERROR_SECURITY
 */
static TEE_Result checkHashTable(const DigestBoundry* boundry, unsigned int pageCount)
{
	current_expected_digest = ELF_DIGEST_TABLE[boundry->startIndex+pageCount].data;
        if (!memcmp(current_expected_digest, current_calculated_digest, DIGEST_SIZE))
            return TEE_SUCCESS;
	return TEE_ERROR_SECURITY; 
}

/**
 * @brief scan_task_vma
 * This function scans every page of given task and also every page of
 * every shared obhect that is linked to this task. It compares
 * the hash of each page with the corresponding index of the hash table
 * in the hash_table.h
 * @param task task_struct of task that will be checked.
 * @return If there isn't any anomaly, it returns HEIMDALL_SUCCESS.
 * If it detects unregistered elf, it returns HEIMDALL_UNREGISTERED_ELF.
 * If it detect unexpected digest, it returns HEIMDALL_UNEXPECTED_DIGEST.
 */
static heimdall_return_t scan_task_vma(const struct task_struct* task)
{
	struct mm_struct* mm_virt;
	struct vm_area_struct* vma_virt;
	struct file* vm_file_virt;
	struct dentry* dentry_virt;
	paddr_t physical_addr;
	uint64_t page;
	int page_num = 0;
	const DigestBoundry* digestBoundry;
        mm_virt  = (struct mm_struct*)linux_virt_to_optee_virt(task->mm); // Convert linux virtual address of mm attribute of task_struct to optee virtual address.
        vma_virt = (struct vm_area_struct*)linux_virt_to_optee_virt(mm_virt->mmap); // Convert linux virtual address of mmap attribute of mm_struct to optee virtual address.
        while (vma_virt) // Iterate until NULL
	{
                vm_file_virt  = (struct file*)linux_virt_to_optee_virt(vma_virt->vm_file); // Convert linux virtual address of vm_file attribute of vm_area_struct to optee virtual address.
                if (vm_file_virt) // If it isn't NULL
		{
                        if ((vma_virt->vm_flags) & VM_EXEC) // Check this area whether executable or not. Only executable segment is checked.
			{
                                page_num = 0; // Because of new vma, clear page number
                                dentry_virt = (struct dentry*)linux_virt_to_optee_virt(vm_file_virt->f_path.dentry); // Convert linux virtual address of f_path.dentry attribute of file to optee virtual address.
                                digestBoundry = findDigestBoundry((char*)dentry_virt->d_iname); // Find boundry of this elf file.d_iname includes name of this elf file.
                                if (!digestBoundry) // If digestBoudry was not found, it means that unregistered elf file
				{
                                        memset(&current_anomaly_info, 0, sizeof(current_anomaly_info)); // Clear global current_anomaly_info
                                        memcpy(current_anomaly_info.unregistered_elf_name, dentry_virt->d_iname, DNAME_INLINE_LEN); // Copy this elf file name to corresponding attribute in current_anomaly_info
                                        return HEIMDALL_UNREGISTERED_ELF; // Return
                                }

                                for (page = vma_virt->vm_start; page < vma_virt->vm_end; page += PAGE_SIZE) // Iterate over every page of this vma
				{
                                        physical_addr = follow_page(vma_virt,page); // Convert virtual address of linux to physical address.
                                        if (physical_addr) // It must be checked whether it is NULL or not. Because of demand paging, this page may have been evicted from memory.
					{
                                                calcutage_page_hash(physical_addr); // Calculate hash of this page.
                                                if (checkHashTable(digestBoundry,page_num) != TEE_SUCCESS) // Check hash table for this page and if hash digest of this page could'n found in hash table,
						{
                                                        memset(&current_anomaly_info, 0, sizeof(current_anomaly_info));//Clear current_anomaly_info

                                                        //Fill current_anomaly_info
                                                        memcpy(current_anomaly_info.expected_digest, current_expected_digest, DIGEST_SIZE);
                                                        memcpy(current_anomaly_info.unexpected_digest, current_calculated_digest, DIGEST_SIZE);
                                                        memcpy(current_anomaly_info.elf_name, dentry_virt->d_iname, DNAME_INLINE_LEN);
                                                        current_anomaly_info.page_number = page_num;
                                                        return HEIMDALL_UNEXPECTED_DIGEST; //Return
	
						}
					}
                                        page_num++; // Increase page number.
				}
			}
		}
                vma_virt = (struct vm_area_struct*)linux_virt_to_optee_virt(vma_virt->vm_next); // Read next vma and convert linux virtual address to optee virtual address
	}
        return HEIMDALL_SUCCESS; //Return as success
}


/**
 * @brief hash_init
 * This fuction initialize optee's hash functions
 * @return  If there isn't any error, it returns TEE_SUCCESS
 */
static TEE_Result hash_init(void)
{
	TEE_Result res;
        res = crypto_hash_alloc_ctx(&hash_ctx, HASH_ALGO); // Allocate hash context.
	if(res)
	{
		EMSG("Hash Context Allocation Error\n");
		return res;
	}
        res=crypto_hash_init(hash_ctx, HASH_ALGO); // Initialize allocated context
	if(res)
	{
		EMSG("Hash Init Error\n");
		return res;
	}
	return TEE_SUCCESS;
}

/**
 * @brief hash_deinit
 * This function frees allocated areas in hash_init function.
 */
static void hash_deinit(void)
{
    crypto_hash_free_ctx(hash_ctx, HASH_ALGO); // Free allocated hash context
}

/**
 * @brief calcutage_page_hashvoid*
 */
static TEE_Result calcutage_page_hash(paddr_t pageAddr)
{
	TEE_Result res;
	uint8_t* page_virt_addr;

        page_virt_addr = (uint8_t*)phys_to_virt(pageAddr, MEM_AREA_RAM_NSEC); // Convert physical address to virtual address

        res=crypto_hash_update(hash_ctx, HASH_ALGO, page_virt_addr, PAGE_SIZE); // Append this page
        if (res)
	{
		EMSG("Hash Update Error\n");
		return res;
	}

        res=crypto_hash_final(hash_ctx, HASH_ALGO, current_calculated_digest, DIGEST_SIZE); // Calculate hash
	if(res)
	{
		EMSG("Hash finalize Error\n");
		return res;
	}
        crypto_hash_init(hash_ctx, HASH_ALGO); // Clear context for calling another crypto_hash_update.

	return TEE_SUCCESS;

}

/**
 * @brief heimdall_get_anomaly_info
 * This function is a getter of anomaly information.
 * It must be called after heimdall_start function.
 * @return address of global anomaly_info struct
 */
const struct anomaly_info* heimdall_get_anomaly_info(void)
{
    return &current_anomaly_info;
}

/**
 * @brief heimdall_start
 * This function starts heimdall. If it returns value other than
 * HEIMDALL_SUCCESS, anomaly info can be get via heimdall_get_anomaly_info
 * function. If it returns HEIMDALL_UNEXPECTED_DIGEST, attributes other than unregistered_elf_name
 * of anomaly_info is meaningful. If it returns HEIMDALL_UNREGISTERED_ELF, only unregistered_elf_name
 * attribute of anomaly_info struct is meaningful.
 * @return Result. If any vulneratbility didn't found, it returns HEIMDALL_SUCCESS
 */
heimdall_return_t heimdall_start(void)
{
        init_task=(struct task_struct*)phys_to_virt(INIT_TASK_PHYSICAL_ADDRESS, MEM_AREA_RAM_NSEC); // Get physical address of init process
        const struct task_struct* task;
        hash_init(); // Init hash function
        heimdall_return_t res = HEIMDALL_SUCCESS;
        for_each_process(task) // Iterate over all running linux tasks
        {
            if (task->mm) // Some task can be kernel thread etc. mm attribute of these task is NULL. We aren't interested in such tasks.
            {
                res = scan_task_vma(task); // Scan all virtual memory area  of curren task.
                if(res != HEIMDALL_SUCCESS) // If there is any anomaly, return
                    break;
            }
        }
        hash_deinit(); // Deinit hash function
        return res;
}


