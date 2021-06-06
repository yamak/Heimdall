#ifndef LINUX_ACCESS_H
#define LINUX_ACCRSS_H

#include "heimdall_config.h" 

//vm_flags in vm_area_struct
#define VM_NONE		0x00000000
#define VM_READ		0x00000001
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

struct mm_struct;

typedef struct { uint64_t pgd; } pgd_t; // First level page table address type

/**
 * @brief The list_head struct
 * list_head struct of linux kernel
 */
struct list_head {
	struct list_head *next, *prev;
};

/**
 * @brief The dentry struct
 * Required part of dentry struct of linux kernel
 */
struct dentry
{
	char padding1[56];
	unsigned char d_iname[DNAME_INLINE_LEN];
};

/**
 * @brief The path struct
 * Required part of path struct of linux kernel
 */
struct path
{
	char padding1[8];
	struct dentry* dentry;
};

/**
 * @brief The file struct
 * Required part of file struct of linux kernel
 */
struct file
{
	char padding1[16];
	struct path f_path;

};

/**
 * @brief The vm_area_struct struct
 * Required part of vm_area_struct struct of linux kernel
 */
struct vm_area_struct
{
	long unsigned int vm_start;
	long unsigned int vm_end;
	struct vm_area_struct* vm_next;
	struct vm_area_struct* vm_prev;
	char padding1[32];
	struct mm_struct* vm_mm;
	char padding2[8];
	long unsigned int vm_flags;
	char padding3[72];
	struct file* vm_file;
};

/**
 * @brief The mm_struct struct
 * Required part of mm_struct struct of linux kernel
 */
struct mm_struct
{
	struct vm_area_struct* mmap;
	char padding1[56];
	pgd_t* pgd;
	char padding2[160];
	unsigned long int start_code;
	unsigned long int end_code;
	unsigned long int start_data;
	unsigned long int end_data;
	unsigned long int start_brk;
	unsigned long int brk;
	unsigned long int start_stack;
};

/**
 * @brief The task_struct struct
 * Required part of task_struct struct of linux kernel
 */
struct task_struct
{
	char padding1[696];
	struct list_head tasks;
	char padding2[64];
	struct mm_struct* mm; 
	char padding3[168];
	int pid;
	char padding4[420];
	char comm[TASK_COMM_LEN];
};

/**
 * @brief The next_task macro
 * This macro returns next task given parameter with p.
 * It works like linux's next_task.Since next attribute of
 * task_task store next task address as virtual, this function
 * convert this virtual address to optee's virtual address.
 * @param p current task_struct's address
 */
#define next_task(p)({ \
	uint64_t physical_addr=linux_virt_to_phys((uint64_t)((p)->tasks.next));\
	struct list_head* nextHead=(struct list_head*)phys_to_virt(physical_addr,MEM_AREA_RAM_NSEC);\
	container_of(nextHead,struct task_struct,tasks);\
})

/**
 * @brief The for_each_process macro
 * This function can be used for iterating over linux task_structs
 * It works like linux version, but this uses new next_task macro.
 * @param p Initial task_struct address
 */
#define for_each_process(p) \
	for (p = init_task ; (p = next_task(p)) != init_task ; )

/**
 * @brief The is_lm_address macro
 * This macro is same as linux version
 * The linear kernel range starts in the middle of the virtual adddress
 * space. Testing the top bit for the start of the region is a
 * sufficient check.
 * @param addr Address that will be checked
 */
#define is_lm_address(addr) (!!(addr&(1UL<<(VA_BITS-1))))

/**
 * @brief The linux_virt_to_phys macro
 * This macro convert linux virtual address to physical address
 * @param addr Address that will be converted
 */
#define linux_virt_to_phys(addr) is_lm_address(addr)?(addr&LINUX_LINEAR_MAPPING_MASK):(addr-KIMAGE_VOFFSET)

/**
 * @brief The linux_virt_to_optee_virt macro
 * This macro convert linux virtual address to optee virtual address
 * @param addr Address that will be converted
 */
#define linux_virt_to_optee_virt(addr) ({\
		paddr_t __x = linux_virt_to_phys((uint64_t)addr);\
		phys_to_virt(__x,MEM_AREA_RAM_NSEC);\
})

#endif //LINUX_ACCESS_H
