## What is Heimdall
Heimdall is OP-TEE based live memory forensics application which was developed for the requirement of Hacettepe University's 'CMP655-Wireless Networks' Course. Because Heimdall is protected by TEE, the integrity of forensics process can not  be broken from non-secure world. 
It is designed for IoT devices that run Linux. At the setup phase, all directories in the root file system are scanned by the ElfHasher tool that is designed for Heimdall, and a hash table is created for each 4KB page of each elf file. At run time, Heimdall reads all code segments of executables and shared objects(.so files) linked to them page by page by iterating over task_struct objects of Linux kernel and calculates hash function of each page. Thus it can check the consistency of an application or detect unregistered executables in the system. 
Because it has a similar task with Heimdall the protector of Asgard, this name was given to this project.  

# How Heimdall Works?

When Heimdall runs, It looks at the Linux kernel's task_struct, mm_struct, and vm_area_struct in memory directly.
### task_struct
Linux kernel creates an instance of task_struct for each task and every task in the system is linked to each other via a linked list. It can be walk through task_struct instances via 'tasks' attribute of task_struct. The first instance of task_struct is init_task that is created for 'swapper' process and its pid is 0.  So init_task is the start point of Heimdall. If KASLR(Kernel Address Space Layout) is the disabled, physical address of init_task is constant. If KASLR is enabled, physical address of init_task changes after reboot. Since init_task address can be manipulated by adversaries, Heimdall uses physical address of init_task as hard code. ** So, Heimdall isn't suitable for KASLR enabled systems. **
### mm_struct
task_struct has mm attribute that is an instance of mm_struct. mm stores all virtual memory areas of a task and first-level page table address(pgd). When converting a virtual address of user space to a physical address, pgd becomes the start point of this process.

### vma_area_struct
mm_struct has mmap attribute that is an instance of vm_area_struct.
While kernel loading an elf file into the memory, it creates memory areas for code and text segment and also does the same things for shared objects that are linked to that application. mmap attribute of mm_struct stores information about these memory areas. Thanks to vm_next and vm_prev attributes of vm_area_struct, it is possible to move back and forth between virtual memory areas of a task. Also, vm_area_struct has vm_file attribute that is an instance of file struct. The name of elf file is read from this struct by Heimdall for searching hash table.

### Virtual Address Conversion
All address that is stored in task_struct, mm_struct, vm_area_struct as virtual address. This virtual address is only valid for Linux. So this address must be converted to the virtual address in the OP-TEE address space. Since Linux kernel space is linear mapping, the virtual addresses of the Linux kernel itself can be converted without reading page tables. (See linux_virt_to_phys macro in linux_access.h). However, virtual addresses of Linux userspace must be converted to a physical address by performing page table walking.(See linux_follow_page in heimdall.c). When the virtual address of Linux is converted to physical, it can be converted to the virtual address of OP-TEE address space easily via phys_to_virt function OP-TEE kernel. 

## ElfHasher Tool
Actually, ElfHasher is a C++ class. It is used for creating hash table. It has a simple interface. It takes executable and shared object directories. It searches given directories, calculates hash of each page of each elf file's code segment, and then generates hash_table.h file. This header file includes two arrays named EXEC_BOUNDRY and ELF_DIGEST_TABLE.  EXEC_BOUNDRY contains {elf_file_name, start_index, end_index} entries for each elf in the system. start and end indexes give start and end points of that file in the ELF_DIGEST_TABLE.E.g, If code segment of libc.so have 372 4KB page, start and end index of 'libc.so' can be 2295 and 2606 respectively. Because data segments are writable, they can be changed at run time. So Heimdall only checks code segments of elf files. ELF_DIGEST_TABLE contains hash digest of each page of each elf file. Thus, Heimdall can find digest of a page quickly.

## Heimdall Client Application
Heimdall client application is a Linux application that starts Heimdall.

# Build Instruction

### Heimdall

`cd /path/to/optee_os/core/pta`

`ln -s /path/to/Heimdall  heimdall`

Add following line to sub.mk in pta directory

`subdirs-y += heimdall`

Build op-tee os according build instruction in the documentation of OP-TEE

### Heimdall Client

`cd /path/to/Heimdall/Client`

`export CROSS_COMPILE=/path/to/your compiler/aarch64-linux-gnu-`

`make TEEC_EXPORT=/path/to/optee_client/build/out --no-builtin-variables`

### ElfHasher
See example code in ElfHasher directory.

# Test Environment
Current release of Heimdall was tested on Avnet UltraZed-EV board with following releases 
* optee_os-3.7.0
* optee_client-3.7.0
* arm-trusted-firmware-xilinx-v2019.2
* linux-xlnx-xilinx-v2019.2.01


# Future Works
1. Heimdall should be activated periodically by requests from the normal world. However, activation mechanism must be protected by a watchdog timer. Otherwise, this mechanism can be stopped by an attacker. Also watchdog timer must be initialized as secure and it is kicked for every request by the secure world. So if an attacker prevents the running of Heimdall, the system will be reset by the watchdog timer.  Example code for this mechanism can be added to project.

2.  When accessing a task_struct, a race condition can be occured between Linux and OP-TEE. To prevent this situation, alloc_lock attribute of task_struct can be used. To use alloc_task, it is necessary to implement spin_lock and spin_unlock functions of Linux kernel for OP-TEE. This features can be added to project.



