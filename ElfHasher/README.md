ElfHasher is a C++ class. It is used for creating hash table. It has a simple interface. It takes executable and shared object
directories. It searches given directories, calculates hash of each page of each elf file’s code segment, and then generates
hash_table.h file. This header file includes two arrays named EXEC_BOUNDRY and ELF_DIGEST_TABLE. EXEC_BOUNDRY contains
{elf_file_name, start_index, end_index} entries for each elf in the system. start and end indexes give start and end points of that file
in the ELF_DIGEST_TABLE.E.g, If code segment of libc.so have 372 4KB page, start and end index of ‘libc.so’ can be 2295 and 2606
respectively. Because data segments are writable, they can be changed at run time. So Heimdall only checks code segments of elf
files. ELF_DIGEST_TABLE contains hash digest of each page of each elf file. Thus, Heimdall can find digest of a page quickly. 
