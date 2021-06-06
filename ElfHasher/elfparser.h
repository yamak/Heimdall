/***************************************************************************
 *
 *   FileName: elfparser.h
 *   Author: yusuf yamak
 *   Created On: 19.05.2021
 *   Desription:
 *
 ***************************************************************************/
#ifndef ELFPARSER_H
#define ELFPARSER_H
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <new>

/**
 * @brief The ElfType enum
 * This enum used as paramter of ElfParser class
 */
enum ElfType {
    ELF32,
    ELF64
};

/**
 * @brief The ElfParser class
 * @param T Elf Type. It can be ELF32 or ELF64
 * This is a template class for elf file parsing.
 *
 */
template <ElfType T>
class ElfParser {
private:
    constexpr static const int EI_NIDENT = 16;
    constexpr static const int PF_X = 1;         // Program header table EXECUTABLE flag
    constexpr static const int PF_W = 2;         // Program header table WRITABLE flag
    constexpr static const int PF_R = 4;         // Program header table READABLE flag
    constexpr static const int PAGE_SIZE = 4096; // 4KB

public:
    using Elf_Addr = typename std::conditional<T == ELF32, uint32_t, uint64_t>::type;
    using Elf_Half = uint16_t;
    using Elf_Off = typename std::conditional<T == ELF32, uint32_t, uint64_t>::type;
    using Elf_Section = uint16_t;
    using Elf_Versym = uint16_t;
    using Elf_Byte = char;
    using Elf_Sword = int32_t;
    using Elf_Word = uint32_t;
    using Elf_Sxword = int64_t;
    using Elf_Xword = uint64_t;
    using Elf_unsigned_long = typename std::conditional<T == ELF32, uint32_t, uint64_t>::type;

    enum Section_Type:uint32_t {
        SHT_NULL           = 0x00,        // Marks the section header as inactive
        SHT_PROGBITS,                     // Holds information defined by the program
        SHT_SYMTAB,                       // Holds symbol table
        SHT_STRTAB,                       // Holds string table
        SHT_RELA,                         // Holds relocation entries
        SHT_HASH,                         // Holds a symbol hash table
        SHT_DYNAMIC,                      // Holds information for dynamic linking
        SHT_NOTE,                         // Holds notes
        SHT_NOBITS,                       // Occupies no space in the file
        SHT_REL,                          // Holds relocation entries
        SHT_SHLIB,                        // Reserved
        SHT_DYNSYM,                       // Holds a minimal set of dynamic linking symbols
        SHT_INIT_ARRAY,                   // Holds an array of constructor
        SHT_FINI_ARRAY,                   // Holds an array of destructor
        SHT_PREINIT_ARRAY,                // Holds an array of pre-constructor
        SHT_GROUP,                        // Section group
        SHT_SYMTAB_SHNDX,                 // Extended symbol table section index
        SHT_LOOS           = 0x60000000,  // Start of OS-specific section types
        SHT_GNU_ATTRIBUTES = 0x6ffffff5,  // Object attributes
        SHT_GNU_HASH       = 0x6FFFFFF6,  // GNU-style hash section
        SHT_GNU_VERDEF     = 0x6ffffffd,  // Version definition section
        SHT_GNU_VERNEED    = 0x6ffffffe,  // Version needs section
        SHT_GNU_VERSYM     = 0x6FFFFFFF,  // Version symbol table
        SHT_LOPROC         = 0x70000000,  // Reserved for processor specific. Lower bound
        SHT_X86_64_UNWIND  = 0x70000001,  //
        SHT_HIPROC         = 0x7FFFFFFF,  // Reserved for processor specific. Upper bound
        SHT_LOUSER         = 0x80000000,  // Reserved for application programs. Lower bound
        SHT_HIUSER         = 0xFFFFFFFF,  // Reserved for application programs. Upper bound

    };

    enum FileType:uint16_t
    {
        ET_NONE=0x0,      // Unknow type
        ET_REL,           // Relocatable file
        ET_EXEC,          // Executable file
        ET_DYN,           // Shared object
        ET_CORE,          // Core file
        ET_LOPROC=0xFF00, // Processor-specific
        ET_HIPROC=0xFFFF  // Processor-specific
    };

    enum Program_Type:uint32_t
    {
        PT_NULL = 0X00,          // Unused element
        PT_LOAD,                 // Loadable Segment
        PT_DYNAMIC,              // Dynamic linking information
        PT_INTERP,               // This segment specifies the location of dynamic linker.
        PT_NOTE,                 // This segment specifies the location of notes.
        PT_SHLIB,                // This segment type is reserved.
        PT_PHDR,                 // This segment specifies location and size of the program header table itself.
        PT_LOPROC = 0x70000000,  // Reserved for reserved for processor-specific semantics.
        PT_HIPROC = 0x7FFFFFFF   // Reserved for reserved for processor-specific semantics.
    };

    enum DynamicArrayTags:Elf_unsigned_long
    {
        DT_NULL   = 0x00,       // Marks end of dynamic section
        DT_NEEDED,              // String table offset to name of a needed library
        DT_PLTRELSZ,            // Size in bytes of PLT relocation entries
        DT_PLTGOT,              // Address of PLT and/or GOT
        DT_HASH,                // Address of symbol hash table
        DT_STRTAB,              // Address of string table
        DT_SYMTAB,              // Address of symbol table
        DT_RELA,                // Address of Rela relocation table
        DT_RELASZ,              // Size in bytes of the Rela relocation table
        DT_RELAENT,             // Size in bytes of a Rela relocation table entry
        DT_STRSZ,               // Size in bytes of string table
        DT_SYMENT,              // Size in bytes of a symbol table entry
        DT_INIT,                // Address of the initialization function
        DT_FINI,                // Address of the termination function
        DT_SONAME,              // String table offset to name of shared object
        DT_RPATH,               // String table offset to library search path
        DT_SYMBOLIC,            // Alert linker to search this shared object before the executable for symbols
        DT_REL,                 // Address of Rel relocation table
        DT_RELSZ,               // Size in bytes of Rel relocation table
        DT_RELENT,              // Size in bytes of a Rel table entry
        DT_PLTREL,              // Type of relocation entry to which the PLT refers
        DT_DEBUG,               // Undefined use for debugging
        DT_TEXTREL,             //Absence of this entry indicates that No relocation entries should apply to a nonwritable segment
        DT_JMPREL,              //Address of relocation entries associated solely with the PLT
        DT_LOPROC = 0x70000000, //Reserved for processor-specific semantics
        DT_HIPROC = 0x7FFFFFFF  //Reserved for processor-specific semantics
    };

    /**
     * @brief The ElfHeader struct
     * Struct of Elf Header.
     */
    struct ElfHeader {

        uint8_t e_ident[EI_NIDENT]; // Elf Indentification. It starts with 0x7F,'E','L','F'
        FileType e_type;            // Elf Type. Executable,Shared Object, Relocatable...
        uint16_t e_machine;         // Architecture info.E.g: x86, ARM, MIPS ...
        uint32_t e_version;         // Elf version
        Elf_Addr e_entry;           // Virtual address to which the system first transfers control.
        Elf_Off e_phoff;            // Program Header Table Offset
        Elf_Off e_shoff;            // Section Header Table Offset
        uint32_t e_flags;           // Processor specifig flags
        uint16_t e_ehsize;          // Elf header size in bytes
        uint16_t e_phentsize;       // size of one entry in the program header table
        uint16_t e_phnum;           // Number of entries in program header table
        uint16_t e_shentsize;       // Section header's size
        uint16_t e_shnum;           // Number of entries in the section header table.
        uint16_t e_shstrndx;        // This holds section header table index associated with the section name string table.
    };

    /**
     * @brief The SectionHeader struct
     * Entry of Section Header Table
     */
    struct SectionHeader {
        Elf_Word sh_name;               // Index into the section header string table.
        Section_Type sh_type;           // Section Type. See 'enum SectionType'
        Elf_unsigned_long sh_flags;     // Section attribute flag. (WRITE, ALLOC, EXECINSTR)
        Elf_Addr sh_addr;               // If the section will appear in memory, this member gives the virtual address of section.Otherwise, it contains 0
        Elf_Off sh_offset;              // First byte offset of section from beginning of the file.
        Elf_unsigned_long sh_size;      // Section's size.
        Elf_Word sh_link;               // Section header table index link. It is only meaningful with sh_info
        Elf_Word sh_info;               // Extra information. It is only meaningful with sh_link
        Elf_unsigned_long sh_addraling; // Alignment Constraint.
        Elf_unsigned_long sh_entsize;   // If a section holds a table of fixed-size entries, this member gives the size of each entry.
    };

    /**
     * @brief The DynamicSectionEntry struct
     * Dynamic Section Entry
     */
    struct DynamicSectionEntry {
        DynamicArrayTags d_tag;      // Type of entry. See enum DynamicArrayTags
        union {
            Elf_unsigned_long d_val; // Contains integer value
            Elf_Addr d_ptr;          // Contains virtual address.
        };
    };

    /**
     * @brief The Elf32_Phdr struct
     * Entry of program header table for elf32
     */
    struct Elf32_Phdr {
        Program_Type p_type; // Segment type
        uint32_t p_offset;   // Offset of segment's firs byte from beginning of the file.
        uint32_t p_vaddr;    // Virtual address of segment's first byte
        uint32_t p_paddr;    // Physical address of segment. This member meaningless on systems which use virtual address.
        uint32_t p_filesz;   // It gives the number of bytes in the file image of the segment
        uint32_t p_memsz;    // It gives the number of bytes in the memory image of the segment
        uint32_t p_flags;    // Segment flags
        uint32_t p_align;    // Alignment information.
    };

    /**
     * @brief The Elf64_Phdr struct
     * Entry of program header table for elf64
     */
    struct Elf64_Phdr {
        Program_Type p_type; // Segment type
        uint32_t p_flags;    // Segment flags
        uint64_t p_offset;   // Offset of segment's first byte from beginning of the file.
        uint64_t p_vaddr;    // Virtual address of segment's first byte
        uint64_t p_paddr;    // Physical address of segment. This member meaningless on systems which use virtual address.
        uint64_t p_filesz;   // It gives the number of bytes in the file image of the segment
        uint64_t p_memsz;    // It gives the number of bytes in the memory image of the segment
        uint64_t p_align;    // Alignment information.
    };

    using ProgramHeader = typename std::conditional<T == ELF32, Elf32_Phdr, Elf64_Phdr>::type;

private:
    ElfHeader m_header = {};
    SectionHeader* m_sectionHeaderTable { nullptr };
    std::string m_elfFilePath;
    Elf_Off m_sectionNameStringTableOffset { 0 };
    char* m_sectionNameStringTable { nullptr };
    DynamicSectionEntry* m_dynamicSection { nullptr };
    char* m_dynamicSectionStringTable { nullptr };
    Elf_unsigned_long m_sectionNameStringTableSize { 0 };
    Elf_unsigned_long m_dynamicSectionStringTableSize { 0 };
    Elf64_Phdr* m_programHeaderTable { nullptr };
    char* m_codeSegment{nullptr};
    char* m_dataSegment{nullptr};
    uint32_t m_codeSegmentSize{0};
    uint32_t m_dataSegmentSize{0};
    uint16_t m_dynamicSectionIndex{0};

public:
    ElfParser(const std::string &elfPath);
    bool parseAll();
    bool parseHeader();
    bool parseSectionHeader();
    bool parseProgramHeader();
    bool parseDynamicSection();

    ~ElfParser();
    ElfHeader* getHeader();
    SectionHeader* getSectionHeaderTable();

    DynamicSectionEntry* getDynamicSection();
    const char* getSectionName(SectionHeader* entry);
    const char* getDynamicSectionName(DynamicSectionEntry* section);
    const char* getCodeSegment();
    const char* getDataSegment();
    uint32_t getCodeSegmentSize();
    uint32_t getDataSegmentSize();
};

/**
 * @brief ElfParser<T>::ElfParser
 * Constructor of ElfParser
 * @param elfPath Name of elf file that will be parsed.
 * E.g: /usr/bin/useradd or /lib/libc.so
 */
template <ElfType T>
ElfParser<T>::ElfParser(const std::string& elfPath)
{

    m_elfFilePath=elfPath;
}

/**
 * @brief ElfParser<T>::~ElfParser
 * Destructor of ElfParser
 */
template <ElfType T>
ElfParser<T>::~ElfParser()
{
    //Free, if allocated before
    if (m_sectionHeaderTable)
        delete[] m_sectionHeaderTable;
    if (m_sectionNameStringTable)
        delete[] m_sectionNameStringTable;
    if (m_dynamicSection)
        delete[] m_dynamicSection;
    if (m_dynamicSectionStringTable)
        delete[] m_dynamicSectionStringTable;
    if (m_programHeaderTable)
        delete[] m_programHeaderTable;
}

/**
 * @brief ElfParser<T>::parseHeader
 * This function parses only header. If only the header is to be wanted to parse,
 * only this function can be called.
 * @return If file is opened successfully, returns true. Otherwise, false
 */
template <ElfType T>
bool ElfParser<T>::parseHeader()
{
    std::ifstream elfFile;
    elfFile.open(m_elfFilePath, std::ifstream::binary);
    if (elfFile.is_open()) // If file opened successfully
        elfFile.read(reinterpret_cast<char*>(&m_header), sizeof(ElfHeader)); // Read header to m_header.
    else
        return false;
    return true;
}

/**
 * @brief ElfParser<T>::parseSectionHeader
 * This function parses only section header table. It must be called after
 * parseHeader function.
 * @return If parsing finish successfully, returns true. Otherwise false.
 */
template <ElfType T>
bool ElfParser<T>::parseSectionHeader()
{
    std::ifstream elfFile;
    elfFile.open(m_elfFilePath, std::ifstream::binary); // Open elf file

    if(!elfFile.is_open()) // If file couldn't open, return false
        return false;
    try
    {
        m_sectionHeaderTable = new SectionHeader[m_header.e_shnum]; // Allocation for section header table according to e_shnum in Elf header.
    }
    catch (std::bad_alloc& e)
    {
        std::cerr <<  e.what() << std::endl;
        return false;
    }

    elfFile.seekg(m_header.e_shoff); // Jump to offset of section header in elf file
    if (!elfFile.fail()) // If there isn't any fail
        elfFile.read(reinterpret_cast<char*>(m_sectionHeaderTable), sizeof(SectionHeader) * m_header.e_shnum); // Read section header table to m_sectionHeaderTable
    else
        return false;
    return true;
}

/**
 * @brief ElfParser<T>::parseProgramHeader
 * This function parses only program header table. It must be call after
 * parseHeader function.
 * @return If parsing finish successfully, returns true. Otherwise false.
 */
template <ElfType T>
bool ElfParser<T>::parseProgramHeader()
{
    std::ifstream elfFile;
    elfFile.open(m_elfFilePath, std::ifstream::binary); // Open elf file

    if(!elfFile.is_open()) // If file couldn't open, return false
        return false;
    try
    {
        m_programHeaderTable = new ProgramHeader[m_header.e_phnum]; // Allocation for program header table.
    }
    catch (std::bad_alloc& e)
    {
        std::cerr <<e.what() << std::endl;
        return false;
    }

    elfFile.seekg(m_header.e_phoff); // Jump to offset of section header in elf file
    if (!elfFile.fail()) // If there isn't any fail
        elfFile.read(reinterpret_cast<char*>(m_programHeaderTable), sizeof(ProgramHeader) * m_header.e_phnum); // Read program header table to m_programHeaderTable
    else
        return false;

    for (int i = 0; i < m_header.e_phnum; i++) { // Iterate over program header table entries and find code and data segment
        if (m_programHeaderTable[i].p_type == PT_LOAD) { // If this is a loadable segment. Both of data and code segment is loadable
            if (m_programHeaderTable[i].p_flags & PF_X) { // If this segment is executable, it is a code segment.

                //Code segment is page aligned, but filesz gives only exact size of code segment.
                //In this line m_codeSegmentSize, making page aligned.
                m_codeSegmentSize = m_programHeaderTable[i].p_filesz + (PAGE_SIZE - m_programHeaderTable[i].p_filesz % PAGE_SIZE);
                try
                {
                    m_codeSegment = new char[m_codeSegmentSize]; // Allocation for code segment.
                }
                catch (std::bad_alloc& e)
                {
                    std::cerr <<  e.what() << std::endl;
                    return false;
                }
                elfFile.seekg(m_programHeaderTable[i].p_offset); // Jump to code segment
                if (!elfFile.fail()) // If there isn't any fail.
                    elfFile.read(reinterpret_cast<char*>(m_codeSegment), m_codeSegmentSize); // Reade code segment to m_codeSegment
                else
                    return false;

            }
            else // If this segment isn't executable, it is a data segment.
            {
                //Data segment is page aligned, but filesz gives only exact size of data segment.
                //In this line m_dataSegmentSize, making page aligned.
                m_dataSegmentSize = m_programHeaderTable[i].p_filesz + (PAGE_SIZE - m_programHeaderTable[i].p_filesz % PAGE_SIZE);
                try
                {
                    m_dataSegment = new char[m_dataSegmentSize]; // Allocation for data segment
                }
                catch (std::bad_alloc& e)
                {
                    std::cerr <<  e.what() << std::endl;
                    return false;
                }
                elfFile.seekg(m_programHeaderTable[i].p_offset); // Jump to data segment
                if (!elfFile.fail())
                    elfFile.read(reinterpret_cast<char*>(m_dataSegment), m_dataSegmentSize); // Reade data segment to m_dataSegment
                else
                    return false;
            }
        }
    }
    return true;
}

/**
 * @brief ElfParser<T>::parseDynamicSection
 * This function parses dynamic section. It must be called
 * after parseSectionHeader. Dynamic section can be useful for
 * finding dependent dynamic libraries of an executable
 * @return If parsing finish successfully, returns true. Otherwise false.
 */
template <ElfType T>
bool ElfParser<T>::parseDynamicSection()
{
    std::ifstream elfFile;
    Elf_unsigned_long sh_size;
    Elf_Addr offset;

    elfFile.open(m_elfFilePath, std::ifstream::binary); // Open elf file

    if(!elfFile.is_open()) // If file couldn't open, return false
        return false;

    offset = m_sectionHeaderTable[m_header.e_shstrndx].sh_offset; // Get offset of section name string table
    sh_size = m_sectionHeaderTable[m_header.e_shstrndx].sh_size; // Get size of section name string table
    try
    {
        m_sectionNameStringTable = new char[sh_size]; // Allocation for section name string table
    }
    catch (std::bad_alloc& e) {
        std::cerr <<  e.what() << std::endl;
        return false;
    }

    elfFile.seekg(offset); // Jump to section name string table
    if (!elfFile.fail()) // If there isn't any error.
        elfFile.read(m_sectionNameStringTable, sh_size); // Read section name string table to m_sectionNameStringTable
    else
        return false;

    for (int i = 0; i < m_header.e_shnum; i++) // find dynamicSection index;
    {

        if (m_sectionHeaderTable[i].sh_type == SHT_DYNAMIC) // If sh_type is SHT_DYNAMIC, this is the dynamic section
        {
            m_dynamicSectionIndex = i; // Get dynamic section index of section header table.
            break;
        }
    }

    if(m_dynamicSectionIndex) // If dynamic section is found
    {
        sh_size = m_sectionHeaderTable[m_dynamicSectionIndex].sh_size; // Get dynamic section size
        try
        {
            m_dynamicSection = new DynamicSectionEntry[sh_size / sizeof(DynamicSectionEntry)]; //Allocate Array of DynamicSectionEntry. sh_size / sizeof(DynamicSectionEntry) gives length.
        }
        catch (std::bad_alloc& e)
        {
            std::cerr <<e.what() << std::endl;
            return false;
        }

        offset = m_sectionHeaderTable[m_dynamicSectionIndex].sh_offset; // Get offset of dynamic section.
        elfFile.seekg(offset); // Jump to dynamic section.
        if (!elfFile.fail()) // If there isn't any error.
            elfFile.read(reinterpret_cast<char*>(m_dynamicSection), sh_size); // Read dynamic section to m_dynamicSection
        else
            return false;

        for (DynamicSectionEntry* entry = m_dynamicSection; entry->d_tag != 0; entry++) { //Iterate over Dynamic section entries and find string table
            if (entry->d_tag == DT_STRTAB) { // If d_tag is DT_STRTAB, this is the string table
                offset = entry->d_val; // Get string table offset
                break;
            }
        }

        for (int i = 0; i < m_header.e_shnum; i++) // Find section of string table and get size of dynamic section string table size
        {
            if (m_sectionHeaderTable[i].sh_addr == offset) { // Compare found offset with current sh_addr
                m_dynamicSectionStringTableSize = m_sectionHeaderTable[i].sh_size; // get dynamic section string table size
                offset = m_sectionHeaderTable[i].sh_offset; // Get dynamic section string table offset
                break;
            }
        }

        if (m_dynamicSectionStringTableSize) { // If m_dynamicSectionStringTableSize is bigger than 0, this means that dynamic section string table is found
            try
            {
                m_dynamicSectionStringTable = new char[m_dynamicSectionStringTableSize];
            }
            catch (std::bad_alloc& e)
            {
                std::cerr << e.what() << std::endl;
                return false;
            }

            elfFile.seekg(offset); // Jump to dynamic section string table
            if (!elfFile.fail()) // If there isn't any error.
                elfFile.read(reinterpret_cast<char*>(m_dynamicSectionStringTable), m_dynamicSectionStringTableSize); // Read dynamic section string table to m_dynamicSectionStringTable
            else
                return false;
        } else
            return false;
    }
    return true;
}

/**
 * @brief ElfParser<T>::parseAll
 * This function parse all of the elf file. If this function called,
 * there is no need to call another  parse function.
 * @return If parsing finish successfully, returns true. Otherwise false.
 */
template <ElfType T>
bool ElfParser<T>::parseAll()
{
    std::ifstream elfFile;

    if(!parseHeader())         // Parse Header
        return false;

    if(!parseSectionHeader()) // Parse section header table
        return false;

    if(!parseProgramHeader()) // Parse program header table
        return false;

    parseDynamicSection();   // Parse dynamic section

    return true;
}

/**
 * @brief ElfParser<T>::getHeader
 * This function is a getter of elf header.This function must be called after
 * parseHeader function. Otherwise, it returns nullptr.
 * @return Address of elf header.
 */
template <ElfType T>
typename ElfParser<T>::ElfHeader* ElfParser<T>::getHeader()
{
    return &m_header;
}

/**
 * @brief ElfParser<T>::getSectionHeaderTable
 * This function is a getter of section header table. This function must be called after
 * parseSectionHeader function. Otherwise, it returns nullptr.
 * @return  Address of section header table
 */
template <ElfType T>
typename ElfParser<T>::SectionHeader* ElfParser<T>::getSectionHeaderTable()
{
    return m_sectionHeaderTable;
}

/**
 * @brief ElfParser<T>::getDynamicSection
 * This function is a getter of dynamic section table. This function must be called after
 * parseDynamicSection function. Otherwise it returns nullptr.
 * @return Address of dynamic section Table.
 */
template <ElfType T>
typename ElfParser<T>::DynamicSectionEntry* ElfParser<T>::getDynamicSection()
{
    return m_dynamicSection;
}

/**
 * @brief ElfParser<T>::getSectionName
 * This function is a getter of section name. This function must be called after
 * parseSectionHeader function. Otherwise it returns nullptr
 * @param entry Address of an entry in Section header table.
 * @return Section name
 */
template <ElfType T>
const char* ElfParser<T>::getSectionName(ElfParser<T>::SectionHeader* entry)
{
    if (entry->sh_name < m_sectionNameStringTableSize) // Boundry checking
        return &m_sectionNameStringTable[entry->sh_name]; // Read section name from m_sectionNameStringTable and return it
    else
        return nullptr;
}

/**
 * @brief ElfParser<T>::getDynamicSectionName
 * This function is a getter of dynamic section name. This function must be called after
 * parseDynamicSection function. Otherwise it returns nullptr. This function can be used
 * for getting name of dependent shared object.
 * @param entry Address of an entry in dynamic section table.
 * @return Dynamic section name
 */
template <ElfType T>
const char* ElfParser<T>::getDynamicSectionName(
        ElfParser<T>::DynamicSectionEntry* entry)
{
    if (entry->d_val < m_dynamicSectionStringTableSize) // Boundry checking
        return &m_dynamicSectionStringTable[entry->d_val]; // Read string from dynamic section string table.
    else
        return nullptr;
}

/**
 * @brief ElfParser<T>::getCodeSegment
 * This function is a getter of code segment. It must be called after
 * parseProgramHeader function. Otherwise, it returns nullptr
 * @return Code segment
 */
template <ElfType T>
const char* ElfParser<T>::getCodeSegment()
{
    return m_codeSegment;
}

template <ElfType T>
/**
 * @brief ElfParser<T>::getDataSegment
 * This function is a getter of data segment. It must be called after
 * parseProgramHeader function. Otherwise, it returns nullptr
 * @return Data segment
 */
const char* ElfParser<T>::getDataSegment()
{
    return m_dataSegment;
}

/**
 * @brief ElfParser<T>::getCodeSegmentSize
 * This function is a getter of size of code segment. It must be called after
 * parseProgramHeader function. Otherwise, it returns 0
 * @return
 */
template <ElfType T>
uint32_t ElfParser<T>::getCodeSegmentSize()
{
    return m_codeSegmentSize;
}


/**
 * @brief ElfParser<T>::getDataSegmentSize
 * This function is a getter of size of data segment. It must be called after
 * parseProgramHeader function. Otherwise, it returns 0
 * @return
 */
template <ElfType T>
uint32_t ElfParser<T>::getDataSegmentSize()
{
    return m_dataSegmentSize;
}

#endif // ELFPARSER_H
