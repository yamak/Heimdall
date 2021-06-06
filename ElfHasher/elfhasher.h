/***************************************************************************
 *
 *   FileName: elfhasher.h
 *   Author: yusuf yamak
 *   Created On: 19.05.2021
 *   Desription:
 *
 ***************************************************************************/
#ifndef ELFHASHER_H
#define ELFHASHER_H
#include <cstdint>
#include <string>
#include <list>
#include "elfparser.h"


/**
 * @brief The ElfHasher class generate a header file named hash_table.h which contains hash digest of
 * every page of elf files's code segment.This file includes two different array named
 * EXEC_BOUNDRY and ELF_DIGEST_TABLE. Each element type of EXEC_BOUNDRY is following structure
 * <pre>
 * typedef struct DigestBoundry
 * {
 *      const char* filename; // name of elf file whose hash is calculated.
 *      uint32_t startIndex;  // Start index of this file in the ELF_DIGEST_TABLE
 *      uint32_t endIndex;    // End index of this file in the ELF_DIGEST_TABLE
 * }DigestBoundry;
 * </pre>
 * ELF_DIGEST_TABLE contains hash digest of every page of elf files. For example,
 * If code segment size of an elf file is 16 kb and page size is 4kb, there will be
 * 4 entry for this elf file in ELF_DIGEST_TABLE.
 *
 */
class ElfHasher
{

private:

    static const uint32_t PAGE_SIZE   = 4096; //4 KB
    static const uint32_t DIGEST_SIZE = 32;  //SHA256
    constexpr static const char* EXECUTABLE_HASH_ARRAY_DEFINITION_STRING  = "const struct Digest ELF_DIGEST_TABLE[]=";
    constexpr static const char* EXECUTABLE_BOUNDRY_DEFINITION_STRING     = "const struct DigestBoundry EXEC_BOUNDRY[]=";
    constexpr static const char* HASH_TABLE_STRUCT_DEFINITIONS            = "typedef struct DigestBoundry\n"
                                                                            "{\n"
                                                                            "\tconst char* filename;\n"
                                                                            "\tuint32_t startIndex;\n"
                                                                            "\tuint32_t endIndex;\n\n"
                                                                            "}DigestBoundry;\n\n"
                                                                            "typedef struct Digest\n"
                                                                            "{\n"
                                                                            "\tunsigned char data[DIGEST_SIZE];\n\n"
                                                                            "}Digest;";
    constexpr static const char* HEADER_GUARD                             = "#ifndef HASH_TABLE_H\n#define HASH_TABLE_H";
    constexpr static const char* END_HEADER_GUARD                         = "#endif // HASH_TABLE_H";
    constexpr static const char* OUTPUT_FILE_NAME                         = "hash_table.h";




    //Default elf file length.
    using ElfParser_t = ElfParser<ELF64>;

    /**
     * @brief The Digest struct
     * Element of ELF_DIGEST_TABLE
     */
    struct Digest
    {
        unsigned char data[DIGEST_SIZE];
    };

    /**
     * @brief The DigestBoundry struct
     * Element of EXEC_BOUNDRY.
     */
    struct DigestBoundry
    {
        std::string filename; //name of elf file whose hash is calculated.
        uint32_t startIndex; //Start index of this file in the ELF_DIGEST_TABLE
        uint32_t endIndex; //End index of this file in the ELF_DIGEST_TABLE
    };

    /**
     * @brief The DigestPair struct
     * File name and Digest pair structure.
     * This is the helper struct for generating hash table.
     */
    struct DigestPair
    {

        std::string filename;
        Digest digest;
    };

    enum FileType {
        EXECUTABLE = ElfParser_t::ET_EXEC,
        SHARED_OBJECT = ElfParser_t::ET_DYN
    };


public:

    ElfHasher(const std::string& filename);
    ~ElfHasher()=default;
    void start();
    void appendExecutableDirectory(const std::string& dir);
    void appendSharedObjectDirectory(const std::string& dir);

private:

    std::list<DigestPair> m_executableDigests;
    std::list<DigestPair> m_sharedObjectDigests;
    std::list<std::string> m_allExecutables;
    std::list<DigestBoundry> m_executableDigestsBoundry;
    std::list<DigestBoundry> m_sharedObjectDigestsBoundry;
    std::list<std::string> m_allExecDirs;
    std::list<std::string> m_allLibDirs;
    std::string m_outputFileName;

private:

    void extractFileNameFromPath(const std::string& path, std::string& filename);
    void extractPathOfFile(const std::string& path, std::string& out);
    void appendDigest(const std::string& name, const Digest& digest, uint16_t pageNum, FileType type, uint16_t totalPageLength);
    bool searchFile(const char* rootDir, const char* fileName, unsigned int depth, std::string& result);
    void findAllElfFiles(FileType fileType);
    void calculateFileHash(const std::string& filename, FileType fileType);
    void createHashArrayString(const unsigned char* hash, size_t size, std::string& out);
    void generateHeaderFile();

};

#endif // ELFHASHER_H
