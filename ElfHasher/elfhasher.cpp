/* Copyright 2021 Yusuf YAMAK. All Rights Reserved.
   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
*/
#include "elfhasher.h"
#include <dirent.h>
#include <elfparser.h>
#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <unordered_map>
#include <utility>
#include <sys/stat.h>
#include <fstream>
#include <unistd.h>

/**
 * @brief ElfHasher::ElfHasher
 * Constructor of Elf Hasher.
 * @param filename Output path name. E.g, /home/heimdall/
 * hash_table.h file will be generated in this path.
 */
ElfHasher::ElfHasher(const std::string& path)
{
    m_outputFileName=path+OUTPUT_FILE_NAME;
}

/**
 * @brief ElfHasher::start
 * This function starts hash table generation and must be called
 * after setting output directory, executable directory and shared object directory
 */
void ElfHasher::start()
{
    findAllElfFiles(EXECUTABLE);
    findAllElfFiles(SHARED_OBJECT);
    for (auto& exec : m_allExecutables)
    {
        calculateFileHash(exec, EXECUTABLE);
    }
    generateHeaderFile();
}

/**
 * @brief ElfHasher::appendExecutableDirectory
 * This function appends executable directory which will be searched while
 * generating hash table.
 * @param dir Executable directory.
 */
void ElfHasher::appendExecutableDirectory(const std::string& dir)
{
    m_allExecDirs.push_back(dir);
}

/**
 * @brief ElfHasher::appendSharedObjectDirectory
 * This function appends shared object directory which will be searched while
 * generating hash table
 * @param dir Shared object directory.
 */
void ElfHasher::appendSharedObjectDirectory(const std::string& dir)
{
    m_allLibDirs.push_back(dir);
}

/**
 * @brief ElfHasher::extractFileNameFromPath
 * This function extract file name from path. e.g, it extracts
 * useradd from /usr/sbin/useradd.
 * @param path File name with path.e.g, /usr/sbin/useradd.
 * @param filename File name without path. For example useradd
 */
void ElfHasher::extractFileNameFromPath(const std::string& path, std::string& filename)
{
    for (int i = path.length(); i>0; i--)
    {
        if (path[i] == '/')
        {
            filename.append(path,i+1);
            break;
        }
    }
}

/**
 * @brief ElfHasher::extractPathOfFile
 * This function extract path of file.e.g, it extracts
 * /usr/sbin from /usr/sbin/useradd.
 * @param path File name with path.e.g /usr/sbin/useradd.
 * @param out File name without path. e.g, useradd
 */
void ElfHasher::extractPathOfFile(const std::string &path, std::string &out)
{
    for (int i = path.length(); i>0; i--)
    {
        if (path[i] == '/')
        {
            out.append(path, 0, i+1);
            break;
        }
    }
}

/**
 * @brief ElfHasher::appendDigest
 * This function appends hash digest of file to m_executableDigests or m_sharedObjectDigests
 * according to elf file type.
 * @param name File name with path. e.g, /usr/sbin/useradd
 * @param digest Hash digest which will be appended
 * @param pageNum Page number of digest
 * @param type Elf File type. Executable or SharedObject
 * @param totalPageLength Page count of elf file.
 */
void ElfHasher::appendDigest(const std::string &name, const ElfHasher::Digest &digest, uint16_t pageNum, ElfHasher::FileType type, uint16_t totalPageLength)
{
    static std::string prevName = {};
    static uint32_t execBoundry = 0;
    static uint32_t soBoundry = 0;
    std::ostringstream key;
    std::string fileName;
    std::string pureFileName;
    bool res = false;

    extractFileNameFromPath(name, fileName); // Extract file name
    pureFileName = fileName;
    key << fileName << ":" << pageNum;// Generate <filename:page No> e.g: useradd:5 or libc.so:55 .This name is used for checking same file's same page is appended before
    if (type == EXECUTABLE) { // If elf type is executable
        for (auto& pair : m_executableDigests) { // Check whether this page appended before.
            if (pair.filename == key.str()) {
                res = true;
                break;
            }
        }

        if (!res) // If this page didn't appended before
        {
            if(prevName != pureFileName) // If this is a new file
            {
                m_executableDigestsBoundry.push_back({fileName, execBoundry, execBoundry + totalPageLength - 1}); // Append boundry of this file to 'm_executableDigestsBoundry'
                execBoundry += totalPageLength; // Increase current page number for executable
            }

            prevName = fileName;
            m_executableDigests.push_back({ key.str(), digest }); // Append this filename - digest pair to executable list
        }

    }
    else // If elf type is shared object
    {
        for (auto& pair : m_sharedObjectDigests) { // Check for this page appended before.
            if (pair.filename == key.str()) { // Check whether this page appended before.
                res = true;
                break;
            }
        }

        if (!res) // If this page didn't appended before
        {
            if(prevName != pureFileName) // If this is a new file
            {
                m_sharedObjectDigestsBoundry.push_back({fileName, soBoundry, soBoundry + totalPageLength-1}); // Append boundry of this file to 'm_executableDigestsBoundry'
                soBoundry += totalPageLength; // Increse current page number for shared object
            }
            prevName = fileName;
            m_sharedObjectDigests.push_back({ key.str(), digest }); // Append this filename - digest pair to shared object list
        }
    }
}

/**
 * @brief ElfHasher::findAllElfFiles
 * This function searches directories in the m_allExecDirs or m_allLibDirs according to file type and
 * appends found files to m_allExecutables
 * @param fileType Elf file type.EXECUTABLE or SHARED_OBJECT.If it is EXECUTABLE,
 * directories in the m_allExecDirs will be searched or if it is SHARED_OBJECT, directories in
 * the m_allLibDirs will be searched
 */
void ElfHasher::findAllElfFiles(FileType fileType)
{
    DIR* d;
    dirent* dir;
    std::ostringstream absoluteName;
    struct stat statBuf;
    const char* searchDir;
    const std::list<std::string>* searchDirList;

    if (fileType == EXECUTABLE) // If file type is executable
        searchDirList = &m_allExecDirs; // Directories in the m_allExecDirs will be searched.
    else
        searchDirList = &m_allLibDirs; // Directories in the m_allLibDirs will be searched.

    for (auto& e : *searchDirList) { // Iterate over searchDirList
        searchDir = e.c_str(); // Convert string to const char*
        d = opendir(searchDir); // Open directory stream
        if (d) { // If directory stream opened successfully
            while ((dir = readdir(d)) != nullptr) { // Read all file name in the current directory
                if (dir->d_type != DT_DIR) {
                    absoluteName.str(""); //Clear absoluteName
                    absoluteName << searchDir << "/" << dir->d_name; // concatenate file name and path
                    if (lstat(absoluteName.str().c_str(), &statBuf) != -1) { // Get file attributes
                        if ((statBuf.st_mode & S_IFMT) != S_IFLNK) { // If this isn't symbolic link. We don't want symbolic link. We only work with real files.

                            ElfParser_t elfParser(absoluteName.str()); // Check for this is elf file or not.
                            elfParser.parseHeader(); // Parse elf header.
                            if (elfParser.getHeader()->e_type == static_cast<ElfParser_t::FileType>(fileType)) // If this is an elf file.
                                m_allExecutables.push_back(absoluteName.str()); // Append this file to m_allExecutables
                        }
                    }
                }
            }
        }
        closedir(d); // Close directory stream.
    }
}

/**
 * @brief ElfHasher::calculateFileHash
 * This function calculates hash of every page of an elf file's code segment. And then It gives these
 * digest to appendDigest function.
 * @param filename File name
 * @param fileType File type
 */
void ElfHasher::calculateFileHash(const std::string& filename, ElfHasher::FileType fileType)
{
    Digest digest;
    ElfParser_t elfParser(filename); // Construct ElfParser/home/yusuf/Heimdall/linux_access.h
    const char* codeSegment;
    uint16_t pageNum = 0;

    if (elfParser.parseAll()) // Parse all section of this elf file.
    {
        codeSegment = elfParser.getCodeSegment(); // Get code segment
        pageNum = 0; // Clear page number.
        for (const char* segment = codeSegment; segment < (codeSegment + elfParser.getCodeSegmentSize()); segment += PAGE_SIZE) // Get every page of code segment
        {
            SHA256(reinterpret_cast<const unsigned char*>(segment), PAGE_SIZE, reinterpret_cast<unsigned char*>(&digest)); // Calculate SHA256 of current page.
            appendDigest(filename, digest, pageNum, fileType, elfParser.getCodeSegmentSize() / PAGE_SIZE); // Append this hash digest
            pageNum++;
        }
    }
}

/**
 * @brief ElfHasher::createHashArrayString
 * This function generates Array definition from memory area which digest is stored in.
 * eg: {0x92,0x58,0xC4,0x18,0xC8,0x32,0x13,0x94,0x6E,.....}
 * @param hash Pointer of digest
 * @param size Digest size
 * @param out Result.
 */
void ElfHasher::createHashArrayString(const unsigned char* hash, size_t size, std::string& out)
{
    char element[5];
    out.append("{"); // Append '{'
    for (size_t i = 0; i < size; i++) { // Get every byte
        sprintf(element, "0x%02X", hash[i]); // Convert current byte to ascii hex
        out.append(element);
        if (i != (size - 1)) // Append ',' between every element
            out.append(",");
    }
    out.append("}");
}

/**
 * @brief ElfHasher::generateHeaderFile
 * This function generates header file which contains hash table.
 */
void ElfHasher::generateHeaderFile()
{
    std::ofstream outputFile;
    unsigned int soOffset;
    soOffset=m_executableDigests.size();
    outputFile.open(m_outputFileName);
    if(outputFile.is_open())
    {
        outputFile<<HEADER_GUARD<<std::endl<<std::endl; // Append header guard.
        outputFile<<"#define DIGEST_SIZE "<<DIGEST_SIZE<<std::endl<<std::endl; // Append definition of Digest size
        outputFile<<HASH_TABLE_STRUCT_DEFINITIONS<<std::endl<<std::endl; // Append definition of required structure.
        outputFile<<EXECUTABLE_BOUNDRY_DEFINITION_STRING; // Start of EXEC_BOUNDRY Definition
        outputFile<<"{"<<std::endl;

        for(const auto& e:m_executableDigestsBoundry) // Add boundry of executables.
        {
            outputFile<<'\t'<<'\t';
            outputFile<<"{"<<"\""<<e.filename<<"\","<<e.startIndex<<","<<e.endIndex<<"}"<<","<<std::endl;
        }

        for(const auto& e:m_sharedObjectDigestsBoundry) // Add boundry of shared objects.
        {
            outputFile<<'\t'<<'\t';
            outputFile<<"{"<<"\""<<e.filename<<"\","<<e.startIndex+soOffset<<","<<e.endIndex+soOffset<<"}"<<","<<std::endl;
        }
        outputFile<<"};"<<std::endl<<std::endl;


        outputFile<<EXECUTABLE_HASH_ARRAY_DEFINITION_STRING; // Start of definition of ELF_DIGEST_TABLE
        outputFile<<"{"<<std::endl;
        for(const auto& pair:m_executableDigests) // Add digests of executables
        {
            outputFile<<'\t'<<'\t';
            std::string hashArray;
            outputFile<<"{";
            createHashArrayString(reinterpret_cast<const unsigned char*>(&pair.digest),DIGEST_SIZE,hashArray); // Create digest array definition
            outputFile<<hashArray<<"},"; // add this result to ELF_DIGEST_TABLE
            if (pair.filename[pair.filename.length()-1]=='0') // If this is the first entry of a file, append file name as a comment,
                outputFile<<"  // "<<pair.filename<<std::endl;
            else
                outputFile<<std::endl; // Append only new line
        }

        for(const auto& pair:m_sharedObjectDigests) // Add digests of executables
        {
            outputFile<<'\t'<<'\t';
            std::string hashArray;
            outputFile<<"{";
            createHashArrayString(reinterpret_cast<const unsigned char*>(&pair.digest),DIGEST_SIZE,hashArray); // Create digest array definition
            outputFile<<hashArray<<"},"; // add this result to ELF_DIGEST_TABLE
            if (pair.filename[pair.filename.length()-1]=='0') // If this is the first entry of a file, append file name as a comment,
                outputFile<<"  // "<<pair.filename<<std::endl;
            else
                outputFile<<std::endl; // Append only new line
        }
        outputFile<<"};"<<std::endl<<std::endl; // Close array definition.
        outputFile<<END_HEADER_GUARD; // #endif for header guard
    }
}




