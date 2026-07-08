#ifndef PE_PARSER_HPP
#define PE_PARSER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

#ifdef _WIN32
#include <windows.h>
#else
#pragma pack(push, 1)

struct IMAGE_DOS_HEADER {
    uint16_t e_magic;           // MZ
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

#define IMAGE_NT_SIGNATURE          0x00004550  // "PE\0\0"

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

#define IMAGE_FILE_MACHINE_I386     0x014c
#define IMAGE_FILE_MACHINE_AMD64    0x8664

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;                     // 0x10B
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;                     // 0x20B
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
};

struct IMAGE_SECTION_HEADER {
    uint8_t  Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

#pragma pack(pop)

#define IMAGE_SCN_CNT_CODE                  0x00000020
#define IMAGE_SCN_MEM_EXECUTE               0x20000000
#define IMAGE_SCN_MEM_READ                  0x40000000
#define IMAGE_SCN_MEM_WRITE                 0x80000000

#endif

struct SectionInfo {
    std::string name;
    uint64_t    virtual_address;     // RVA + ImageBase
    uint64_t    raw_offset;
    uint64_t    raw_size;
    uint32_t    characteristics;
    bool        is_executable() const;
};

class PeParser {
public:
    explicit PeParser(const std::string& filepath);
    PeParser(const std::vector<uint8_t>& buffer, const std::string& filepath);
    ~PeParser() = default;

    bool is_valid() const { return valid_; }
    std::string get_error() const { return error_msg_; }

    bool is_64bit() const { return is_64bit_; }
    uint64_t get_image_base() const { return image_base_; }
    uint32_t get_entry_point_rva() const { return entry_point_rva_; }

    const std::vector<SectionInfo>& get_executable_sections() const {
        return executable_sections_;
    }

    const std::vector<uint8_t>& get_buffer() const { return buffer_; }

private:
    bool parse();

    std::string filepath_;
    std::vector<uint8_t> buffer_;
    bool valid_ = false;
    std::string error_msg_;

    bool is_64bit_ = false;
    uint64_t image_base_ = 0;
    uint32_t entry_point_rva_ = 0;

    std::vector<SectionInfo> executable_sections_;
};

#endif // PE_PARSER_HPP