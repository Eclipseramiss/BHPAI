#ifndef PE_ANALYZER_HPP
#define PE_ANALYZER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include <nlohmann/json.hpp>

#pragma pack(push, 1)
struct DosHeader {
    uint16_t e_magic;
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
#pragma pack(pop)

#pragma pack(push, 1)
struct PeHeader {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct SectionHeader {
    char     Name[8];
    union {
        uint32_t VirtualSize;
        uint32_t Misc_VirtualSize;
    };
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

struct FileHashes {
    std::string md5;
    std::string sha256;
    std::string fuzzy;
};

struct PeHeaderFeatures {
    // DOS
    bool     is_invalid_dos         = true;
    uint32_t e_lfanew               = 0;
    bool     e_lfanew_too_large     = false;
    bool     e_lfanew_not_aligned   = false;

    // File Header
    uint16_t machine                = 0;
    uint16_t number_of_sections     = 0;
    uint32_t time_date_stamp        = 0;
    uint16_t size_of_optional_header= 0;
    uint16_t characteristics        = 0;
    bool     is_dll                 = false;

    bool     likely_pos_scraper             = false;
    int      pos_malware_score              = 0;
    bool     has_track_pattern_strings      = false;
    bool     has_luhn_or_cc_validation      = false;
    bool     has_memory_scraping_apis       = false;
    bool     has_child_process_injection    = false;
    bool     has_mutex_persistence          = false;
    bool     has_http_post_exfil            = false;
    bool     has_base64_xor_routines        = false;
    size_t   suspicious_pos_apis_count      = 0;
    double   code_section_entropy           = 0.0;

    // Optional Header
    uint16_t magic                  = 0;
    uint8_t  major_linker_version   = 0;
    uint8_t  minor_linker_version   = 0;
    uint32_t size_of_code           = 0;
    uint32_t size_of_initialized_data = 0;
    uint32_t size_of_uninitialized_data = 0;
    uint32_t address_of_entry_point = 0;
    uint32_t base_of_code           = 0;
    uint64_t image_base             = 0;
    uint32_t section_alignment      = 0;
    uint32_t file_alignment         = 0;
    uint16_t major_os_version       = 0;
    uint16_t minor_os_version       = 0;
    uint16_t major_subsystem_version= 0;
    uint16_t minor_subsystem_version= 0;
    uint32_t size_of_image          = 0;
    uint32_t size_of_headers        = 0;
    uint32_t checksum               = 0;
    uint16_t subsystem              = 0;
    uint16_t dll_characteristics    = 0;

    // Derived flags
    bool     timestamp_zero_or_future = false;
    bool     checksum_zero            = false;
    bool     os_version_low           = false;
    bool     alignment_weird          = false;
    bool     is_gui                   = false;
    bool     is_console               = false;
    bool     aslr_enabled             = false;
    bool     nx_enabled               = false;
    bool     cfg_enabled              = false;

    // Data Directories
    uint32_t import_rva    = 0;
    uint32_t import_size   = 0;
    uint32_t export_rva    = 0;
    uint32_t export_size   = 0;
    uint32_t resource_rva  = 0;
    uint32_t resource_size = 0;
    uint32_t tls_rva       = 0;
    uint32_t tls_size      = 0;
    uint32_t debug_rva     = 0;
    uint32_t debug_size    = 0;
    uint32_t security_size = 0;

    bool     has_tls       = false;
    bool     has_debug     = false;
    bool     has_signature = false;
    bool     digital_signature_valid = false;
    double   code_ratio    = 0.0;
    bool     no_imports    = false;
};

struct ImportStats {
    size_t total_functions = 0;
    size_t suspicious_count = 0;
    size_t pos_specific_count = 0;
    bool has_memory_scraping_apis = false;
    bool has_VirtualAllocEx = false;
    bool has_WriteProcessMemory = false;
    bool has_CreateRemoteThread = false;
    bool has_NtMapViewOfSection = false;
    bool has_NtAllocateVirtualMemory = false;
    bool has_NtWriteVirtualMemory = false;
    bool has_NtProtectVirtualMemory = false;
    std::vector<std::string> imported_function_names;
};

double calc_entropy(const uint8_t* data, size_t len);
FileHashes compute_hashes(const std::vector<uint8_t>& buffer);
bool analyze_pe(const std::string& filepath);
void ParseImports(LPBYTE lpBase);
DWORD RVAToOffset(const IMAGE_NT_HEADERS* nt, DWORD rva);
std::string ToLower(std::string s);
std::string MD5String(const std::string& input);

PeHeaderFeatures extract_pe_header_features(const std::vector<uint8_t>& buffer);
ImportStats GetImportStats(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats);
size_t GetTLSCallbackCount(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats);
bool VerifyDigitalSignature(const std::wstring& filePath);

nlohmann::json features_to_json(
    const PeHeaderFeatures& feats,
    const FileHashes& hashes,
    const std::string& filepath,
    size_t filesize,
    const ImportStats& import_stats,
    size_t tls_callbacks,
    double reloc_entropy,
    size_t overlay_size,
    bool signature_valid
);

nlohmann::json features_to_json(const PeHeaderFeatures& feats, const FileHashes& hashes, 
                                const std::string& filepath, size_t filesize);

PeHeaderFeatures extract_pe_header_features(const std::vector<uint8_t>& buffer);

void scan_for_pos_indicators(
    const std::vector<uint8_t>& buffer,
    PeHeaderFeatures& feats
    //const std::vector<SectionHeader>& sections
);

#endif