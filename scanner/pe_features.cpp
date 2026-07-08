#define NOMINMAX
#include <windows.h>

#include "pe_analyzer.hpp"

#include <wintrust.h>
#include <softpub.h>
#include <set>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <string>

#pragma comment(lib, "wintrust.lib")

static const std::set<std::string> suspicious_apis = {
    "CreateRemoteThread",      "WriteProcessMemory",     "VirtualAllocEx",
    "NtCreateSection",         "NtMapViewOfSection",     "ZwCreateSection",
    "LoadLibraryA",            "GetProcAddress",         "VirtualProtect",
    "IsDebuggerPresent",       "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess","ZwQueryInformationProcess",
    "HeapCreate",              "RtlMoveMemory",           "memcpy", "memmove",
    "VirtualAlloc",            "HeapAlloc",

    "ReadProcessMemory",       "CreateToolhelp32Snapshot","Process32First",
    "Process32Next",           "EnumProcesses",           "OpenProcess",
    "DuplicateHandle",         "GetLastInputInfo",

    "InternetOpenA",           "InternetConnectA",        "HttpOpenRequestA",
    "HttpSendRequestA",

    "RegNotifyChangeKeyValue", "RegSetValueExA",          "CreateMutexA",
    "RegSetValueExA",         "RegCreateKeyExA",         "RegOpenKeyExA"
};

static const uint8_t* my_memmem(
    const uint8_t* haystack,
    size_t haystack_len,
    const uint8_t* needle,
    size_t needle_len)
{
    if (!needle || needle_len == 0) {
        return haystack;
    }
    if (needle_len > haystack_len) {
        return nullptr;
    }

    auto first = haystack;
    auto last  = haystack + haystack_len;

    auto it = std::search(first, last, needle, needle + needle_len);
    return (it != last) ? it : nullptr;
}

PeHeaderFeatures extract_pe_header_features(const std::vector<uint8_t>& buffer) {
    PeHeaderFeatures feats{};

    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
        return feats;
    }

    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, buffer.data(), sizeof(dos));

    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        feats.is_invalid_dos = true;
        return feats;
    }

    feats.is_invalid_dos = false;
    feats.e_lfanew = dos.e_lfanew;

    if (feats.e_lfanew < 64 || feats.e_lfanew > buffer.size() - 4 || feats.e_lfanew % 8 != 0) {
        feats.e_lfanew_not_aligned = true;
    }
    feats.e_lfanew_too_large = (feats.e_lfanew > 0x2000);

    if (feats.e_lfanew + sizeof(IMAGE_NT_HEADERS32) > buffer.size()) {
        return feats;
    }

    IMAGE_NT_HEADERS32 nt32{};
    std::memcpy(&nt32, buffer.data() + feats.e_lfanew, sizeof(IMAGE_NT_HEADERS32));

    if (nt32.Signature != IMAGE_NT_SIGNATURE) {
        return feats;
    }

    bool is_64bit = (nt32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    feats.machine                 = nt32.FileHeader.Machine;
    feats.number_of_sections      = nt32.FileHeader.NumberOfSections;
    feats.time_date_stamp         = nt32.FileHeader.TimeDateStamp;
    feats.size_of_optional_header = nt32.FileHeader.SizeOfOptionalHeader;
    feats.characteristics         = nt32.FileHeader.Characteristics;
    feats.is_dll                  = (feats.characteristics & IMAGE_FILE_DLL) != 0;

    size_t nt_size = is_64bit ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
    if (feats.e_lfanew + nt_size > buffer.size()) {
        return feats;
    }

    IMAGE_NT_HEADERS64 nt64{};
    if (is_64bit) {
        std::memcpy(&nt64, buffer.data() + feats.e_lfanew, sizeof(IMAGE_NT_HEADERS64));
    }

    if (is_64bit) {
        const auto& opt = nt64.OptionalHeader;
        feats.magic                  = opt.Magic;
        feats.image_base             = opt.ImageBase;
        feats.section_alignment      = opt.SectionAlignment;
        feats.file_alignment         = opt.FileAlignment;
        feats.major_linker_version   = opt.MajorLinkerVersion;
        feats.minor_linker_version   = opt.MinorLinkerVersion;
        feats.major_os_version       = opt.MajorOperatingSystemVersion;
        feats.minor_os_version       = opt.MinorOperatingSystemVersion;
        feats.major_subsystem_version= opt.MajorSubsystemVersion;
        feats.minor_subsystem_version= opt.MinorSubsystemVersion;
        feats.size_of_code           = opt.SizeOfCode;
        feats.size_of_initialized_data = opt.SizeOfInitializedData;
        feats.size_of_uninitialized_data = opt.SizeOfUninitializedData;
        feats.address_of_entry_point = opt.AddressOfEntryPoint;
        feats.base_of_code           = opt.BaseOfCode;
        feats.size_of_image          = opt.SizeOfImage;
        feats.size_of_headers        = opt.SizeOfHeaders;
        feats.checksum               = opt.CheckSum;
        feats.subsystem              = opt.Subsystem;
        feats.dll_characteristics    = opt.DllCharacteristics;

        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            feats.import_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            feats.import_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            feats.export_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            feats.export_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            feats.resource_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            feats.resource_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
            feats.tls_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            feats.tls_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
            feats.has_tls  = (feats.tls_rva != 0 && feats.tls_size > 0);
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
            feats.debug_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            feats.debug_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
            feats.has_debug  = (feats.debug_rva != 0 && feats.debug_size > 0);
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            feats.security_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            feats.has_signature = (feats.security_size > 0);
        }
    } else {
        const auto& opt = nt32.OptionalHeader;
        feats.magic                  = opt.Magic;
        feats.image_base             = opt.ImageBase;
        feats.section_alignment      = opt.SectionAlignment;
        feats.file_alignment         = opt.FileAlignment;
        feats.major_linker_version   = opt.MajorLinkerVersion;
        feats.minor_linker_version   = opt.MinorLinkerVersion;
        feats.major_os_version       = opt.MajorOperatingSystemVersion;
        feats.minor_os_version       = opt.MinorOperatingSystemVersion;
        feats.major_subsystem_version= opt.MajorSubsystemVersion;
        feats.minor_subsystem_version= opt.MinorSubsystemVersion;
        feats.size_of_code           = opt.SizeOfCode;
        feats.size_of_initialized_data = opt.SizeOfInitializedData;
        feats.size_of_uninitialized_data = opt.SizeOfUninitializedData;
        feats.address_of_entry_point = opt.AddressOfEntryPoint;
        feats.base_of_code           = opt.BaseOfCode;
        feats.size_of_image          = opt.SizeOfImage;
        feats.size_of_headers        = opt.SizeOfHeaders;
        feats.checksum               = opt.CheckSum;
        feats.subsystem              = opt.Subsystem;
        feats.dll_characteristics    = opt.DllCharacteristics;

        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            feats.import_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            feats.import_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            feats.export_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            feats.export_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            feats.resource_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            feats.resource_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
            feats.tls_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            feats.tls_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
            feats.has_tls  = (feats.tls_rva != 0 && feats.tls_size > 0);
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
            feats.debug_rva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            feats.debug_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
            feats.has_debug  = (feats.debug_rva != 0 && feats.debug_size > 0);
        }
        if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            feats.security_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            feats.has_signature = (feats.security_size > 0);
        }
    }

    feats.no_imports = (feats.import_size == 0);

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    feats.timestamp_zero_or_future = (feats.time_date_stamp == 0 ||
                                     static_cast<uint64_t>(feats.time_date_stamp) > static_cast<uint64_t>(now) + 86400ULL * 365 * 2);
    feats.checksum_zero            = (feats.checksum == 0);
    feats.os_version_low           = (feats.major_os_version < 6);
    feats.alignment_weird          = (feats.section_alignment < feats.file_alignment && feats.section_alignment != 0);

    feats.is_gui    = (feats.subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI);
    feats.is_console= (feats.subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI);

    feats.aslr_enabled = (feats.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    feats.nx_enabled   = (feats.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    feats.cfg_enabled  = (feats.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;

    std::vector<SectionHeader> sections;
    scan_for_pos_indicators(buffer, feats);

    return feats;
}

// ───────────────────────────────────────────────
void scan_for_pos_indicators(
    const std::vector<uint8_t>& buffer,
    PeHeaderFeatures& feats)
{
    static const char* pos_signatures[] = {
        "response=", "&ump=", "&opt=", "varUID", "varDumps",
        "IsValidCC", "DigitsLen", "IsEndDataValid", "Track3",
        "WindowsResilienceServiceMutex", "Software\\Resilience Software",
        "Luhn", "check digit", "card number", "^.{1,79}^", ";\\d{13,19}=",
        nullptr
    };

    int score = 0;

    const uint8_t* data = buffer.data();
    size_t size = buffer.size();

    feats.code_section_entropy = calc_entropy(data, size);
    if (feats.code_section_entropy > 7.1) score += 10;

    for (int i = 0; pos_signatures[i]; ++i) {
        const char* sig = pos_signatures[i];
        size_t sig_len = std::strlen(sig);

        if (my_memmem(data, size, reinterpret_cast<const uint8_t*>(sig), sig_len)) {
            feats.has_track_pattern_strings = true;
            score += 15;

            if (std::strstr(sig, "response=") || std::strstr(sig, "&ump=")) {
                feats.has_http_post_exfil = true;
                score += 20;
            }
            if (std::strstr(sig, "IsValidCC") || std::strstr(sig, "Luhn")) {
                feats.has_luhn_or_cc_validation = true;
                score += 25;
            }
            if (std::strstr(sig, "Mutex") || std::strstr(sig, "Resilience")) {
                feats.has_mutex_persistence = true;
                score += 10;
            }
        }
    }

    feats.pos_malware_score = std::min(100, score);
    feats.likely_pos_scraper = (feats.pos_malware_score >= 55);
}

// ────────────────────────────────────────────────
ImportStats GetImportStats(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats) {
    ImportStats stats{};

    if (feats.import_rva == 0 || feats.import_size == 0) return stats;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer.data() + feats.e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return stats;

    DWORD import_offset = RVAToOffset(nt, feats.import_rva);
    if (import_offset == 0 || import_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > buffer.size()) {
        return stats;
    }

    auto* import_desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(buffer.data() + import_offset);

    while (import_desc->Name && import_desc->OriginalFirstThunk) {
        DWORD thunk_rva = import_desc->OriginalFirstThunk;
        DWORD thunk_off = RVAToOffset(nt, thunk_rva);
        if (thunk_off == 0 || thunk_off + 8 > buffer.size()) break;

        auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA*>(buffer.data() + thunk_off);

        while (thunk->u1.AddressOfData) {
            stats.total_functions++;

            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                DWORD name_rva = static_cast<DWORD>(thunk->u1.AddressOfData);
                DWORD name_off = RVAToOffset(nt, name_rva + 2); // skip hint/ordinal
                if (name_off != 0 && name_off + 64 <= buffer.size()) {
                    std::string func_name(reinterpret_cast<const char*>(buffer.data() + name_off));
                    stats.imported_function_names.push_back(func_name);
                    if (func_name == "VirtualAllocEx")          stats.has_VirtualAllocEx = true;
                    if (func_name == "WriteProcessMemory")      stats.has_WriteProcessMemory = true;
                    if (func_name == "CreateRemoteThread")      stats.has_CreateRemoteThread = true;
                    if (func_name == "NtMapViewOfSection")      stats.has_NtMapViewOfSection = true;
                    if (func_name == "NtAllocateVirtualMemory") stats.has_NtAllocateVirtualMemory = true;
                    if (func_name == "NtWriteVirtualMemory")    stats.has_NtWriteVirtualMemory = true;
                    if (func_name == "NtProtectVirtualMemory")  stats.has_NtProtectVirtualMemory = true;
                    if (suspicious_apis.find(func_name) != suspicious_apis.end()) {
                        stats.suspicious_count++;
                    }
                }
            }
            ++thunk;
        }
        ++import_desc;
    }
    for (const auto& api : suspicious_apis) {
        if (my_memmem(buffer.data(), buffer.size(),
                      reinterpret_cast<const uint8_t*>(api.c_str()), api.size())) {
            stats.pos_specific_count++;

            if (api == "ReadProcessMemory" ||
                api == "CreateToolhelp32Snapshot" ||
                api == "Process32Next" ||
                api == "HttpSendRequestA") {
            }
        }
    }

    stats.has_memory_scraping_apis = (stats.pos_specific_count >= 3);

    return stats;
}

// ────────────────────────────────────────────────
size_t GetTLSCallbackCount(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats) {
    if (!feats.has_tls || feats.tls_rva == 0 || feats.tls_size < sizeof(IMAGE_TLS_DIRECTORY)) {
        return 0;
    }

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer.data() + feats.e_lfanew);
    if (!nt) return 0;

    DWORD tls_off = RVAToOffset(nt, feats.tls_rva);
    if (tls_off == 0 || tls_off + sizeof(IMAGE_TLS_DIRECTORY) > buffer.size()) {
        return 0;
    }

    auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(buffer.data() + tls_off);
    if (tls->AddressOfCallBacks == 0) return 0;

    DWORD cb_rva = static_cast<DWORD>(tls->AddressOfCallBacks);
    DWORD cb_off = RVAToOffset(nt, cb_rva);
    if (cb_off == 0) return 0;

    size_t count = 0;
    const ULONGLONG* ptr = reinterpret_cast<const ULONGLONG*>(buffer.data() + cb_off);
    const uint8_t* buffer_end = buffer.data() + buffer.size();

    while (ptr && *ptr != 0 && count < 1024) {
        ++count;
        ++ptr;

        if (reinterpret_cast<const uint8_t*>(ptr) + sizeof(ULONGLONG) > buffer_end) {
            break;
        }
    }
    return count;
}

// ────────────────────────────────────────────────
bool VerifyDigitalSignature(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct       = sizeof(fileInfo);
    fileInfo.pcwszFilePath  = filePath.c_str();
    fileInfo.hFile          = INVALID_HANDLE_VALUE;
    fileInfo.pgKnownSubject = nullptr;

    WINTRUST_DATA winTrustData{};
    winTrustData.cbStruct            = sizeof(winTrustData);
    winTrustData.dwUIChoice          = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    winTrustData.dwUnionChoice       = WTD_CHOICE_FILE;
    winTrustData.pFile               = &fileInfo;
    winTrustData.dwStateAction       = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG result = WinVerifyTrust(nullptr, &action, &winTrustData);

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &winTrustData);

    return (result == 0);
}


// ────────────────────────────────────────────────
DWORD RVAToOffset(const IMAGE_NT_HEADERS* nt, DWORD rva) {
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (rva >= section->VirtualAddress &&
            rva < section->VirtualAddress + section->Misc.VirtualSize) {
            return section->PointerToRawData + (rva - section->VirtualAddress);
        }
    }
    return 0;
}

// ────────────────────────────────────────────────
nlohmann::json features_to_json(const PeHeaderFeatures& feats, const FileHashes& hashes,
                                const std::string& filepath, size_t filesize,
                                const ImportStats& import_stats,
                                size_t tls_callbacks,
                                double reloc_entropy,
                                size_t overlay_size,
                                bool signature_valid) {
    nlohmann::json j;

    j["file"]          = filepath;
    j["size_bytes"]    = filesize;
    j["md5"]           = hashes.md5;
    j["sha256"]        = hashes.sha256;
    j["fuzzy_hash"]    = hashes.fuzzy;

    j["is_invalid_dos"]         = feats.is_invalid_dos;
    j["e_lfanew"]               = feats.e_lfanew;
    j["e_lfanew_too_large"]     = feats.e_lfanew_too_large;
    j["e_lfanew_not_aligned"]   = feats.e_lfanew_not_aligned;

    j["machine"]                = feats.machine;
    j["num_sections"]           = feats.number_of_sections;
    j["time_date_stamp"]        = feats.time_date_stamp;
    j["is_dll"]                 = feats.is_dll;

    j["magic"]                  = feats.magic;
    j["image_base"]             = feats.image_base;
    j["entry_point_rva"]        = feats.address_of_entry_point;
    j["size_of_image"]          = feats.size_of_image;
    j["size_of_headers"]        = feats.size_of_headers;
    j["section_alignment"]      = feats.section_alignment;
    j["file_alignment"]         = feats.file_alignment;

    j["timestamp_zero_or_future"]= feats.timestamp_zero_or_future;
    j["checksum_zero"]          = feats.checksum_zero;
    j["os_version_low"]         = feats.os_version_low;
    j["alignment_weird"]        = feats.alignment_weird;
    j["is_gui"]                 = feats.is_gui;
    j["is_console"]             = feats.is_console;
    j["aslr_enabled"]           = feats.aslr_enabled;
    j["nx_enabled"]             = feats.nx_enabled;
    j["cfg_enabled"]            = feats.cfg_enabled;

    j["has_tls"]                = feats.has_tls;
    j["has_debug"]              = feats.has_debug;
    j["has_signature"]          = feats.has_signature;
    j["no_imports"]             = feats.no_imports;

    j["import_rva"]             = feats.import_rva;
    j["import_size"]            = feats.import_size;
    j["resource_size"]          = feats.resource_size;
    j["tls_size"]               = feats.tls_size;
    j["security_size"]          = feats.security_size;

    j["import_function_count"]     = import_stats.total_functions;
    j["suspicious_api_count"]      = import_stats.suspicious_count;
    j["suspicious_api_ratio"]      = import_stats.total_functions > 0 ?
                                     static_cast<double>(import_stats.suspicious_count) / import_stats.total_functions : 0.0;
    j["has_memory_scraping_apis"]  = import_stats.has_memory_scraping_apis;
    j["tls_callback_count"]        = tls_callbacks;
    j["relocation_entropy"]        = reloc_entropy;
    j["overlay_size_bytes"]        = overlay_size;
    j["digital_signature_valid"]   = signature_valid;

    j["likely_pos_scraper"]          = feats.likely_pos_scraper;
    j["pos_malware_score"]           = feats.pos_malware_score;
    j["has_track_pattern_strings"]   = feats.has_track_pattern_strings;
    j["has_luhn_or_cc_validation"]   = feats.has_luhn_or_cc_validation;
    j["has_http_post_exfil"]         = feats.has_http_post_exfil;
    j["has_mutex_persistence"]       = feats.has_mutex_persistence;
    j["code_section_entropy"]        = feats.code_section_entropy;

    if (feats.size_of_image > 0) {
        j["code_ratio"] = static_cast<double>(feats.size_of_code) / feats.size_of_image;
    } else {
        j["code_ratio"] = 0.0;
    }

    return j;
}