#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "pe_analyzer.hpp"
#include "Disassembler.hpp"
#include "PeParser.hpp"
#include "StringEx.hpp"
#include "pe_opcode_ngram.hpp"
#include "YaraGen.hpp"
#include "detect.hpp"
#include "opcode_tfidf.hpp"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <chrono>

std::unordered_set<std::string> get_suspicious_apis_lowercase() {
    static const std::vector<std::string> apis = {
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
        "NtCreateSection", "NtMapViewOfSection", "ZwCreateSection",
        "LoadLibraryA", "GetProcAddress", "VirtualProtect",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "ZwQueryInformationProcess",
        "HeapCreate", "RtlMoveMemory", "memcpy", "memmove",
        "VirtualAlloc", "HeapAlloc",
        "ReadProcessMemory", "CreateToolhelp32Snapshot", "Process32First",
        "Process32Next", "EnumProcesses", "OpenProcess",
        "DuplicateHandle", "GetLastInputInfo",
        "InternetOpenA", "InternetConnectA", "HttpOpenRequestA",
        "HttpSendRequestA",
        "RegNotifyChangeKeyValue", "RegSetValueExA", "CreateMutexA"
    };

    std::unordered_set<std::string> s;
    for (const auto& api : apis) {
        std::string lower = api;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        s.insert(std::move(lower));
    }
    return s;
}


void PDAR(const std::vector<uint8_t>& buffer, const PeHeaderFeatures& feats, uint32_t rva, size_t how_many_bytes = 1024, size_t max_instructions = 400)
{
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<uint8_t*>(buffer.data() + feats.e_lfanew));
    auto* section = IMAGE_FIRST_SECTION(nt);

    uint64_t image_base = feats.image_base;
    if (image_base == 0 && feats.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        image_base = 0x400000;
    }
    uint64_t va         = image_base + rva;
    DWORD raw_offset    = 0;

    bool found = false;
    for (WORD i = 0; i < feats.number_of_sections; ++i, ++section)
    {
        if (rva >= section->VirtualAddress &&
            rva < section->VirtualAddress + section->Misc.VirtualSize)
        {
            DWORD offset_in_section = rva - section->VirtualAddress;
            if (offset_in_section >= section->SizeOfRawData)
            {
                std::cerr << "[!] RVA 0x" << std::hex << rva
                          << " nằm ngoài raw data của section " << section->Name << "\n";
                return;
            }

            raw_offset = section->PointerToRawData + offset_in_section;
            found = true;
            break;
        }
    }

    if (!found)
    {
        std::cerr << "[!] Không tìm thấy section chứa RVA 0x" << std::hex << rva << "\n";
        return;
    }

    if (raw_offset == 0 || raw_offset >= buffer.size())
    {
        std::cerr << "[ERROR] Invalid file offset: 0x" << std::hex << raw_offset << "\n";
        return;
    }

    Disassembler disasm;
    bool is_64bit = (feats.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if (!disasm.initialize(is_64bit))
    {
        std::cerr << "[ERROR] Failed to initialize Capstone disassembler\n";
        return;
    }

    size_t bytes_available = buffer.size() - raw_offset;
    size_t bytes_to_disasm = std::min(how_many_bytes, bytes_available);

    auto instructions = disasm.disassemble(
        buffer.data() + raw_offset,
        bytes_to_disasm,
        va,  
        max_instructions
    );

    if (instructions.empty())
    {
        std::cout << "[!] No instructions disassembled at RVA 0x" << std::hex << rva << "\n";
        return;
    }

    std::cout << "\n=== Disassembly at RVA 0x" << std::hex << std::setw(8) << std::setfill('0') << rva;
    if (is_64bit) {
        std::cout << " (VA 0x" << std::hex << va << ")";
    }
    std::cout << "  ── " << instructions.size() << " instructions / "
              << bytes_to_disasm << " bytes ===\n";

    for (const auto& inst : instructions)
    {
        std::cout << disasm.format_instruction(inst, true) << "\n";
    }

    if (instructions.size() >= max_instructions || bytes_to_disasm >= how_many_bytes)
    {
        std::cout << "   ... (truncated – increase how_many_bytes or max_instructions if needed)\n";
    }
    std::cout << std::dec << "\n";
}

std::vector<std::string> capture_disassembly_for_json(
    const std::vector<uint8_t>& buffer,
    const PeHeaderFeatures& feats,
    uint32_t rva,
    size_t how_many_bytes = 768,
    size_t max_instructions = 220)
{
    std::vector<std::string> result;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<uint8_t*>(buffer.data() + feats.e_lfanew));
    auto* section = IMAGE_FIRST_SECTION(nt);

    uint64_t image_base = feats.image_base;
    if (image_base == 0 && feats.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        image_base = 0x400000;
    }

    uint64_t va = image_base + rva;
    DWORD raw_offset = 0;
    bool found = false;

    for (WORD i = 0; i < feats.number_of_sections; ++i, ++section)
    {
        if (rva >= section->VirtualAddress &&
            rva < section->VirtualAddress + section->Misc.VirtualSize)
        {
            DWORD offset_in_section = rva - section->VirtualAddress;
            if (offset_in_section < section->SizeOfRawData)
            {
                raw_offset = section->PointerToRawData + offset_in_section;
                found = true;
                break;
            }
        }
    }

    if (!found || raw_offset == 0 || raw_offset >= buffer.size()) {
        return result; // trả về mảng rỗng
    }

    Disassembler disasm;
    bool is_64bit = (feats.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if (!disasm.initialize(is_64bit)) {
        return result;
    }

    size_t bytes_available = buffer.size() - raw_offset;
    size_t bytes_to_disasm = std::min(how_many_bytes, bytes_available);

    auto instructions = disasm.disassemble(
        buffer.data() + raw_offset,
        bytes_to_disasm,
        va,
        max_instructions
    );

    for (const auto& inst : instructions) {
        result.push_back(disasm.format_instruction(inst, true));
    }

    return result;
}

bool analyze_pe(const std::string& filepath, const std::string& label = "unknown")
{
    PeParser parser(filepath);
    if (!parser.is_valid()) {
        std::cerr << "[ERROR] " << parser.get_error() << "\n";
        return false;
    }

    MalwareTraits traits;

    const auto& buffer = parser.get_buffer();
    size_t filesize = buffer.size();

    if (filesize < 0x40) {
        std::cerr << "[ERROR] File too small to be a PE file\n";
        return false;
    }

    auto hashes        = compute_hashes(buffer);
    auto feats         = extract_pe_header_features(buffer);
    ImportStats import_stats = GetImportStats(buffer, feats);
    size_t tls_callbacks = GetTLSCallbackCount(buffer, feats);

    std::wstring wpath(filepath.begin(), filepath.end());
    bool sig_valid = VerifyDigitalSignature(wpath);
    feats.digital_signature_valid = sig_valid;
    feats.code_ratio = (feats.size_of_image > 0) ? static_cast<double>(feats.size_of_code) / feats.size_of_image : 0.0;

    size_t pe_end = 0;
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<uint8_t*>(buffer.data()) + feats.e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < feats.number_of_sections; ++i) {
        size_t sec_end = static_cast<size_t>(sections[i].PointerToRawData) + sections[i].SizeOfRawData;
        pe_end = std::max(pe_end, sec_end);
    }
    size_t overlay_size = (pe_end < filesize) ? filesize - pe_end : 0;

    // === Reloc entropy ===
    double reloc_entropy = 0.0;
    size_t section_table_offset = feats.e_lfanew + sizeof(IMAGE_NT_HEADERS32) +
        (feats.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ?
         sizeof(IMAGE_OPTIONAL_HEADER64) - sizeof(IMAGE_OPTIONAL_HEADER32) : 0);

    for (WORD i = 0; i < feats.number_of_sections; ++i) {
        size_t sec_off = section_table_offset + i * sizeof(IMAGE_SECTION_HEADER);
        if (sec_off + sizeof(IMAGE_SECTION_HEADER) > filesize) break;

        IMAGE_SECTION_HEADER sec{};
        memcpy(&sec, buffer.data() + sec_off, sizeof(sec));

        std::string name(reinterpret_cast<char*>(sec.Name), 8);
        name.erase(std::find(name.begin(), name.end(), '\0'), name.end());

        if (name == ".reloc" && sec.PointerToRawData && sec.SizeOfRawData) {
            size_t raw_size = std::min(static_cast<size_t>(sec.SizeOfRawData),
                                       filesize - static_cast<size_t>(sec.PointerToRawData));
            reloc_entropy = calc_entropy(buffer.data() + sec.PointerToRawData, raw_size);
            break;
        }
    }

    uint32_t entry_rva = parser.get_entry_point_rva();
    uint64_t image_base = parser.get_image_base();

    ScanResult scan_result = ScanBuffer(buffer, entry_rva);

    // === Opcode n-grams ===
    std::vector<OpcodeFeature> opcode_features;
    try {
        auto suspicious_apis = get_suspicious_apis_lowercase();

        NgramConfig ngram_cfg;
        ngram_cfg.n                = 4;
        ngram_cfg.use_operand_type = true;
        ngram_cfg.max_features     = 250;
        ngram_cfg.boost_multiplier = 4.0;
        ngram_cfg.context_radius   = 96;

        opcode_features = extract_suspicious_opcode_ngrams(parser, suspicious_apis, ngram_cfg);
    }
    catch (const std::exception& e) {
        std::cerr << "[WARNING] Opcode n-gram extraction failed: " << e.what() << "\n";
        opcode_features.clear();
    }
    catch (...) {
        std::cerr << "[WARNING] Opcode n-gram extraction failed with unknown error\n";
        opcode_features.clear();
    }
    


    // ==================== HUMAN READABLE REPORT (std::cout) ====================
    std::cout << "\n=== PE Analysis Report ===\n";
    std::cout << "File:       " << filepath << "\n";
    std::cout << "Size:       " << filesize << " bytes\n";
    std::cout << "MD5:        " << hashes.md5 << "\n";
    std::cout << "SHA256:     " << hashes.sha256 << "\n";
    std::cout << "Fuzzy:      " << hashes.fuzzy << "\n\n";

    std::cout << "Entry Point RVA: 0x" << std::hex << entry_rva << std::dec << "\n";
    std::cout << "Image Base:      0x" << std::hex << image_base << std::dec << "\n";
    std::cout << "VA EP:           0x" << std::hex << (image_base + entry_rva) << std::dec << "\n\n";

    std::cout << "Machine:              0x" << std::hex << feats.machine << std::dec << "\n";
    std::cout << "Number of sections:   " << feats.number_of_sections << "\n";
    std::cout << "Imports:              " << import_stats.total_functions 
              << " functions (" << import_stats.suspicious_count << " suspicious)\n";
    std::cout << "TLS callbacks:        " << tls_callbacks << "\n";
    std::cout << "Overlay:              " << overlay_size << " bytes\n";
    std::cout << "Digital signature:    " << (sig_valid ? "VALID" : "INVALID / NONE") << "\n";

    std::cout << "\n=== Top suspicious opcode n-grams (top 15) ===\n";
    size_t show_count = std::min<size_t>(15, opcode_features.size());
    for (size_t i = 0; i < show_count; ++i) {
        const auto& f = opcode_features[i];
        std::cout << std::left << std::setw(60) << f.signature
                  << " count=" << std::setw(6) << f.count
                  << " weight=" << std::fixed << std::setprecision(2) << f.weight
                  << " near_sus=" << f.near_suspicious;
        if (f.first_va != 0) {
            std::cout << "  first@0x" << std::hex << f.first_va;
        }
        std::cout << "\n";
    }
    if (opcode_features.size() > show_count) {
        std::cout << "   ... (" << (opcode_features.size() - show_count) << " more)\n";
    }

    std::cout << "\n=== TF-IDF Opcode Vectorization ===\n";
    static OpcodeTfidfVectorizer tfidf_vectorizer;
    auto tfidf_result = tfidf_vectorizer.extract_and_vectorize(parser);
    std::cout << "Top TF-IDF terms:\n";
    for (size_t i = 0; i < std::min<size_t>(15, tfidf_result.top_terms.size()); ++i) {
        const auto& p = tfidf_result.top_terms[i];
        std::cout << "  " << p.first << " = " << std::fixed << std::setprecision(4) << p.second << "\n";
    }

    std::cout << "\n=== STRING & ENCODING ANALYSIS ===\n";

    nlohmann::json string_analysis = nlohmann::json::object();
    nlohmann::json interesting_strings = nlohmann::json::array();
    nlohmann::json decoded_results = nlohmann::json::array();

    std::vector<std::string> strings;
    std::string current;

    // ASCII strings
    for (uint8_t byte : buffer) {
        if (byte >= 32 && byte <= 126) {
            current += static_cast<char>(byte);
        } else {
            if (current.length() >= 8) strings.push_back(std::move(current));
            current.clear();
        }
    }
    if (current.length() >= 8) strings.push_back(std::move(current));

    // Unicode strings (wide)
    current.clear();
    for (size_t i = 0; i + 1 < buffer.size(); i += 2) {
        if (buffer[i] >= 32 && buffer[i] <= 126 && buffer[i + 1] == 0) {
            current += static_cast<char>(buffer[i]);
        } else {
            if (current.length() >= 8) strings.push_back(std::move(current));
            current.clear();
        }
    }
    if (current.length() >= 8) strings.push_back(std::move(current));

    std::cout << "Found " << strings.size() << " strings (length >= 8)\n";

    size_t analyzed = 0;
    const size_t max_analyze = 50;

    for (const auto& s : strings) {
        if (analyzed >= max_analyze) break;
        if (s.length() < 12) continue;

        nlohmann::json str_obj;
        str_obj["string"]   = (s.length() > 200 ? s.substr(0, 197) + "..." : s);
        str_obj["length"]   = s.length();
        str_obj["entropy"]  = calc_entropy(reinterpret_cast<const uint8_t*>(s.data()), s.size());

        str_obj["looks_like_text"] = looks_like_text(s);
        str_obj["is_caesar"]       = is_Caesar(s);
        str_obj["is_base64"]       = is_base64(s);
        str_obj["is_hex"]          = is_hex(s);

        if (is_base64(s)) {
            auto dec_data = decode_base64(s);
            if (!dec_data.empty() && is_printable_ascii(dec_data.data(), dec_data.size())) {
                std::string dec_str(dec_data.begin(), dec_data.end());
                nlohmann::json dec;
                dec["type"] = "base64";
                dec["original"] = s.length() > 150 ? s.substr(0,147)+"..." : s;
                dec["decoded"]  = dec_str;
                dec["length"]   = dec_data.size();
                decoded_results.push_back(dec);
            }
        }
        else if (is_hex(s)) {
            auto dec_data = decode_hex(s);
            if (!dec_data.empty() && is_printable_ascii(dec_data.data(), dec_data.size())) {
                std::string dec_str(dec_data.begin(), dec_data.end());
                nlohmann::json dec;
                dec["type"] = "hex";
                dec["original"] = s.length() > 150 ? s.substr(0,147)+"..." : s;
                dec["decoded"]  = dec_str;
                dec["length"]   = dec_data.size();
                decoded_results.push_back(dec);
            }
        }

        interesting_strings.push_back(str_obj);

        std::cout << "String [" << s.length() << "]: "
                  << (s.length() > 100 ? s.substr(0,97)+"..." : s) << "\n";
        analyze_string(s, 0);
        std::cout << "────────────────────────────────────\n";

        analyzed++;
    }

    string_analysis["total_strings_found"] = strings.size();
    string_analysis["analyzed"]            = analyzed;
    string_analysis["interesting_strings"] = std::move(interesting_strings);
    if (!decoded_results.empty()) {
        string_analysis["decoded_results"] = std::move(decoded_results);
    }

    if (overlay_size > 64) {
        std::cout << "\n[!] Overlay detected (" << overlay_size 
                  << " bytes). Running brute-force XOR scan...\n";
        std::vector<uint8_t> overlay(buffer.begin() + pe_end, buffer.end());
        brute_xor_all(overlay);
    }

    std::cout << "\n=== STRING ANALYSIS COMPLETED ===\n";

    std::cout << "\nSections:\n";
    std::cout << std::left << std::setw(12) << "Name"
              << std::setw(14) << "Entropy"
              << std::setw(14) << "Raw Size"
              << "Status\n";

    double max_ent = 0.0;
    std::vector<nlohmann::json> section_list;
    std::set<std::string> seen_names;
    WORD num_sec = static_cast<WORD>(std::min<size_t>(feats.number_of_sections, 96));

    for (WORD i = 0; i < num_sec; ++i) {
        size_t sec_off = section_table_offset + i * sizeof(IMAGE_SECTION_HEADER);
        if (sec_off + sizeof(IMAGE_SECTION_HEADER) > filesize) break;

        IMAGE_SECTION_HEADER sec{};
        memcpy(&sec, buffer.data() + sec_off, sizeof(sec));

        std::string name(reinterpret_cast<char*>(sec.Name), 8);
        name.erase(std::find(name.begin(), name.end(), '\0'), name.end());
        if (name.empty()) name = "(no name)";

        std::string status;
        if (seen_names.count(name)) status += "duplicate ";
        seen_names.insert(name);

        if (name.length() > 8 || name.find_first_not_of("._-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != std::string::npos) {
            status += "invalid_chars ";
        }

        size_t raw_start = sec.PointerToRawData;
        if (raw_start >= filesize || sec.SizeOfRawData == 0) {
            std::cout << std::left << std::setw(12) << name
                      << std::setw(14) << "-" << std::setw(14) << "0"
                      << "No raw data" << (status.empty() ? "" : " [" + status + "]") << "\n";
            continue;
        }

        size_t raw_size = std::min(static_cast<size_t>(sec.SizeOfRawData),
                                   filesize - static_cast<size_t>(raw_start));

        double ent = calc_entropy(buffer.data() + raw_start, raw_size);
        max_ent = std::max(max_ent, ent);

        nlohmann::json sec_json;
        sec_json["name"]          = name;
        sec_json["entropy"]       = ent;
        sec_json["raw_size"]      = raw_size;
        sec_json["virtual_size"]  = sec.Misc.VirtualSize;
        sec_json["characteristics"] = sec.Characteristics;
        section_list.push_back(sec_json);

        std::cout << std::left << std::setw(12) << name
                  << std::fixed << std::setprecision(3) << std::setw(14) << ent
                  << std::setw(14) << raw_size;

        if (ent > 7.2) std::cout << " HIGH ENTROPY (possible packing/obfuscation)";
        if (!status.empty()) std::cout << " [" << status << "]";
        std::cout << "\n";
    }

    if (max_ent > 7.3)
        std::cout << "\n[!] High entropy section(s) detected → may indicate packing, compression, or encryption\n";
    if (overlay_size > 1024 * 1024)
        std::cout << "[!] Large overlay detected (" << overlay_size << " bytes) → possible appended data / dropper\n";
    if (tls_callbacks > 3)
        std::cout << "[!] Unusual number of TLS callbacks (" << tls_callbacks << ") → often used in protectors / anti-debug\n";

    if (feats.address_of_entry_point != 0) {
        std::cout << "\nDisassembling near Entry Point...\n";
        PDAR(buffer, feats, feats.address_of_entry_point, 768, 220);
    }

    for (const auto& api : import_stats.imported_function_names) {
        std::string lower_api = api;
        std::transform(lower_api.begin(), lower_api.end(), lower_api.begin(), ::tolower);

        if (lower_api == "virtualallocex") { traits.api_VirtualAllocEx = true; traits.has_injection = true; }
        if (lower_api == "writeprocessmemory") { traits.api_WriteProcessMemory = true; traits.has_injection = true; }
        if (lower_api == "createremotethread") { traits.api_CreateRemoteThread = true; traits.has_injection = true; }
        if (lower_api == "ntmapviewofsection") { traits.api_NtMapViewOfSection = true; traits.has_injection = true; }
        if (lower_api == "isdebuggerpresent") { traits.api_IsDebuggerPresent = true; traits.has_anti_debug = true; }
        if (lower_api == "checkremotedebuggerpresent") { traits.api_CheckRemoteDebuggerPresent = true; traits.has_anti_debug = true; }
        if (lower_api == "minidumpwritedump") { traits.api_MiniDumpWriteDump = true; traits.has_credential_theft = true; }
    }

    for (const auto& s : strings) {
        if (s.find(".pdb") != std::string::npos && (s.find(":\\") != std::string::npos || s.find("/") != std::string::npos)) {
            traits.found_pdb_paths.push_back(s);
        }
        if (s.find("Software\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos) {
            traits.found_registry_keys.push_back(s);
            traits.has_persistence = true;
        }
        if (s.rfind("http://", 0) == 0 || s.rfind("https://", 0) == 0) {
            traits.found_urls.push_back(s);
            traits.has_networking = true;
        }   
    }

    try {
        YaraGenerator yara_gen;
        YaraRule yara_rule = yara_gen.generate(filepath, feats, import_stats, opcode_features, strings, hashes);
        std::string yara_text = yara_gen.generate_rule_string(yara_rule);
        std::string yara_filename = filepath + ".yar";
        std::ofstream yara_file(yara_filename);
        if (yara_file.is_open()) {
            yara_file << yara_text << "\n";
            yara_file.close();
            std::cout << "YARA rule written to: " << yara_filename << "\n";
        } else {
            std::cerr << "[ERROR] Failed to write YARA rule: " << yara_filename << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception occurred while generating YARA rule: " << e.what() << "\n";
    }

    std::cout << "\n=== ANALYSIS COMPLETED ===\n";

    auto json_out = features_to_json(feats, hashes, filepath, filesize,
                                     import_stats, tls_callbacks,
                                     reloc_entropy, overlay_size, sig_valid);

    json_out["opcode_ngrams"]     = opcode_features_to_json(opcode_features, 0);

    nlohmann::json top_ngrams = nlohmann::json::array();
    for (size_t i = 0; i < std::min<size_t>(30, opcode_features.size()); ++i) {
        const auto& f = opcode_features[i];
        nlohmann::json ngram;
        ngram["signature"]      = f.signature;
        ngram["count"]          = f.count;
        ngram["weight"]         = f.weight;
        ngram["near_suspicious"] = f.near_suspicious;
        ngram["first_va"]       = f.first_va;
        top_ngrams.push_back(ngram);
    }
    json_out["top_suspicious_ngrams"] = std::move(top_ngrams);
    json_out["opcode_tfidf"] = tfidf_result.to_json(50);

    json_out["disassembly_near_ep"] = capture_disassembly_for_json(
        buffer, feats, feats.address_of_entry_point, 768, 220);
    
    json_out["string_analysis"]   = std::move(string_analysis);
    json_out["sections"]          = std::move(section_list);
    json_out["label"]             = label;                    // "malware" or "benign"
    json_out["analysis_timestamp"]= std::time(nullptr);
    json_out["filename"]          = filepath;
    json_out["is_upx"]            = scan_result.upx;
    json_out["is_fsg"]            = scan_result.fsg;
    json_out["score"]             = scan_result.score;

    std::string json_str = json_out.dump(2);

    std::cerr << json_str << "\n";

    std::string json_filename = filepath + ".json";
    std::ofstream json_file(json_filename);
    if (json_file.is_open()) {
        json_file << json_str << "\n";
        json_file.close();
        std::cout << "Clean JSON written to: " << json_filename << "\n";
    } else {
        std::cerr << "[ERROR] Failed to write JSON: " << json_filename << "\n";
    }

    return true;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "Usage: pe_analyzer <path_to_pe_file> [label]\n";
        std::cerr << "Example: pe_analyzer sample.exe malware\n";
        return 1;
    }

    std::string label = (argc >= 3) ? argv[2] : "unknown";

    std::cout << "-----------------------------------------\n";
    std::cout << "Analyzing: " << argv[1] << " (label: " << label << ")\n";
    std::cout << "-----------------------------------------\n";

    if (!analyze_pe(argv[1], label)) {
        return 1;
    }

    return 0;
}