#include "YaraGen.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include "StringEx.hpp"

bool YaraGenerator::is_printable(const std::string& s) {
    for (char c : s) {
        if (!std::isprint(static_cast<unsigned char>(c)) && c != '\r' && c != '\n' && c != '\t') {
            return false;
        }
    }
    return !s.empty();
}

std::string YaraGenerator::to_hex_string(const std::string& s) {
    std::ostringstream oss;
    for (size_t i = 0; i < s.length(); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(s[i]) & 0xFF) << " ";
    }
    return oss.str();
}

std::string YaraGenerator::escape_string(const std::string& s) {
    std::string escaped;
    escaped.reserve(s.length() * 2);
    for (char c : s) {
        if (c == '\\') escaped += "\\\\";
        else if (c == '"')  escaped += "\\\"";
        else if (c == '\n') escaped += "\\n";
        else if (c == '\r') escaped += "\\r";
        else if (c == '\t') escaped += "\\t";
        else escaped += c;
    }
    if (escaped.length() > 100) {
        escaped = escaped.substr(0, 100);
    }
    return escaped;
}

std::string YaraGenerator::generate_strings_section(const std::vector<std::string>& strings, 
                                                     const std::vector<OpcodeFeature>& ngrams, 
                                                     const ImportStats& imports,
                                                     const PeHeaderFeatures& feats) 
{
    std::ostringstream oss;
    oss << "    strings:\n";

    static const std::vector<std::string> rust_blacklist = {
        "/rustc/",
        "panicking.rs",
        "Option::unwrap",
        "attempt to divide by zero",
        "index out of bounds",
        "char boundary",
        "slice index",
        "raw_vec"
    };

    size_t s_count = 0;
    for (const auto& s : strings) {
        bool skip = false;
        for (const auto& x : rust_blacklist) {
            if (s.find(x) != std::string::npos) {
                skip = true;
                break;
            }
        }
        if (skip) continue;

        if (s.length() >= 14 && looks_like_text(s) && s.find(":\\") == std::string::npos && s.rfind("http", 0) != 0) {
            if (is_printable(s)) {
                oss << "        $s" << s_count << " = \"" << escape_string(s) << "\" ascii wide xor(0x01-0x20)\n";
            } else {
                oss << "        $s" << s_count << " = { " << to_hex_string(s) << "}\n";
            }
            s_count++;
            if (s_count >= 12) break;
        }
    }

    if (imports.has_VirtualAllocEx)      oss << "        $api_va = \"VirtualAllocEx\" ascii nocase\n";
    if (imports.has_WriteProcessMemory)  oss << "        $api_wpm = \"WriteProcessMemory\" ascii nocase\n";
    if (imports.has_CreateRemoteThread)  oss << "        $api_crt = \"CreateRemoteThread\" ascii nocase\n";
    if (imports.has_NtMapViewOfSection)  oss << "        $api_ntmap = \"NtMapViewOfSection\" ascii nocase\n";
    if (imports.has_NtAllocateVirtualMemory) oss << "        $nt0 = \"NtAllocateVirtualMemory\" ascii nocase\n";
    if (imports.has_NtWriteVirtualMemory)    oss << "        $nt1 = \"NtWriteVirtualMemory\" ascii nocase\n";
    if (imports.has_NtProtectVirtualMemory)  oss << "        $nt2 = \"NtProtectVirtualMemory\" ascii nocase\n";

    if (feats.likely_pos_scraper || imports.pos_specific_count > 0) {
        oss << "        $pos_track1 = /((4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14}))/ ascii wide\n";
        oss << "        $pos_track2 = /=[0-9]{14,20}/ ascii wide\n";
    }

    return oss.str();
}

std::string YaraGenerator::generate_condition(const PeHeaderFeatures& feats, 
                                               const ImportStats& imports, 
                                               size_t string_count) 
{
    std::ostringstream oss;
    oss << "    condition:\n";
    oss << "        uint16(0)==0x5A4D and\n";
    oss << "        uint32(0x3C)<filesize-4 and\n";
    oss << "        uint32(uint32(0x3C))==0x4550 and\n";
    oss << "        (\n";

    bool has_native_injection = imports.has_NtAllocateVirtualMemory && imports.has_NtWriteVirtualMemory &&
                               (imports.has_NtProtectVirtualMemory || imports.has_NtMapViewOfSection);

    bool first = true;
    if (has_native_injection) {
        oss << "            all of ($nt*)";
        first = false;
    }

    if (string_count >= 4) {
        if (!first) oss << " and\n";
        oss << "            4 of ($s*)";
        first = false;
    }

    if (feats.has_tls) {
        if (!first) oss << " and\n";
        oss << "            pe.number_of_sections >= 4";
        first = false;
    }

    if (first) {
        oss << "            false";
    }

    oss << "\n        )\n";
    return oss.str();
}

YaraRule YaraGenerator::generate(const std::string& filepath, 
                                  const PeHeaderFeatures& feats, 
                                  const ImportStats& imports, 
                                  const std::vector<OpcodeFeature>& ngrams, 
                                  const std::vector<std::string>& strings, 
                                  const FileHashes& hashes)
{
    YaraRule rule;
    rule.name = "malware_heuristic_" + hashes.md5.substr(0, 16);
    rule.description = "Auto-generated refined heuristic rule for " + filepath;
    rule.tags = {"malware", "pe"};

    bool has_native_injection = imports.has_NtAllocateVirtualMemory && imports.has_NtWriteVirtualMemory &&
                                (imports.has_NtProtectVirtualMemory || imports.has_NtMapViewOfSection);

    bool rust_binary = false;
    for (const auto& s : strings) {
        if (s.find("/rustc/") != std::string::npos || s.find("panicking.rs") != std::string::npos || s.find("raw_vec") != std::string::npos) {
            rust_binary = true;
            break;
        }
    }

    int score = 0;
    if (has_native_injection)              score += 50;
    if (imports.has_CreateRemoteThread)    score += 20;
    if (imports.has_VirtualAllocEx)        score += 15;
    if (imports.has_WriteProcessMemory)    score += 15;
    if (feats.has_tls)                     score += 15;
    if (feats.code_section_entropy > 7.5)  score += 20;
    if (feats.code_ratio < 0.10)           score += 20;
    if (feats.has_signature)               score -= 40;
    if (feats.digital_signature_valid)      score -= 20;
    score = std::clamp(score, 0, 100);
    rule.score = score;

    if (feats.has_tls) {
        rule.tags.push_back("has_tls");
    }
    if (feats.likely_pos_scraper) {
        rule.tags.push_back("pos_scraper");
    }
    if (rust_binary && has_native_injection) {
        rule.tags.push_back("rust");
        rule.score += 20;
        rule.score = std::clamp(rule.score, 0, 100);
    }

    size_t valid_strings_count = 0;
    for (const auto& s : strings) {
        if (s.length() >= 14 && looks_like_text(s) && s.find(":\\") == std::string::npos && s.rfind("http", 0) != 0) {
            valid_strings_count++;
        }
    }

    std::ostringstream oss;
    oss << "import \"pe\"\n";
    oss << "rule " << rule.name;
    if (!rule.tags.empty()) {
        oss << " : ";
        for (size_t i = 0; i < rule.tags.size(); ++i) {
            oss << rule.tags[i] << (i == rule.tags.size() - 1 ? "" : " ");
        }
    }
    oss << "\n{\n";

    oss << "    meta:\n";
    oss << "        description = \"" << rule.description << "\"\n";
    oss << "        author = \"" << rule.author << "\"\n";
    oss << "        calculated_malware_score = " << rule.score << "\n";
    oss << "        md5 = \"" << hashes.md5 << "\"\n";
    oss << "        threat_level = \"" << (rule.score >= 70 ? "HIGH" : (rule.score >= 40 ? "MEDIUM" : "LOW")) << "\"\n";
    oss << "\n";

    oss << generate_strings_section(strings, ngrams, imports, feats);
    oss << "\n";
    oss << generate_condition(feats, imports, std::min<size_t>(12, valid_strings_count));
    oss << "}\n";

    rule.rule_text = oss.str();
    return rule;
}

std::string YaraGenerator::generate_rule_string(const YaraRule& rule) {
    return rule.rule_text;
}