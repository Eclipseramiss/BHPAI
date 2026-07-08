#ifndef YARA_GENERATOR_HPP
#define YARA_GENERATOR_HPP

#include "pe_analyzer.hpp"
#include "pe_opcode_ngram.hpp"
#include <string>
#include <vector>

struct YaraRule {
    std::string name;
    std::string description;
    std::string author = "AutoAnalyzer";
    int score = 0;
    std::string rule_text;
    std::vector<std::string> tags;
};

struct MalwareTraits {
    bool has_injection = false;
    bool has_persistence = false;
    bool has_credential_theft = false;
    bool has_anti_debug = false;
    bool has_anti_vm = false;
    bool has_networking = false;

    bool api_VirtualAllocEx = false;
    bool api_WriteProcessMemory = false;
    bool api_CreateRemoteThread = false;
    bool api_NtMapViewOfSection = false;
    bool api_QueueUserAPC = false;
    
    bool api_IsDebuggerPresent = false;
    bool api_CheckRemoteDebuggerPresent = false;
    
    bool api_MiniDumpWriteDump = false;
    bool api_LsaEnumerateLogonSessions = false;

    std::vector<std::string> found_pdb_paths;
    std::vector<std::string> found_registry_keys;
    std::vector<std::string> found_urls;
};

class YaraGenerator {
public:
    YaraRule generate(const std::string& filepath, 
                      const PeHeaderFeatures& feats, 
                      const ImportStats& imports, 
                      const std::vector<OpcodeFeature>& ngrams, 
                      const std::vector<std::string>& strings, 
                      const FileHashes& hashes);

    std::string generate_rule_string(const YaraRule& rule);

private:
    std::string generate_strings_section(const std::vector<std::string>& strings, 
                                         const std::vector<OpcodeFeature>& ngrams, 
                                         const ImportStats& imports,
                                         const PeHeaderFeatures& feats);
                                         
    std::string generate_condition(const PeHeaderFeatures& feats, 
                                   const ImportStats& imports, 
                                   size_t string_count);

    std::string escape_string(const std::string& s);
    bool is_printable(const std::string& s);
    std::string to_hex_string(const std::string& s);
};

#endif // YARA_GENERATOR_HPP