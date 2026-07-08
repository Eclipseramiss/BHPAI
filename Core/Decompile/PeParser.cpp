#include "PeParser.hpp"
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <cstring>

bool SectionInfo::is_executable() const {
    return (characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0;
}

PeParser::PeParser(const std::string& filepath) : filepath_(filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        error_msg_ = "Cannot open file: " + filepath;
        return;
    }

    size_t size = file.tellg();
    if (size < sizeof(IMAGE_DOS_HEADER)) {
        error_msg_ = "File too small";
        return;
    }

    buffer_.resize(size);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer_.data()), size);
    file.close();

    valid_ = parse();
}

PeParser::PeParser(const std::vector<uint8_t>& buffer, const std::string& filepath)
    : filepath_(filepath), buffer_(buffer) {
    valid_ = parse();
}

bool PeParser::parse() {
    if (buffer_.size() < sizeof(IMAGE_DOS_HEADER)) {
        error_msg_ = "File too small for DOS header";
        return false;
    }

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer_.data());
    if (dos->e_magic != 0x5A4D) { // MZ
        error_msg_ = "Not a DOS MZ executable";
        return false;
    }

    if (dos->e_lfanew < 0 || static_cast<size_t>(dos->e_lfanew) >= buffer_.size() - sizeof(uint32_t)) {
        error_msg_ = "Invalid e_lfanew offset";
        return false;
    }

    auto* nt_sig = reinterpret_cast<const uint32_t*>(buffer_.data() + dos->e_lfanew);
    if (*nt_sig != IMAGE_NT_SIGNATURE) {
        error_msg_ = "Not a PE file (missing PE signature)";
        return false;
    }

    size_t nt_offset = dos->e_lfanew;
    auto* file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(buffer_.data() + nt_offset + 4);

    is_64bit_ = (file_hdr->Machine == IMAGE_FILE_MACHINE_AMD64);

    if (file_hdr->Machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << "[DEBUG] Machine type: 0x" << std::hex << file_hdr->Machine << std::dec << "\n";
    }
    const size_t opt_offset = nt_offset + 4 + sizeof(IMAGE_FILE_HEADER);
    if (opt_offset + file_hdr->SizeOfOptionalHeader > buffer_.size()) {
        error_msg_ = "Optional header out of bounds";
        return false;
    }

    const uint16_t* magic = reinterpret_cast<const uint16_t*>(buffer_.data() + opt_offset);

    uint64_t image_base = 0;
    uint32_t entry_point_rva = 0;

    if (*magic == 0x10B) { 
        if (!is_64bit_) {
            const auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
                buffer_.data() + opt_offset);
            if (opt->Magic != 0x10B) {
                error_msg_ = "Magic PE32 không khớp";
                return false;
            }
            image_base      = opt->ImageBase;
            entry_point_rva = opt->AddressOfEntryPoint;
        } else {
            error_msg_ = "Machine là x64 nhưng Optional Header là PE32";
            return false;
        }
    }
    else if (*magic == 0x20B) {
        if (is_64bit_) {
            const auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
                buffer_.data() + opt_offset);
            if (opt->Magic != 0x20B) {
                error_msg_ = "Magic PE32+ không khớp";
                return false;
            }
            image_base      = opt->ImageBase;
            entry_point_rva = opt->AddressOfEntryPoint;
        } else {
            error_msg_ = "Machine là x86 nhưng Optional Header là PE32+";
            return false;
        }
    }
    else {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "Optional Header magic không hợp lệ: 0x%04x", *magic);
        error_msg_ = buffer;
        return false;
    }

    image_base_       = image_base;
    entry_point_rva_  = entry_point_rva;

    const size_t section_offset = opt_offset + file_hdr->SizeOfOptionalHeader;
    if (section_offset + file_hdr->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > buffer_.size()) {
        error_msg_ = "Bảng section tràn ra ngoài file";
        return false;
    }

    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        buffer_.data() + section_offset);

    for (int i = 0; i < file_hdr->NumberOfSections; ++i) {
        const auto& sec = sections[i];

        SectionInfo info;
        info.name = std::string(reinterpret_cast<const char*>(sec.Name), 8);
        auto it = std::find(info.name.c_str(), info.name.c_str() + info.name.size(), '\0');
        info.name.erase(it - info.name.c_str());

        info.virtual_address = image_base + sec.VirtualAddress;
        info.raw_offset      = sec.PointerToRawData;
        info.raw_size        = sec.SizeOfRawData;
        info.characteristics = sec.Characteristics;

        if (info.is_executable() && info.raw_size > 0) {
            executable_sections_.push_back(std::move(info));
        }
    }

    return true;
}