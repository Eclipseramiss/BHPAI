#pragma once
#include <vector>
#include <cstdint>

struct ExeSection {
    uint32_t rva;   // Relative Virtual Address
    uint32_t vsz;   // Virtual Size
    uint32_t rsz;   // Raw Size
};

class WWPackUnpacker {
public:
    static bool isWWPack(const std::vector<uint8_t>& buffer);
    static bool unpack(const std::vector<uint8_t>& packed, std::vector<uint8_t>& unpacked);
};
