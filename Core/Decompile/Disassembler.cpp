#include "Disassembler.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>

Disassembler::Disassembler() = default;

Disassembler::~Disassembler() {
    if (initialized_) {
        cs_close(&handle_);
    }
}

bool Disassembler::initialize(bool is_64bit)
{
    cs_mode mode = is_64bit ? CS_MODE_64 : CS_MODE_32;
    cs_err err = cs_open(CS_ARCH_X86, mode, &handle_);
    
    if (err != CS_ERR_OK) {
        std::cerr << "[CAPSTONE LỖI] cs_open thất bại: " << cs_strerror(err) << "\n";
        return false;
    }

    err = cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
    if (err != CS_ERR_OK) {
        std::cerr << "[CAPSTONE LỖI] Không bật được CS_OPT_DETAIL: " << cs_strerror(err) << "\n";
        std::cerr << "[CAPSTONE LỖI] Nguyên nhân phổ biến: Capstone build ở chế độ diet/reduced → không hỗ trợ detail\n";
        cs_close(&handle_);
        return false;
    }

    cs_option(handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    initialized_ = true;
    std::cout << "[CAPSTONE OK] Khởi tạo thành công - Mode: " 
              << (is_64bit ? "64-bit" : "32-bit") 
              << " | Detail: BẬT\n";
    return true;
}

std::vector<Instruction> Disassembler::disassemble(
    const uint8_t* code,
    size_t size,
    uint64_t start_address,
    size_t max_count)
{
    std::vector<Instruction> result;

    if (!initialized_) return result;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle_, code, size, start_address, max_count, &insn);

    if (count == 0) {
        return result;
    }

    for (size_t i = 0; i < count; ++i) {
        Instruction inst;
        inst.address  = insn[i].address;
        inst.mnemonic = insn[i].mnemonic;
        inst.operands = insn[i].op_str;
        inst.length   = std::min<size_t>(insn[i].size, 32);
        if (inst.length == 0) inst.length = 1;
        inst.bytes.assign(insn[i].bytes, insn[i].bytes + inst.length);
        inst.id = insn[i].id;
        if (insn[i].detail) {
            inst.x86 = insn[i].detail->x86;
            inst.has_detail = true;
        } else {
            inst.has_detail = false;
        }

        result.push_back(std::move(inst));
    }

    cs_free(insn, count);
    return result;
}

std::string Disassembler::format_instruction(const Instruction& inst, bool /*color*/) const {
    std::ostringstream oss;

    oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << inst.address << "  ";

    size_t max_bytes_show = std::min(inst.bytes.size(), size_t(24));
    for (size_t i = 0; i < max_bytes_show; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(inst.bytes[i]) << " ";
    }

    size_t bytes_len = max_bytes_show * 3;
    if (bytes_len < 24) {
        oss << std::string(24 - bytes_len, ' ');
    } else if (inst.bytes.size() > 24) {
        oss << "... ";
    }

    oss << inst.mnemonic;
    if (!inst.operands.empty()) {
        oss << " " << inst.operands;
    }

    return oss.str();
}