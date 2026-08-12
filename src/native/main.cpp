#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>

#include <emscripten/bind.h>
#include <emscripten/val.h>

// ============================================================
// Section resolution — figures out where .text / __text lives
// ============================================================

struct TextSection {
    uint64_t file_offset;
    uint64_t vaddr;
    uint64_t size;
    bool is_arm64;
};

enum class BinFormat { ELF, MACHO, UNKNOWN };

BinFormat detect_format(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return BinFormat::UNKNOWN;
    uint32_t magic = *reinterpret_cast<const uint32_t*>(&data[0]);
    if (magic == 0x464C457F) return BinFormat::ELF;         // "\x7FELF" as LE u32
    if (magic == 0xFEEDFACF || magic == 0xCFFAEDFE) return BinFormat::MACHO;
    return BinFormat::UNKNOWN;
}

TextSection find_text_macho(const std::vector<uint8_t>& data) {
    if (data.size() < 32) throw std::runtime_error("File too small to be Mach-O");

    uint32_t cputype = *reinterpret_cast<const uint32_t*>(&data[4]);
    bool is_arm64 = (cputype == 0x0100000C);

    uint32_t ncmds = *reinterpret_cast<const uint32_t*>(&data[16]);
    size_t offset = 32;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (offset + 8 > data.size()) break;
        uint32_t cmd     = *reinterpret_cast<const uint32_t*>(&data[offset]);
        uint32_t cmdsize = *reinterpret_cast<const uint32_t*>(&data[offset + 4]);

        if (cmd == 0x19) { // LC_SEGMENT_64
            uint32_t nsects = *reinterpret_cast<const uint32_t*>(&data[offset + 64]);
            size_t sect_offset = offset + 72;
            for (uint32_t j = 0; j < nsects; j++) {
                std::string sectname(reinterpret_cast<const char*>(&data[sect_offset]), 16);
                std::string segname(reinterpret_cast<const char*>(&data[sect_offset + 16]), 16);
                uint64_t addr    = *reinterpret_cast<const uint64_t*>(&data[sect_offset + 32]);
                uint64_t size    = *reinterpret_cast<const uint64_t*>(&data[sect_offset + 40]);
                uint32_t fileoff = *reinterpret_cast<const uint32_t*>(&data[sect_offset + 48]);
                sect_offset += 80;

                // trim embedded NULs so find() behaves like a normal C-string compare
                sectname = sectname.c_str();
                segname  = segname.c_str();

                if (sectname == "__text" && segname == "__TEXT") {
                    return { fileoff, addr, size, is_arm64 };
                }
            }
        }
        offset += cmdsize;
    }
    throw std::runtime_error("Could not find __TEXT,__text section");
}

TextSection find_text_elf(const std::vector<uint8_t>& data) {
    if (data.size() < 0x40) throw std::runtime_error("File too small to be ELF");

    uint16_t e_machine   = *reinterpret_cast<const uint16_t*>(&data[0x12]);
    bool is_arm64 = (e_machine == 0xB7); // EM_AARCH64

    uint64_t e_shoff      = *reinterpret_cast<const uint64_t*>(&data[0x28]);
    uint16_t e_shentsize  = *reinterpret_cast<const uint16_t*>(&data[0x3A]);
    uint16_t e_shnum      = *reinterpret_cast<const uint16_t*>(&data[0x3C]);
    uint16_t e_shstrndx   = *reinterpret_cast<const uint16_t*>(&data[0x3E]);

    auto section_header = [&](int i) -> const uint8_t* {
        return &data[e_shoff + i * e_shentsize];
    };

    const uint8_t* shstrtab_hdr = section_header(e_shstrndx);
    uint64_t shstrtab_offset = *reinterpret_cast<const uint64_t*>(shstrtab_hdr + 0x18);

    for (uint16_t i = 0; i < e_shnum; i++) {
        const uint8_t* sh = section_header(i);
        uint32_t name_off = *reinterpret_cast<const uint32_t*>(sh + 0x00);
        uint64_t addr      = *reinterpret_cast<const uint64_t*>(sh + 0x10);
        uint64_t offset     = *reinterpret_cast<const uint64_t*>(sh + 0x18);
        uint64_t size       = *reinterpret_cast<const uint64_t*>(sh + 0x20);

        const char* name = reinterpret_cast<const char*>(&data[shstrtab_offset + name_off]);
        if (std::string(name) == ".text") {
            return { offset, addr, size, is_arm64 };
        }
    }
    throw std::runtime_error("Could not find .text section");
}

TextSection find_text_section(const std::vector<uint8_t>& data) {
    switch (detect_format(data)) {
        case BinFormat::MACHO: return find_text_macho(data);
        case BinFormat::ELF:   return find_text_elf(data);
        default: throw std::runtime_error("Unrecognized binary format (not ELF or Mach-O)");
    }
}

// ============================================================
// Raw byte helpers
// ============================================================

uint32_t read_u32(const std::vector<uint8_t>& data, size_t off) {
    if (off + 4 > data.size()) throw std::runtime_error("Read out of bounds");
    return *reinterpret_cast<const uint32_t*>(&data[off]);
}
void write_u32(std::vector<uint8_t>& data, size_t off, uint32_t val) {
    if (off + 4 > data.size()) throw std::runtime_error("Write out of bounds");
    *reinterpret_cast<uint32_t*>(&data[off]) = val;
}

// ============================================================
// Branch classification + inversion (arch-agnostic dispatch)
// ============================================================

enum class BranchKind {
    NONE,
    ARM64_CBZ_CBNZ,
    ARM64_TBZ_TBNZ,
    ARM64_BCOND,
    X86_SHORT_JCC,
    X86_NEAR_JCC
};

struct ClassifyResult {
    BranchKind kind;
    size_t instr_len;
};

ClassifyResult classify_arm64(const std::vector<uint8_t>& data, size_t off) {
    uint32_t instr = read_u32(data, off);

    // cbz/cbnz: bits 30-25 = 011010 (fixed), bit31(sf) and bit24(op) both vary
    if ((instr & 0x7E000000) == 0x34000000)
        return { BranchKind::ARM64_CBZ_CBNZ, 4 };

    // tbz/tbnz: bits 30-25 = 011011 (fixed), bit31(part of bit pos) and bit24(op) both vary
    if ((instr & 0x7E000000) == 0x36000000)
        return { BranchKind::ARM64_TBZ_TBNZ, 4 };

    if ((instr & 0xFF000000) == 0x54000000) // b.cond — this one was already correct
        return { BranchKind::ARM64_BCOND, 4 };

    return { BranchKind::NONE, 0 };
}

ClassifyResult classify_x86(const std::vector<uint8_t>& data, size_t off) {
    if (off >= data.size()) return { BranchKind::NONE, 0 };
    uint8_t b0 = data[off];

    if (b0 >= 0x70 && b0 <= 0x7F)
        return { BranchKind::X86_SHORT_JCC, 2 };

    if (b0 == 0x0F && off + 1 < data.size()) {
        uint8_t b1 = data[off + 1];
        if (b1 >= 0x80 && b1 <= 0x8F)
            return { BranchKind::X86_NEAR_JCC, 6 };
    }

    return { BranchKind::NONE, 0 };
}

ClassifyResult classify_instruction(const std::vector<uint8_t>& data, size_t off, bool is_arm64) {
    return is_arm64 ? classify_arm64(data, off) : classify_x86(data, off);
}

void invert_instruction(std::vector<uint8_t>& data, size_t off, BranchKind kind) {
    switch (kind) {
        case BranchKind::ARM64_CBZ_CBNZ:
        case BranchKind::ARM64_TBZ_TBNZ: {
            uint32_t instr = read_u32(data, off);
            write_u32(data, off, instr ^ 0x01000000); // flip op bit (bit 24)
            break;
        }
        case BranchKind::ARM64_BCOND: {
            uint32_t instr = read_u32(data, off);
            uint32_t cond = (instr & 0xF) ^ 0x1;
            write_u32(data, off, (instr & 0xFFFFFFF0) | cond);
            break;
        }
        case BranchKind::X86_SHORT_JCC: {
            if (off >= data.size()) throw std::runtime_error("Write out of bounds");
            data[off] ^= 0x01;
            break;
        }
        case BranchKind::X86_NEAR_JCC: {
            if (off + 1 >= data.size()) throw std::runtime_error("Write out of bounds");
            data[off + 1] ^= 0x01;
            break;
        }
        default:
            throw std::runtime_error("Unsupported branch kind for inversion");
    }
}

// ============================================================
// Public patch operations (operate on a full-file byte copy)
// ============================================================

// Flip a conditional branch at a virtual address. Works across
// ELF/Mach-O and ARM64/x86 automatically.
std::vector<uint8_t> flip_branch(std::vector<uint8_t> data, uint64_t target_addr) {
    TextSection sec = find_text_section(data);
    size_t file_offset = sec.file_offset + (target_addr - sec.vaddr);

    ClassifyResult result = classify_instruction(data, file_offset, sec.is_arm64);
    if (result.kind == BranchKind::NONE) {
        throw std::runtime_error("No recognized conditional branch at this address");
    }

    invert_instruction(data, file_offset, result.kind);
    return data;
}

// NOP out `length` bytes starting at a virtual address. ARM64 uses the
// fixed 4-byte NOP encoding; x86 repeats the single-byte 0x90.
std::vector<uint8_t> nop_range(std::vector<uint8_t> data, uint64_t target_addr, size_t length) {
    TextSection sec = find_text_section(data);
    size_t file_offset = sec.file_offset + (target_addr - sec.vaddr);

    if (file_offset + length > data.size()) {
        throw std::runtime_error("NOP range out of bounds");
    }

    if (sec.is_arm64) {
        if (length % 4 != 0) throw std::runtime_error("ARM64 NOP range must be a multiple of 4 bytes");
        const uint8_t nop[4] = { 0x1F, 0x20, 0x03, 0xD5 };
        for (size_t i = 0; i < length; i += 4)
            for (int j = 0; j < 4; j++) data[file_offset + i + j] = nop[j];
    } else {
        for (size_t i = 0; i < length; i++) data[file_offset + i] = 0x90;
    }

    return data;
}

// Raw overwrite. newBytes must be exactly as long as the region being
// replaced, so file offsets after it never shift.
std::vector<uint8_t> write_bytes(std::vector<uint8_t> data, uint64_t target_addr,
                                  const std::vector<uint8_t>& newBytes) {
    TextSection sec = find_text_section(data);
    size_t file_offset = sec.file_offset + (target_addr - sec.vaddr);

    if (file_offset + newBytes.size() > data.size()) {
        throw std::runtime_error("Write out of bounds");
    }

    std::memcpy(&data[file_offset], newBytes.data(), newBytes.size());
    return data;
}

// ============================================================
// Emscripten bindings — JS-facing surface
// ============================================================

using namespace emscripten;

std::vector<uint8_t> jsBytesToVector(const val& jsBytes) {
    unsigned int len = jsBytes["length"].as<unsigned int>();
    std::vector<uint8_t> data(len);
    val{ typed_memory_view(len, data.data()) }.call<void>("set", jsBytes);
    return data;
}

val toJsUint8Array(const std::vector<uint8_t>& buf) {
    val view = val(typed_memory_view(buf.size(), buf.data()));
    val Uint8Array = val::global("Uint8Array");
    return Uint8Array.new_(view); // constructor copies immediately — independent of WASM heap after this
}

val flip_branch_binding(val jsBytes, uint32_t addr_lo, uint32_t addr_hi) {
    uint64_t target_addr = (static_cast<uint64_t>(addr_hi) << 32) | addr_lo;
    try {
        std::vector<uint8_t> data = jsBytesToVector(jsBytes);
        std::vector<uint8_t> patched = flip_branch(std::move(data), target_addr);
        return val(typed_memory_view(patched.size(), patched.data()));
    } catch (const std::exception&) {
        return val::null();
    }
}

val nop_range_binding(val jsBytes, uint64_t target_addr, size_t length) {
    try {
        std::vector<uint8_t> data = jsBytesToVector(jsBytes);
        std::vector<uint8_t> patched = nop_range(std::move(data), target_addr, length);
        return toJsUint8Array(patched);
    } catch (const std::exception&) {
        return val::null();
    }
}

val write_bytes_binding(val jsBytes, uint64_t target_addr, val jsNewBytes) {
    try {
        std::vector<uint8_t> data = jsBytesToVector(jsBytes);
        std::vector<uint8_t> newBytes = jsBytesToVector(jsNewBytes);
        std::vector<uint8_t> patched = write_bytes(std::move(data), target_addr, newBytes);
        return toJsUint8Array(patched);
    } catch (const std::exception&) {
        return val::null();
    }
}

val debug_offset(val jsBytes, uint64_t target_addr) {
    try {
        std::vector<uint8_t> data = jsBytesToVector(jsBytes);
        TextSection sec = find_text_section(data);
        size_t file_offset = sec.file_offset + (target_addr - sec.vaddr);

        val out = val::object();
        out.set("target_addr_received", val(std::to_string(target_addr)));
        out.set("section_vaddr", val(std::to_string(sec.vaddr)));
        out.set("section_file_offset", val(std::to_string(sec.file_offset)));
        out.set("section_size", val(std::to_string(sec.size)));
        out.set("computed_file_offset", val(std::to_string(file_offset)));
        out.set("is_arm64", sec.is_arm64);

        if (file_offset + 4 <= data.size()) {
            uint32_t raw = read_u32(data, file_offset);
            char buf[11];
            snprintf(buf, sizeof(buf), "0x%08x", raw);
            out.set("raw_u32_at_offset", val(std::string(buf)));

            ClassifyResult cr = classify_instruction(data, file_offset, sec.is_arm64);
            out.set("classified_kind", (int)cr.kind);
        } else {
            out.set("error", val("computed offset is out of bounds"));
        }

        return out;
    } catch (const std::exception& e) {
        val out = val::object();
        out.set("error", val(std::string(e.what())));
        return out;
    }
}

EMSCRIPTEN_BINDINGS(patcher_module) {
    function("flip_branch", &flip_branch_binding);
    function("nop_range", &nop_range_binding);
    function("write_bytes", &write_bytes_binding);
    function("debug_offset", &debug_offset);
}