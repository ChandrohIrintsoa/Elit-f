#include "pch.h"
#include "ElfHelper.h"
PRAGMA_WARNING(push, 0)
#include <platform/elf.h>
PRAGMA_WARNING(pop)
#include <algorithm>
#include <stdexcept>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

struct ElfIdent {
        uint8_t ei_magic[4];
        uint8_t ei_class;
        uint8_t ei_data;
        uint8_t ei_version;
        uint8_t ei_osabi;
        uint8_t ei_abiversion;
        uint8_t pad1[7];
};

using namespace dart::elf;

static void* load_map_file(const char* path, uint64_t& fsize)
{
        int fd = open(path, O_RDONLY);
        if (fd < 0)
                throw std::runtime_error(std::string("Cannot open input file: ") + path);
        struct stat st;
        if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(ElfHeader))
                throw std::runtime_error(std::string("Invalid or too small ELF file: ") + path);
        // need RW because dart initialization need writing data in BSS
        void* mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        close(fd);
        if (mem == MAP_FAILED)
                throw std::runtime_error(std::string("Cannot map input file: ") + path);
        fsize = (uint64_t)st.st_size;
        return mem;
}

LibAppInfo ElfHelper::findSnapshots(const uint8_t* elf, uint64_t fsize)
{
        auto* hdr = (const ElfHeader*)elf;
        if (hdr->section_table_entry_size != sizeof(SectionHeader))
                throw std::invalid_argument("ELF: Invalid section entry size");
        if ((uint64_t)hdr->section_table_offset + (uint64_t)hdr->num_section_headers * sizeof(SectionHeader) > fsize)
                throw std::invalid_argument("ELF: Section table out of range");

        auto* section = (SectionHeader*)(elf + hdr->section_table_offset);
        auto sh_num = hdr->num_section_headers;

        const char* dynstr = nullptr;
        const Symbol* dynsym = nullptr;
        const Symbol* dynsym_end = nullptr;

        for (uint16_t i = 0; i < sh_num; i++, section++) {
                // SHT_NOBITS (.bss) occupies no bytes in the file
                if (section->type != SectionHeaderType::SHT_NOBITS &&
                    (uint64_t)section->file_offset + (uint64_t)section->file_size > fsize)
                        throw std::invalid_argument("ELF: Section out of range");
                if (section->type == SectionHeaderType::SHT_STRTAB && dynstr == nullptr) {
                        const char* strtab = (const char*)elf + section->file_offset;
                        const char* last = strtab + section->file_size;
#ifdef ELITF_DART_SINGLE_SNAPSHOT
                        const char* s_first = kSnapshotDataAsmSymbol;
#else
                        const char* s_first = kVmSnapshotDataAsmSymbol;
#endif
                        const char* s_last = s_first + strlen(s_first) + 1;
                        if (std::search(strtab, last, s_first, s_last) != last) {
                                dynstr = strtab;
                        }
                }
                if (section->type == SectionHeaderType::SHT_DYNSYM) {
                        if (section->entry_size != sizeof(Symbol))
                                throw std::invalid_argument("ELF: Invalid DYNSYM entry size");
                        dynsym = (Symbol*)(elf + section->file_offset);
                        dynsym_end = (Symbol*)(elf + section->file_offset + section->file_size);
                }
                if (dynsym != nullptr && dynstr != nullptr)
                        break;
        }

        if (dynstr == nullptr || dynsym == nullptr)
                throw std::invalid_argument("ELF: Cannot find Dart snapshot symbols");

#ifdef ELITF_DART_SINGLE_SNAPSHOT
        const uint8_t* snapshot_data = nullptr;
        const uint8_t* snapshot_text = nullptr;
        for (; dynsym < dynsym_end; dynsym++) {
                if (dynsym->info == 0)
                        continue;
                const char* name = dynstr + dynsym->name;
                if (strcmp(name, kSnapshotDataAsmSymbol) == 0) {
                        snapshot_data = elf + dynsym->value;
                }
                else if (strcmp(name, kSnapshotTextAsmSymbol) == 0) {
                        snapshot_text = elf + dynsym->value;
                }
        }
        if (snapshot_data == nullptr)
                throw std::invalid_argument("ELF: Cannot find Dart Snapshot Data");
        if (snapshot_text == nullptr)
                throw std::invalid_argument("ELF: Cannot find Dart Snapshot Text");
        return LibAppInfo{
                .lib = elf,
                .vm_snapshot_data = nullptr,
                .vm_snapshot_instructions = nullptr,
                .isolate_snapshot_data = snapshot_data,
                .isolate_snapshot_instructions = snapshot_text,
        };
#else
        const uint8_t* vm_snapshot_data = nullptr;
        const uint8_t* vm_snapshot_instructions = nullptr;
        const uint8_t* isolate_snapshot_data = nullptr;
        const uint8_t* isolate_snapshot_instructions = nullptr;
        for (; dynsym < dynsym_end; dynsym++) {
                if (dynsym->info == 0)
                        continue;
                const char* name = dynstr + dynsym->name;
                if (strcmp(name, kVmSnapshotDataAsmSymbol) == 0) {
                        vm_snapshot_data = elf + dynsym->value;
                }
                else if (strcmp(name, kVmSnapshotInstructionsAsmSymbol) == 0) {
                        vm_snapshot_instructions = elf + dynsym->value;
                }
                else if (strcmp(name, kIsolateSnapshotDataAsmSymbol) == 0) {
                        isolate_snapshot_data = elf + dynsym->value;
                }
                else if (strcmp(name, kIsolateSnapshotInstructionsAsmSymbol) == 0) {
                        isolate_snapshot_instructions = elf + dynsym->value;
                }
        }
        if (vm_snapshot_data == nullptr)
                throw std::invalid_argument("ELF: Cannot find Dart VM Snapshot Data");
        if (vm_snapshot_instructions == nullptr)
                throw std::invalid_argument("ELF: Cannot find Dart VM Snapshot Instructions");
        if (isolate_snapshot_data == nullptr)
                throw std::invalid_argument("ELF: Cannot find Dart Isolate Snapshot Data");
        if (isolate_snapshot_instructions == nullptr)
                throw std::invalid_argument("ELF: Cannot find Dart Isolate Snapshot Instructions");
        return LibAppInfo{
                .lib = elf,
                .vm_snapshot_data = vm_snapshot_data,
                .vm_snapshot_instructions = vm_snapshot_instructions,
                .isolate_snapshot_data = isolate_snapshot_data,
                .isolate_snapshot_instructions = isolate_snapshot_instructions,
        };
#endif
}

LibAppInfo ElfHelper::MapLibAppSo(const char* path)
{
        uint64_t fsize;
        void* lib = load_map_file(path, fsize);
        auto* elf = (uint8_t*)(lib);
        auto* hdr = (ElfHeader*)elf;
        auto* ident = (ElfIdent*)hdr->ident;
        if (memcmp(ident->ei_magic, "\x7f" "ELF", 4) != 0)
                throw std::invalid_argument("ELF: Invalid magic header");
        if (ident->ei_data != 1)
                throw std::invalid_argument("ELF: Support only little endian");
        if (ident->ei_class != ELFCLASS64)
                throw std::invalid_argument("ELF: Support only 64 bits");

        return findSnapshots(elf, fsize);
}
