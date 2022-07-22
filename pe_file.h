#pragma once

#include "types.h"

#include "libpe/resources.h"
#include "types.h"
#include "libpe/pe.h"
#include <cstdint>
#include <vector>

extern pe_ctx_t pe_ctx;
extern const char* exe_filename;

void create_pe_context(const char* file_path);

static inline void sanitise_name(char* name, char replacement_char)
{
    while (*name)
    {
        if (*name == '=' || *name < ' ' || *name > '~')
        {
            *name = replacement_char;
        }

        name++;
    }
}

static inline uint32_t segment_addr_to_rva(uint16_t segment, uint32_t address)
{
    IMAGE_SECTION_HEADER* section = pe_ctx.pe.sections[segment];
    return pe_ctx.pe.imagebase + section->VirtualAddress + address;
}

static inline uint32_t rva_to_image_offset(uint32_t rva)
{
    return rva - pe_ctx.pe.imagebase;
}

static inline IMAGE_SECTION_HEADER* get_section_of_rva(uint32_t rva)
{
    rva -= pe_ctx.pe.imagebase;

    for (size_t i = 0; i < pe_ctx.pe.num_sections; i++)
    {
        IMAGE_SECTION_HEADER* section = pe_ctx.pe.sections[i];

        if (rva >= section->VirtualAddress && rva <= section->VirtualAddress + section->SizeOfRawData)
        {
            return section;
        }
    }

    return nullptr;
}

struct s_pe_relocation_map
{
    std::vector<uint32_t> relocated_rvas;

    void parse_relocations();
    void get_relocations_for_memory_range(uint32_t rva, uint32_t length, std::vector<uint32_t>& offsets_out);
};
