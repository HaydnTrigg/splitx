#include "pe_file.h"
#include "libpe/pe.h"

typedef struct _IMAGE_BASE_RELOCATION {
  uint32_t   VirtualAddress;
  uint32_t   SizeOfBlock;
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

pe_ctx_t pe_ctx;
const char* exe_filename;

void create_pe_context(const char* file_path)
{
    pe_err_e err = pe_load_file(&pe_ctx, file_path);
    assert(err == LIBPE_E_OK);
    err = pe_parse(&pe_ctx);
    assert(err == LIBPE_E_OK);
    assert(pe_is_pe(&pe_ctx));

    exe_filename = file_path;

    printf("loaded %s...\n", file_path);
}

void s_pe_relocation_map::parse_relocations()
{
    IMAGE_SECTION_HEADER* reloc_section = pe_section_by_name(&pe_ctx, ".reloc");
    assert(reloc_section);

    const uint8_t* reloc_data = (uint8_t*)pe_ctx.pe.dos_hdr + reloc_section->PointerToRawData;
    const uint8_t* end_of_reloc_data = reloc_data + reloc_section->SizeOfRawData;

    for (;;)
    {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)reloc_data;
        size_t num_relocs = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

        if (!reloc->SizeOfBlock)
        {
            break;
        }

        for (size_t i = 0; i < num_relocs; i++)
        {
            uint16_t offset = *(uint16_t*)(reloc_data + sizeof(IMAGE_BASE_RELOCATION) + (i * 2)) & 0x0fff;

            if (offset >> 12 == offset && i != 0)
            {
                break;
            }

            relocated_rvas.push_back(pe_ctx.pe.imagebase + reloc->VirtualAddress + offset);
        }

        reloc_data += reloc->SizeOfBlock;
    }

    printf("%zu relocations\n", relocated_rvas.size());
}

void s_pe_relocation_map::get_relocations_for_memory_range(uint32_t rva, uint32_t length, std::vector<uint32_t>& offsets_out)
{
    bool finding = false;

    for (uint32_t address : relocated_rvas)
    {
        if (address >= rva && address < rva + length)
        {
            if (!finding)
            {
                finding = true;
            }

            offsets_out.push_back(address);
        }
        else if (finding)
        {
            break;
        }
    }
}
