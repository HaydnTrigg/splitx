#include "splitx_private_pch.h"

void c_disassembler::disassemble_function(FILE* fp, const s_symbol* symbol) const
{
    ZyanUSize offset = 0;

    for (;;)
    {
        
    }
}

void c_disassembler::disassemble_data(FILE* fp, const s_symbol* symbol) const
{
    const u8* raw_data = pe_reader.get_raw_data() + pe_resolver.get_file_offset(symbol->rva);

    std::vector<u64> relocated_rvas;
    reloc_finder.get_relocations_in_rva_range(relocated_rvas, symbol->rva, symbol->size);

    if (!relocated_rvas.empty())
    {
        u64 head = symbol->rva;

        for (u64 offset : relocated_rvas)
        {
            u64 size_difference = offset - head;
            if (size_difference)
            {
                u64 head_offset = pe_resolver.get_file_offset(head);
                fprintf(fp, "incbin \"baserom.exe\", %lu, %lu\n", head_offset, size_difference);
            }

            u64 file_offset = pe_resolver.get_file_offset(offset);
            u32 reloc_destination = *(u32*)(pe_reader.get_raw_data() + file_offset);

            u32 symbol_offset = 0;
            const s_symbol* reloc_symbol = symbol_list.get_symbol(reloc_destination, &symbol_offset);
            assert(reloc_symbol);

            char offset_str[16] = {};
            if (symbol_offset)
                snprintf(offset_str, sizeof(offset_str), "+%u", symbol_offset);

            fprintf(fp, "dd %s%s\n", reloc_symbol->name, offset_str);

            head = offset + 4;
        }
    }
    else
    {
        u64 physical_offset = pe_resolver.get_file_offset(symbol->rva);
        fprintf(fp, "incbin \"baserom.exe\", %lu, %u\n", physical_offset, symbol->size);
    }
}

inline void write_splitx_header(FILE* fp)
{
    time_t timer;
    char buffer[32];
    tm* tm_info;

    timer = time(nullptr);
    tm_info = localtime(&timer);
    strftime(buffer, sizeof(buffer), "%d/%m/%Y %H:%M:%S", tm_info);
    fprintf(fp, "; splitx @ %s\n\n", buffer);
}

inline void write_symbol_preamble(FILE* fp, const s_symbol* symbol)
{
    fprintf(fp, "; %08x %08lx-%08lx (%u) %s\n",
        symbol->characteristics,
        symbol->rva,
        symbol->rva + symbol->size,
        symbol->size,
        symbol->name);

    u32 alignment = 1 << (((symbol->characteristics & 0x00f00000) >> 20) - 1);

    switch(symbol->characteristics & 0xf0)
    {
    case IMAGE_SCN_CNT_CODE:
        fprintf(fp, "align %u, db 0x90\n", alignment);
        break;
    case IMAGE_SCN_CNT_UNINITIALIZED_DATA:
        fprintf(fp, "align %u, resb 1\n", alignment);
        break;
    default:
        fprintf(fp, "align %u, db 0\n", alignment);
        break;
    }

    if (symbol->was_public || symbol->characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
    {
        fprintf(fp, ".global %s\n", symbol->name);
    }

    fprintf(fp, "%s:\n", symbol->name);
}

// TODO: proper characteristics flags here instead of hacking it in later (seemingly impossible on nasm?)
inline void write_section_definition(const c_pe_reader& pe_reader, FILE* fp, u16 section_index, bool bss)
{
    u16 num_sections = 0;
    const IMAGE_SECTION_HEADER* section_table = pe_reader.get_section_table(num_sections);
    const IMAGE_SECTION_HEADER* section = &section_table[section_index];
    char section_name_buf[9] = {};

    assert(section_index < num_sections);
    memcpy(section_name_buf, section->Name, 8);
    fprintf(fp, "section %s\n\n", section_name_buf);
}

void c_disassembler::disassemble_to_file(FILE* fp, const std::vector<const s_symbol*>& symbols) const
{
    u16 previous_section_index = 0xffff;

    write_splitx_header(fp);
    fputs("%include \"externs.inc\"\n\n", fp);

    for (const s_symbol* symbol : symbols)
    {
        bool bss = (symbol->characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA);
        u16 section_index = bss ? 0xffff : symbol->section_index;

        if (previous_section_index != section_index)
        {
            write_section_definition(pe_reader, fp, symbol->section_index, bss);
        }

        write_symbol_preamble(fp, symbol);

        if (symbol->characteristics & IMAGE_SCN_CNT_CODE)
        {
            disassemble_function(fp, symbol);
        }
        else if (bss)
        {
            fprintf(fp, "resb %u\n", symbol->size);
        }
        else
        {
            disassemble_data(fp, symbol);
        }

        putc('\n', fp);
        previous_section_index = section_index;
    }
}

c_disassembler::~c_disassembler()
{}

c_disassembler::c_disassembler(
    const c_symbol_list& symbol_list,
    const c_pe_reader& pe_reader,
    const c_pe_reloc_finder& reloc_finder,
    const c_pe_address_resolver& pe_resolver)
    : symbol_list(symbol_list),
    pe_reader(pe_reader),
    reloc_finder(reloc_finder),
    pe_resolver(pe_resolver)
{
    assert(ZYAN_SUCCESS(ZydisDecoderInit(
            &decoder,
            ZYDIS_MACHINE_MODE_LEGACY_32,
            ZYDIS_STACK_WIDTH_32)));
    assert(ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)));
}
