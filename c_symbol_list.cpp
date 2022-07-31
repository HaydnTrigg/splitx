#include "splitx_private_pch.h"

s_symbol::s_symbol(
    u16 object_index,
    u16 section_index,
    u64 rva,
    u32 size,
    u32 characteristics,
    const char* name_ptr)
    : object_index(object_index),
    section_index(section_index),
    rva(rva),
    size(size),
    characteristics(characteristics)
{
    strncpy(name, name_ptr, sizeof(name));
    name[sizeof(name)-1] = '\0';
}

void c_symbol_list::read_symbols()
{
    for (const s_cvdump_segment_contribution& segment_contribution : cvdump_reader.get_segment_contributions())
    {
        char name_buffer[64];
        const char* name_format = "unk_%08lx";
        u64 rva = address_resolver.get_rva(segment_contribution.address);

        if (segment_contribution.characteristics & IMAGE_SCN_CNT_CODE)
        {
            name_format = "func_%08lx";
        }
        else if (segment_contribution.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
        {
            if (segment_contribution.characteristics & IMAGE_SCN_MEM_WRITE)
            {
                name_format = "data_%08lx";
            }
            else
            {
                name_format = "rdata_%08lx";
            }
        }
        else if (segment_contribution.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        {
            name_format = "bss_%08lx";
        }

        snprintf(name_buffer, sizeof(name_buffer), name_format, rva);

        symbols.emplace_back(s_symbol(
            segment_contribution.object_index - 1,
            segment_contribution.address.segment,
            rva,
            segment_contribution.size,
            segment_contribution.characteristics,
            name_buffer));
    }

    for (const s_cvdump_public& public_name : cvdump_reader.get_public_names())
    {
        u64 rva = address_resolver.get_rva(public_name.address);
        size_t candidate_index = SIZE_MAX;
        bool split = false;

        if (rva == UINT64_MAX)
        {
            continue;
        }

        size_t symbols_size = symbols.size();
        for (size_t i = 0; i < symbols_size; i++)
        {
            s_symbol* symbol = &symbols[i];

            if (symbol->rva == rva)
            {
                candidate_index = i;
                break;
            }
            else if (rva > symbol->rva && rva < symbol->rva + symbol->size)
            {
                candidate_index = i;
                split = true;
                break;
            }
        }

        assert(candidate_index != SIZE_MAX);

        s_symbol* symbol = &symbols[candidate_index];

        if (split)
        {
            //assert(!(symbol->characteristics & IMAGE_SCN_CNT_CODE));

            s_symbol copy_symbol = *symbol;
            size_t split_size = rva - symbol->rva;

            copy_symbol.rva = rva;
            copy_symbol.size = symbol->size - split_size;
            memcpy(copy_symbol.name, public_name.name, sizeof(symbol->name));
            copy_symbol.was_public = true;

            symbol->size = split_size;

            symbols.emplace(symbols.begin() + candidate_index + 1, copy_symbol);
        }
        else
        {
            memcpy(symbol->name, public_name.name, sizeof(symbol->name));
            symbol->was_public = true;
        }
    }

    printf("%zu symbols\n", symbols.size());
}

const std::vector<s_symbol>& c_symbol_list::get_symbols() const
{
    return symbols;
}

void c_symbol_list::get_symbols_by_object_id(std::vector<const s_symbol*>& symbols_out, u16 object_index) const
{
    for (const s_symbol& symbol : symbols)
    {
        if (symbol.object_index == object_index)
        {
            symbols_out.push_back(&symbol);
        }
    }
}

const s_symbol* c_symbol_list::get_symbol(u64 rva, u32* offset) const
{
    const s_symbol* candidate = nullptr;

    size_t symbols_size = symbols.size();
    for (size_t i = 0; i < symbols_size; i++)
    {
        const s_symbol* symbol = &symbols[i];

        if (symbol->rva == rva)
        {
            candidate = symbol;
            break;
        }
        else if (rva > symbol->rva && rva < symbol->rva + symbol->size && offset != nullptr)
        {
            candidate = symbol;
            *offset = rva - candidate->rva;
            break;
        }
    }

    return candidate;
}

c_symbol_list::~c_symbol_list()
{}

c_symbol_list::c_symbol_list(
    const c_cvdump_reader &cvdump_reader,
    const c_pe_address_resolver &address_resolver)
    : cvdump_reader(cvdump_reader),
    address_resolver(address_resolver)
{

}
