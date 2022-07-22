#include "symbol_map.h"
#include "pe_file.h"
#include "types.h"

s_symbol::s_symbol(e_symbol_type type, uint16_t alignment, uint32_t rva, uint32_t size, uint16_t object_index, const char* name_ptr, uint32_t raw_characteristics)
    : type(type), alignment(alignment), rva(rva), size(size), object_index(object_index), raw_characteristics(raw_characteristics)
{
    if (name_ptr)
    {
        strncpy(name, name_ptr, sizeof(name));
    }
    else
    {
        memset(name, 0, sizeof(name));
    }
}

inline void extract_info_from_characteristics(e_symbol_type* type, uint16_t* alignment, uint32_t characteristics)
{
    *type = k_symbol_type_unknown;
    *alignment = 1 << (((characteristics & 0x00f00000) >> 20) - 1);

    switch(characteristics & 0x000000f0)
    {
    case IMAGE_SCN_CNT_CODE:
        *type = k_symbol_type_function;
        break;
    case IMAGE_SCN_CNT_INITIALIZED_DATA:
        *type = k_symbol_type_data;
        break;
    case IMAGE_SCN_CNT_UNINITIALIZED_DATA:
        *type = k_symbol_type_bss;
    default:
        break;
    }
}

void s_symbol_map::load_segment_contributions(const char* cvdump_log)
{
    static const char* header_search_string = "  Imod  Address        Size      Characteristics\n";
    const char* position = strstr(cvdump_log, header_search_string);
    assert(position);
    position += strlen(header_search_string);

    while (*position != '\n')
    {
        /*  01D9  0001:00000000  00000080  60501020\n*/
        uint16_t object_idx = strtoul(position + 2, nullptr, 16) - 1;
        uint16_t segment = strtoul(position + 8, nullptr, 16) - 1;
        uint32_t address = strtoul(position + 13, nullptr, 16);
        uint32_t size = strtoul(position + 23, nullptr, 16);
        uint32_t characteristics = strtoul(position + 33, nullptr, 16);

        uint32_t rva = segment_addr_to_rva(segment, address);
        e_symbol_type type;
        uint16_t alignment;
        extract_info_from_characteristics(&type, &alignment, characteristics);

        symbols.push_back(s_symbol(type, alignment, rva, size, object_idx, nullptr, characteristics));

        position += 42;
    }
    
    printf("%zu segment contributions\n", symbols.size());
}

struct s_public_name
{
    uint32_t rva;
    char512 name;

    s_public_name(uint32_t rva, const char* name_ptr)
        : rva(rva)
    {
        strncpy(name, name_ptr, sizeof(name));
    }
};

void s_symbol_map::load_public_symbols(const char* cvdump_log)
{
    const char* position = strstr(cvdump_log, "S_PUB32: ");
    std::vector<s_public_name> publics;

    assert(position);

    while (*position != '\n')
    {
        char name[512] = {};

        /* S_PUB32: [0014:0022D740], Flags: 00000000,  */
        uint16_t segment = strtoul(position + 10, nullptr, 16) - 1;
        uint32_t address = strtoul(position + 15, nullptr, 16);

        position += 43;

        const char* next_line = position;
        while (*next_line != '\n')
            next_line++;

        strncpy(name, position, next_line - position);

        // __except_list
        if (segment < pe_ctx.pe.num_sections)
        {
            publics.push_back(s_public_name(segment_addr_to_rva(segment, address), name));
        }

        position = next_line + 1;
    }
    
    printf("%zu symbols\n", publics.size());

    // merge segment contributions and public names
    for (size_t i = publics.size(); i != 1; i--)
    {
        s_public_name* name = &publics[i-1];
        ssize_t low_symbol_index = -1;
        
        for (size_t j = 0; j < symbols.size(); j++)
        {
            s_symbol* symbol = &symbols[j];

            if (name->rva >= symbol->rva && name->rva < symbol->rva + symbol->size)
            {
                low_symbol_index = j;
                break;
            }
        }

        assert(low_symbol_index != -1);
        s_symbol* symbol = &symbols[low_symbol_index];

        if (symbol->rva == name->rva)
        {
            memcpy(symbol->name, name->name, sizeof(symbol->name));
            symbol->was_public = true;
        }
        else
        {
            // more than one name in the same segment contribution
            // shrink segment contribution for public symbol

            size_t size_to_cut = (symbol->size) - (name->rva - symbol->rva);
            symbol->size -= size_to_cut;

            symbols.insert(symbols.begin() + low_symbol_index + 1, s_symbol(symbol->type, symbol->alignment, name->rva, size_to_cut, symbol->object_index, name->name, symbol->raw_characteristics));
            symbols[low_symbol_index + 1].was_public = true;
        }
    }
}

void s_symbol_map::perform_symbol_fixups()
{
    // fixups on:
    // seg contribution without public: symbols without names

    uint32_t number_of_name_fixups = 0;

    size_t size = symbols.size();
    for (size_t i = 0; i < size; i++)
    {
        s_symbol* symbol = &symbols[i];

        // dummy name
        if (symbol->name[0] == '\0')
        {
            char512 dummy_name;
            const char* dummy_name_format = "unk_%08x";

            if (symbol->type == k_symbol_type_function)
            {
                dummy_name_format = "func_%08x";
            }
            else if (symbol->type == k_symbol_type_data)
            {
                dummy_name_format = "data_%08x";
            }
            else if (symbol->type == k_symbol_type_bss)
            {
                dummy_name_format = "bss_%08x";
            }

            snprintf(dummy_name, sizeof(dummy_name), dummy_name_format, symbol->rva);
            memcpy(symbol->name, dummy_name, sizeof(symbol->name));
            number_of_name_fixups++;
        }
        else
        {
            sanitise_name(symbol->name, '_');
        }
    }

    printf("symbol herustics: inserted %u dummy names\n", number_of_name_fixups);
}

void s_symbol_map::populate_symbol_indices_list()
{
    size_t size = object_list->object_names.size();
    size_t symbols_size = symbols.size();

    symbols_by_object.resize(size);

    for (size_t i = 0; i < size; i++)
    {
        auto& list = symbols_by_object.at(i);

        for (size_t j = 0; j < symbols_size; j++)
        {
            if (symbols[j].object_index == i)
            {
                list.push_back(j);
            }
        }
    }
}

void s_symbol_map::load(const char *cvdump_log, s_object_list* objects)
{
    object_list = objects;

    load_segment_contributions(cvdump_log);
    load_public_symbols(cvdump_log);
    perform_symbol_fixups();
    populate_symbol_indices_list();
}

s_symbol* s_symbol_map::find_symbol_for_rva(uint32_t rva, uint32_t* offset)
{
    s_symbol* candidate = nullptr;

    if (offset)
    {
        size_t i = symbols.size();
        while (i > 0)
        {
            s_symbol* symbol = &symbols[i-1];

            if (rva >= symbol->rva && rva <= symbol->rva + symbol->size)
            {
                candidate = symbol;
                break;
            }

            i--;
        }

        if (candidate)
        {
            *offset = rva - candidate->rva;
        }
        else
        {
            *offset = 0;
        }
    }
    else
    {
        for (s_symbol& symbol : symbols)
        {
            if (rva == symbol.rva)
            {
                candidate = &symbol;
                break;
            }
        }
    }

    return candidate;
}
