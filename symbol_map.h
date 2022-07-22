#pragma once

#include "types.h"
#include "object_list.h"

enum e_symbol_type
{
    k_symbol_type_unknown,
    k_symbol_type_function,
    k_symbol_type_data,
    k_symbol_type_bss,
};

struct s_symbol
{
    e_symbol_type type;
    uint16_t alignment;

    uint32_t rva;
    uint32_t size;
    uint16_t object_index;
    char512 name;

    bool was_public = false;

    uint32_t raw_characteristics;

    s_symbol(e_symbol_type type, uint16_t alignment, uint32_t rva, uint32_t size, uint16_t object_index, const char* name_ptr, uint32_t raw_characteristics);
};

struct s_symbol_map
{
    s_object_list* object_list;

    std::vector<s_symbol> symbols;
    std::vector<std::vector<size_t>> symbols_by_object;

    void populate_symbol_indices_list();

    void load_segment_contributions(const char* cvdump_log);
    void load_public_symbols(const char* cvdump_log);
    void perform_symbol_fixups();

    void load(const char* cvdump_log, s_object_list* object_list);
    s_symbol* find_symbol_for_rva(uint32_t rva, uint32_t* offset = nullptr);
};
