#pragma once

#include "pe_file.h"
#include "symbol_map.h"

struct s_characteristics_lookup_generator
{
    s_symbol_map* symbol_map;

    void dump_characteristics_lookup(const char* output_file);

    s_characteristics_lookup_generator(s_symbol_map* symbol_map);
};
