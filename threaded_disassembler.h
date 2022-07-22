#pragma once

#include "pe_file.h"
#include "symbol_map.h"
#include "object_list.h"

#include <capstone/capstone.h>

struct s_threaded_disassembler
{
    s_symbol_map* symbol_map;
    s_object_list* object_list;
    s_pe_relocation_map* pe_relocation_map;
    csh capstone_ctx;

    void write_instuction(FILE* fp, uint16_t object_index, cs_insn* instruction, uint32_t* local_branches);
    void do_local_branch_pass(cs_insn* instructions, size_t length, size_t code_length, uint32_t* local_branches);
    void disassemble_function(FILE* fp, s_symbol* symbol, const uint8_t* code, size_t code_length);

    void disassemble_data(FILE* fp, uint32_t rva, const uint8_t* data, size_t data_length);

    void disassemble_single_file(FILE* fp, std::vector<s_symbol*>& symbols);
    void disassemble_all(const char* output_directory);

    void write_extern_list(const char* output_file);

    s_threaded_disassembler(s_symbol_map* symbol_map, s_object_list* object_list, s_pe_relocation_map* pe_relocation_map);
    ~s_threaded_disassembler();
};
