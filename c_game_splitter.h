#pragma once

class c_game_splitter final
{
private:
    const c_disassembler& disassembler;
    const c_pe_reloc_finder& reloc_finder;
    const c_symbol_list& symbol_list;
    const c_pe_reader& pe_reader;

    void split_single_object_thread(const std::vector<s_symbol*>& symbols, const char* output_file);
public:
    void split_all_objects(const char* output_directory);

    ~c_game_splitter();
    c_game_splitter(
        const c_disassembler& disassembler,
        const c_pe_reloc_finder& reloc_finder,
        const c_symbol_list& symbol_list,
        const c_pe_reader& pe_reader);
};
