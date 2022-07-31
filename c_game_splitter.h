#pragma once

class c_game_splitter final
{
private:
    const c_disassembler& disassembler;
    const c_symbol_list& symbol_list;
    const c_cvdump_reader& cvdump_reader;

    static void split_single_object_thread(
        u16 object_index,
        const std::vector<const s_symbol*>& symbols,
        const char* output_path,
        const c_disassembler& disassembler);
public:
    void split_all_objects(const char* output_directory) const;

    ~c_game_splitter();
    c_game_splitter(
        const c_disassembler& disassembler,
        const c_symbol_list& symbol_list,
        const c_cvdump_reader& cvdump_reader);
};
