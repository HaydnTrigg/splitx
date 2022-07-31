#pragma once

class c_disassembler final
{
private:
    const c_symbol_list& symbol_list;
    const c_pe_reloc_finder& reloc_finder;
    const c_pe_reader& pe_reader;
    const c_pe_address_resolver& pe_resolver;

    ZydisDecoder decoder;
    ZydisFormatter formatter;

    void disassemble_data(FILE* fp, const s_symbol* symbol) const;
    void disassemble_function(FILE* fp, const s_symbol* symbol) const;
public:
    void disassemble_to_file(FILE* fp, const std::vector<const s_symbol*>& symbols) const;

    ~c_disassembler();
    c_disassembler(
        const c_symbol_list& symbol_list,
        const c_pe_reader& pe_reader,
        const c_pe_reloc_finder& reloc_finder,
        const c_pe_address_resolver& pe_resolver);
};
