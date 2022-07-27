#include "splitx_private_pch.h"

int main(int argc, char* argv[])
{
    if (argc < 4)
    {
        fprintf(stderr, "%s usage: cvdump, exe, output directory\n", argv[0]);
        return EXIT_FAILURE;
    }

    c_buffer<char> cvdump_text = load_file_to_buffer<char>(argv[1]);
    c_buffer<u8> exe_data = load_file_to_buffer<u8>(argv[2], 'b');

    c_cvdump_reader cvdump_reader(cvdump_text);
    c_pe_reader pe_reader(exe_data);
    c_pe_address_resolver resolver(pe_reader);
    c_pe_reloc_finder finder(pe_reader);

    cvdump_reader.read_cvdump();
    finder.read_relocations();

    c_symbol_list symbol_list(cvdump_reader, resolver);
    symbol_list.read_symbols();

//    for (const auto& symbol : symbol_list.get_symbols())
//    {
//        printf("0x%08lx 0x%08x %s\n", symbol.rva, symbol.size, symbol.name);
//    }

    return EXIT_SUCCESS;
}
