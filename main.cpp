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

    cvdump_reader.read_cvdump();

    c_pe_reloc_finder finder(pe_reader);
    finder.read_relocations();
    c_symbol_list symbol_list(cvdump_reader, resolver);
    symbol_list.read_symbols();
    c_disassembler disassembler(symbol_list, pe_reader, finder, resolver);
    c_game_splitter game_splitter(disassembler, symbol_list, cvdump_reader);

//    for (auto& sym : symbol_list.get_symbols())
//    {
//        const u8* raw_data = pe_reader.get_raw_data() + resolver.get_file_offset(sym.rva);
//
//        std::vector<u64> relocated_rvas;
//        finder.get_relocations_in_rva_range(relocated_rvas, sym.rva, sym.size);
//
//        for (auto reloc : relocated_rvas)
//        {
//            u64 file_offset = resolver.get_file_offset(reloc);
//            u32 reloc_destination = *(u32*)(pe_reader.get_raw_data() + file_offset);
//
//            printf("%s %08lx %08lx %08x\n", sym.name, reloc, file_offset, reloc_destination);
//        }
//    }

    game_splitter.split_all_objects(argv[3]);

    return EXIT_SUCCESS;
}
