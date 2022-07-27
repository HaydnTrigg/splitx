cmake_minimum_required(VERSION 3.22)

project(splitx)

add_executable(splitx
        pe_format/dir_import.h
        pe_format/dir_resources.h
        pe_format/dir_security.h
        pe_format/hdr_coff.h
        pe_format/hdr_dos.h
        pe_format/hdr_optional.h
        pe_format/sections.h

        splitx_private_pch.h
        main.cpp

        c_buffer.h
        s_segmented_address.h

        c_cvdump_reader.cpp
        c_cvdump_reader.h

        c_pe_reader.cpp
        c_pe_reader.h

        c_symbol_list.cpp
        c_symbol_list.h c_game_splitter.cpp c_game_splitter.h c_disassembler.cpp c_disassembler.h)

target_precompile_headers(splitx PRIVATE splitx_private_pch.h)
