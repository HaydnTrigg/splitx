#pragma once

extern "C"
{
    #include "pe_format/dir_import.h"
    #include "pe_format/dir_resources.h"
    #include "pe_format/dir_security.h"
    #include "pe_format/hdr_coff.h"
    #include "pe_format/hdr_dos.h"
    #include "pe_format/hdr_optional.h"
    #include "pe_format/sections.h"
}

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

#include <vector>

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

using s8  = int8_t;
using s16 = int16_t;
using s32 = int32_t;
using s64 = int64_t;

#include "s_segmented_address.h"
#include "c_buffer.h"
#include "c_cvdump_reader.h"
#include "c_pe_reader.h"
#include "c_symbol_list.h"
#include "c_disassembler.h"
#include "c_game_splitter.h"
