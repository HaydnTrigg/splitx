#include "threaded_disassembler.h"

#include <algorithm>
#include <tbb/tbb.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <libgen.h>

#include <ctime>

#define THE_GIGA_SPAM 0

#if THE_GIGA_SPAM
    #define DBG printf
    #define USE_SINGLE_THREADED_DISASSEMBLER 1
#else
    #define DBG(...)
    #define USE_SINGLE_THREADED_DISASSEMBLER 1
#endif

void s_threaded_disassembler::disassemble_data(FILE* fp, uint32_t rva, const uint8_t* data, size_t data_length)
{
    std::vector<uint32_t> relocated_rvas;
    pe_relocation_map->get_relocations_for_memory_range(rva, data_length, relocated_rvas);

    if (relocated_rvas.size())
    {
        uint32_t head = rva;

        for (uint32_t offset : relocated_rvas)
        {
            uint32_t size_difference = offset - head;
            if (size_difference)
            {
                uint32_t head_offset = rva_to_image_offset(head);
                fprintf(fp, "incbin \"%s\", %u, %u\n", exe_filename, head_offset, size_difference);
            }

            uint32_t reloc_destination = *(uint32_t*)(data + (offset - rva));

            uint32_t symbol_offset;
            s_symbol* symbol = symbol_map->find_symbol_for_rva(reloc_destination, &symbol_offset);
            assert(symbol);

            char offset_str[16] = {};
            if (symbol_offset)
                snprintf(offset_str, sizeof(offset_str), "+%u", symbol_offset);

            fprintf(fp, "dd %s%s\n", symbol->name, offset_str);

            head = offset + 4;
        }
    }
    else
    {
        uint32_t physical_offset = rva_to_image_offset(rva);
        fprintf(fp, "incbin \"%s\", %u, %zu\n", exe_filename, physical_offset, data_length);
    }
}

enum
{
    k_local_branches_container_length = 2048,

    k_local_branches_container_is_lut_flag = 0x80000000,
    k_local_branches_container_address_mask = 0x7fffffff,
};

inline uint32_t get_local_branch_number_for_address(uint32_t* local_branches, uint32_t address)
{
    for (uint32_t i = 0; i < k_local_branches_container_length; i++)
    {
        if (!local_branches[i])
        {
            break;
        }

        if ((local_branches[i] & k_local_branches_container_address_mask) == address)
        {
            return i + 1;
        }
    }

    return 0;
}

inline void disassembler_address_to_symbol(uint32_t* local_branches, s_symbol_map* symbol_map, uint16_t object_id, uint32_t value, char512 symbol_string)
{
    char offset_str[16] = {};
    s_symbol* symbol = nullptr;
    uint32_t offset = 0;

    offset = get_local_branch_number_for_address(local_branches, value);

    if (offset)
    {
        sprintf(symbol_string + strlen(symbol_string), ".L%u", offset);
        return;
    }
    
    symbol = symbol_map->find_symbol_for_rva(value, &offset);

    if (!symbol || (!symbol->was_public && symbol->object_index != object_id))
    {
        offset = 0;

        //if (value > pe_ctx.pe.imagebase + pe_ctx.pe.optional_hdr._32->SizeOfImage)
        //{
            snprintf(offset_str, sizeof(offset_str), "0x%08x", value);
        //}

        //strcat(symbol_string, "(ImageBase");
        //offset = value - pe_ctx.pe.imagebase;
    }
    else
    {
        if (offset)
        {
            symbol_string[strlen(symbol_string)] = '(';
        }

        strcat(symbol_string, symbol->name);
    }

    if (offset)
    {
        snprintf(offset_str, sizeof(offset_str), "+%u)", offset);
    }

    strcat(symbol_string, offset_str);
}

inline const char* get_size_prefix_for_op_size(unsigned int instruction_id, uint8_t size)
{
    static const char* size_table[] =
    {
        nullptr,
        "byte",
        "word",
        nullptr,
        "dword",
        nullptr,
        nullptr,
        nullptr,
        "qword",
        nullptr,
        "tword",
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        "oword",
    };

    switch(instruction_id)
    {
    case X86_INS_FNSAVE:
    case X86_INS_FRSTOR:
        return "/* 108 bytes */";
    case X86_INS_FNSTSW:
        return size_table[2];
    default:
        return size_table[size];
    }
}

inline const char* get_register_name(csh capstone_ctx, unsigned int register_index)
{
    static const char* st_name_fixup_hack[] =
    {
        "st0",
        "st1",
        "st2",
        "st3",
        "st4",
        "st5",
        "st6",
        "st7"
    };

    if (register_index >= X86_REG_ST0 && register_index <= X86_REG_ST7)
    {
        return st_name_fixup_hack[register_index - X86_REG_ST0];
    }

    return cs_reg_name(capstone_ctx, register_index);
}

void s_threaded_disassembler::write_instuction(FILE* fp, uint16_t object_index, cs_insn* instruction, uint32_t* local_branches)
{
    int op_count = instruction->detail->x86.op_count;
    char instruction_string[256] = {};

    // https://www.nasm.us/doc/nasmdoc2.html#section-2.2.3
    if (!memcmp(instruction->mnemonic, "rep movs", 8) ||
        !memcmp(instruction->mnemonic, "rep stos", 8) ||
        !memcmp(instruction->mnemonic, "insb", 4) ||
        !memcmp(instruction->mnemonic, "insd", 4) ||
        !memcmp(instruction->mnemonic, "movsb", 5) ||
        !memcmp(instruction->mnemonic, "movsd", 5) ||
        !memcmp(instruction->mnemonic, "movsw", 5) ||
        !memcmp(instruction->mnemonic, "stos", 4) ||
        !memcmp(instruction->mnemonic, "repe cmps", 9) ||
        !memcmp(instruction->mnemonic, "repne scas", 10))
    {
        fprintf(fp, "%s\n", instruction->mnemonic);
        return;
    }

    strcat(instruction_string, instruction->mnemonic);

    for (int j = 0; j < op_count; j++)
    {
        cs_x86_op* operand = &instruction->detail->x86.operands[j];
        char512 operand_string = {};

        switch (operand->type)
        {
        case X86_OP_REG:
            snprintf(operand_string, sizeof(operand_string), " %s", get_register_name(capstone_ctx, operand->reg));
            break;
        case X86_OP_IMM:
            {
                int64_t value = operand->imm;

                if (value >= pe_ctx.pe.imagebase && value < pe_ctx.pe.imagebase + pe_ctx.pe.optional_hdr._32->SizeOfImage)
                {
                    operand_string[0] = ' ';
                    disassembler_address_to_symbol(local_branches, symbol_map, object_index, (uint32_t)value, operand_string);
                }
                else if (value > 256)
                {
                    snprintf(operand_string, sizeof(operand_string), " 0x%08x", (uint32_t)value);
                }
                else
                {
                    snprintf(operand_string, sizeof(operand_string), " %ld", value);
                }
            }
            break;
        case X86_OP_MEM:
            {
                char segment_str[32] = {};
                char base_str[32] = {};
                char index_str[32] = {};
                char512 disp_str = {};

                if (operand->mem.segment != X86_REG_INVALID)
                {
                    sprintf(segment_str, "%s:", cs_reg_name(capstone_ctx, operand->mem.segment));
                }
                
                if (operand->mem.base != X86_REG_INVALID)
                {
                    strcpy(base_str, cs_reg_name(capstone_ctx, operand->mem.base));
                }

                if (operand->mem.index != X86_REG_INVALID)
                {
                    char* index_str_head = index_str;

                    if (base_str[0])
                    {
                        *index_str_head = '+';
                        index_str_head++;
                    }

                    if (operand->mem.scale != 1)
                    {
                        sprintf(index_str_head, "%d*", operand->mem.scale);
                        index_str_head += strlen(index_str_head);
                    }

                    sprintf(index_str_head, "%s", cs_reg_name(capstone_ctx, operand->mem.index));
                }

                if (operand->mem.disp != 0 || (operand->mem.disp == 0 && operand->mem.base == X86_REG_INVALID))
                {
                    bool added_on = base_str[0] || index_str[0];
                    int64_t value = operand->mem.disp;

                    if (value >= pe_ctx.pe.imagebase && value < pe_ctx.pe.imagebase + pe_ctx.pe.optional_hdr._32->SizeOfImage)
                    {
                        if (added_on)
                            disp_str[0] = '+';
                        
                        disassembler_address_to_symbol(local_branches, symbol_map, object_index, value, disp_str);
                    }
                    else if (value > 256)
                    {
                        sprintf(disp_str, added_on ? "+0x%08lx" : "0x%08lx", value);
                    }
                    else
                    {
                        sprintf(disp_str, added_on ? "%+ld" : "%ld", value);
                    }
                }

                snprintf(operand_string, sizeof(operand_string), " %s [%s%s%s%s]",
                    get_size_prefix_for_op_size(instruction->id, operand->size),
                    segment_str,
                    base_str,
                    index_str,
                    disp_str);
            }
            break;
        default:
            break;
        }

        if (j)
        {
            instruction_string[strlen(instruction_string)] = ',';
        }

        strcat(instruction_string, operand_string);
    }

    fprintf(fp, "%s\n", instruction_string);
}

inline void append_local_branch_or_die(uint32_t* local_branches, uint32_t branch)
{
    for (size_t i = 0; i < k_local_branches_container_length; i++)
    {
        if (!local_branches[i])
        {
            local_branches[i] = branch;
            return;
        }
        else if (local_branches[i] == branch)
        {
            return;
        }
    }

    __builtin_trap();
}

// yuck
void s_threaded_disassembler::do_local_branch_pass(cs_insn* instructions, size_t length, size_t code_length, uint32_t* local_branches)
{
    uint32_t function_base_address = instructions[0].address;
    uint32_t num_local_branches = 0;
    bool found_switchcase = false;

    // pass 1: memory access
    for (size_t i = 0; i < length; i++)
    {
        cs_insn* instruction = &instructions[i];
        int op_count = instruction->detail->x86.op_count;

        for (int j = 0; j < op_count; j++)
        {
            cs_x86_op* operand = &instruction->detail->x86.operands[j];

            if (operand->access & CS_AC_WRITE)
            {
                continue;
            }

            int32_t value = (operand->type == X86_OP_MEM) ? operand->mem.disp : operand->imm;

            if (value >= function_base_address && value < function_base_address + code_length)
            {
                if (operand->type == X86_OP_MEM && found_switchcase)
                {
                    // find previous switch case value and update address
                    for (uint32_t k = num_local_branches; ; k--)
                    {
                        if (local_branches[k] & k_local_branches_container_is_lut_flag
                            && (local_branches[k] ^ k_local_branches_container_is_lut_flag) > value)
                        {
                            local_branches[k] = value | k_local_branches_container_is_lut_flag;
                            DBG("updated switch case tgt %08x, %s @ %08lx\n", value, instruction->mnemonic, instruction->address);
                        }

                        if (k == 0) break;
                    }
                }
                else
                {
                    append_local_branch_or_die(local_branches, (operand->type == X86_OP_MEM) ? value | k_local_branches_container_is_lut_flag : value);
                    num_local_branches++;

                    DBG("identified local branch %u @ %08x, %s @ %08lx", num_local_branches, value, instruction->mnemonic, instruction->address);

                    if (operand->type == X86_OP_MEM)
                    {
                        DBG(" (switch case)");
                        found_switchcase = true;
                    }

                    DBG("\n");
                }
                
            }
        }
    }

    // pass 2: switch cases
    for (uint32_t i = 0, branch = 0; local_branches[i] != 0; i++, branch = local_branches[i])
    {
        if (!(branch & k_local_branches_container_is_lut_flag))
        {
            continue;
        }

        uint32_t real_branch_value = branch ^ k_local_branches_container_is_lut_flag;
        uint32_t switchcase_table_size = code_length - (real_branch_value - function_base_address);
        uint32_t offset = real_branch_value;

        DBG("switch case %u @ %08x, switch case table size %08x\n", i + 1, real_branch_value, switchcase_table_size);

        while (offset + 4 <= real_branch_value + switchcase_table_size)
        {
            const uint8_t* image_base = (uint8_t*)pe_ctx.pe.dos_hdr;
            uint32_t switchcase_target = *(const uint32_t*)(image_base + rva_to_image_offset(offset));
            
            DBG("offset %08x tgt %08x\n", offset, switchcase_target);

            if (switchcase_target >= function_base_address && switchcase_target < function_base_address + code_length)
            {
                DBG("branch\n");
                append_local_branch_or_die(local_branches, switchcase_target);
                offset += 4;
            }
            else
            {
                DBG("byte\n");
                offset++;
            }
        }
    }
}

void s_threaded_disassembler::disassemble_function(FILE* fp, s_symbol* symbol, const uint8_t* code, size_t code_length)
{
    uint32_t local_branches[k_local_branches_container_length] = {};
    cs_insn *insns;
    size_t count;

    DBG("\ndisassembling %08x-%08lx, size %zu...\n", symbol->rva, symbol->rva + code_length, code_length);

    count = cs_disasm(capstone_ctx, code, code_length, symbol->rva, 0, &insns);
    assert(count);

    do_local_branch_pass(insns, count, code_length, local_branches);

    uint32_t switch_table_rva = 0;
    for (size_t i = 0; i < k_local_branches_container_length; i++)
    {
        if (!local_branches[i])
        {
            break;
        }
        else if (local_branches[i] & k_local_branches_container_is_lut_flag)
        {
            switch_table_rva = local_branches[i] & k_local_branches_container_address_mask;
            break;
        }
    }

    for (size_t i = 0; i < count; i++)
    {
        cs_insn* insn = &insns[i];
        uint32_t local_branch = get_local_branch_number_for_address(local_branches, insn->address);

        if (switch_table_rva && switch_table_rva <= insn->address)
        {
            goto process_switch_table;
        }

        if (local_branch)
        {
            uint32_t branch_location = local_branches[local_branch - 1];

            DBG("instruction %zu: gone to local branch %u @ %08lx\n", i, local_branch, insn->address);

            fprintf(fp, ".L%u:\n", local_branch);
        }

        DBG("INSN %zu 0x%08lx\n", i, insn->address);
        //DBG("/* Live Capstone Reaction %s */\n", insn->op_str);

        fprintf(fp, "/* %08lx */ ", insn->address);
        write_instuction(fp, symbol->object_index, insn, local_branches);
    }

    if (switch_table_rva)
    {
process_switch_table:
        fputs("/* switch case table(s) and/or lookup table(s) */\n", fp);
                
        uint32_t offset = switch_table_rva;
        uint32_t end = symbol->rva + code_length;
        
        DBG("processing switch table, offset %08x, end %08x\n", offset, end);

        while (offset < end)
        {
            const uint8_t* image_base = (uint8_t*)pe_ctx.pe.dos_hdr;
            uint32_t switchcase_target = *(const uint32_t*)(image_base + rva_to_image_offset(offset));
            uint32_t branch_num = get_local_branch_number_for_address(local_branches, switchcase_target);

            uint32_t my_branch = get_local_branch_number_for_address(local_branches, offset);
            if (my_branch)
            {
                fprintf(fp, ".L%u:\n", my_branch);
                DBG(".L%u:\n", my_branch);
            }

            DBG("offset %08x ", offset);
            fprintf(fp, "/* %08x */ ", offset);

            if (!branch_num)
            {
                fprintf(fp, "db 0x%02x\n", switchcase_target & 0xff);
                DBG("db 0x%02x\n", switchcase_target & 0xff);
                offset++;
            }
            else if (offset + 4 <= end)
            {
                fprintf(fp, "dd .L%u\n", branch_num);
                DBG("dd .L%u\n", branch_num);
                offset += 4;
            }
        }
    }
}

inline size_t cut_padding_from_function_size(const uint8_t* code, size_t code_length)
{
    size_t size_to_cut = 0;

    for (size_t i = code_length - 1; i >= 0; i--)
    {
        if (code[i] == 0x90)
        {
            size_to_cut++;
        }
        else
        {
            break;
        }
    }

    return code_length - size_to_cut;
}

inline void do_common_declarations(FILE* fp, s_symbol* symbol, uint8_t padding_pattern)
{
    if (symbol->alignment)
    {
        fprintf(fp, "align %u, db %u\n", symbol->alignment, padding_pattern);
    }
    
    if (symbol->was_public)
    {
        fprintf(fp, "global %s\n", symbol->name);
    }

    fprintf(fp, "%s:\n", symbol->name);
}

void s_threaded_disassembler::disassemble_single_file(FILE* fp, std::vector<s_symbol*>& symbols)
{
    const uint8_t* image_base = (uint8_t*)pe_ctx.pe.dos_hdr;
    const char* previous_section_name = nullptr;
    time_t current_time;

    time(&current_time);
    fprintf(fp, "// splitx @ %s// %zu symbol(s)\n\ncpu p3\n%%define _OBJECT_ID %u\n%%include \"externs.inc\"\n", ctime(&current_time), symbols.size(), symbols[0]->object_index);

    for (s_symbol* symbol : symbols)
    {
        const IMAGE_SECTION_HEADER* section = get_section_of_rva(symbol->rva);
        assert(section);

        const char* section_name = symbol->type == k_symbol_type_bss ? ".bss" : (const char*)section->Name;

        if (previous_section_name != section_name)
        {
            char segment_buffer[9] = {};
            memcpy(segment_buffer, section_name, std::min(sizeof(segment_buffer) -1, strlen(section_name)));
            sanitise_name(segment_buffer, '\0');
            fprintf(fp, "\nsection %s\n", segment_buffer);
        }

        fprintf(fp, "\n/* %08x %s(%u) */\n", symbol->rva, symbol->name, symbol->size);

        const uint8_t* raw_data = image_base + rva_to_image_offset(symbol->rva);

        switch (symbol->type)
        {
        case k_symbol_type_function:
            {
                size_t function_size = cut_padding_from_function_size(raw_data, symbol->size);
                
                do_common_declarations(fp, symbol, 0x90);
                disassemble_function(fp, symbol, raw_data, cut_padding_from_function_size(raw_data, symbol->size));
            }
            break;
        case k_symbol_type_data:
            {
                do_common_declarations(fp, symbol, 0x0);
                disassemble_data(fp, symbol->rva, raw_data, symbol->size);
            }
            break;
        case k_symbol_type_bss:
            {
                if (symbol->alignment)
                {
                    fprintf(fp, "align %u, resb 1\n", symbol->alignment);
                }

                // bss_0071df40
                //if (symbol->was_public)
                //{
                    fprintf(fp, "global %s\n", symbol->name);
                //}

                fprintf(fp, "%s:\nresb %u\n", symbol->name, symbol->size);
            }
            break;
        default:
            fprintf(stderr, "warning: invalid symbol type %u\n", symbol->type);
            break;
        }

        previous_section_name = section_name;
    }
}

void s_threaded_disassembler::disassemble_all(const char* output_directory)
{
    #if USE_SINGLE_THREADED_DISASSEMBLER
    size_t size = symbol_map->symbols_by_object.size();
    for (size_t i = 0; i < size; i++)
    #else
    tbb::parallel_for(size_t(0), symbol_map->symbols_by_object.size(),
    [&](size_t i)
    #endif
    {
        auto& list = symbol_map->symbols_by_object.at(i);

        if (!list.size())
        {
            #if USE_SINGLE_THREADED_DISASSEMBLER
            continue;
            #else
            return;
            #endif
        }

        char filename[PATH_MAX] = {};

        printf("%s...\n", object_list->object_names[i].file_name);
        snprintf(filename, PATH_MAX, "%s/%s", output_directory, object_list->object_names[i].file_name);

        char* dot_obj = strstr(filename, ".obj");
        strcpy(dot_obj ? dot_obj : &filename[0] + strlen(filename), ".asm");

        char directory[PATH_MAX] = {};
        memcpy(directory, filename, PATH_MAX);
        mkdir(dirname(directory), 0777);

        std::vector<s_symbol*> symbols;
        for (size_t& indice : list)
        {
            symbols.push_back(&symbol_map->symbols[indice]);
        }

        FILE* fp = fopen(filename, "w");
        assert(fp);
        disassemble_single_file(fp, symbols);
        fclose(fp);
    }
    #if USE_SINGLE_THREADED_DISASSEMBLER
    #else
    );
    #endif
}

void s_threaded_disassembler::write_extern_list(const char* output_file)
{
    FILE* fp = fopen(output_file, "w");
    assert(fp);

    time_t current_time;
    time(&current_time);
    fprintf(fp, "; splitx @ %s\n", ctime(&current_time));

    size_t size = symbol_map->symbols_by_object.size();
    for (size_t i = 0; i < size; i++)
    {
        auto& list = symbol_map->symbols_by_object.at(i);

        if (!list.size())
        {
            continue;
        }

        fprintf(fp, "\n%%if _OBJECT_ID != %zu\n", i);

        for (uint32_t index : list)
        {
            s_symbol* symbol = &symbol_map->symbols[index];
            fprintf(fp, "    ; %08x-%08x, %u bytes\n    extern %s\n", symbol->rva, symbol->rva + symbol->size, symbol->size, symbol->name);
        }

        fputs("%endif\n", fp);
    }  

    fclose(fp);

    printf("wrote %s...\n", output_file);
}

s_threaded_disassembler::s_threaded_disassembler(s_symbol_map* symbol_map, s_object_list* object_list, s_pe_relocation_map* pe_relocation_map)
    : symbol_map(symbol_map), object_list(object_list), pe_relocation_map(pe_relocation_map)
{
    assert(cs_open(CS_ARCH_X86, CS_MODE_32, &capstone_ctx) == CS_ERR_OK);
    assert(cs_option(capstone_ctx, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
}

s_threaded_disassembler::~s_threaded_disassembler()
{
    cs_close(&capstone_ctx);
}
