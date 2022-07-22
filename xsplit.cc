#include "types.h"

#include "pe_file.h"
#include "symbol_map.h"
#include "object_list.h"
#include "threaded_disassembler.h"
#include "characteristics_lookup_gen.h"

static s_object_list object_list;
static s_symbol_map symbol_map;
static s_pe_relocation_map pe_relocation_map;
static s_threaded_disassembler threaded_disassembler(&symbol_map, &object_list, &pe_relocation_map);
static s_characteristics_lookup_generator characteristics_lookup_generator(&symbol_map);

inline char* read_cvdump(const char* cvdump_log_filename)
{
    FILE* cvdump_fp = nullptr;
    size_t cvdump_size = 0;
    char* cvdump = nullptr;

    if (!(cvdump_fp = fopen(cvdump_log_filename, "r")))
        return nullptr;

    fseek(cvdump_fp, 0, SEEK_END);
    cvdump_size = ftell(cvdump_fp);
    fseek(cvdump_fp, 0, SEEK_SET);

    if (!(cvdump = (char*)malloc(cvdump_size + 1)))
        return nullptr;

    fread(cvdump, cvdump_size, 1, cvdump_fp);
    fclose(cvdump_fp);
    cvdump[cvdump_size] = '\0';

    printf("read %zu bytes from %s...\n", cvdump_size, cvdump_log_filename);

    return cvdump;
}

int main(int argc, char* argv[])
{
    puts("xsplit " __TIMESTAMP__);

    char* cvdump = read_cvdump("cvdump.log.utf8");
    assert(cvdump);

    create_pe_context("cachebeta.exe");
    pe_relocation_map.parse_relocations();
    object_list.load(cvdump);
    symbol_map.load(cvdump, &object_list);

    threaded_disassembler.disassemble_all("./out");
    threaded_disassembler.write_extern_list("./out/externs.inc");

    characteristics_lookup_generator.dump_characteristics_lookup("./out/characteristics.inc.c");
}
