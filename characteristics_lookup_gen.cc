#include "characteristics_lookup_gen.h"

#define XXH_INLINE_ALL
#include "xxhash.h"

#include <cassert>
#include <ctime>

s_characteristics_lookup_generator::s_characteristics_lookup_generator(s_symbol_map* symbol_map)
    : symbol_map(symbol_map)
{

}

void s_characteristics_lookup_generator::dump_characteristics_lookup(const char* output_file)
{
    FILE* fp = fopen(output_file, "w");
    assert(fp);

    time_t current_time;
    time(&current_time);
    fprintf(fp,
    "// splitx @ %s\n#include <stdint.h>\n\n"
    "typedef struct s_characteristic_lookup_entry\n"
    "{\n"
    "    uint32_t hash;\n"
    "    uint32_t characteristics;\n"
    "} s_characteristic_lookup_entry;\n\n"
    "static s_characteristic_lookup_entry symbol_lookup[] =\n{\n",
    ctime(&current_time));

    for (const s_symbol& symbol : symbol_map->symbols)
    {
        fprintf(fp, "    { 0x%08x, 0x%08x }, // %s\n", XXH32(symbol.name, strlen(symbol.name), 0), symbol.raw_characteristics, symbol.name);
    }

    fputs("    { 0 }\n};\n\nstatic s_characteristic_lookup_entry section_lookup[] =\n{\n", fp);

    for (size_t i = 0; i < pe_ctx.pe.num_sections; i++)
    {
        char name[9] = {};
        memcpy(name, pe_ctx.pe.sections[i]->Name, sizeof(name) - 1);
        sanitise_name(name, '\0');
        
        fprintf(fp, "    { 0x%08x, 0x%08x }, // %s\n", XXH32(name, strlen(name), 0), pe_ctx.pe.sections[i]->Characteristics, name);
    }

    fputs("    { 0 }\n};\n", fp);

    fclose(fp);

    printf("wrote %s...\n", output_file);
}
