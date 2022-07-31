#include "splitx_private_pch.h"
#include <tbb/tbb.h>

void c_game_splitter::split_single_object_thread(
    u16 object_index,
    const std::vector<const s_symbol*>& symbols,
    const char* output_path,
    const c_disassembler& disassembler)
{
    u32 thread_index = tbb::this_task_arena::current_thread_index();

    printf("(thread %u) %04hx: %s...\n", thread_index, object_index + 1, output_path);

    FILE* fp = fopen(output_path, "w");
    assert(fp);
    disassembler.disassemble_to_file(fp, symbols);
    fclose(fp);
}

inline char* base_name(char* path)
{
    char* p = path;
    char* c = path;

    while (*c)
    {
        if (*c == '\\' || *c == '/')
        {
            p = c + 1;
        }

        c++;
    }

    return p;
}

inline void format_output_object_name(
    const s_cvdump_module& module,
    char* object_name,
    size_t object_name_size,
    char* folder_name,
    size_t folder_name_size)
{
    char* cutting_point = nullptr;
    char* extension = nullptr;

    if (module.module_library[0] != '\0')
    {
        memcpy(folder_name, module.module_library, folder_name_size);
        cutting_point = base_name(folder_name);
        memmove(folder_name, cutting_point, object_name_size - (cutting_point - folder_name));
    }
    else
    {
        memcpy(folder_name, "game", 5);
    }

    memcpy(object_name, module.module_name, object_name_size);
    cutting_point = base_name(object_name);
    memmove(object_name, cutting_point, object_name_size - (cutting_point - object_name));

    extension = &object_name[strlen(object_name) - 4];
    if (!memcmp(extension, ".obj", 4))
    {
        memcpy(extension, ".asm", 4);
    }
    else
    {
        strcat(object_name, ".asm");
    }
}

void c_game_splitter::split_all_objects(const char* output_directory) const
{
    const std::vector<s_cvdump_module>& modules = cvdump_reader.get_module_names();
    tbb::blocked_range<size_t> thread_range(0, modules.size());

    tbb::parallel_for(thread_range,
    [&](const tbb::blocked_range<size_t> &r)
    {
        for (size_t i = r.begin(); i != r.end(); i++)
        {
            const s_cvdump_module& module = cvdump_reader.get_module_names()[i];
            std::vector<const s_symbol*> symbols;
            char object_name[256] = {};
            char folder_name[256] = {};
            char output_path[1024] = {};

            symbol_list.get_symbols_by_object_id(symbols, i);

            if (!symbols.size())
            {
                return;
            }

            format_output_object_name(
                module,
                object_name,
                sizeof(object_name) - 1,
                folder_name,
                sizeof(folder_name) - 1);

            snprintf(
                output_path,
                sizeof(output_path) - 1,
                "%s/%s/%s",
                output_directory,
                folder_name,
                object_name);

            char directory[PATH_MAX];
            strncpy(directory, output_path, PATH_MAX);
            dirname(directory);
            mkdir(directory, 0777);

            split_single_object_thread(i, symbols, output_path, disassembler);
        }
    });
}

c_game_splitter::~c_game_splitter()
{}

c_game_splitter::c_game_splitter(
    const c_disassembler& disassembler,
    const c_symbol_list& symbol_list,
    const c_cvdump_reader& cvdump_reader)
    : disassembler(disassembler),
    symbol_list(symbol_list),
    cvdump_reader(cvdump_reader)
{

}
