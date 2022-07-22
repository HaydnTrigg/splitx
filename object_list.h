#pragma once

#include "types.h"

enum e_source_language
{
    k_source_language_unknown,
    k_source_language_c,
    k_source_language_cplusplus,
    k_source_language_masm,
};

struct s_object_file_name
{
    char512 file_name;
    s_object_file_name(const char* file_name_ptr);
};

struct s_object_list
{
    std::vector<s_object_file_name> object_names;

    void load(char* cvdump_log);
};
