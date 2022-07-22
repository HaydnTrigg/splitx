#include "object_list.h"
#include "types.h"

s_object_file_name::s_object_file_name(const char* file_name_ptr)
{
    strncpy(file_name, file_name_ptr, sizeof(file_name));
}

void s_object_list::load(char *cvdump_log)
{
    static const char* header_search_string = "*** MODULES\n\n";
    char* position = strstr(cvdump_log, header_search_string);
    assert(position);
    position += strlen(header_search_string);

    while (*position != '\n')
    {
        char* quote = nullptr;
        char path_1[256] = {};
        char path_2[256] = {};
        char512 filename = {};

        // get the next line
        char* position2 = strstr(position, "\n");

        for (char* i = position + 5; i < position2; i++)
        {
            if (*i == '\"')
            {
                if (quote)
                {
                    char* src = quote + 1;
                    char* dest = nullptr;

                    if (!path_1[0])
                    {
                        dest = path_1;
                    }
                    else if (!path_2[0])
                    {
                        dest = path_2;
                    }
                    else
                    {
                        break;
                    }

                    strncpy(dest, src, i - src);

                    quote = nullptr;
                }
                else
                {
                    quote = i;
                }
            }

            if (*i == '\\')
            {
                *i = '/';
            }
        }

        if (!strcmp(path_1, "* Linker *"))
        {
            strcpy(path_1, "_linker_common");
        }

        snprintf(filename, sizeof(filename), "%s/%s", path_2[0] ? basename(path_1) : "halobetacache", path_2[0] ? basename(path_2) : basename(path_1));

        object_names.push_back(s_object_file_name(filename));
        position = position2 + 1;
    }

    printf("%zu object filenames\n", object_names.size());
}
