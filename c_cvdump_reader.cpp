#include "splitx_private_pch.h"

s_cvdump_public::s_cvdump_public(
    s_segmented_address address,
    u32 flags,
    const char *name_ptr)
    : address(address), flags(flags)
{
    strncpy(name, name_ptr, sizeof(name));
    name[sizeof(name)-1] = '\0';
}

s_cvdump_segment_contribution::s_cvdump_segment_contribution(
    u16 object_index,
    s_segmented_address address,
    u32 size,
    u32 characteristics)
    : object_index(object_index),
    address(address),
    size(size),
    characteristics(characteristics)
{}

s_cvdump_module::s_cvdump_module(
    const char* module_library_ptr,
    const char* module_name_ptr)
{
    strncpy(module_library, module_library_ptr, sizeof(module_library));
    module_library[sizeof(module_library)-1] = '\0';

    strncpy(module_name, module_name_ptr, sizeof(module_name));
    module_name[sizeof(module_name)-1] = '\0';
}

inline const char* skip_line(const char* string, size_t n = 1)
{
    const char* next_line = string;

    for(;;)
    {
        if (*next_line == '\n')
        {
            n--;
        }

        if (!*next_line)
        {
            return nullptr;
        }

        if (!n)
        {
            break;
        }

        next_line++;
    }

    return next_line + 1;
}

void c_cvdump_reader::read_module_names()
{
    const char* position = strstr(cvdump_text.get_data(), "*** MODULES\n");

    assert(position);
    position = skip_line(position, 2);

    while (*position != '\n')
    {
        char paths[2][256] = {};
        size_t lengths[2] = {};
        size_t num_quotes = 0;

        while (*position != '\n')
        {
            if (*position == '"')
            {
                num_quotes++;
            }
            else if (num_quotes & 1)
            {
                size_t index = num_quotes >> 1;

                paths[index][lengths[index]++] = *position;
            }

            position++;
        }

        module_names.emplace_back(s_cvdump_module(
            paths[1][0] ? paths[0] : "",
            paths[1][0] ? paths[1] : paths[0]));

        position++;
    }

    printf("%zu modules\n", module_names.size());
}

void c_cvdump_reader::read_public_names()
{
    const char* position = strstr(cvdump_text.get_data(), "S_PUB32: ");

    assert(position);

    while (*position != '\n')
    {
        char name_buffer[256] = {};

        /* S_PUB32: [0014:0022D740], Flags: 00000000,  */
        u16 segment = strtoul(position + 10, nullptr, 16) - 1;
        u64 address = strtoull(position + 15, nullptr, 16);
        u32 flags = strtoul(position + 33, nullptr, 16);

        position += 43;

        const char* next_line = skip_line(position);

        strncpy(name_buffer,position,
        std::min(static_cast<unsigned long>(next_line - position - 1), sizeof(name_buffer)));

        public_names.emplace_back(
            s_segmented_address(segment, address),
            flags,
            name_buffer);

        position = next_line;
    }

    printf("%zu public names\n", public_names.size());
}

void c_cvdump_reader::read_module_info()
{
//    const char* position = strstr(cvdump_text.get_data(), "*** SYMBOLS\n");
//    assert(position);
//
//    for(;;)
//    {
//        char line[1024];
//
//        if (!memcmp(line, "*** GLOBALS", 11))
//        {
//            break;
//        }
//
//        if (!memcmp(line, "** Module: \"", 12))
//        {
//
//        }
//
//        position = skip_line(position);
//    }

    printf("%zu module info blocks\n", module_info.size());
}

void c_cvdump_reader::read_segment_contributions()
{
    const char* position = strstr(cvdump_text.get_data(),
        "  Imod  Address        Size      Characteristics\n");

    assert(position);
    position = skip_line(position);

    while (*position != '\n')
    {
        /*  01D9  0001:00000000  00000080  60501020\n*/
        u16 object_index = strtoul(position + 2, nullptr, 16);
        u16 segment = strtoul(position + 8, nullptr, 16) - 1;
        u64 address = strtoull(position + 13, nullptr, 16);
        u32 size = strtoul(position + 23, nullptr, 16);
        u32 characteristics = strtoul(position + 33, nullptr, 16);

        segment_contributions.emplace_back(s_cvdump_segment_contribution(
            object_index,
            s_segmented_address(segment, address),
            size,
            characteristics));

        position += 42;
    }

    printf("%zu segment contributions\n", segment_contributions.size());
}

void c_cvdump_reader::read_cvdump()
{
    read_module_names();
    read_public_names();
    read_module_info();
    read_segment_contributions();
}

const std::vector<s_cvdump_module>& c_cvdump_reader::get_module_names() const
{
    return module_names;
}

const std::vector<s_cvdump_public>& c_cvdump_reader::get_public_names() const
{
    return public_names;
}

const std::vector<s_cvdump_segment_contribution>& c_cvdump_reader::get_segment_contributions() const
{
    return segment_contributions;
}

const std::vector<s_cvdump_module_info>& c_cvdump_reader::get_module_info() const
{
    return module_info;
}

c_cvdump_reader::~c_cvdump_reader()
{}

c_cvdump_reader::c_cvdump_reader(const c_buffer<char> &cvdump_text)
    : cvdump_text(cvdump_text)
{}
