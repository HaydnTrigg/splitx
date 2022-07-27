#pragma once

struct s_cvdump_public
{
    s_segmented_address address;
    u32 flags;
    char name[256];

    s_cvdump_public(
        s_segmented_address address,
        u32 flags,
        const char* name_ptr);
};

struct s_cvdump_segment_contribution
{
    u16 object_index;
    s_segmented_address address;
    u32 size;
    u32 characteristics;

    s_cvdump_segment_contribution(
        u16 object_index,
        s_segmented_address address,
        u32 size,
        u32 characteristics);
};

struct s_cvdump_module
{
    char module_library[256];
    char module_name[256];

    s_cvdump_module(
        const char* module_library_ptr,
        const char* module_name_ptr);
};

enum e_module_compiler_language
{
    k_module_compiler_language_unknown,
    k_module_compiler_language_c,
    k_module_compiler_language_cpp,
    k_module_compiler_language_masm,

    k_module_compiler_language_count
};

struct s_cvdump_module_info
{
    e_module_compiler_language compiler_language;

};

class c_cvdump_reader final
{
private:
    const c_buffer<char> &cvdump_text;

    std::vector<s_cvdump_public> public_names;
    std::vector<s_cvdump_segment_contribution> segment_contributions;
    std::vector<s_cvdump_module> module_names;
    std::vector<s_cvdump_module_info> module_info;

    void read_module_names();
    void read_public_names();
    void read_module_info();
    void read_segment_contributions();

public:
    void read_cvdump();

    const std::vector<s_cvdump_module>& get_module_names() const;
    const std::vector<s_cvdump_public>& get_public_names() const;
    const std::vector<s_cvdump_module_info>& get_module_info() const;
    const std::vector<s_cvdump_segment_contribution>& get_segment_contributions() const;

    ~c_cvdump_reader();
    c_cvdump_reader(const c_buffer<char> &cvdump_text);
};
