#pragma once

struct s_symbol
{
    u16 object_index;
    u16 section_index;
    u64 rva;
    u32 size;
    u32 characteristics;
    char name[256];

    bool was_public = false;

    s_symbol(
        u16 object_index,
        u16 section_index,
        u64 rva,
        u32 size,
        u32 characteristics,
        const char* name_ptr);
};

class c_symbol_list final
{
private:
    const c_cvdump_reader& cvdump_reader;
    const c_pe_address_resolver& address_resolver;

    std::vector<s_symbol> symbols;

public:
    void read_symbols();

    const std::vector<s_symbol>& get_symbols() const;
    void get_symbols_by_object_id(std::vector<const s_symbol*>& symbols_out, u16 object_index) const;
    const s_symbol* get_symbol(u64 rva, u32* offset = nullptr) const;

    ~c_symbol_list();
    c_symbol_list(
        const c_cvdump_reader& cvdump_reader,
        const c_pe_address_resolver& address_resolver);
};
