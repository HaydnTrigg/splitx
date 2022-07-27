#pragma once

class c_pe_reader final
{
private:
    const c_buffer<u8> &pe_data;

public:
    const std::vector<u64>& get_relocation_addresses();

    const u8* get_raw_data() const;

    const IMAGE_COFF_HEADER* get_coff_header() const;
    const void* get_optional_header(u16 header_magic = MAGIC_PE32) const;

    const IMAGE_SECTION_HEADER* get_section_table(u16& num_sections) const;
    const IMAGE_SECTION_HEADER* get_section_by_name(const char* section_name) const;

    ~c_pe_reader();
    c_pe_reader(const c_buffer<u8> &pe_data);
};

class c_pe_address_resolver final
{
private:
    const c_pe_reader& reader;

public:
    u64 get_rva(const s_segmented_address& address) const;
    u64 get_file_offset(const s_segmented_address& address) const;

    ~c_pe_address_resolver();
    c_pe_address_resolver(const c_pe_reader& reader);
};

struct s_image_base_relocation
{
    u32 virtual_address;
    u32 size_of_block;
};

class c_pe_reloc_finder final
{
private:
    const u8* reloc_data;
    u64 image_base;

    std::vector<u64> relocated_rvas;

public:
    void read_relocations();

    void get_relocations_in_rva_range(std::vector<u64> &relocations_out, u64 rva, u32 length) const;

    ~c_pe_reloc_finder();
    c_pe_reloc_finder(const c_pe_reader& reader);
};
