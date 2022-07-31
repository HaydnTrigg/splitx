#include "splitx_private_pch.h"

const u8* c_pe_reader::get_raw_data() const
{
    return pe_data.get_data();
}

const IMAGE_COFF_HEADER* c_pe_reader::get_coff_header() const
{
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe_data.get_data());
    return reinterpret_cast<IMAGE_COFF_HEADER*>(pe_data.get_data() + dos->e_lfanew + 4);
}

const void* c_pe_reader::get_optional_header(u16 header_magic) const
{
    const u8* coff = reinterpret_cast<const u8*>(get_coff_header());
    const u16* magic = reinterpret_cast<const u16*>(coff + sizeof(IMAGE_COFF_HEADER));

    if (*magic == header_magic)
    {
        return magic;
    }

    return nullptr;
}

const IMAGE_SECTION_HEADER* c_pe_reader::get_section_table(u16& num_sections) const
{
    const IMAGE_COFF_HEADER* coff = get_coff_header();
    num_sections = coff->NumberOfSections;

    const IMAGE_SECTION_HEADER* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const u8*>(coff) + sizeof(IMAGE_COFF_HEADER) + coff->SizeOfOptionalHeader);

    return sections;
}

const IMAGE_SECTION_HEADER* c_pe_reader::get_section_by_name(const char *section_name) const
{
    u16 num_sections;
    const IMAGE_SECTION_HEADER* sections = get_section_table(num_sections);

    for (u16 i = 0; i < num_sections; i++)
    {
        const IMAGE_SECTION_HEADER* section = &sections[i];

        if (!memcmp(section->Name,
            section_name,
            std::min(strnlen(section_name, sizeof(section->Name)), sizeof(section->Name))))
        {
            return section;
        }
    }

    return nullptr;
}

c_pe_reader::~c_pe_reader()
{}

c_pe_reader::c_pe_reader(const c_buffer<u8> &pe_data)
    : pe_data(pe_data)
{}

u64 c_pe_address_resolver::get_rva(const s_segmented_address &address) const
{
    u16 num_sections;
    const IMAGE_SECTION_HEADER* sections = reader.get_section_table(num_sections);

    if (address.segment < num_sections)
    {
        return optional_header->ImageBase + sections[address.segment].VirtualAddress + address.address;
    }

    return UINT64_MAX;
}

u64 c_pe_address_resolver::get_file_offset(u64 rva) const
{
    return rva - optional_header->ImageBase;
}

c_pe_address_resolver::~c_pe_address_resolver()
{}

c_pe_address_resolver::c_pe_address_resolver(const c_pe_reader& reader)
    : reader(reader)
{
    optional_header =
            reinterpret_cast<const IMAGE_OPTIONAL_HEADER_32*>(reader.get_optional_header());
    assert(optional_header);
}

void c_pe_reloc_finder::read_relocations()
{
    const s_image_base_relocation* header = reinterpret_cast<const s_image_base_relocation*>(reloc_data);

    while (header->size_of_block != 0)
    {
        if (!header->size_of_block)
        {
            break;
        }

        //printf("block vaddr %08x sizeof block %08x\n", header->virtual_address, header->size_of_block);

        for (size_t i = 0; ; i++)
        {
            const u16 *offset_ptr = reinterpret_cast<const u16*>(
                reinterpret_cast<const u8*>(header) + sizeof(s_image_base_relocation) + (i * 2));
            u16 ptr = *offset_ptr & 0x0fff;

            //printf("%p %04hx %08lx\n", offset_ptr, ptr, image_base + header->virtual_address + ptr);

            if (!ptr && i != 0)
            {
                break;
            }

            relocated_rvas.push_back(image_base + header->virtual_address + ptr);
        }

        header = reinterpret_cast<const s_image_base_relocation*>(
                reinterpret_cast<const u8*>(header) + header->size_of_block);
    }

    printf("%zu relocations\n", relocated_rvas.size());
}

void c_pe_reloc_finder::get_relocations_in_rva_range(std::vector<u64> &relocations_out, u64 rva, u32 length) const
{
    bool finding = false;

    for (u64 address : relocated_rvas)
    {
        if (address >= rva && address < rva + length)
        {
            if (!finding)
            {
                finding = true;
            }

            relocations_out.push_back(address);
        }
        else if (finding)
        {
            break;
        }
    }
}

c_pe_reloc_finder::~c_pe_reloc_finder()
{}

c_pe_reloc_finder::c_pe_reloc_finder(const c_pe_reader& reader)
{
    const IMAGE_SECTION_HEADER* reloc_section = reader.get_section_by_name(".reloc");
    assert(reloc_section);

    const IMAGE_OPTIONAL_HEADER_32* optional_header =
            reinterpret_cast<const IMAGE_OPTIONAL_HEADER_32*>(reader.get_optional_header());
    assert(optional_header);

    reloc_data = reader.get_raw_data() + reloc_section->PointerToRawData;
    image_base = optional_header->ImageBase;
}
