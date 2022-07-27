#pragma once

struct s_segmented_address
{
    u16 segment;
    u64 address;

    inline s_segmented_address(u16 segment, u64 address)
        : segment(segment), address(address)
    {}
};
