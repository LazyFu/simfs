#include "bitmap.h"
#include "fs.h"
#include <string.h>

// Get the value of the bit at the index
int get_bitmap_bit(const uint8_t *bitmap, uint32_t index)
{
    return (bitmap[BYTE_INDEX(index)] >> BIT_OFFSET(index)) & 1;
}

// Set the bit at the index to 1
void set_bitmap_bit(uint8_t *bitmap, uint32_t index)
{
    bitmap[BYTE_INDEX(index)] |= (1 << BIT_OFFSET(index));
}

// Clear the bit at the index to 0
void clear_bitmap_bit(uint8_t *bitmap, uint32_t index)
{
    bitmap[BYTE_INDEX(index)] &= ~(1 << BIT_OFFSET(index));
}

// Allocate the first free bit and return its index, or UINT32_MAX if none are free
uint32_t allocate_bitmap_bit(uint8_t *bitmap, uint32_t total_bits)
{
    uint32_t total_bytes = BYTE_INDEX(total_bits) + 1;
    for (uint32_t bit_index = 0; bit_index < total_bytes; bit_index++)
    {
        if (bitmap[bit_index] != 0xFF)
        {
            for (uint32_t bit_offset = 0; bit_offset < 8; bit_offset++)
            {
                uint32_t global_index = (bit_index * 8) + bit_offset;
                if (global_index >= total_bits)
                {
                    return UINT32_MAX;
                }
                set_bitmap_bit(bitmap, global_index);
                return global_index;
            }
        }
    }
    return UINT32_MAX;
}