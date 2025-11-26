#include <stdint.h>

#define BYTE_INDEX(bit_index) ((bit_index) / 8)
#define BIT_OFFSET(bit_index) ((bit_index) % 8)

int get_bitmap_bit(const uint8_t *bitmap, uint32_t index);
void set_bitmap_bit(uint8_t *bitmap, uint32_t index);
void clear_bitmap_bit(uint8_t *bitmap, uint32_t index);
uint32_t allocate_bitmap_bit(uint8_t *bitmap, uint32_t total_bits);