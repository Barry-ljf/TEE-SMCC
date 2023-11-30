#ifndef __BLOCK_H_
#define __BLOCK_H_
// typedef __int128_t block
#include <stdint.h>
#include <string.h>

struct block {
    __int128_t mdata;

    block() = default;
    block(const block&) = default;
    block(const __int128_t& x);
    block(uint64_t high, uint64_t low);
    block(char e15, char e14, char e13, char e12, char e11, char e10, char e9,
          char e8, char e7, char e6, char e5, char e4, char e3, char e2,
          char e1, char e0);
    block operator^(const block& rhs);
    block operator&(const block& rhs);
    block operator|(const block& rhs);

    block operator+(const block& rhs);
    block operator-(const block& rhs);

    bool operator==(const block& rhs);
    bool operator!=(const block& rhs);
};

inline block toBlock(uint64_t high_u64, uint64_t low_u64) {
    block ret(high_u64, low_u64);
    return ret;
}

inline block toBlock(uint64_t low_u64) { return toBlock(0, low_u64); }

inline block toBlock(const uint8_t* data) {
    return toBlock(((uint64_t*)data)[1], ((uint64_t*)data)[0]);
}
#endif
