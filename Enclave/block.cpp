#include "block.h"
block::block(const __int128_t& x) { mdata = x; }

block::block(uint64_t high, uint64_t low) {
    mdata = high;
    mdata <<= 64;
    mdata |= low;
}

block::block(char e15, char e14, char e13, char e12, char e11, char e10,
             char e9, char e8, char e7, char e6, char e5, char e4, char e3,
             char e2, char e1, char e0) {
    char data[16] = {e15, e14, e13, e12, e11, e10, e9, e8,
                     e7,  e6,  e5,  e4,  e3,  e2,  e1, e0};
    mdata = 0;
    for (int i = 0; i < 16; i++) {
        mdata = (mdata << 8 | data[i]);
    }
}

block block::operator^(const block& rhs) {
    block ret = *this;
    ret.mdata = (ret.mdata) ^ (rhs.mdata);

    return ret;
}

block block::operator&(const block& rhs) {
    block ret = *this;
    ret.mdata = (ret.mdata) & (rhs.mdata);

    return ret;
}

block block::operator|(const block& rhs) {
    block ret = *this;
    ret.mdata = (ret.mdata) | (rhs.mdata);

    return ret;
}

block block::operator+(const block& rhs) {
    block ret = *this;
    ret.mdata = (ret.mdata) + (rhs.mdata);
    return ret;
}

block block::operator-(const block& rhs) {
    block ret = *this;
    ret.mdata = (ret.mdata) - (rhs.mdata);

    return ret;
}

bool block::operator==(const block& rhs) { return this->mdata == rhs.mdata; }

bool block::operator!=(const block& rhs) { return *this != rhs; }
