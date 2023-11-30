#include <array>
#include <cstring>
#include <vector>

#include "aes.h"

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define LOCATION __FILE__ ":" STRINGIZE(__LINE__)
#define RTE_LOC std::runtime_error(LOCATION)
class PRNG {
   public:
    // default construct leaves the PRNG in an invalid state.
    // SetSeed(...) must be called before get(...)
    PRNG() = default;

    // explicit constructor to initialize the PRNG with the
    // given seed and to buffer bufferSize number of AES block
    PRNG(const block &seed, uint64_t bufferSize = 256);

    // standard move constructor. The moved from PRNG is invalid
    // unless SetSeed(...) is called.
    PRNG(PRNG &&s);

    // Copy is not allowed.
    PRNG(const PRNG &) = delete;

    // standard move assignment. The moved from PRNG is invalid
    // unless SetSeed(...) is called.
    void operator=(PRNG &&);

    // Set seed from a block and set the desired buffer size.
    void SetSeed(const block &b, uint64_t bufferSize = 256);

    block get() {
        block ret;
        if (mBufferByteCapacity - mBytesIdx >= sizeof(block)) {
            memcpy(&ret, ((uint8_t *)mBuffer.data()) + mBytesIdx,
                   sizeof(block));
            mBytesIdx += sizeof(block);
        } else
            get(&ret, 1);
        return ret;
    }

    void get(block *dest, uint64_t length) {
        uint64_t lengthu8 = length * sizeof(block);
        uint8_t *destu8 = (uint8_t *)dest;
        implGet(destu8, lengthu8);
    }

    void implGet(uint8_t *datau8, uint64_t lengthu8);

    // internal buffer to store future random values.
    std::vector<block> mBuffer;

    // AES that generates the randomness by computing AES_seed({0,1,2,...})
    AES mAes;

    // Indicators denoting the current state of the buffer.
    uint64_t mBytesIdx = 0, mBlockIdx = 0, mBufferByteCapacity = 0;

    // refills the internal buffer with fresh randomness
    void refillBuffer();
};
