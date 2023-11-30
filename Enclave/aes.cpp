#include "aes.h"

AES::AES(const block &userKey) { setKey(userKey); }
void AES::ecbEncCounterMode(block baseIdx, uint64_t blockLength,
                            block *ciphertext) const {
    const int32_t step = 8;
    int32_t idx = 0;
    int32_t length = int32_t(blockLength - blockLength % step);
    const auto b0 = toBlock(0, 0);
    const auto b1 = toBlock(1ull);
    const auto b2 = toBlock(2ull);
    const auto b3 = toBlock(3ull);
    const auto b4 = toBlock(4ull);
    const auto b5 = toBlock(5ull);
    const auto b6 = toBlock(6ull);
    const auto b7 = toBlock(7ull);

    block temp[step];
    for (; idx < length; idx += step) {
        temp[0] = (baseIdx + b0) ^ mRoundKey[0];
        temp[1] = (baseIdx + b1) ^ mRoundKey[0];
        temp[2] = (baseIdx + b2) ^ mRoundKey[0];
        temp[3] = (baseIdx + b3) ^ mRoundKey[0];
        temp[4] = (baseIdx + b4) ^ mRoundKey[0];
        temp[5] = (baseIdx + b5) ^ mRoundKey[0];
        temp[6] = (baseIdx + b6) ^ mRoundKey[0];
        temp[7] = (baseIdx + b7) ^ mRoundKey[0];
        baseIdx = baseIdx + toBlock(step);

        temp[0] = roundEnc(temp[0], mRoundKey[1]);
        temp[1] = roundEnc(temp[1], mRoundKey[1]);
        temp[2] = roundEnc(temp[2], mRoundKey[1]);
        temp[3] = roundEnc(temp[3], mRoundKey[1]);
        temp[4] = roundEnc(temp[4], mRoundKey[1]);
        temp[5] = roundEnc(temp[5], mRoundKey[1]);
        temp[6] = roundEnc(temp[6], mRoundKey[1]);
        temp[7] = roundEnc(temp[7], mRoundKey[1]);

        temp[0] = roundEnc(temp[0], mRoundKey[2]);
        temp[1] = roundEnc(temp[1], mRoundKey[2]);
        temp[2] = roundEnc(temp[2], mRoundKey[2]);
        temp[3] = roundEnc(temp[3], mRoundKey[2]);
        temp[4] = roundEnc(temp[4], mRoundKey[2]);
        temp[5] = roundEnc(temp[5], mRoundKey[2]);
        temp[6] = roundEnc(temp[6], mRoundKey[2]);
        temp[7] = roundEnc(temp[7], mRoundKey[2]);

        temp[0] = roundEnc(temp[0], mRoundKey[3]);
        temp[1] = roundEnc(temp[1], mRoundKey[3]);
        temp[2] = roundEnc(temp[2], mRoundKey[3]);
        temp[3] = roundEnc(temp[3], mRoundKey[3]);
        temp[4] = roundEnc(temp[4], mRoundKey[3]);
        temp[5] = roundEnc(temp[5], mRoundKey[3]);
        temp[6] = roundEnc(temp[6], mRoundKey[3]);
        temp[7] = roundEnc(temp[7], mRoundKey[3]);

        temp[0] = roundEnc(temp[0], mRoundKey[4]);
        temp[1] = roundEnc(temp[1], mRoundKey[4]);
        temp[2] = roundEnc(temp[2], mRoundKey[4]);
        temp[3] = roundEnc(temp[3], mRoundKey[4]);
        temp[4] = roundEnc(temp[4], mRoundKey[4]);
        temp[5] = roundEnc(temp[5], mRoundKey[4]);
        temp[6] = roundEnc(temp[6], mRoundKey[4]);
        temp[7] = roundEnc(temp[7], mRoundKey[4]);

        temp[0] = roundEnc(temp[0], mRoundKey[5]);
        temp[1] = roundEnc(temp[1], mRoundKey[5]);
        temp[2] = roundEnc(temp[2], mRoundKey[5]);
        temp[3] = roundEnc(temp[3], mRoundKey[5]);
        temp[4] = roundEnc(temp[4], mRoundKey[5]);
        temp[5] = roundEnc(temp[5], mRoundKey[5]);
        temp[6] = roundEnc(temp[6], mRoundKey[5]);
        temp[7] = roundEnc(temp[7], mRoundKey[5]);

        temp[0] = roundEnc(temp[0], mRoundKey[6]);
        temp[1] = roundEnc(temp[1], mRoundKey[6]);
        temp[2] = roundEnc(temp[2], mRoundKey[6]);
        temp[3] = roundEnc(temp[3], mRoundKey[6]);
        temp[4] = roundEnc(temp[4], mRoundKey[6]);
        temp[5] = roundEnc(temp[5], mRoundKey[6]);
        temp[6] = roundEnc(temp[6], mRoundKey[6]);
        temp[7] = roundEnc(temp[7], mRoundKey[6]);

        temp[0] = roundEnc(temp[0], mRoundKey[7]);
        temp[1] = roundEnc(temp[1], mRoundKey[7]);
        temp[2] = roundEnc(temp[2], mRoundKey[7]);
        temp[3] = roundEnc(temp[3], mRoundKey[7]);
        temp[4] = roundEnc(temp[4], mRoundKey[7]);
        temp[5] = roundEnc(temp[5], mRoundKey[7]);
        temp[6] = roundEnc(temp[6], mRoundKey[7]);
        temp[7] = roundEnc(temp[7], mRoundKey[7]);

        temp[0] = roundEnc(temp[0], mRoundKey[8]);
        temp[1] = roundEnc(temp[1], mRoundKey[8]);
        temp[2] = roundEnc(temp[2], mRoundKey[8]);
        temp[3] = roundEnc(temp[3], mRoundKey[8]);
        temp[4] = roundEnc(temp[4], mRoundKey[8]);
        temp[5] = roundEnc(temp[5], mRoundKey[8]);
        temp[6] = roundEnc(temp[6], mRoundKey[8]);
        temp[7] = roundEnc(temp[7], mRoundKey[8]);

        temp[0] = roundEnc(temp[0], mRoundKey[9]);
        temp[1] = roundEnc(temp[1], mRoundKey[9]);
        temp[2] = roundEnc(temp[2], mRoundKey[9]);
        temp[3] = roundEnc(temp[3], mRoundKey[9]);
        temp[4] = roundEnc(temp[4], mRoundKey[9]);
        temp[5] = roundEnc(temp[5], mRoundKey[9]);
        temp[6] = roundEnc(temp[6], mRoundKey[9]);
        temp[7] = roundEnc(temp[7], mRoundKey[9]);

        temp[0] = finalEnc(temp[0], mRoundKey[10]);
        temp[1] = finalEnc(temp[1], mRoundKey[10]);
        temp[2] = finalEnc(temp[2], mRoundKey[10]);
        temp[3] = finalEnc(temp[3], mRoundKey[10]);
        temp[4] = finalEnc(temp[4], mRoundKey[10]);
        temp[5] = finalEnc(temp[5], mRoundKey[10]);
        temp[6] = finalEnc(temp[6], mRoundKey[10]);
        temp[7] = finalEnc(temp[7], mRoundKey[10]);

        memcpy((uint8_t *)(ciphertext + idx), temp, sizeof(temp));
    }

    for (; idx < static_cast<int32_t>(blockLength); ++idx) {
        auto temp = baseIdx ^ mRoundKey[0];
        baseIdx = baseIdx + toBlock(1);
        temp = roundEnc(temp, mRoundKey[1]);
        temp = roundEnc(temp, mRoundKey[2]);
        temp = roundEnc(temp, mRoundKey[3]);
        temp = roundEnc(temp, mRoundKey[4]);
        temp = roundEnc(temp, mRoundKey[5]);
        temp = roundEnc(temp, mRoundKey[6]);
        temp = roundEnc(temp, mRoundKey[7]);
        temp = roundEnc(temp, mRoundKey[8]);
        temp = roundEnc(temp, mRoundKey[9]);
        temp = finalEnc(temp, mRoundKey[10]);

        memcpy((uint8_t *)(ciphertext + idx), &temp, sizeof(temp));
    }
}

void AES::setKey(const block &userKey) {
    // This function produces 4(4+1) round keys. The round keys are used in each
    // round to decrypt the states.
    auto RoundKey = (uint8_t *)mRoundKey.data();
    auto Key = (const uint8_t *)&userKey;

    unsigned i, j, k;
    uint8_t tempa[4];  // Used for the column/row operations

    // The first round key is the key itself.
    for (i = 0; i < 4; ++i) {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (i = 4; i < 4 * (11); ++i) {
        {
            k = (i - 1) * 4;
            tempa[0] = RoundKey[k + 0];
            tempa[1] = RoundKey[k + 1];
            tempa[2] = RoundKey[k + 2];
            tempa[3] = RoundKey[k + 3];
        }

        if (i % 4 == 0) {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()
            {
                const uint8_t uint8_ttmp = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = uint8_ttmp;
            }

            // SubWord() is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output
            // word.

            // Function Subword()
            {
                tempa[0] = getSBoxValue(tempa[0]);
                tempa[1] = getSBoxValue(tempa[1]);
                tempa[2] = getSBoxValue(tempa[2]);
                tempa[3] = getSBoxValue(tempa[3]);
            }

            tempa[0] = tempa[0] ^ Rcon[i / 4];
        }

        j = i * 4;
        k = (i - 4) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
    }
}

block AES::roundEnc(block state, const block &roundKey) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    state = state ^ roundKey;
    return state;
}

block AES::finalEnc(block state, const block &roundKey) {
    SubBytes(state);
    ShiftRows(state);
    state = state ^ roundKey;
    return state;
}
