#include "aes256_sw.h"
#include <string.h>

// Standard AES S-Box table
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static uint8_t get_sbox(uint8_t val) {
    return sbox[val];
}

// AES Round Constants (Rcon)
static const uint32_t rcon[11] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

// GF(2^8) multiplication by 2
static uint8_t xtime(uint8_t b) {
    return (b & 0x80) ? ((b << 1) ^ 0x1b) : (b << 1);
}

// 32-bit Rotate Word (RotWord)
static uint32_t rot_word(uint32_t temp) {
    return (temp << 8) | (temp >> 24);
}

// 32-bit Substitute Word (SubWord)
static uint32_t sub_word(uint32_t temp) {
    return ((uint32_t)get_sbox((temp >> 24) & 0xFF) << 24) |
           ((uint32_t)get_sbox((temp >> 16) & 0xFF) << 16) |
           ((uint32_t)get_sbox((temp >> 8)  & 0xFF) << 8)  |
            (uint32_t)get_sbox(temp         & 0xFF);
}

// AES-256 Key Expansion
void aes256_sw_init(const uint8_t *key, uint32_t *round_keys) {
    int j;
    uint32_t temp;

    // Load first 8 words directly from the 256-bit key (Big Endian)
    for (j = 0; j < 8; j++) {
        round_keys[j] = ((uint32_t)key[4 * j]     << 24) |
                        ((uint32_t)key[4 * j + 1] << 16) |
                        ((uint32_t)key[4 * j + 2] << 8)  |
                         (uint32_t)key[4 * j + 3];
    }

    // Expand the remaining 52 words
    for (j = 8; j < 60; j++) {
        temp = round_keys[j - 1];
        if (j % 8 == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[j / 8];
        } else if (j % 8 == 4) {
            temp = sub_word(temp);
        }
        round_keys[j] = round_keys[j - 8] ^ temp;
    }
}

// Single block (16-byte) AES-256 encryption
void aes256_sw_encrypt_block(const uint8_t *plaintext, uint8_t *ciphertext, const uint32_t *round_keys) {
    uint8_t state[4][4];
    uint8_t temp[4][4];
    int r, c, round;

    // 1. Copy plaintext to state array (Column-major order)
    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            state[r][c] = plaintext[r + 4 * c];
        }
    }

    // 2. Initial Round (AddRoundKey with Key 0)
    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            state[r][c] ^= (round_keys[c] >> (24 - 8 * r)) & 0xFF;
        }
    }

    // 3. Rounds 1 to 13
    for (round = 1; round <= 13; round++) {
        // SubBytes
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                state[r][c] = get_sbox(state[r][c]);
            }
        }

        // ShiftRows
        // Row 0: no shift
        // Row 1: circular shift left by 1
        uint8_t t1 = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = t1;

        // Row 2: circular shift left by 2
        uint8_t t2_0 = state[2][0];
        uint8_t t2_1 = state[2][1];
        state[2][0] = state[2][2];
        state[2][1] = state[2][3];
        state[2][2] = t2_0;
        state[2][3] = t2_1;

        // Row 3: circular shift left by 3 (shift right by 1)
        uint8_t t3 = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = t3;

        // MixColumns
        for (c = 0; c < 4; c++) {
            uint8_t a = state[0][c];
            uint8_t b = state[1][c];
            uint8_t cv = state[2][c];
            uint8_t d = state[3][c];

            temp[0][c] = xtime(a) ^ (xtime(b) ^ b) ^ cv ^ d;
            temp[1][c] = a ^ xtime(b) ^ (xtime(cv) ^ cv) ^ d;
            temp[2][c] = a ^ b ^ xtime(cv) ^ (xtime(d) ^ d);
            temp[3][c] = (xtime(a) ^ a) ^ b ^ cv ^ xtime(d);
        }
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                state[r][c] = temp[r][c];
            }
        }

        // AddRoundKey
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                state[r][c] ^= (round_keys[4 * round + c] >> (24 - 8 * r)) & 0xFF;
            }
        }
    }

    // 4. Round 14 (Final round - no MixColumns)
    // SubBytes
    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            state[r][c] = get_sbox(state[r][c]);
        }
    }

    // ShiftRows
    uint8_t t1 = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = t1;

    uint8_t t2_0 = state[2][0];
    uint8_t t2_1 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = t2_0;
    state[2][3] = t2_1;

    uint8_t t3 = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = t3;

    // AddRoundKey with Key 14
    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            state[r][c] ^= (round_keys[4 * 14 + c] >> (24 - 8 * r)) & 0xFF;
        }
    }

    // 5. Copy state back to ciphertext (Column-major order)
    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            ciphertext[r + 4 * c] = state[r][c];
        }
    }
}

// AES-256 CTR encryption/decryption
void aes256_sw_ctr_crypt(const uint8_t *in, uint8_t *out, uint32_t len, const uint8_t *key, const uint8_t *iv) {
    uint32_t round_keys[60];
    uint8_t ctr_block[16];
    uint8_t keystream[16];
    uint32_t offset = 0;
    int i;

    // Initialize key expansion
    aes256_sw_init(key, round_keys);

    // Load initial counter (IV)
    memcpy(ctr_block, iv, 16);

    // Process blocks of 16 bytes
    while (offset + 16 <= len) {
        // Encrypt the counter block
        aes256_sw_encrypt_block(ctr_block, keystream, round_keys);

        // XOR plaintext with keystream
        for (i = 0; i < 16; i++) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }

        // Increment counter (128-bit big-endian)
        for (i = 15; i >= 0; i--) {
            ctr_block[i]++;
            if (ctr_block[i] != 0) {
                break;
            }
        }

        offset += 16;
    }

    // Process remaining partial block (if any)
    if (offset < len) {
        aes256_sw_encrypt_block(ctr_block, keystream, round_keys);
        for (i = 0; offset + i < len; i++) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }
    }
}
