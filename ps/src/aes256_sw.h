#ifndef AES256_SW_H
#define AES256_SW_H

#include <stdint.h>

// Initialize key expansion for AES-256. Round keys buffer must hold 60 words (240 bytes).
void aes256_sw_init(const uint8_t *key, uint32_t *round_keys);

// Encrypt a single 16-byte block of plaintext.
void aes256_sw_encrypt_block(const uint8_t *plaintext, uint8_t *ciphertext, const uint32_t *round_keys);

// Encrypt or decrypt an arbitrary buffer of data using AES-256 CTR mode.
// Handles partial blocks at the end of the buffer by XORing with the active keystream.
void aes256_sw_ctr_crypt(const uint8_t *in, uint8_t *out, uint32_t len, const uint8_t *key, const uint8_t *iv);

#endif // AES256_SW_H
