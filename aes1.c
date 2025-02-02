#include "aes1.h"
#include <string.h>  // for memcpy, memset
#include <stdlib.h>  // for NULL

// BTW I DID IT BECAUSE THEY SAID I WOULDNT!!!!

// S-box and inverse S-box
static const uint8_t SBOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// Round constants
static const uint8_t RCON[11] = {
    0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// Helper function prototypes
static void sub_bytes(uint8_t *state);
static void inv_sub_bytes(uint8_t *state);
static void shift_rows(uint8_t *state);
static void inv_shift_rows(uint8_t *state);
static void mix_columns(uint8_t *state);
static void inv_mix_columns(uint8_t *state);
static void add_round_key(uint8_t *state, const uint8_t *round_key);
static void key_expansion(const uint8_t *key, uint8_t *round_keys, size_t key_len);
static uint8_t gmul(uint8_t a, uint8_t b);

// Helper functions
static void sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = SBOX[state[i]];
    }
}

static void inv_sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = INV_SBOX[state[i]];
    }
}

static void shift_rows(uint8_t *state) {
    uint8_t temp;

    // Row 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 3
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

static void inv_shift_rows(uint8_t *state) {
    uint8_t temp;

    // Row 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // Row 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 3
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// Galois Field multiplication
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t carry = a & 0x80;
        a <<= 1;
        if (carry) a ^= 0x1B; // XOR with irreducible polynomial x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

static void mix_columns(uint8_t *state) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[0] = state[i * 4 + 0];
        temp[1] = state[i * 4 + 1];
        temp[2] = state[i * 4 + 2];
        temp[3] = state[i * 4 + 3];

        state[i * 4 + 0] = gmul(temp[0], 2) ^ gmul(temp[1], 3) ^ temp[2] ^ temp[3];
        state[i * 4 + 1] = temp[0] ^ gmul(temp[1], 2) ^ gmul(temp[2], 3) ^ temp[3];
        state[i * 4 + 2] = temp[0] ^ temp[1] ^ gmul(temp[2], 2) ^ gmul(temp[3], 3);
        state[i * 4 + 3] = gmul(temp[0], 3) ^ temp[1] ^ temp[2] ^ gmul(temp[3], 2);
    }
}

static void inv_mix_columns(uint8_t *state) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[0] = state[i * 4 + 0];
        temp[1] = state[i * 4 + 1];
        temp[2] = state[i * 4 + 2];
        temp[3] = state[i * 4 + 3];

        state[i * 4 + 0] = gmul(temp[0], 0x0E) ^ gmul(temp[1], 0x0B) ^ gmul(temp[2], 0x0D) ^ gmul(temp[3], 0x09);
        state[i * 4 + 1] = gmul(temp[0], 0x09) ^ gmul(temp[1], 0x0E) ^ gmul(temp[2], 0x0B) ^ gmul(temp[3], 0x0D);
        state[i * 4 + 2] = gmul(temp[0], 0x0D) ^ gmul(temp[1], 0x09) ^ gmul(temp[2], 0x0E) ^ gmul(temp[3], 0x0B);
        state[i * 4 + 3] = gmul(temp[0], 0x0B) ^ gmul(temp[1], 0x0D) ^ gmul(temp[2], 0x09) ^ gmul(temp[3], 0x0E);
    }
}

// Key expansion
static void key_expansion(const uint8_t *key, uint8_t *round_keys, size_t key_len) {
    uint8_t temp[4];
    int i;

    // The first round key is the key itself.
    for (i = 0; i < key_len; i++) {
        round_keys[i] = key[i];
    }

    // All other round keys are found from the previous round keys.
    for (i = key_len; i < 240; i += 4) {
        temp[0] = round_keys[i - 4];
        temp[1] = round_keys[i - 3];
        temp[2] = round_keys[i - 2];
        temp[3] = round_keys[i - 1];

        if (i % key_len == 0) {
            // Rotate the 4 bytes in a word to the left once.
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // Apply the S-box to each of the four bytes.
            temp[0] = SBOX[temp[0]];
            temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]];
            temp[3] = SBOX[temp[3]];

            // XOR with the round constant.
            temp[0] ^= RCON[i / key_len - 1];
        }

        round_keys[i] = round_keys[i - key_len] ^ temp[0];
        round_keys[i + 1] = round_keys[i - key_len + 1] ^ temp[1];
        round_keys[i + 2] = round_keys[i - key_len + 2] ^ temp[2];
        round_keys[i + 3] = round_keys[i - key_len + 3] ^ temp[3];
    }
}

// Add round key
static void add_round_key(uint8_t *state, const uint8_t *round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

EXPORT AES_STATUS AES_init_ctx(AES_CTX *ctx, const uint8_t *key, size_t key_len) {
    if (!ctx || !key) {
        return AES_NULL_POINTER;
    }

    // Validate key size
    switch (key_len) {
        case AES_KEY_SIZE_128:
            ctx->num_rounds = 10;
            break;
        case AES_KEY_SIZE_192:
            ctx->num_rounds = 12;
            break;
        case AES_KEY_SIZE_256:
            ctx->num_rounds = 14;
            break;
        default:
            return AES_INVALID_KEY_SIZE;
    }

    // Clear context memory first
    memset(ctx->round_keys, 0, sizeof(ctx->round_keys));
    
    // Perform key expansion
    key_expansion(key, ctx->round_keys, key_len);
    return AES_SUCCESS;
}

EXPORT AES_STATUS AES_encrypt(const AES_CTX *ctx, const uint8_t *plaintext, uint8_t *ciphertext) {
    if (!ctx || !plaintext || !ciphertext) {
        return AES_NULL_POINTER;
    }

    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, plaintext, AES_BLOCK_SIZE);

    // Initial round key addition
    add_round_key(state, ctx->round_keys);

    // Main rounds
    for (size_t round = 1; round < ctx->num_rounds; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ctx->round_keys[round * AES_BLOCK_SIZE]);
    }

    // Final round (no mix columns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ctx->round_keys[ctx->num_rounds * AES_BLOCK_SIZE]);

    memcpy(ciphertext, state, AES_BLOCK_SIZE);
    return AES_SUCCESS;
}

EXPORT AES_STATUS AES_decrypt(const AES_CTX *ctx, const uint8_t *ciphertext, uint8_t *plaintext) {
    if (!ctx || !ciphertext || !plaintext) {
        return AES_NULL_POINTER;
    }

    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, ciphertext, AES_BLOCK_SIZE);

    // Initial round
    add_round_key(state, &ctx->round_keys[ctx->num_rounds * AES_BLOCK_SIZE]);

    // Main rounds
    for (size_t round = ctx->num_rounds - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &ctx->round_keys[round * AES_BLOCK_SIZE]);
        inv_mix_columns(state);
    }

    // Final round (no inverse mix columns)
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, ctx->round_keys);

    memcpy(plaintext, state, AES_BLOCK_SIZE);
    return AES_SUCCESS;
}