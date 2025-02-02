#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

// AES block size in bytes
#define AES_BLOCK_SIZE 16

// Key sizes in bytes
#define AES_KEY_SIZE_128 16
#define AES_KEY_SIZE_192 24
#define AES_KEY_SIZE_256 32

// Maximum number of rounds and expanded key size
#define AES_MAX_ROUNDS 14
#define AES_MAX_EXPANDED_KEY_SIZE 240  // 14 rounds + 1 initial round = 15 * 16 bytes

// AES context structure
typedef struct {
    uint8_t round_keys[AES_MAX_EXPANDED_KEY_SIZE];  // Expanded key schedule
    size_t num_rounds;                              // Number of rounds (10, 12, or 14)
} AES_CTX;

// Error codes
typedef enum {
    AES_SUCCESS = 0,
    AES_INVALID_KEY_SIZE = -1,
    AES_INVALID_INPUT = -2,
    AES_NULL_POINTER = -3,
    AES_MEMORY_ERROR = -4
} AES_STATUS;

// Function prototypes
EXPORT AES_STATUS AES_init_ctx(AES_CTX *ctx, const uint8_t *key, size_t key_len);
EXPORT AES_STATUS AES_encrypt(const AES_CTX *ctx, const uint8_t *plaintext, uint8_t *ciphertext);
EXPORT AES_STATUS AES_decrypt(const AES_CTX *ctx, const uint8_t *ciphertext, uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif // AES_H