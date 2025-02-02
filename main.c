#include "aes1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>  // for _getch()
#endif

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
    fflush(stdout);  // Force output to display
}

void wait_for_key(void) {
    #ifdef _WIN32
    printf("\nPress any key to exit...");
    fflush(stdout);
    _getch();
    #endif
}

int main(void) {
    #ifdef _WIN32
    // Set console output to UTF-8
    SetConsoleOutputCP(CP_UTF8);
    #endif

    // Example key (128-bit)
    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // Example text to encrypt
    const char* text = "Hello, AES!";
    size_t text_len = strlen(text);
    size_t block_count = (text_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    size_t padded_size = block_count * AES_BLOCK_SIZE;

    // Prepare input buffer with padding
    uint8_t* input = (uint8_t*)calloc(padded_size, 1);
    uint8_t* encrypted = (uint8_t*)malloc(padded_size);
    uint8_t* decrypted = (uint8_t*)malloc(padded_size);

    if (!input || !encrypted || !decrypted) {
        printf("Memory allocation failed!\n");
        wait_for_key();
        return 1;
    }

    memcpy(input, text, text_len);

    // Initialize AES context
    AES_CTX ctx;
    AES_STATUS status = AES_init_ctx(&ctx, key, AES_KEY_SIZE_128);
    if (status != AES_SUCCESS) {
        printf("Failed to initialize AES context: %d\n", status);
        goto cleanup;
    }

    // Encrypt each block
    for (size_t i = 0; i < block_count; i++) {
        status = AES_encrypt(&ctx, &input[i * AES_BLOCK_SIZE], 
                           &encrypted[i * AES_BLOCK_SIZE]);
        if (status != AES_SUCCESS) {
            printf("Encryption failed at block %zu: %d\n", i, status);
            goto cleanup;
        }
    }

    // Decrypt each block
    for (size_t i = 0; i < block_count; i++) {
        status = AES_decrypt(&ctx, &encrypted[i * AES_BLOCK_SIZE], 
                           &decrypted[i * AES_BLOCK_SIZE]);
        if (status != AES_SUCCESS) {
            printf("Decryption failed at block %zu: %d\n", i, status);
            goto cleanup;
        }
    }

    // Print results with flushing
    printf("\n=== Test Results ===\n");
    printf("Original text: %s\n", text);
    print_hex("Key", key, AES_KEY_SIZE_128);
    print_hex("Encrypted", encrypted, padded_size);
    printf("Decrypted text: %s\n", decrypted);

    // Verify decryption
    if (memcmp(input, decrypted, padded_size) == 0) {
        printf("\nTest PASSED: Encryption/Decryption successful!\n");
    } else {
        printf("\nTest FAILED: Decryption does not match original!\n");
    }

cleanup:
    // Cleanup
    if (input) free(input);
    if (encrypted) free(encrypted);
    if (decrypted) free(decrypted);

    wait_for_key();
    return 0;
} 