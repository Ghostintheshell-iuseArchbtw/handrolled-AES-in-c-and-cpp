#include "aes1.h"
#include <stdio.h>

int main() {
    // Test key (128-bit)
    uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // Test data
    uint8_t plaintext[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    // Initialize AES context
    AES_CTX ctx;
    AES_STATUS status = AES_init_ctx(&ctx, key, AES_KEY_SIZE_128);
    if (status != AES_SUCCESS) {
        printf("Failed to initialize AES context\n");
        return 1;
    }

    // Encrypt
    status = AES_encrypt(&ctx, plaintext, ciphertext);
    if (status != AES_SUCCESS) {
        printf("Encryption failed\n");
        return 1;
    }

    // Print encrypted data
    printf("Encrypted: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    // Decrypt
    status = AES_decrypt(&ctx, ciphertext, decrypted);
    if (status != AES_SUCCESS) {
        printf("Decryption failed\n");
        return 1;
    }

    // Verify
    int match = 1;
    for (int i = 0; i < 16; i++) {
        if (decrypted[i] != plaintext[i]) {
            match = 0;
            break;
        }
    }

    if (match) {
        printf("Test passed: Decrypted data matches original\n");
    } else {
        printf("Test failed: Decryption mismatch\n");
    }

    return 0;
}