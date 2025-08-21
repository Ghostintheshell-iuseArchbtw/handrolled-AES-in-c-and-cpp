#include "aes.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>

AES::AES(const std::vector<uint8_t>& key) : key_(key) {
    validate_key_size(key_);
    
    // Set key size and number of rounds based on key length
    if (key.size() == static_cast<size_t>(KeySize::AES_128)) {
        key_size_ = KeySize::AES_128;
        num_rounds_ = 10;
    } else if (key.size() == static_cast<size_t>(KeySize::AES_192)) {
        key_size_ = KeySize::AES_192;
        num_rounds_ = 12;
    } else {
        key_size_ = KeySize::AES_256;
        num_rounds_ = 14;
    }

    key_expansion();
}

std::vector<uint8_t> AES::encrypt(const std::vector<uint8_t>& plaintext) {
    // Apply PKCS7 padding
    size_t padding_len = BLOCK_SIZE - (plaintext.size() % BLOCK_SIZE);
    std::vector<uint8_t> padded_text = plaintext;
    padded_text.insert(padded_text.end(), padding_len, static_cast<uint8_t>(padding_len));

    std::vector<uint8_t> ciphertext(padded_text.size());
    
    // Process each block
    for (size_t i = 0; i < padded_text.size(); i += BLOCK_SIZE) {
        std::vector<uint8_t> block(padded_text.begin() + i, 
                                 padded_text.begin() + i + BLOCK_SIZE);
        
        add_round_key(block, 0);
        
        for (size_t r = 1; r < num_rounds_; ++r) {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, r);
        }
        
        sub_bytes(block);
        shift_rows(block);
        add_round_key(block, num_rounds_);
        
        std::copy(block.begin(), block.end(), ciphertext.begin() + i);
    }

    return ciphertext;
}

std::vector<uint8_t> AES::decrypt(const std::vector<uint8_t>& ciphertext) {
    // Validate input size
    validate_block_size(ciphertext, "Ciphertext");

    std::vector<uint8_t> padded_text(ciphertext.size());
    
    // Process each block
    for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE) {
        std::vector<uint8_t> block(ciphertext.begin() + i, 
                                 ciphertext.begin() + i + BLOCK_SIZE);
        
        add_round_key(block, num_rounds_);
        
        for (size_t r = num_rounds_ - 1; r > 0; --r) {
            inv_shift_rows(block);
            inv_sub_bytes(block);
            add_round_key(block, r);
            inv_mix_columns(block);
        }
        
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, 0);
        
        std::copy(block.begin(), block.end(), padded_text.begin() + i);
    }

    // Remove and verify PKCS7 padding
    if (padded_text.empty()) {
        throw std::runtime_error("Decryption failed: empty result");
    }

    uint8_t padding_len = padded_text.back();
    if (padding_len == 0 || padding_len > BLOCK_SIZE) {
        throw std::runtime_error("Decryption failed: invalid padding length");
    }

    // Verify padding
    if (padded_text.size() < padding_len) {
        throw std::runtime_error("Decryption failed: padding length exceeds data size");
    }

    for (size_t i = 0; i < padding_len; ++i) {
        if (padded_text[padded_text.size() - 1 - i] != padding_len) {
            throw std::runtime_error("Decryption failed: invalid padding");
        }
    }

    // Remove padding
    padded_text.resize(padded_text.size() - padding_len);
    return padded_text;
}

void AES::key_expansion() {
    // Calculate expanded key size based on number of rounds
    size_t expanded_key_size = (num_rounds_ + 1) * BLOCK_SIZE;
    round_keys_.resize(expanded_key_size);
    
    // First round key is the original key
    std::copy(key_.begin(), key_.end(), round_keys_.begin());

    size_t nk = static_cast<size_t>(key_size_) / 4;
    size_t nb = 4;
    size_t nr = num_rounds_;
    size_t words = nb * (nr + 1);

    for (size_t i = nk; i < words; i++) {
        std::vector<uint8_t> temp(4);
        for (size_t j = 0; j < 4; j++) {
            temp[j] = round_keys_[(i-1) * 4 + j];
        }
        
        if (i % nk == 0) {
            // Rotate word
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubBytes
            for (uint8_t& byte : temp) {
                byte = SUB_BYTE(byte);
            }
            
            // XOR with RCON
            temp[0] ^= RCON[i/nk - 1];
        }
        else if (nk > 6 && i % nk == 4) {  // Additional SubBytes for AES-256
            for (uint8_t& byte : temp) {
                byte = SUB_BYTE(byte);
            }
        }
        
        for (size_t j = 0; j < 4; j++) {
            round_keys_[i * 4 + j] = round_keys_[(i-nk) * 4 + j] ^ temp[j];
        }
    }

}

void AES::sub_bytes(std::vector<uint8_t>& state) {
    for (auto& byte : state) {
        byte = SUB_BYTE(byte);
    }
}

void AES::inv_sub_bytes(std::vector<uint8_t>& state) {
    for (auto& byte : state) {
        byte = INV_SUB_BYTE(byte);
    }
}

void AES::shift_rows(std::vector<uint8_t>& state) {
    std::vector<uint8_t> temp = state;
    // Row 1: shift left by 1
    state[1] = temp[5];
    state[5] = temp[9];
    state[9] = temp[13];
    state[13] = temp[1];
    // Row 2: shift left by 2
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    // Row 3: shift left by 3
    state[3] = temp[15];
    state[7] = temp[3];
    state[11] = temp[7];
    state[15] = temp[11];
}

void AES::inv_shift_rows(std::vector<uint8_t>& state) {
    std::vector<uint8_t> temp = state;
    // Row 1: shift right by 1
    state[1] = temp[13];
    state[5] = temp[1];
    state[9] = temp[5];
    state[13] = temp[9];
    // Row 2: shift right by 2
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    // Row 3: shift right by 3
    state[3] = temp[7];
    state[7] = temp[11];
    state[11] = temp[15];
    state[15] = temp[3];
}

void AES::mix_columns(std::vector<uint8_t>& state) {
    for (size_t i = 0; i < 16; i += 4) {
        uint8_t s0 = state[i];
        uint8_t s1 = state[i + 1];
        uint8_t s2 = state[i + 2];
        uint8_t s3 = state[i + 3];
        
        state[i]     = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3;
        state[i + 1] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
        state[i + 2] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3);
        state[i + 3] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3);
    }
}

void AES::inv_mix_columns(std::vector<uint8_t>& state) {
    for (size_t i = 0; i < 16; i += 4) {
        uint8_t s0 = state[i];
        uint8_t s1 = state[i + 1];
        uint8_t s2 = state[i + 2];
        uint8_t s3 = state[i + 3];
        
        state[i]     = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
        state[i + 1] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
        state[i + 2] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
        state[i + 3] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
    }
}

void AES::add_round_key(std::vector<uint8_t>& state, size_t round) {
    for (size_t i = 0; i < 16; i++) {
        state[i] ^= round_keys_[round * 16 + i];
    }
}

int main() {
    // Example key (128 bits = 16 bytes)
    std::vector<uint8_t> key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // Example plaintext (can be any length)
    std::string message = "Hello, AES encryption!";
    std::vector<uint8_t> plaintext(message.begin(), message.end());

    try {
        // Create AES instance
        AES aes(key);
        
        // Encrypt
        std::vector<uint8_t> ciphertext = aes.encrypt(plaintext);
        
        // Print encrypted data in hex
        std::cout << "Encrypted (hex): ";
        for (uint8_t byte : ciphertext) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
        
        // Decrypt
        std::vector<uint8_t> decrypted = aes.decrypt(ciphertext);
        
        // Convert back to string and print
        std::string decrypted_text(decrypted.begin(), decrypted.end());
        std::cout << "Decrypted text: " << decrypted_text << std::endl;
        
        // Verify decryption matches original plaintext
        if (decrypted == plaintext) {
            std::cout << "Encryption/Decryption successful!" << std::endl;
            return 0;
        } else {
            std::cerr << "Error: Decrypted text doesn't match original!" << std::endl;
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
