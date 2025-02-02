# handrolled-AES-in-c-and-cpp
##IN DEVELOPMENT KNOWN BUGS In the C++ code, the RCON is defined up to 15 elements, which is sufficient for AES-256's 14 rounds. But the C code's RCON is insufficient.

So, to summarize, the main issues in the C code are:

1. Incorrect RCON array values and indices.

2. Missing SubWord step in key expansion for AES-256 (i % key_len == 16 when key_len=32).

3. Possibly incorrect shift_rows and inv_shift_rows for row 3, but upon closer inspection, they might be correct.

4. The key expansion loop uses i/key_len -1 to index RCON, which is incorrect because RCON starts at the wrong value.

Let's address these step by step.

First, fix the RCON array. The standard Rcon values start at Rcon[1] = 0x01, up to Rcon[10] = 0x36 for AES-128 (10 rounds). For AES-256 (14 rounds), we need Rcon up to Rcon[14], which would be 0x6c, 0xd8, etc. But the C code's RCON array is:

static const uint8_t RCON[11] = {0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

This starts with 0x8D, which is incorrect. The first Rcon value (for the first round key) should be 0x01. So the RCON array should be:

static const uint8_t RCON[11] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, ...};

Wait, the standard Rcon is Rcon[i] = x^(i-1) in GF(2^8), with x=0x02. So Rcon[1] = 0x01, Rcon[2] = 0x02, Rcon[3] = 0x04, up to Rcon[10] = 0x36 (for i=10). For AES-256 (14 rounds), we need up to Rcon[14], which would be 0x6C, 0xD8, 0xAB, 0x4D, 0x9A. So the C code's RCON array is incorrect. It should be:

static const uint8_t RCON[] = {

0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A

};

And the size should be 15 elements (for rounds up to 14). But in the C code, the key expansion uses i/key_len -1. For AES-128 (key_len=16), the first round is i=16, key_len=16 → i/key_len =1 → RCON[0] (0x01). Then for i=32, key_len=16 → i/key_len=2 → RCON[1] (0x02), etc. This is correct. So the RCON array should start at index 0 with 0x01, and have enough elements for the maximum number of rounds (14 for AES-256). So the RCON array in the C code needs to be corrected.

Next, the key expansion for AES-256. The current code only applies the S-box when i % key_len ==0. For AES-256 (key_len=32), when i=32, 64, etc., it applies the rotation and S-box. However, according to the AES spec, for Nk=8 (256-bit key), when (i % Nk) == 4, we need to apply SubWord. So in the C code's key_expansion function, after handling the i % key_len ==0 case, there should be an additional check for (key_len ==32) && (i % key_len == 16), which is equivalent to (i - key_len) % 32 ==16 → (i %32 ==16). Wait, for key_len=32, i starts at 32 and increments by 4 each loop. Wait, no: in the loop, i starts at key_len (32 for AES-256) and increments by 4 each iteration. So for AES-256, i runs from 32 to 240, stepping by 4. For each i, if i %32 ==0 → handle RotWord, SubWord, Rcon. But for AES-256, when (i-32) %32 ==16 → i%32 ==16, we need to apply SubWord. So the code should check if key_len==32 and i%32 ==16, then apply SubWord.

So in the key_expansion function:

if (i % key_len ==0) {

// rotate, sub bytes, rcon

} else if (key_len ==32 && (i % key_len) ==16) {

// apply SubWord to temp

}

But the current code doesn't have this condition, leading to incorrect key expansion for AES-256.

Additionally, the RCON index in the C code is calculated as (i/key_len -1), which for AES-128 with key_len=16, i=16 → 16/16=1 → RCON[0], which is correct if RCON starts with 0x01. So with the corrected RCON array, this calculation is correct.

Putting it all together, the fixes needed are:

1. Correct the RCON array to start with 0x01 and have enough elements.

2. Fix the key expansion to handle AES-256's additional SubWord steps.

3. Verify the shift_rows and inv_shift_rows functions (but they seem correct upon rechecking).

4. Ensure that the key expansion uses the correct RCON indices.

Other minor issues: in the C code's AES_init_ctx, after checking the key length, the code uses memset to clear the round_keys, but in C, using memset on a uint8_t array is okay. However, for security, it's better to use a secure memset that isn't optimized out, but that's beyond the current scope.

Also, in the AES_encrypt and AES_decrypt functions, the code uses memcpy to copy the plaintext/ciphertext into the state array. That's correct.

Testing the code with known test vectors would help identify issues. For example, using the AES-128 test vector from the AES specification to see if the encryption produces the correct ciphertext.

In conclusion, the main fixes are in the RCON array and the key expansion logic for AES-256. The shift_rows functions seem correct upon re-examination.
