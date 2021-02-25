/**
 * @file Decryption.ino
 * @author Gutierrez PS (https://github.com/gutierrezps)
*         Fahrizal HU (https://github.com/k2biru)
 * @brief Decryption example using PracticalCrypto library
 * @version 0.1.0
 * @date 2021-02-25
 * 
 */

#include <Arduino.h>
#include <PracticalCrypto.h>

PracticalCrypto crypto;

void setup() {
    Serial.begin(9600);
    delay(1000);

    // the key must be 64-char long and must be the same used on encryption:
    String key = "07BN(%$*Xs-`9YKjRIv=5[a&HTn3s%@@OnKFPBjh`d=]t#wH)qDOW9yWW+fZT1xL";
    crypto.setKey(key);

    // let's make sure the key was set.
    // if the key is empty, it's likely your key doesn't have the right length
    key = crypto.getKey();
    Serial.printf("\nEncryption key: %s\n", key.c_str());

    // here's a ciphertext encrypted with the example key above
    char cipherText[] = "18CB4B32D8269490C9770AD74214D5DA33BFA0B32879D59BAE2348168083BBC39F1463D4CED259F9404A0EB79FDF4EB195024D02";
    Serial.printf("Ciphertext: '%s'\n", ciphertext.c_str());

    size_t cipherLen = strlen(cipherText);
    char *buffer = reinterpret_cast<char*>(malloc(cipherLen+1));
    memcpy(buffer, cipherText, cipherLen);
    buffer[cipherLen] = '\0';
    size_t plainLen = crypto.decryptArray(buffer,cipherText);

    if (plainLen) {
        Serial.printf("Plaintext: '%s'\n", buffer);
    }
    else {
        // decryption failed if an empty string was returned

        String reason;
        switch (crypto.lastStatus()) {
            case crypto.InvalidCiphertextLength:
                reason = "invalid ciphertext length";
                break;

            case crypto.CiphertextTooLong:
                reason = "ciphertext too long";
                break;

            case crypto.InvalidHexString:
                reason = "invalid hex string";
                break;

            case crypto.HashMismatch:
                reason = "hash mismatch";
                break;

            case crypto.BufferAllocationFailed:
                reason = "buffer allocation failed";
                break;

            default:
                reason = "unknown reason (status ";
                reason += (int)crypto.lastStatus();
                reason += ")";
        }
        Serial.printf("Decryption failed (%s)\n", reason.c_str());
    }
    
    free (buffer);  // free malloc
}

void loop() {
    // ...
}
