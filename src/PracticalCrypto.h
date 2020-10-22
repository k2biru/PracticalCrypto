/**
 * @file PracticalCrypto.cpp
 * @author Gutierrez PS (https://github.com/gutierrezps)
 *         Fahhrizal HU (https://github.com/k2biru)
 * @brief Library for easy encryption and decryption of Strings in ESP8266 Arduino core.
 * @version 0.1.1
 * @date 2020-10-20
 * 
 * Library for easy encryption and decryption of Strings in ESP8266 Arduino core.
 * 
 * Based on "Practical IoT Cryptography On The Espressif ESP8266",
 * by Sean Boyce on Hackaday, published at June 20, 2017.
 * https://hackaday.com/2017/06/20/practical-iot-cryptography-on-the-espressif-esp8266/
 * 
 * Uses BearSSL library, included in ESP8266 Arduino Core:
 * - Block Cypher (AES128 used): https://bearssl.org/apidoc/bearssl__block_8h.html
 * - HMAC (SHA1 used): https://bearssl.org/apidoc/bearssl__hmac_8h.html
 * 
 */

#ifndef PracticalCrypto_h
#define PracticalCrypto_h

#include "Arduino.h"

/**
 * @brief String encryption and decryption class with hashing included.
 * 
 * Uses AES128-CBC for encryption and HMAC-SHA1 for hashing.
 * After setting a valid encryption key with setKey(), simply call encrypt()
 * or decrypt(). No additional configuration is necessary.
 * 
 */
class PracticalCrypto {
public:
    /**
     * @brief Possible status for encryption, decryption and hexStringToArray
     */
    enum Status : char {
        Ok = 0,
        InvalidKey,
        InvalidCiphertextLength,
        InvalidHexString,
        PlaintextTooLong,
        CiphertextTooLong,
        HexStringTooLong,
        HashMismatch,
        BufferAllocationFailed
    };
    
    PracticalCrypto(const uint16_t maxDataLength = 1024) : kMaxDataLength_(maxDataLength) {
        dataBuffer_ = (uint8_t*) malloc(kMaxDataLength_ + 16);
    }

    /**
     * @brief Set the encryption key. Must constain exactly 64 chars, where:
     * - [0..15]  is the static initialization vector
     * - [16..31] is the initialization vector encryption key
     * - [32..47] is the data encryption key
     * - [48..63] is the hashing key
     * 
     * If an invalid key is provided, the current key will be reset, so
     * encryption and decryption will not be possible until a valid
     * key is set.
     * 
     * @param key   String with exactly 64 chars
     * @return      true if key has the right length
     */
    bool setKey(String key);

    /**
     * @return Current encryption key
     */
    String getKey() const {
        return key_;
    }

    /**
     * @brief Generates a random key of 64 printable chars (ASCII 32-122)
     * 
     * @return key string
     */
    String generateKey();

    /**
     * @brief Encrypt the provided plaintext String using the key set, 
     * and returns the ciphertext encoded as an hex string.
     * 
     * The key must be sucessfully set before trying to encrypt.
     * 
     * An empty string is returned in case of error. Possible statuses
     * are BufferAllocationFailed, InvalidKey, PlaintextTooLong
     * or Ok if encrypted correctly.
     * 
     * Ciphertext is composed of the following parts, where 'n' is its length:
     * - [0..31]  is the encrypted initialization vector
     * - [32..(n-41)] is the encrypted plaintext
     * - [(n-40)..(n-1)] is the SHA1 hash
     * 
     * @param plainText     String to be encrypted, must be shorter than maxLength
     * @return              ciphertext, empty string if failed
     */
    const String encrypt(String &plainText);

    /**
     * @brief Encrypt the provided plaintext String using the key set, 
     * and returns the ciphertext encoded as an hex string.
     * 
     * The key must be sucessfully set before trying to encrypt.
     * 
     * An empty string is returned in case of error. Possible statuses
     * are BufferAllocationFailed, InvalidKey, PlaintextTooLong
     * or Ok if encrypted correctly.
     * 
     * Ciphertext is composed of the following parts, where 'n' is its length:
     * - [0..31]  is the encrypted initialization vector
     * - [32..(n-41)] is the encrypted plaintext
     * - [(n-40)..(n-1)] is the SHA1 hash
     * 
     * @param plainText     Array to be encrypted, must be shorter than maxLength
     * @param plainSize     size of plainText
     * @return              ciphertext, empty string if failed
     */
    const String encrypt(const char*plainText, const size_t plainSize);

    /**
     * @brief Encrypt the provided plainText Array using the key set, 
     * and returns cipher Size encoded as an hex string.
     * 
     * The key must be sucessfully set before trying to encrypt.
     * 
     * return 0 if there any error. Possible statuses
     * are BufferAllocationFailed, InvalidKey, PlaintextTooLong
     * or Ok if encrypted correctly.
     * 
     * Ciphertext is composed of the following parts, where 'n' is its length:
     * - [0..31]  is the encrypted initialization vector
     * - [32..(n-41)] is the encrypted plaintext
     * - [(n-40)..(n-1)] is the SHA1 hash
     * 
     * @param plainText     Array to be encrypted, must be shorter 
     *                      than maxLength
     * @param plainSize     size of plainText
     * @param cipher        char * to be save as cipher
     * @return              cipher size, 0 if failed
     */
    const size_t encryptArray(const char *plainText,size_t plainSize,char* cipher);

    /**
     * @brief Calculate size of buffer to be use for any given plaint Size
     * 
     * buffer size is calculate from following parts, where 'n' is its plainSize:
     * - [0..31]  is the encrypted initialization vector
     * - [32..(n-41)] is the encrypted plaintext
     * - [(n-40)..(n-1)] is the SHA1 hash
     * 
     * @param plainSize     size of plainText
     * @return              cipher size
     */
    size_t calculateBuffer(const size_t plainSize);

    /**
     * Decrypt the provided ciphertext String using the key set,
     * and returns the plaintext.
     * 
     * The key must be sucessfully set before trying to decrypt.
     * 
     * An empty string is returned in case of error. Possible statuses
     * are BufferAllocationFailed, InvalidKey, InvalidCiphertextLength,
     * InvalidHexString, HashMismatch, CiphertextTooLong, or Ok
     * if decrypted correctly.
     * 
     * Ciphertext is interpreted as an hex string composed of the following
     * parts, where 'n' is its length:
     * - [0..31]  is the encrypted initialization vector
     * - [32..(n-41)] is the encrypted plaintext
     * - [(n-40)..(n-1)] is the SHA1 hash
     * 
     * Therefore, ciphertext must have an even number of chars, be at least
     * 104 chars long, and encrypted plaintext length must be a multiple of 32,
     * since the encryption block size is 16.
     * 
     * @param ciphertext    encrypted String
     * @return String       plaintext, empty string if failed
     */
    const String decrypt(String &cipherText);

     /**
     * @brief Decrypt the provided ciphertext array using the key set,
     * and returns the plaintext String.
     * 
     * The key must be sucessfully set before trying to decrypt.
     * 
     * An empty string is returned in case of error. Possible statuses
     * are BufferAllocationFailed, InvalidKey, InvalidCiphertextLength,
     * InvalidHexString, HashMismatch, CiphertextTooLong, or Ok
     * if decrypted correctly.
     * 
     * Ciphertext is interpreted as an hex string composed of the following
     * parts, where 'n' is its length:
     * - [0..31]  is the encrypted initialization vector
     * - [32..(n-41)] is the encrypted plaintext
     * - [(n-40)..(n-1)] is the SHA1 hash
     * 
     * Therefore, ciphertext must have an even number of chars, be at least
     * 104 chars long, and encrypted plaintext length must be a multiple of 32,
     * since the encryption block size is 16.
     * 
     * @param ciphertext    encrypted const char*
     * @param size          size of ciphertext
     * @return String       plaintext, empty string if failed
     */
    const String decrypt(const char* cipherText, size_t size);
    
    /**
     * @brief Decrypt the provided data array ciphertext using the key set,
     * and returns size of plaintext.
     * 
     * The key must be sucessfully set before trying to decrypt.
     * 
     * An empty size is returned in case of error. Possible statuses
     * are BufferAllocationFailed, InvalidKey, InvalidCiphertextLength,
     * InvalidHexString, HashMismatch, CiphertextTooLong, or Ok
     * if decrypted correctly.
     * 
     * Ciphertext is interpreted as an hex string composed of the following
     * parts, where 'n' is its length:
     * - [0..31]  is the encrypted initialization vector
     * - [32..(n-41)] is the encrypted plaintext
     * - [(n-40)..(n-1)] is the SHA1 hash
     * 
     * Therefore, data array must have an even number of chars, be at least
     * 104 chars long, and encrypted plaintext length must be a multiple of 32,
     * since the encryption block size is 16.
     * 
     * @param data          buffer (array) of data ciphertext and if decrypt plaintext successfully
     * @param cipherSize    size of cipher
     * @return size_t       return size of plaintext in data array, return 0 if failed
     */
    const size_t decryptArray(char* data, size_t cipherSize);

    /**
     * @brief Get last status, set by encrypt or decrypt methods.
     * 
     * @return Status
     */
    Status lastStatus() const {
        return lastStatus_;
    }

    /**
     * @brief Converts an hex string to a byte array. In case of error,
     * 0 is returned and lastStatus() will indicate what happened.
     * 
     * Possible errors are InvalidHexString (invalid chars detected)
     * or HexStringTooLong (input larger than capacity).
     * 
     * @param  input        length must be even and must fit into capacity
     * @param  inputStart   input start index
     * @param  inputStop    input stop index
     * @param  output       output byte array
     * @param  capacity     output capacity
     * @return              number of bytes converted, 0 in case of error
     */
    uint16_t hexStringToArray(char *input, uint16_t inputStart, const uint16_t inputStop, uint8_t *output, const uint16_t capacity);

    /**
     * @brief Converts a byte array to an hex string.
     * 
     * @param  input    byte array to be converted
     * @param  len      byte array length
     * @return      hex string
     */
    const String arrayToHexString(uint8_t *input, uint16_t len);
    const size_t arrayToHexCharArray(uint8_t *input, size_t len, char *output);
    const size_t arrayToHexCharArray(uint8_t *input, size_t inputLen, char *output, size_t outputStart);


private:
    String key_ = "";
    Status lastStatus_ = Status::Ok;
    uint8_t *dataBuffer_ = nullptr;
    const uint16_t kMaxDataLength_;
    uint8_t staticIv_[17] = {0};
    uint8_t ivKey_[17] = {0};
    uint8_t dataKey_[17] = {0};
    uint8_t hashKey_[17] = {0};
};


#endif