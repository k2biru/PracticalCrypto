/**
 * @file PracticalCrypto.cpp
 * @author Gutierrez PS (https://github.com/gutierrezps)
 *         Fahhrizal HU (https://github.com/k2biru)
 * @brief Library for easy encryption and decryption of Strings in ESP8266 Arduino core.
 * @version 0.1.1
 * @date 2020-10-20
 * 
 */
#include <Arduino.h>
#include <bearssl/bearssl_block.h>
#include <bearssl/bearssl_hmac.h>

#include "PracticalCrypto.h"

#define BLK_SZ   br_aes_big_BLOCK_SIZE


bool PracticalCrypto::setKey(String key)
{
    if (key.length() != 64) {
        key_ = "";
        return false;
    }

    key_ = key;

    key_.toCharArray((char*)staticIv_, 17, 0);
    key_.toCharArray((char*)ivKey_, 17, 16);
    key_.toCharArray((char*)dataKey_, 17, 32);
    key_.toCharArray((char*)hashKey_, 17, 48);

    return true;
}


String PracticalCrypto::generateKey()
{
    String key = "";
    for (uint8_t i = 0; i < 64; ++i) {
        key += (char)(32 + secureRandom(90));
    }
    return key;
}

/**
 * Calculate size of buffer to be use for any given plaint Size
 * 
 * buffer size is calculate from following parts, where 'n' is its plainSize:
 * - [0..31]  is the encrypted initialization vector
 * - [32..(n-41)] is the encrypted plaintext
 * - [(n-40)..(n-1)] is the SHA1 hash
 * 
 * @param plainSize     size of plainText
 * @return              cipher size
 */

size_t PracticalCrypto::calculateBuffer(const size_t plainSize){
    return (BLK_SZ+br_sha1_SIZE+(plainSize/ BLK_SZ + 1)*BLK_SZ)*2;
}

/**
 * Encrypts the provided plaintext String. The following steps are done:
 * 
 * 1. Plaintext is padded to be evenly divided into blocks of BLK_SZ bytes
 *      If it's already evenly divided, a whole padding block is added,
 *      The value of the byte used to pad is the number of padding bytes needed.
 * 2. A random initialization vector (IV) is generated
 * 3. The random IV is encryted (AES128-CBC) using ivKey_ and staticIv_
 * 4. The data is encrypted (AES128-CBC) using dataKey_ and the random IV
 * 5. The hash (HMAC-SHA1) of encrypted IV + encrypted data is calculated,
 *      using hashKey_ and following the Encrypt-then-MAC approach.
 * 6. The output String (ciphertext) is formed by concatenating hex strings of
 *      encrypted IV, encrypted data and hash.
 * 
 * @param plainText     String to be encrypted
 * @return String       ciphertext
 */
const String PracticalCrypto::encrypt(String &plainText)
{
    return encrypt(plainText.c_str(), plainText.length());
}

const String PracticalCrypto::encrypt(const char*plainText, const size_t plainSize){
    size_t cipherSize = calculateBuffer(plainSize);
    char *buffer =  reinterpret_cast<char*>(malloc(cipherSize+1));
    memcpy(buffer, plainText, plainSize);
    size_t size = encryptArray(buffer,plainSize,buffer);
    String ret;
    ret.reserve(size);
    if (size !=0){
        ret = buffer;
    }
    free(buffer);
    return ret;
}

const size_t PracticalCrypto::encryptArray(const char *plainText,size_t plainSize,char* cipher)
{
    size_t size = 0;
    if (key_.length() == 0) {
        lastStatus_ = InvalidKey;
        return size;
    }

    if (plainSize > kMaxDataLength_) {
        lastStatus_ = PlaintextTooLong;
        return size;
    }

    if (!dataBuffer_ || !cipher) {
        lastStatus_ = BufferAllocationFailed;
        return size;
    }
    // Serial.printf("here1 plainSize %i %s\n",plainSize,plainText);

    uint16_t i = 0;

    // dataBuffer_ will turn into the encrypted plaintext later
    memcpy(dataBuffer_, plainText, plainSize);

    
    // number of blocks required for data is rounded up if division has decimals,
    // otherwise a full padding block is added if the division is even
    uint8_t dataBlocksQty = plainSize / BLK_SZ + 1;

    // add padding to dataBuffer_
    uint8_t dataPadding = dataBlocksQty * BLK_SZ - plainSize;
    const uint16_t paddingStart = dataBlocksQty * BLK_SZ - dataPadding;
    for (i = paddingStart; i < dataBlocksQty * BLK_SZ; ++i) {
        dataBuffer_[i] = dataPadding;
    }

    // generating a random IV of printable chars (ASCII 32-122)
    uint8_t iv[BLK_SZ] = {0};
    for (i = 0; i < BLK_SZ-1; ++i) {
        iv[i] = 32 + secureRandom(90);
    }

    // manual padding is added in order to encrypted IV be exactly BLK_SZ bytes;
    // otherwise, when decrypting in PHP a whole padding block would be expected
    iv[BLK_SZ-1] = 1;

    yield();    // reset watchdog

    // encryption context
    br_aes_big_cbcenc_keys encCtx;

    // encrypt IV
    uint8_t staticIv[BLK_SZ] = {0};
    memcpy(staticIv, staticIv_, BLK_SZ);      // copy to local, modifiable variable

    uint8_t ivCipher[BLK_SZ] = {0};
    memcpy(ivCipher, iv, BLK_SZ);

    br_aes_big_cbcenc_init(&encCtx, ivKey_, BLK_SZ);
    br_aes_big_cbcenc_run(&encCtx, staticIv, ivCipher, BLK_SZ);

    yield();    // reset watchdog

    // reset the encryption context and encrypt the data
    br_aes_big_cbcenc_init(&encCtx, dataKey_, BLK_SZ);
    br_aes_big_cbcenc_run(&encCtx, iv, dataBuffer_, dataBlocksQty * BLK_SZ);

    yield();

    // calculate hash

    // contexts
    br_hmac_key_context hashKc;
    br_hmac_context hashCtx;


    // initialize key context with the SHA1 algorithm, the given key and its length
    br_hmac_key_init(&hashKc, &br_sha1_vtable, hashKey_, BLK_SZ);


    // initialize hashing context, setting the output size
    br_hmac_init(&hashCtx, &hashKc, br_sha1_SIZE);


    // hash encrypted IV and encrypted data
    br_hmac_update(&hashCtx, ivCipher, BLK_SZ);
    br_hmac_update(&hashCtx, dataBuffer_, dataBlocksQty * BLK_SZ);


    yield();

    // get the output hash
    uint8_t hash[br_sha1_SIZE] = {0};
    br_hmac_out(&hashCtx, hash);


    size = (arrayToHexCharArray(ivCipher,BLK_SZ,cipher,size));
    size = (arrayToHexCharArray(dataBuffer_,dataBlocksQty * BLK_SZ,cipher,size));
    size = (arrayToHexCharArray(hash, br_sha1_SIZE,cipher,size));

    lastStatus_ = Ok;

    return size;
}


/**
 * Decrypts the provided ciphertext String. The following steps are done:
 * 
 * 1. Ciphertext is validated and converted to byte arrays.
 * 2. Hash of encrypted IV + encrypted data is calculated using hashKey_
 *      and compared with hash extracted from ciphertext
 * 3. IV is decrypted using ivKey_ and staticIv_
 * 4. Data is decrypted using IV and dataKey_
 * 5. Output string (plaintext) is generated from data, excluding padding bytes
 * 
 * @param ciphertext    String to be decrypted
 * @return String       plaintext data
 */
const String PracticalCrypto::decrypt(String cipherText)
{
    return decrypt(cipherText.c_str(),cipherText.length());
}

/**
 * Decrypts the provided ciphertext array. The following steps are done:
 * 
 * 1. Ciphertext is validated and converted to byte arrays.
 * 2. Hash of encrypted IV + encrypted data is calculated using hashKey_
 *      and compared with hash extracted from ciphertext
 * 3. IV is decrypted using ivKey_ and staticIv_
 * 4. Data is decrypted using IV and dataKey_
 * 5. Output string (plaintext) is generated from data, excluding padding bytes
 * 
 * @param ciphertext    encrypted const char*
 * @param size          size of ciphertext
 * @return String       plaintext, empty string if failed
 */
const String PracticalCrypto::decrypt(const char* cipherText, size_t size)
{   
    String out;
    out.reserve(size);
    char buffer[size];
    memcpy(buffer,cipherText,size);
    if(!decryptArray(buffer,size)){
        return out;
    }
    out = String(buffer);
    return out;
}

/**
 * Decrypts the provided data array ciphertext. The following steps are done:
 * 
 * 1. Ciphertext is validated and converted to byte arrays.
 * 2. Hash of encrypted IV + encrypted data is calculated using hashKey_
 *      and compared with hash extracted from ciphertext
 * 3. IV is decrypted using ivKey_ and staticIv_
 * 4. Data is decrypted using IV and dataKey_
 * 5. Output plaintext save to data if decrypts successfully, excluding padding bytes
 * 
 * @param data          buffer (array) of data ciphertext and if decrypt plaintext successfully 
 * @param cipherSize    size of cipher
 * @return size_t       return size of plaintext in data array, return 0 if failed
 */
const size_t PracticalCrypto::decryptArray(char* data, size_t cipherSize)
{   
    size_t decSize = 0;
    if (key_.length() == 0) {
        lastStatus_ = InvalidKey;
        return decSize;
    }

    if (!dataBuffer_) {
        lastStatus_ = BufferAllocationFailed;
        return decSize;
    }

    // minimum ciphertext hex string length:
    // iv + min plaintext length (padded) + sha1 output length
    const uint16_t minCiphertextLength = (16 + 16 + 20)*2;

    if (cipherSize < minCiphertextLength || cipherSize % 2 != 0) {
        lastStatus_ = InvalidCiphertextLength;
        return decSize;
    }

    // maximum ciphertext hex string length:
    // iv + max plaintext length (padded) + sha1 output length
    const uint16_t maxCiphertextLength = (16 + (kMaxDataLength_ + 16) + 20)*2;

    if (cipherSize > maxCiphertextLength) {
        lastStatus_ = CiphertextTooLong;
        return decSize;
    }

    const uint16_t ivEnd = BLK_SZ*2;
    const uint16_t hashStart = cipherSize - br_sha1_SIZE*2;


    uint16_t converted = 0;
    const uint16_t dataLength = (hashStart-ivEnd) / 2;

    uint8_t ivCipher[BLK_SZ] = {0};
    uint8_t hashCipher[br_sha1_SIZE] = {0};

    converted = hexStringToArray((char*)data,0,ivEnd, ivCipher, BLK_SZ);
    if (converted == 0) {
        // last status already set
        return decSize;
    }

    converted = hexStringToArray((char*)data,ivEnd, hashStart, dataBuffer_, dataLength);
    if (converted == 0) {
        // last status already set
        return decSize;
    }

    converted = hexStringToArray((char*)data,hashStart,cipherSize,hashCipher,br_sha1_SIZE);
    if (converted == 0) {
        // last status already set
        return decSize;
    }

    yield();

    // calculate hash

    // contexts
    br_hmac_key_context hashKc;
    br_hmac_context hashCtx;

    // initialize key context with the SHA1 algorithm, the given key and its length
    br_hmac_key_init(&hashKc, &br_sha1_vtable, hashKey_, BLK_SZ);

    // initialize hashing context, setting the output size
    br_hmac_init(&hashCtx, &hashKc, br_sha1_SIZE);

    // hash encrypted IV and encrypted data
    br_hmac_update(&hashCtx, ivCipher, BLK_SZ);
    br_hmac_update(&hashCtx, dataBuffer_, dataLength);

    yield();

    // get the hash value
    uint8_t hashExpected[br_sha1_SIZE] = {0};
    br_hmac_out(&hashCtx, hashExpected);

    if (memcmp(hashExpected, hashCipher, br_sha1_SIZE) != 0) {
        lastStatus_ = HashMismatch;
        return decSize;
    }

    // decryption context
    br_aes_big_cbcdec_keys decCtx;

    uint8_t staticIv[BLK_SZ] = {0};
    memcpy(staticIv, staticIv_, BLK_SZ);

    // decrypt IV
    br_aes_big_cbcdec_init(&decCtx, ivKey_, BLK_SZ);
    br_aes_big_cbcdec_run(&decCtx, staticIv, ivCipher, BLK_SZ);

    yield();

    // decrypt data
    br_aes_big_cbcdec_init(&decCtx, dataKey_, BLK_SZ);
    br_aes_big_cbcdec_run(&decCtx, ivCipher, dataBuffer_, dataLength);

    yield();
    
    // get number of padding bytes used
    const uint8_t dataPadding = dataBuffer_[dataLength - 1];
    
    decSize = dataLength - dataPadding;

    // insert a null char to terminate the string
    dataBuffer_[decSize] = 0;

    lastStatus_ = Ok;

    // copy paintext to data
    memcpy(data, dataBuffer_,decSize);
    // add null char to terminate the string
    data[decSize] = 0;
    
    return decSize;
}




inline int8_t hexToByte(char hex)
{
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    }
    else if (hex >= 'a' && hex <= 'f') {
        return hex - 'a' + 10;
    }
    else if (hex >= 'A' && hex <= 'F') {
        return hex - 'A' + 10;
    }
    
    return -1;
}


uint16_t PracticalCrypto::hexStringToArray(
    char * input,
    uint16_t inputStart,
    const uint16_t inputStop,
    uint8_t *output,
    const uint16_t capacity)
{
    uint8_t val = 0;
    uint16_t i = 0;
    char ch = 0;
    uint16_t bytesQty = (inputStop-inputStart) / 2;

    if (((inputStop-inputStart) % 2) != 0) {
        lastStatus_ = InvalidHexString;
        return 0;
    }

    if (bytesQty > capacity) {
        lastStatus_ = HexStringTooLong;
        return 0;
    }
    if(inputStart!=0){
        inputStart = inputStart/2;
    }
    for (i = 0; i < bytesQty; ++i) {
        val = 0;
        ch = input[inputStart*2];
        if (hexToByte(ch) < 0) {
            lastStatus_ = InvalidHexString;
            return 0;
        }
        val += hexToByte(ch);
        val *= 16;
        ch = input[(inputStart * 2) + 1];
        if (hexToByte(ch) < 0) {
            lastStatus_ = InvalidHexString;
            return 0;
        }
        val += hexToByte(ch);
        output[i] = val;
        inputStart ++;
    }
    lastStatus_ = Ok;
    return i;
}


const String PracticalCrypto::arrayToHexString(uint8_t *input, uint16_t len)
{
    String ret = "";

    for (uint16_t i = 0; i < len; ++i) {
        char ch = (input[i] >> 4) & 0x0F;
        if (ch < 10) ch += '0';
        else ch += 'A' - 10;
        ret += ch;

        ch = input[i] & 0x0F;
        if (ch < 10) ch += '0';
        else ch += 'A' - 10;
        ret += ch;
    }
    

    return ret;
}

/////

const size_t PracticalCrypto::arrayToHexCharArray(uint8_t *input, size_t len, char *output)
{
    size_t size = 0;
    for (uint16_t i = 0; i < len; ++i) {
        size = i*2;
        char ch = (input[i] >> 4) & 0x0F;
        if (ch < 10) ch += '0';
        else ch += 'A' - 10;
        output[size] = ch;

        size++;

        ch = input[i] & 0x0F;
        if (ch < 10) ch += '0';
        else ch += 'A' - 10;
        output[size] = ch;
    }
    return size;
}

const size_t PracticalCrypto::arrayToHexCharArray(uint8_t *input, size_t inputLen, char *output, size_t outputStart)
{
    size_t size = 0;
    size_t sizeOffset = outputStart;
    for (uint16_t i = 0; i < inputLen; ++i) {
        size = (i*2)+sizeOffset;
        char ch = (input[i] >> 4) & 0x0F;
        if (ch < 10) ch += '0';
        else ch += 'A' - 10;
        output[size] = ch;

        size++;

        ch = input[i] & 0x0F;
        if (ch < 10) ch += '0';
        else ch += 'A' - 10;
        output[size] = ch;

        // Serial.printf("%i in %2x -> %c%c\n",i,input[i],output[size-1],output[size]);
    }
    size++;
    output[size] = 0;
    return size;
}

#undef BLK_SZ
