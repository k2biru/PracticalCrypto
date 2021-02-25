/**
 * @file Encryption.ino
 * @author Gutierrez PS (https://github.com/gutierrezps)
 *         Fahrizal HU (https://github.com/k2biru)
 * @brief Encryption example using PracticalCrypto library
 * @version 0.1.0
 * @date 2021-02-25
 * 
 */

#include <Arduino.h>
#include <PracticalCrypto.h>

PracticalCrypto crypto;

void setup()
{
    Serial.begin(9600);

    // generates a valid key for the library
    String key = crypto.generateKey();

    // you can also set your own key, that must have 64 chars. here's an example:
    // String key = "07BN(%$*Xs-`9YKjRIv=5[a&HTn3s%@@OnKFPBjh`d=]t#wH)qDOW9yWW+fZT1xL";

    crypto.setKey(key);
    
    // let's make sure the key was set.
    // if the key is empty, it's likely your key doesn't have the right length
    key = crypto.getKey();
    Serial.printf("\nEncryption key: %s\n", key.c_str());


    char plainText[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Volutpat sed cras ornare arcu. Eget nulla facilisi etiam dignissim diam quis. Vel facilisis volutpat est velit egestas. Lacus sed turpis tincidunt id. Consequat mauris nunc congue nisi. Adipiscing tristique risus nec feugiat. Ullamcorper sit amet risus nullam eget felis eget nunc. Est pellentesque elit ullamcorper dignissim cras. Volutpat sed cras ornare arcu dui vivamus. Donec adipiscing tristique risus nec feugiat in fermentum posuere urna.\0";
    Serial.printf("Plaintext: '%s'\n", plainText);

    size_t inputLen = strlen(plainText);
    size_t cipherLen = _aesCrypto.calculateBuffer(inputLen);
    
    char *buffer = reinterpret_cast<char*>(malloc(cipherLen+1));
    memcpy(buffer, plainText, inputLen);
    buffer[cipherLen] = 0;

    cipherLen = crypto.encryptArray(buffer, cipherLen,buffer);

    if (cipherLen == 0) {
        Serial.printf("Encryption failed (status %d)\n", crypto.lastStatus());
        while (1) yield();
    }

    Serial.printf("Ciphertext: '%s'\n", buffer);

    free(buffer); // free malloc
}

void loop()
{
    // ...
}
