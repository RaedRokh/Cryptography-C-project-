#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void generate_symmetric_key(unsigned char* key, int key_length) {
    EVP_CIPHER_CTX* ctx;
    int success;

    /* initialize the cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        /* handle error */
    }

    /* generate the key */
    success = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, key, key_length, 1, NULL, NULL);
    if (success != 1) {
        /* handle error */
    }

    /* clean up the context */
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    clock_t start, end;
    double elapsed_time;
    unsigned char key[32];  // allocate a buffer for the key
    int key_length = 32;    // set the key length to 256 bits

    generate_symmetric_key(key, key_length);

    // print the generated key as hexadecimal
    printf("Symmetric key: ");
    for (int i = 0; i < key_length; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    for (int buffer_size = 262144; buffer_size <= 922226384; buffer_size *= 2) {
        printf("Buffer size: %d\n", buffer_size);

        // allocate space for the plaintext, ciphertext, and decrypted buffers
        unsigned char* plaintext = malloc(buffer_size);
        unsigned char* ciphertext = malloc(buffer_size + EVP_MAX_BLOCK_LENGTH);
        unsigned char* decrypted = malloc(buffer_size);

        // generate random plaintext
        for (int i = 0; i < buffer_size; i++) {
            plaintext[i] = rand() % 256;
        }

        // initialize the cipher context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            /* handle error */
        }

        // set up the cipher parameters
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL);

        // start timer
        start = clock();

        // encrypt the message
        int ciphertext_len;
        EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, buffer_size);
        EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &ciphertext_len);

        // stop timer
        end = clock();
        elapsed_time = (double)(end - start) / CLOCKS_PER_SEC;
        printf("Encryption time: %f seconds\n", elapsed_time);

    }
}