#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>

void generate_ecdsa_signature(const unsigned char* msg, size_t msg_len, const BIGNUM* priv_key, ECDSA_SIG** sig)
{
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL) {
        printf("Error: Failed to create EC key object.\n");
        return;
    }

    if (!EC_KEY_set_private_key(eckey, priv_key)) {
        printf("Error: Failed to set private key.\n");
        EC_KEY_free(eckey);
        return;
    }

    unsigned int sig_len = ECDSA_size(eckey);
    *sig = ECDSA_do_sign(msg, msg_len, eckey);
    if (*sig == NULL) {
        printf("Error: Failed to generate ECDSA signature.\n");
        EC_KEY_free(eckey);
        return;
    }

    EC_KEY_free(eckey);
}

int verify_ecdsa_signature(const unsigned char* msg, size_t msg_len, const EC_POINT* pub_key, const ECDSA_SIG* sig)
{
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL) {
        printf("Error: Failed to create EC key object.\n");
        return 0;
    }

    if (!EC_KEY_set_public_key(eckey, pub_key)) {
        printf("Error: Failed to set public key.\n");
        EC_KEY_free(eckey);
        return 0;
    }

    int result = ECDSA_do_verify(msg, msg_len, sig, eckey);
    if (result == 0) {
        printf("Verification failed.\n");
    }
    else if (result == 1) {
        printf("Verification succeeded.\n");
    }
    else {
        printf("Error: Verification failed with error code %d.\n", result);
    }

    EC_KEY_free(eckey);
    return result;
}
void print_ecdsa_signature(ECDSA_SIG* sig) {
    const BIGNUM* r, * s;
    ECDSA_SIG_get0(sig, &r, &s);
    printf("r = ");
    BN_print_fp(stdout, r);
    printf("\n");
    printf("s = ");
    BN_print_fp(stdout, s);
    printf("\n");
}
int main()
{
    EC_KEY* eckey = NULL;
    const EC_GROUP* ecgroup = NULL;
    EC_POINT* ecpoint = NULL;
    BIGNUM* privkey = NULL;
    unsigned char* privkey_buf = NULL, * pubkey_buf = NULL;
    int privkey_len = 0, pubkey_len = 0;

    // Create a new EC key object using the NIST P-256 curve
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL) {
        printf("Error: Failed to create EC key object.\n");
        return -1;
    }

    // Generate a new private/public key pair
    if (!EC_KEY_generate_key(eckey)) {
        printf("Error: Failed to generate EC key pair.\n");
        EC_KEY_free(eckey);
        return -1;
    }

    // Get the EC group and public key point from the EC key object
    ecgroup = EC_KEY_get0_group(eckey);
    ecpoint = EC_KEY_get0_public_key(eckey);
    if (ecgroup == NULL || ecpoint == NULL) {
        printf("Error: Failed to get EC group or public key point.\n");
        EC_KEY_free(eckey);
        return -1;
    }

    // Get the private key from the EC key object
    privkey = EC_KEY_get0_private_key(eckey);
    if (privkey == NULL) {
        printf("Error: Failed to get private key.\n");
        EC_KEY_free(eckey);
        return -1;
    }

    // Convert the private key to a binary format
    privkey_len = BN_num_bytes(privkey);
    privkey_buf = (unsigned char*)malloc(privkey_len);
    if (privkey_buf == NULL) {
        printf("Error: Failed to allocate memory for private key buffer.\n");
        EC_KEY_free(eckey);
        return -1;
    }
    BN_bn2bin(privkey, privkey_buf);

    // Convert the public key point to a binary format
    pubkey_len = EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    pubkey_buf = (unsigned char*)malloc(pubkey_len);
    if (pubkey_buf == NULL) {
        printf("Error: Failed to allocate memory for public key buffer.\n");
        free(privkey_buf);
        EC_KEY_free(eckey);
        return -1;
    }
    EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_COMPRESSED, pubkey_buf, pubkey_len, NULL);

    // Generate a message to sign
    const char* msg = "Hello, world!";
    size_t msg_len = strlen(msg);

    // Generate ECDSA signature
    ECDSA_SIG* sig = NULL;
    generate_ecdsa_signature((unsigned char*)msg, msg_len, privkey, &sig);
    if (sig == NULL) {
        printf("Error: Failed to generate ECDSA signature.\n");
        free(pubkey_buf);
        free(privkey_buf);
        EC_KEY_free(eckey);
        return -1;
    }
    // Print ECDSA signature
        print_ecdsa_signature(sig);
   /* EC_POINT* test = EC_POINT_new(ecgroup);*/

    // Verify ECDSA signature
    int result = verify_ecdsa_signature((unsigned char*)msg, msg_len, ecpoint, sig);


    // Free memory and clean up
    ECDSA_SIG_free(sig);
    free(pubkey_buf);
    free(privkey_buf);
    EC_KEY_free(eckey);

    return 0;
}