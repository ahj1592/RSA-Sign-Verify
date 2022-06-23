#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

#define KEY_LENGTH  2048

int createKeys(char* username) {
    
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    char   msg[KEY_LENGTH/8];  // Message to encrypt
    char   *encrypt = NULL;    // Encrypted message
    char   *decrypt = NULL;    // Decrypted message
    char   *err;               // Buffer for any error messages

    char prikey_path[115];
    char pubkey_path[115];

    sprintf(prikey_path, "%s_prikey.pem", username);
    sprintf(pubkey_path, "%s_pubkey.pem", username);


    // Generate key pair
    printf("Generating RSA (%d bits) keypair...\n", KEY_LENGTH);
    fflush(stdout);
    //RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
    RSA *keypair = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(keypair, KEY_LENGTH, e, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    //-------------------------------------------------------------------------------------------
    //RSA *pri_rsa = NULL, *pub_rsa = NULL;
    //pri_rsa = PEM_read_bio_RSAPrivateKey(pri, &pri_rsa, NULL, NULL);
    //pub_rsa = PEM_read_bio_RSAPublicKey(pub, &pub_rsa, NULL, NULL);
    //--------------------------------------------------------------------------------------------

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = malloc(pri_len + 1);
    pub_key = malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';


    FILE *fp_pri = NULL, *fp_pub = NULL;
    if((fp_pri = fopen(prikey_path, "wb")) != NULL){
        fwrite(pri_key, sizeof(char),  pri_len, fp_pri);
        fclose(fp_pri);
    }
    if((fp_pub = fopen(pubkey_path, "wb")) != NULL){
        fwrite(pub_key, sizeof(char),  pub_len, fp_pub);
        fclose(fp_pub);
    }
    
    printf("done.\n");
    return 0;
}

RSA *loadPrivateKey(char *prikey_path){
    FILE *fp_pri = NULL;
    RSA *pri_rsa = NULL;
    
    // Read Private Key from file 
    if((fp_pri = fopen(prikey_path, "r")) == NULL){
        fprintf(stderr, "Cannot open private key from %s\n", prikey_path);
        return NULL;
    }

    if((pri_rsa = PEM_read_RSAPrivateKey(fp_pri, NULL, NULL, NULL)) == NULL){
        fprintf(stderr, "load failed [private key]\n");
    }

    if(fp_pri != NULL) fclose(fp_pri);
    return pri_rsa;
}