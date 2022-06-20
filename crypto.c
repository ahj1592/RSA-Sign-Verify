#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define KEY_LENGTH  2048
//#define PUB_EXP     3
#define PRINT_KEYS 1
#define WRITE_TO_FILE 1

int createRSAKeys(char* username) {

    RSA *keypair = NULL;
    BIGNUM *e = NULL;
    BIO *pri = NULL, *pub = NULL;
    FILE *fp_pri = NULL, *fp_pub = NULL;

    size_t pri_len = 0;            // Length of private key
    size_t pub_len = 0;            // Length of public key
    char   *pri_key = NULL;           // Private key
    char   *pub_key = NULL;           // Public key
    char   *err = NULL;               // Buffer for any error messages
    char prikey_path[115];
    char pubkey_path[115];

    sprintf(prikey_path, "%s_prikey.pem", username);
    sprintf(pubkey_path, "%s_pubkey.pem", username);


    // Generate key pair
    printf("Generating RSA (%d bits) keypair...\n", KEY_LENGTH);
    //RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
    keypair = RSA_new();
    e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(keypair, KEY_LENGTH, e, NULL);

    // To get the C-string PEM form:
    pri = BIO_new(BIO_s_mem());
    pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = malloc(pri_len + 1);
    pub_key = malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    
    
    if((fp_pri = fopen(prikey_path, "wb")) != NULL){
        fwrite(pri_key, sizeof(char),  pri_len, fp_pri);
        fclose(fp_pri);
    }
    if((fp_pub = fopen(pubkey_path, "wb")) != NULL){
        fwrite(pub_key, sizeof(char),  pub_len, fp_pub);
        fclose(fp_pub);
    }

    printf("done.\n");

    if(keypair != NULL) RSA_free(keypair);
    if(pub != NULL) BIO_free_all(pub);
    if(pri != NULL) BIO_free_all(pri);
    if(pri_key != NULL) free(pri_key);
    if(pub_key != NULL) free(pub_key);
    if(err != NULL) free(err);

    return 0;
}

int encrypt_decrypt(char *username){
    int ret = 0;
    FILE *fp_pri = NULL, *fp_pub = NULL;
    RSA *pri_rsa = NULL, *pub_rsa = NULL;

    char prikey_path[115];
    char pubkey_path[115];

    sprintf(prikey_path, "%s_prikey.pem", username);
    sprintf(pubkey_path, "%s_pubkey.pem", username);

    if((fp_pri = fopen(prikey_path, "rb")) == NULL){
        printf("Cannot open file [%s]\n", prikey_path);
        ret = -1;
        goto free_encrypt_decrypt;
    }

    if((fp_pub = fopen(pubkey_path, "rb")) == NULL){
        printf("Cannot open file [%s]\n", pubkey_path);
        ret = -1;
        goto free_encrypt_decrypt;
    }

    if((pri_rsa = PEM_read_RSAPrivateKey(fp_pri, NULL, NULL, NULL)) == NULL){
        printf("Cannot read private key.\n");
        ret = -1;
        goto free_encrypt_decrypt;
    }

    if((pub_rsa = PEM_read_RSAPublicKey(fp_pub, NULL, NULL, NULL)) == NULL){
        printf("Cannot read public key.\n");
        ret = -1;
        goto free_encrypt_decrypt;
    }

    

    free_encrypt_decrypt:
    if(fp_pri != NULL) fclose(fp_pri);
    if(fp_pub != NULL) fclose(fp_pub);
    if(pri_rsa != NULL) RSA_free(pri_rsa);
    if(pub_rsa != NULL) RSA_free(pub_rsa);

    return ret;

}