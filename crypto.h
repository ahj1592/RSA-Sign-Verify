#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>

int createKeys(const char *secure_root, const char* username);
RSA * load_RSA_PrivateKey(const char *filename);
RSA * load_RSA_PublicKey(const char *filename);
int encryptFile(const char *plain_path, const char *encrypt_path, const char *pubkey_path);
int decryptFile(const char *encrypt_path, const char *decrypt_path, const char *privkey_path);