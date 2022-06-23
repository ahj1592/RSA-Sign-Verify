#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define PORT 9998

int createKeys(char *username);
RSA *loadPrivateKey(char *prikey_path);