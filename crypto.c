#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>

#define KEY_LENGTH  (2048)

const char *PUB_EXP = "65537";


int createKeys(const char *secure_root, const char* username){
    int ret_value = -1;
    char privkey_path[100], pubkey_path[100];
	FILE *fp_pub = NULL, *fp_priv;
	RSA *rsa = NULL;
	BIGNUM *e = NULL;

    memset(privkey_path, 0, sizeof(privkey_path));
    memset(pubkey_path, 0, sizeof(pubkey_path));
    sprintf(privkey_path, "%s/%s_privkey.pem", secure_root, username);
    sprintf(pubkey_path, "%s/%s_pubkey.pem", secure_root, username);

    rsa = RSA_new();
    e = BN_new();
    if(e == NULL || rsa == NULL){
		if(e == NULL){
			fprintf(stderr, "Cannot allocate BIGNUM.\n");
		}
		if(rsa == NULL){
			fprintf(stderr, "Cannot allocate RSA.\n");
		}
		goto free_stuffs;
	}
	

	// Initialize Exponent(e)
    if (BN_set_word(e, RSA_F4) == 0){
		fprintf(stderr, "Cannot set BIGNUM as %lu.\n", RSA_F4);
		goto free_stuffs;
	}
    

	// Create key pair
    if (RSA_generate_key_ex(rsa, KEY_LENGTH, e, NULL) == 0){
		fprintf(stderr, "Cannot generate key pair.\n");
		goto free_stuffs;
	}
 
 	// Create Private Key
    // ----- Open the file where private key is stored
	if ( (fp_priv = fopen(privkey_path, "w")) == NULL ){
		fprintf(stderr, "Cannot open the file %s.\n", privkey_path);
		goto free_stuffs;
	}

	// ----- Create and Store the private key
    if ( PEM_write_RSAPrivateKey(fp_priv, rsa, NULL, NULL, 0, 0, NULL) == 0 ){
		fprintf(stderr, "Cannot write private key.\n");
		goto free_stuffs;
	}

	// ----- Close the file



	// Create Public Key
	// ----- Open the file where public key is stored
    if ((fp_pub = fopen(pubkey_path, "w")) == NULL){
		fprintf(stderr, "Cannot open file %s.\n", pubkey_path);
        return -1;
		goto free_stuffs;
	}

	// PEM_write_RSA_PUBKEY(fp, rsa)
    // PEM_write_RSAPublicKey
    if ( PEM_write_RSA_PUBKEY(fp_pub, rsa) == 0){
		fprintf(stderr, "Cannot write public key.\n");
		goto free_stuffs;
	}



	ret_value = 1;

	// Free allocated pointers
free_stuffs:
    if(e != NULL) BN_free(e);
	if(rsa != NULL) RSA_free(rsa);
	if(fp_priv != NULL) fclose(fp_priv);
    if(fp_pub != NULL) fclose(fp_pub);
	// return 1 if all process are successful
	return (ret_value == 1);

}



RSA * load_RSA_PrivateKey(const char *filename){
	FILE *fp = NULL;
	RSA *rsa = NULL;

    // Open Private Key File
	fp = fopen(filename, "r");
	if (fp == NULL){
		fprintf (stderr, "Cannot open file: %s\n", filename);
		return NULL;
	}

    // Read RSA Private Key
    rsa = RSA_new();
	if ( (rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL)) == NULL){
		fprintf(stderr, "Cannot read private key.\n");
		return NULL;
	}


	if (fclose(fp) == EOF){
		fprintf(stderr, "Cannot close the file %s.\n", filename);
		return NULL;
	}

	printf ("Successfully Load private key from [%s].\n", filename);
	return rsa;
}

RSA * load_RSA_PublicKey(const char *filename){
	FILE *fp = NULL;
	RSA *rsa = NULL;

	fp = fopen(filename, "r");
	if (fp == NULL){
		fprintf (stderr, "Cannot open file: %s\n", filename);
		return NULL;
	}
	

	if((rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)) == NULL){
		fprintf(stderr, "Cannot read public key from [%s].\n", filename);
		return NULL;
	}
	
	if(fclose(fp) == EOF){
		fprintf(stderr, "Cannot close the file %s.\n", filename);
		return NULL;
	}

	printf ("Successfully Load public key from [%s].\n", filename);
	return rsa;
}



int encryptFile(const char *plain_path, const char *encrypt_path, const char *pubkey_path){
	FILE *fp = NULL;
	char *plain = NULL;
    char encrypted[4098];
	int file_size = 0;
    RSA *rsa_pubkey = NULL;

	fp = fopen(plain_path, "r");
	if (fp == NULL){
		printf ("Cannot open file %s.\n", plain_path);
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// memory allocation 
	plain = (char *)malloc(sizeof(char) * file_size);
    if(plain == NULL){
        fprintf(stderr, "Failed to allocate memory.\n");
        return -1;
    }
	fread(plain, sizeof(char), file_size, fp);
    printf("plaintext:\n%s\n", plain);
    if(fp != NULL){
        fclose(fp);
    }
	printf("ASDFSAFDFASD\n");

	// Encryption Process
	// --- load public key file
	FILE *fp_pubkey = NULL;
	fp_pubkey = fopen(pubkey_path, "r");
	if(fp_pubkey == NULL){
		printf ("Cannot open public key file %s.\n", pubkey_path);
		return -1;
	}
	
	// --- read public key
    //rsa = load_RSA_PublicKey(pubkey_path);
    //rsa_pubkey = PEM_read_RSAPublicKey(fp_pubkey, NULL, NULL, NULL);
    rsa_pubkey = PEM_read_RSA_PUBKEY(fp_pubkey, NULL, NULL, NULL);
	if(rsa_pubkey == NULL){
		printf ("Cannot read public key.\n");
		return -1;
	}
    
    if(fp_pubkey != NULL){
        fclose(fp_pubkey);
    }
    printf("NNNNNNNNN\n");

    

    // padding: RSA_PKCS1_PADDING
    // RSA_PKCS1_OAEP_PADDING
	int encrypt_len = RSA_public_encrypt(strlen(plain), plain, encrypted, rsa_pubkey, RSA_PKCS1_PADDING);
	if(encrypt_len == -1){
		printf ("Encryption Process failed.\n");
		return -1;
	}
    printf("Encrypted len, file_size: %d %d\n", encrypt_len, file_size);
    printf("Encrypted: \n%s\n", encrypted);

	FILE *fp_encrypt = fopen(encrypt_path, "wb");
	if (fp_encrypt == NULL){
		printf ("Cannot open file: %s.\n", encrypt_path);
		return -1;
	}
    
    
	int num_write = fwrite(encrypted, file_size, 1, fp_encrypt);
    //printf("%d\n", num_write);
    if(fp_encrypt != NULL){
        fclose(fp_encrypt);
    }
	printf("11111111111111\n");
    // if(encrypted != NULL){
    //     free(encrypted);
    // }
	printf("22222222222222\n");
    if(rsa_pubkey != NULL){
        RSA_free(rsa_pubkey);
    }
    printf("33333333333333333\n");
    return 1;

}

int decryptFile(const char *encrypt_path, const char *decrypt_path, const char *privkey_path){
	FILE *fp_encrypt = NULL, *fp_decrypt = NULL, *fp_privkey = NULL;
	char *cipher = NULL;// *decrypted = NULL;
	RSA *rsa = NULL;
	int file_size = 0;
    char decrypted[4098];

	fp_encrypt = fopen(encrypt_path, "rb");
	if (fp_encrypt == NULL){
		printf ("Cannot open file %s.\n", encrypt_path);
		return -1;
	}
    
	fseek(fp_encrypt, 0, SEEK_END);
	file_size = ftell(fp_encrypt);
	fseek(fp_encrypt, 0, SEEK_SET);

	// memory allocation 
	cipher = (char *)malloc(sizeof(char) * file_size);
    if(cipher == NULL){
        fprintf(stderr, "Cannot allocate memory.\n");
        return -1;
    }
    else{
        printf("Succellfully allocate memory.\n");
    }
	fread(cipher, sizeof(char), file_size, fp_encrypt);
    printf("file size: %d\n", file_size);
    printf("cipher text:\n%s\n", cipher);
	//fclose(fp_encrypt);

	// Decryption Process
    
	fp_privkey = fopen(privkey_path, "r");
	if(fp_privkey == NULL){
		fprintf (stderr, "Cannot open private key file %s.\n", privkey_path);
		return -1;
	}
    printf("Successfully open the file.\n");


    //rsa = load_RSA_PrivateKey(privkey_path);
    //printf("%d %X\n", fp_privkey, fp_privkey);
    printf("AAAAAAAAA\n");
    
    rsa = PEM_read_RSAPrivateKey(fp_privkey, &rsa, NULL, NULL);
	printf("BBBBBBBBB\n");
    if (rsa == NULL){
        fprintf(stderr, "Cannot load private key.\n");
        return -1;
    }
    printf("Successfully Load private key.\n");

	//fclose(fp_privkey);
	//decrypted = (char*)malloc(sizeof(char) * 256);
    //memset(decrypted, 0, sizeof(decrypted));
	int decrypt_len = RSA_private_decrypt(256, cipher, decrypted, rsa, RSA_PKCS1_PADDING);
	if (decrypt_len == -1){
		printf ("Decryption Process failed.\n");
		return -1;
	}

	fp_decrypt = fopen(decrypt_path, "w");
	if (fp_decrypt == NULL){
		printf ("Cannot open file: %s.\n", decrypt_path);
		return -1;
	}
	fwrite(decrypted, decrypt_len, 1, fp_decrypt);
	if(fp_decrypt != NULL) fclose(fp_decrypt);
    //if(decrypted != NULL) free(decrypted);
    if(rsa != NULL) free(rsa);
	return 1;

}
