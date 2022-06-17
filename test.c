#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "menu.h"

const char *secure_root = "securestorage";

int main(void){
    char username[100];
    char privkey_path[115];
    char pubkey_path[115];
    char plain_path[100];
    char encrypt_path[100];
    char decrypt_path[100];
    
    printf("Your name:");
    scanf("%s", username);

    memset(privkey_path, 0, sizeof(privkey_path));
    memset(pubkey_path, 0, sizeof(pubkey_path));
    memset(plain_path, 0, sizeof(plain_path));
    memset(encrypt_path, 0, sizeof(encrypt_path));
    memset(decrypt_path, 0, sizeof(decrypt_path));

    sprintf(privkey_path, "%s/%s_privkey.pem", secure_root, username);
    sprintf(pubkey_path, "%s/%s_pubkey.pem", secure_root, username);
    sprintf(plain_path, "%s/IVI_small.xml", secure_root);
    sprintf(encrypt_path, "%s/aaaa", secure_root);
    sprintf(decrypt_path, "%s/bbbb", secure_root);

    int option;
    int ret;
    int loop_condition = 1;
    while(loop_condition){
        menu_print();
        scanf("%d", &option);
        switch (option){
            case 1:
                if(createKeys(secure_root, username) == 1){
                    printf("Create key pairs completed.\n");
                }
                else{
                    printf("Fail to create key pakrs.\n");
                }
                
                break;
            case 2:
                if(encryptFile(plain_path, encrypt_path, pubkey_path) == 1){
                    printf("Encryption completed.\n");
                }
                else{
                    printf("Encryption failed.\n");
                }
                
                break;

            case 3:
                if(decryptFile(encrypt_path, decrypt_path, privkey_path) == 1){
                    printf("Decryption completed.\n");
                }
                else{
                    printf("Decryption failed.\n");
                }
                
                break;
            
            default:
            loop_condition = 0;
            printf("Quit menu.\n\n");
            break;
        }
    }

    return 0;
}