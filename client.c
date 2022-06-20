#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "list.h"
#include "utils.h"

#define PORT 9998

int main(){
	int clientSocket, ret;
	struct sockaddr_in serverAddr;
	char buffer[1024];
	char send_buffer[1024];
	char recv_buffer[1024];
	char client_name[100];

	char prikey_path[115];
    char pubkey_path[115];

	printf("Welcome! Input your name: ");
	fgets(client_name, 100, stdin);
	client_name[strlen(client_name) - 1] = '\0';

	printf("Your name is %s\n", client_name);
	printf("Try to connect to server...\n");

	clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	if(clientSocket < 0){
		printf("[-]Error in making socket.\n");
		exit(1);
	}
	printf("[+]Client Socket is created.\n");

	memset(&serverAddr, '\0', sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	ret = connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	if(ret < 0){
		printf("[-]Error in connection.\n");
		exit(1);
	}

	printf("[+]Connected to Server.\n");
	if(send(clientSocket, client_name, strlen(client_name), 0) < 0){
		printf("Send failed\n");
		exit(1);
	}
	
	memset(buffer, 0, 1024);
	if(recv(clientSocket, buffer, 1024, 0) < 0){
		printf("Receive Error\n");
		close(clientSocket);
		exit(1);
	}

	if(strcmp(buffer, "Not Allowed") == 0){
		printf("%s\n", buffer);
		close(clientSocket);
		exit(0);
	}

	while(1){
		int menu = 0;
		//printf("Client: (quit to \":exit\"): ");
		printf("\n===== MENU =====.\n");
		printf("1. Create RSA Key pairs.\n");
		printf("2. Send Message.\n");
		printf("3. Receive Message.\n");
		printf("0. Quit\n");
		printf("input number: ");
		scanf("%d", &menu);

		if(menu == 0){
			send(clientSocket, "exit", sizeof("exit"), 0);
			close(clientSocket);
			printf("[-]Disconnected from server.\n");
			exit(1);
		}
		else if(menu == 1){
			// create keys
			createKeys(client_name);
		}
		else if(menu == 2){
			unsigned char digest[SHA256_DIGEST_LENGTH];
    		char mdString[SHA256_DIGEST_LENGTH*2+1];
			char receiver[100];
			char data[200];
			// send message

			getchar();
			printf("Input Message: ");
			memset(buffer, 0, 1024);
			fgets(buffer, 1024, stdin);
			buffer[strlen(buffer) - 1] = '\0';
			printf("%s\n", buffer);

			printf("Input receiver: ");
			scanf("%s", receiver);
			printf("%s\n", receiver);

			sprintf(prikey_path, "%s_prikey.pem", client_name);
    		sprintf(pubkey_path, "%s_pubkey.pem", client_name);

			printf("Load %s's private key....\n", client_name);
			FILE *fp_pri = NULL;
			RSA *pri_rsa = NULL;
			if((fp_pri = fopen(prikey_path, "r")) == NULL){
				printf("Cannot open private key file.\n");
				continue;
			}

			if((pri_rsa = PEM_read_RSAPrivateKey(fp_pri, NULL, NULL, NULL)) == NULL){
				fprintf(stderr, "load failed [private key]\n");
				continue;
			}
    		if(fp_pri != NULL) fclose(fp_pri);
			
			printf("Digest message process...\n");
			SHA256_CTX ctx;
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, buffer, strlen(buffer));
			SHA256_Final(digest, &ctx);

			for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
				sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
			}
				
			printf("SHA256 digest: %s\n", mdString);
			printf("length: %ld\n", strlen(mdString));
			unsigned char *sig = NULL;
			unsigned int sig_len = 0;

			sig = malloc(RSA_size(pri_rsa));
			if(sig == NULL) {
				printf("sig is NULL\n");
				continue;
			}

			if(RSA_sign(NID_sha1, digest, sizeof(digest), sig, &sig_len, pri_rsa) != 1){
				printf("sign process failed\n");
			}
			send(clientSocket, "send", strlen("send"), 0);
			send(clientSocket, digest, SHA256_DIGEST_LENGTH, 0);
			send(clientSocket, sig, 256, 0);
			send(clientSocket, receiver, strlen(receiver), 0);
			

		}
		else if(menu == 3){
			// receiver message
			send(clientSocket, "recv", strlen("recv"), 0);

		}


		// send(clientSocket, buffer, sizeof(buffer), 0);

		// memset(recv_buffer, 0, 1024);
		// if(recv(clientSocket, recv_buffer, 1024, 0) < 0){
		// 	printf("[-]Error in receiving data.\n");
		// }else{
		// 	printf("Server: %s", recv_buffer);
		// }
	}

	return 0;
}