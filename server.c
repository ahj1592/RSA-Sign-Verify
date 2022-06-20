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
	int sockfd, ret;
	struct sockaddr_in serverAddr;

	int newSocket;
	struct sockaddr_in newAddr;

	socklen_t addr_size;

	char buffer[1024];
	char sender[100];
	char receiver[100];
	char client_name[100];
	pid_t childpid;

	// Create Whitelist from file
	printf("Create whitelist...\n");
	FILE *fp_read = NULL;
	if((fp_read = fopen("securestorage/readlist.dat", "r")) == NULL){
		fprintf(stderr, "Cannot open file.\n");
		exit(1);
	}

	Data_List *data_list;
	if((data_list = Data_List_new_fp(fp_read)) == NULL){
		fprintf(stderr, "Cannot create list from file.\n");
		exit(1);
	}

	Data_List *msg_list = NULL;
	if((msg_list = Data_List_new()) == NULL){
		printf("Cannot create message list.\n");
		exit(1);
	}
	

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0){
		printf("[-]Error in connection.\n");
		exit(1);
	}
	printf("[+]Server Socket is created.\n");

	memset(&serverAddr, '\0', sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	ret = bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	if(ret < 0){
		printf("[-]Error in binding.\n");
		exit(1);
	}
	printf("[+]Bind to port %d\n", PORT);

	if(listen(sockfd, 10) == 0){
		printf("[+]Listening....\n");
	}else{
		printf("[-]Error in binding.\n");
	}

	int result = 0;
	while(1){
		newSocket = accept(sockfd, (struct sockaddr*)&newAddr, &addr_size);
		if(newSocket < 0){
			//printf("Accept failed\n");
			exit(1);
		}

		printf("Connection accepted from %s:%d\n", inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));
		memset(client_name, 0, 100);
		if(recv(newSocket, client_name, 100, 0) < 0){
			printf("Cannot receive client's name.\n");
		}
		printf("Client's name: %s\n", client_name);
		

		if(Data_List_has_name(data_list, client_name) < 0){
			printf("%s is not allowed user name\n", client_name);
			send(newSocket, "Not Allowed", strlen("Not Allowed"), 0);
			//continue;
		}
		else{
			printf("%s is allowed user\n", client_name);
			send(newSocket, "Allowed", strlen("Allowed"), 0);
		}


		while(1){
			memset(buffer, 0, 1024);
			result = recv(newSocket, buffer, 4, 0);
			printf("%d, %s\n", result, buffer);
			if(result <= 0){
				printf("1. Receiver Error.\n");
				exit(1);
			}

			if(strcmp(buffer, "exit") == 0){
				printf("Disconnected from %s:%d\n", inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));
				break;
			}

			else if(strcmp(buffer, "send") == 0){
				unsigned char sig[256];
				unsigned char digest[SHA256_DIGEST_LENGTH];
				char mdString[SHA256_DIGEST_LENGTH*2+1];
				char receiver[100];

				memset(sig, 0, 256);
				memset(digest, 0, SHA256_DIGEST_LENGTH);
				memset(mdString, 0, SHA256_DIGEST_LENGTH*2+1);
				memset(receiver, 0, 100);

				result = recv(newSocket, digest, SHA256_DIGEST_LENGTH, 0);
				if(result < 0){
					printf("receive digest failed.\n");
				}
				result = recv(newSocket, sig, 256, 0);
				if(result < 0){
					printf("receive sig failed.\n");
				}
				result = recv(newSocket, receiver, 100, 0);
				if(result < 0){
					printf("receive receiver name failed.\n");
				}

				
				for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
					sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
				}
				printf("mdstring: %s\n", mdString);
				printf("receiver: %s\n", receiver);
				printf("clientname: %s\n", client_name);

				Data *msg = Data_new();
				
				strcpy(msg->sender, client_name);
				strcpy(msg->receiver, receiver);
				memcpy(msg->sig, sig, 256);
				memcpy(msg->digest, digest, SHA256_DIGEST_LENGTH);
				msg->sig_len = 256;

				printf("%s %s\n", msg->sender, msg->receiver);
				Data_List_append(msg_list, msg);
				Data_List_msg_print(msg_list);

			}
			else if(strcmp(buffer, "recv") == 0){
				char mdString[SHA256_DIGEST_LENGTH*2+1];
				Data_List_msg_print(msg_list);
				Data *data = msg_list->head;

				while(data != NULL){
					if(strcmp(data->receiver, client_name) == 0){
						memset(mdString, 0, SHA256_DIGEST_LENGTH*2+1);
						for(int i = 0; i < SHA224_DIGEST_LENGTH; i++){
							sprintf(&mdString[i*2], "%02x", (unsigned int)data->digest[i]);
						}
						printf("(%s, %s)\n", data->sender, mdString);
						FILE *fp_pub = NULL;
						RSA *pub_rsa = NULL;
						char pubkey_path[115];
						memset(pubkey_path, 0, 115);
						sprintf(pubkey_path, "%s_pubkey.pem", data->sender);
						fp_pub = fopen(pubkey_path, "rb");
						if((pub_rsa = PEM_read_RSAPublicKey(fp_pub, NULL, NULL, NULL)) == NULL){
        					fprintf(stderr, "load failed [public key]\n");
							continue;
						}
						result = RSA_verify(NID_sha1, data->digest, strlen(data->digest), data->sig, data->sig_len, pub_rsa);
						printf("verify result: %d\n", result);
					}
					else{
						printf("a\n");
					}
					data = data->next;
				}
			}
			else{
				printf("Unknown command.\n");
			}

		}
	}

	close(newSocket);


	return 0;
}