#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "list.h"

#define PORT 4444

int main(){
	int sockfd, ret;
	struct sockaddr_in serverAddr;

	int newSocket;
	struct sockaddr_in newAddr;

	socklen_t addr_size;

	char buffer[1024];
	char client_name[100];
	pid_t childpid;

	// Create Whitelist from file
	printf("Create whitelist...\n");
	FILE *fp_read;
	if((fp_read = fopen("readlist.dat", "r")) == NULL){
		fprintf(stderr, "Cannot open file.\n");
		exit(1);
	}

	Data_List *data_list;
	if((data_list = Data_List_new_fp(fp_read)) == NULL){
		fprintf(stderr, "Cannot create list from file.\n");
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


	while(1){
		newSocket = accept(sockfd, (struct sockaddr*)&newAddr, &addr_size);
		if(newSocket < 0){
			exit(1);
		}
		printf("Connection accepted from %s:%d\n", inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));
		memset(client_name, 0, 100);
		recv(newSocket, client_name, 100, 0);
		printf("Client's name: %s\n", client_name);
		
		if(Data_List_has_name(data_list, client_name) < 0){
			printf("%s is not allowed user name\n", client_name);
			send(newSocket, "Not Allowed", strlen("Not Allowed"), 0);
		}
		else{
			printf("%s is allowed user\n", client_name);
			send(newSocket, "Allowed", strlen("Allowed"), 0);
		}


		
		if((childpid = fork()) == 0){
			close(sockfd);

			while(1){
				memset(buffer, 0, sizeof(buffer));
				if(recv(newSocket, buffer, 1024, 0) <= 0){
					//printf("Receive Error.\n");
					exit(1);
				}
				
				if(strcmp(buffer, ":exit\n") == 0){
					printf("Disconnected from %s:%d\n", inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));
					//close(newSocket);
					break;
				}else{
					printf("Client: %s", buffer);
					send(newSocket, buffer, strlen(buffer), 0);
					memset(buffer, 0, sizeof(buffer));
				}
			}
		}
	}

	close(newSocket);


	return 0;
}