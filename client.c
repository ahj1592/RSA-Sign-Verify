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
	int clientSocket, ret;
	struct sockaddr_in serverAddr;
	char buffer[1024];
	char send_buffer[1024];
	char recv_buffer[1024];
	char client_name[100];

	printf("Welcome! Input your name: ");
	fgets(client_name, 100, stdin);
	client_name[strlen(client_name) - 1] = '\0';

	printf("Your name is %s\n", client_name);
	printf("Try to connect to server...\n");

	clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	if(clientSocket < 0){
		printf("[-]Error in connection.\n");
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
	send(clientSocket, client_name, strlen(client_name), 0);
	
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
		printf("Client: (quit to \":exit\"): ");
		//scanf("%s", &buffer[0]);
		memset(buffer, 0, 1024);
		fgets(buffer, 1024, stdin);
		//buffer[strlen(buffer) - 1] = '\0';

		if(strcmp(buffer, ":exit\n") == 0){
			close(clientSocket);
			printf("[-]Disconnected from server.\n");
			exit(1);
		}
		send(clientSocket, buffer, sizeof(buffer), 0);

		memset(recv_buffer, 0, 1024);
		if(recv(clientSocket, recv_buffer, 1024, 0) < 0){
			printf("[-]Error in receiving data.\n");
		}else{
			printf("Server: %s", recv_buffer);
		}
	}

	return 0;
}