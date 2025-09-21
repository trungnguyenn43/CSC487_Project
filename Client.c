/****************************************************
 *
 *    Basic minimal socket client program for use
 *    in CSc 487 final projects.  You will have to
 *    enhance this for your projects!!
 *
 *                                  RSF    11/14/20
 *
 ****************************************************/
#include <stdio.h> // used printf/scanf for demo (puts/getchar would be leaner)
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_addr and sockaddr_in structs

static char SERVER_ADDR[9] = "10.0.0.2"; // IP address of the server by default
int SERVER_PORT = 49152;				 // Port number of the server by default

int main(int argc, char *argv[])
{
	// getting server address and port
	char inputBuffer[100];
	printf("Enter server IP address or type '/' to use default (10.0.0.2) >> ");
	scanf("%s", inputBuffer);

	if (strncmp(inputBuffer, "/", 1) != 0)
	{
		strncpy(SERVER_ADDR, inputBuffer, 9);
	}

	printf("Enter server port number or '/' to use default (49152) >> ");
	scanf("%s", inputBuffer);

	if (strncmp(inputBuffer, "/", 1) != 0)
	{
		for (int i = 0; i < strlen(inputBuffer); i++)
		{
			if (!isdigit(inputBuffer[i]))
			{
				printf("Invalid port number. Using default port %d\n", SERVER_PORT);
				break;
			}
		}
		
		SERVER_PORT = atoi(inputBuffer); //to int
	}

	printf("Using server IP: %s, Port: %d\n", SERVER_ADDR, SERVER_PORT);

	int socket_desc; // file descripter returned by socket command
	int read_size;
	struct sockaddr_in server;					 // in arpa/inet.h
	char server_reply[100], client_message[100]; // will need to be bigger

	// Create socket
	socket_desc = socket(AF_INET, SOCK_STREAM, 0);

	printf("Trying to create socket\n");
	if (socket_desc == -1)
	{
		printf("Unable to create socket\n");
		exit(1);
	}

	// *********** This is the line you need to edit ****************
	server.sin_addr.s_addr = inet_addr(SERVER_ADDR); // using SERVER_ADDR for server IP
	server.sin_family = AF_INET;
	server.sin_port = htons(SERVER_PORT); // random "high"  port number

	// Connect to remote server
	if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		printf("connect error\n");
		return 1;
	}

	printf("Connected to server %s on port %d\n", SERVER_ADDR, SERVER_PORT);

	char *plaintext, *key;

	// //Get data from keyboard and send  to server
	// printf("Plaintext in Hex >> \n");
	// scanf("%s", &plaintext);

	// printf("Key in Hex (3 digits) >> \n");
	// scanf("%s", &key);

	// strcpy(client_message, plaintext);
	// strcat(client_message, "\0");  // append '\0' to plaintext
	// strcat(client_message, key);

	// while(strncmp(client_message,"b",1))      // quit on "b" for "bye"
	// {
	// 	memset(client_mssage,'\0',100);

	// 	if( send(socket_desc , &client_message, strlen(client_message) , 0) < 0)
	// 	{
	// 		printf("Send failed");
	// 		return 1;
	// 	}

	// 	printf("\nSending Message: %.*s\n", (int) strlen(client_message),client_message);

	// 	//Receive a reply from the server
	// 	if( (read_size = recv(socket_desc, server_reply , 100 , 0)) < 0)
	// 	{
	// 		printf("recv failed");
	// 	}
	// 	printf("Server  Replies: %.*s\n\n", read_size,server_reply);
	// }

	return 0;
}
