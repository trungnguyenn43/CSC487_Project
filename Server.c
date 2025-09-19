
// Essential
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

// Socket dependency
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr

const int SERVER_PORT = 49512; // Port number of the server


int main(int argc , char *argv[])
{
	int socket_desc , new_socket , c, read_size, i;
	struct sockaddr_in server , client;
	char *message, client_message[100];

	char *list;	
	list = "ls -l\n";

	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("ERROR: Could not create socket");
	}
	
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY; 					// From any network interface
	server.sin_port = htons( SERVER_PORT );                 // Random high (assumed unused) port
	
	//Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		printf("ERROR: unable to bind\n");
		return 1;
	}

	//Print server details
	printf("INFO: Server IP: %s, Port: %d\n", inet_ntoa(server.sin_addr), ntohs(server.sin_port));
	printf("INFO: Server listening on port %d\n", ntohs(server.sin_port));
	printf("INFO: Socket bound, ready for and waiting on a client\n");
	
	//Listen
	listen(socket_desc , 3);
	
	//Accept incoming connection
	printf("INFO: Waiting for incoming connections... \n");
	
	
	c = sizeof(struct sockaddr_in);
	new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);

	if (new_socket<0)
	{
		perror("ERROR: accept failed");
		return 1;
	}
	
	printf("INFO: Connection accepted\n");
	printf("INFO: Client connected from IP: %s, Port: %d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
	
	//Receive a message from client
	while( (read_size = recv(new_socket , client_message , 100 , 0)) > 0 )
	{
		printf("\nINFO: Client sent %2i byte message:  %.*s\n",read_size, read_size ,client_message);

		if(!strncmp(client_message,"showMe",6)) 
		{
			printf("\nFiles in this directory: \n");
			system(list);
			printf("\n\n");
		}
		//Send the message back to client
		for(i=0;i< read_size;i++)
		{
			if ( i%2)
				client_message[i] = 'z';
		}

            printf("INFO: Sending back Z'd up message:  %.*s \n", read_size ,client_message);

		//write(new_socket, client_message , strlen(client_message));
		write(new_socket, client_message , read_size);
		
		
		if(read_size == 0)
		{
			printf("INFO: client disconnected\n");
			fflush(stdout);
		}
		else if(read_size == -1)
		{
			perror("ERROR: receive failed");
		}
	}
	
	//Free the socket pointer
	close(socket_desc);
	return 0;
}