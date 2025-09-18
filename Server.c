
// Essential
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

// Socket dependency
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr

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
		printf("Could not create socket");
	}
	
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( 8421 );                 // Random high (assumed unused) port
	
	//Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		printf(" unable to bind\n");
		return 1;
	}
	printf(" socket bound, ready for and waiting on a client\n");
	
	//Listen
	listen(socket_desc , 3);
	
	//Accept incoming connection
	printf(" Waiting for incoming connections... \n");
	
	
	c = sizeof(struct sockaddr_in);
	new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
	if (new_socket<0)
	{
		perror("accept failed");
		return 1;
	}
	
	printf("Connection accepted\n");

	
	//Reply to the client
	message = "You have located Server X at our undisclosed location.  What would you like to say?\n";
	//write(new_socket , message , strlen(message));
	
	//Receive a message from client
	while( (read_size = recv(new_socket , client_message , 100 , 0)) > 0 )
	{

		printf("\n Client sent %2i byte message:  %.*s\n",read_size, read_size ,client_message);

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

               	printf(" Sending back Z'd up message:  %.*s \n", read_size ,client_message);

		//write(new_socket, client_message , strlen(client_message));
		write(new_socket, client_message , read_size);
	}
	
	if(read_size == 0)
	{
		printf("client disconnected\n");
		fflush(stdout);
	}
	else if(read_size == -1)
	{
		perror("receive failed");
	}
		
	//Free the socket pointer
	close(socket_desc);
	return 0;
}