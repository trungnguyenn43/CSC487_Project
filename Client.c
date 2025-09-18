/****************************************************
*
*    Basic minimal socket client program for use
*    in CSc 487 final projects.  You will have to
*    enhance this for your projects!!
*
*                                  RSF    11/14/20
*
****************************************************/
#include<stdio.h>      // used printf/scanf for demo (puts/getchar would be leaner)
#include<string.h>	
#include<sys/socket.h>
#include<arpa/inet.h>  // for inet_addr and sockaddr_in structs

int main(int argc , char *argv[])
{
	int socket_desc;    // file descripter returned by socket command
	int read_size;
	struct sockaddr_in server;    // in arpa/inet.h
	char  server_reply[100], client_message[100];   // will need to be bigger
	
	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);

	printf("Trying to create socket\n");
	if (socket_desc == -1)
	{
		printf("Unable to create socket\n");
	}
		
// *********** This is the line you need to edit ****************
	server.sin_addr.s_addr = inet_addr("10.0.0.2");  // doesn't like localhost?
	server.sin_family = AF_INET;
	server.sin_port = htons( 8421 );    // random "high"  port number

	//Connect to remote server
	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
		printf(" connect error");
		return 1;
	}
	

	//Get data from keyboard and send  to server
	printf("What do you want to send to the server. (b for bye)\n");
	while(strncmp(client_message,"b",1))      // quit on "b" for "bye"
	{
		memset(client_message,'\0',100);
		scanf("%s",client_message);

		if( send(socket_desc , &client_message, strlen(client_message) , 0) < 0)
		{
			printf("Send failed");
			return 1;
		}

		printf("\nSending Message: %.*s\n", (int) strlen(client_message),client_message);
	
		//Receive a reply from the server
		if( (read_size = recv(socket_desc, server_reply , 100 , 0)) < 0)
		{
			printf("recv failed");
		}
		printf("Server  Replies: %.*s\n\n", read_size,server_reply);
	}

	
	return 0;
}
