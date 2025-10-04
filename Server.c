
// Essential
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

// Socket dependency
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr

#include "SDES.h"

// Function prototypes
char *inputSplit(const char *);
void encrypt(const char [8], const bool[10], bool[8]);

// Define server port
const int SERVER_PORT = 49152; // Port number of the server

int main(int argc, char *argv[])
{
	int socket_desc, new_socket, c, read_size, i;
	struct sockaddr_in server, client;
	char *message, client_message[100];

	// Create socket
	socket_desc = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_desc == -1)
	{
		printf("ERROR: Could not create socket");
	}

	// Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;  // From any network interface
	server.sin_port = htons(SERVER_PORT); // Random high (assumed unused) port

	// Bind
	if (bind(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		printf("ERROR: unable to bind\n");
		return 1;
	}

	// Print server details
	printf("INFO: Socket bound, ready for and waiting on a client\n");
	printf("INFO: Server IP: %s, Port: %d\n", inet_ntoa(server.sin_addr), ntohs(server.sin_port));

	// Listen
	listen(socket_desc, 3);

	bool isExit = false;

	while (!isExit)
	{
		// Accept incoming connection
		printf("INFO: Waiting for incoming connections... \n");

		c = sizeof(struct sockaddr_in);
		new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t *)&c);

		if (new_socket < 0)
		{
			printf("ERROR: accept failed");
			isExit = true;
			break;
		}

		printf("INFO: Connection accepted\n");
		printf("INFO: Client connected from IP: %s, Port: %d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

		// Receive a message from client
		while ((read_size = recv(new_socket, client_message, 100, 0)) > 0)
		{
			printf("\nINFO: Client sent %2i byte message:  %.*s\n", read_size, read_size, client_message);

			// Parse the input to extract plaintext and key
			char plaintext[3]; // 2 hex digits + null terminator
			strcpy(plaintext, inputSplit(client_message));

			char key[4]; // 3 hex digits + null terminator
			strcpy(key, inputSplit(client_message + strlen(plaintext) + 1)); // +1 to skip the space

			bool encryptedMsg[8]; // 8 bits encrypted message
			
			encrypt(plaintext, key, encryptedMsg);

			// Convert the boolean array back to hex
			for (i = 0; i < 8; i += 4)
			{	
				// Process 4 bits at a time
				char hexChar = bin2Hex(&encryptedMsg[i]); //get 4 bits starting from index i
				client_message[i / 4] = hexChar;
			}
			
			// Send the message back to client
			printf("INFO: Sending back ciphertext message:  %s \n", client_message);

			// write(new_socket, client_message , strlen(client_message));
			write(new_socket, client_message, strlen(client_message));

		}

		if (read_size == 0)
		{
			printf("INFO: client disconnected\n");
			fflush(stdout);
			isExit = true;
			break;
		}
		else if (read_size == -1)
		{
			printf("ERROR: receive failed");
		}
	}

	// Free the socket pointer
	close(socket_desc);
	return 0;
}

void encrypt(const char plaintext[8], const bool key[10], bool output[8]){
	
		// Bit arrays
		bool plaintextBits[8]; // 8 bits plaintext in bits
		bool keyBits[12];     // 10 bits key in bits

		// Convert hex strings to binary bit arrays
		hex2Bin(plaintext, plaintextBits);
		hex2Bin(key, keyBits);
		
		//ignore the first 2 bits of keyBits to make it 10 bits
		for (i = 0; i < 10; i++)
			keyBits[i] = keyBits[i + 2];
		keyBits[10] = '\0'; // Null terminate
		keyBits[11] = '\0'; // Null terminate

		// Encrypt the plaintext using SDES with the provided key
		SDES(plaintextBits, keyBits, output);
}

char *inputSplit(const char *input)
{
	static char output[100];
	memset(output, 0, sizeof(output)); // Clear the output array

	int i = 0;
	while (input[i] != ' ' && input[i] != '\0' && i < 99)
	{
		output[i] = input[i];
		i++;
	}
	output[i] = '\0'; // Null terminate

	return output;
}