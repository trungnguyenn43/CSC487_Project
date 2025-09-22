
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
char *bin2Hex(const char *);
char binDigits2Hex(const char *);
char *inputSplit(const char *);

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

			char key[4];													 // 3 hex digits + null terminator
			strcpy(key, inputSplit(client_message + strlen(plaintext) + 1)); // +1 to skip the space

			// Encrypt the plaintext using SDES with the provided key
			strcpy(client_message, SDES(plaintext, key));

			// Convert binary ciphertext to hexadecimal
			static char hexCiphertext[3]; // 2 hex digits
			strcpy(hexCiphertext, bin2Hex(client_message));

			// Send the message back to client
			printf("INFO: Sending back ciphertext message:  %s \n", hexCiphertext);

			// write(new_socket, client_message , strlen(client_message));
			write(new_socket, hexCiphertext, strlen(hexCiphertext));

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

char *bin2Hex(const char *bin)
{
	static char output[2];			   // Maximum 16 hex digits + null terminator
	memset(output, 0, sizeof(output)); // Clear the output array

	int len = strlen(bin);
	if (len % 4 != 0)
	{
		printf("Error: Binary input length is not a multiple of 4 (code: 3)\n");
		return NULL;
	}
	else
	{
		for (int i = 0; i < len; i += 4)
		{
			static char temp[5]; // 4 bits + null terminator
			strncpy(temp, &bin[i], 4);
			temp[4] = '\0'; // Null terminate

			char hexDigit = binDigits2Hex(temp);
			if (hexDigit == '\0')
			{
				return NULL;
			}
			strcat(output, &hexDigit);
		}
	}

	return output;
}

char binDigits2Hex(const char *binary_str)
{
	char hex_digits[] = "0123456789ABCDEF";
	int decimal_value = 0;

	// Validate input length
	if (strlen(binary_str) != 4)
	{
		return '\0';
	}

	// Convert 4-bit binary string to decimal
	for (int i = 0; i < 4; i++)
	{
		if (binary_str[i] == '1')
		{
			decimal_value += (1 << (3 - i)); // (1 * 2^3) for first bit, (1 * 2^2) for second, etc.
		}
		else if (binary_str[i] != '0')
		{
			return '\0'; // Invalid character
		}
	}

	return hex_digits[decimal_value];
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