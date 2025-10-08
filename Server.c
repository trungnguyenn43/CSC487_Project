// Essential
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

// Socket dependency
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr

#include "SDES.h"
#include "DiffHellman.h"

// Function prototypes
void corectKeyLength(const int, char[4]);
void decipherMessage(char[4], char[100], const int, bool *);
void messageClient(char[4], char[100], bool *);

// Define server port
const int SERVER_PORT = 49152; // Port number of the server

int main(int argc, char *argv[])
{
	int socket_desc, new_socket, c, read_size, i;
	struct sockaddr_in server, client;
	char client_message[100];

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

	// Accept incoming connection
	printf("INFO: Waiting for incoming connections... \n");

	c = sizeof(struct sockaddr_in);
	new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t *)&c);

	if (new_socket < 0)
	{
		printf("ERROR: accept failed");
		return 1;
	}

	printf("INFO: Connection accepted\n");
	printf("INFO: Client connected from IP: %s, Port: %d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

	// generate and display public key
	int prime = -1;
	int exp = -1;
	int publicKey = DiffHellman_GenPublicKey(&exp, &prime);
	int shareKey = -1;
	if (publicKey == -1)
	{
		printf("ERROR: Unable to generate public key. Exiting...\n");
		close(new_socket);
		return 1;
	}
	printf("INFO: Using prime number: %d\n", prime);
	printf("INFO: Using private exponent: %d\n", exp);
	printf("INFO: Public key: %d\n", publicKey);

	// send the public key to client
	sprintf(client_message, "%d %d %d", publicKey, prime, exp);
	write(new_socket, client_message, strlen(client_message));

	// wait for client to send its public key
	memset(client_message, '\0', 100); // Clear the buffer
	if ((read_size = recv(new_socket, client_message, 100, 0)) < 0)
	{
		printf("ERROR: receive failed");
		close(new_socket);
		return 1;
	}
	else
	{
		int clientPublicKey;
		sscanf(client_message, "%d", &clientPublicKey); // just to check if it's a valid integer
		printf("INFO: Client sent public key: %s\n", client_message);
		shareKey = DiffHellman_GenShareKey(clientPublicKey, exp, prime);
		printf("INFO: Shared key: %d\n", shareKey);
	}

	char key[4];					// 3 hex digits + null terminator
	corectKeyLength(shareKey, key); // Convert int to 3-char string with leading zeros if necessary

	printf("INFO: Using SDES with shared key: %s\n", key);

	memset(client_message, '\0', 100); // Clear the buffer

	// Server will start receive first
	printf("WAITING FOR CLIENT MESSAGE...\n");

	while (!isExit)
	{
		// Receive a message from client
		if ((read_size = recv(new_socket, client_message, 100, 0)) > 0)
		{
			if (read_size == -1)
			{
				printf("ERROR: receive failed");
				isExit = true;
				break;
			}

			printf("\nINFO: Client sent %d byte message:  %s\n", read_size, client_message);

			decipherMessage(key, client_message, read_size, &isExit);

			/*
				If the client sent an exit message with the correct key, the isExit flag will be set to true
				The exit message format is "exit+<key>", where <key> is the shared key in hexadecimal format
			*/

			if (isExit)
				break;

			// write message back to client
			messageClient(key, client_message, &isExit);

			// send the encrypted message to client
			write(new_socket, client_message, strlen(client_message));

			if (isExit)
				break;

			printf("WAITING FOR CLIENT MESSAGE...\n");

			memset(client_message, '\0', 100); // Clear the buffer for next message
		}
	}

	// Free character arrays
	memset(client_message, '\0', 100); // Clear the buffer

	// Free the socket pointer
	close(socket_desc);
	return 0;
}

void corectKeyLength(const int key, char keyStr[4])
{
	// Get the last 3 digits of the integer and convert them to hexadecimal
	int lastThreeDigits = key % 1000;
	sprintf(keyStr, "%03X", lastThreeDigits); // Convert to 3 hex digits

	keyStr[3] = '\0';
}

void decipherMessage(char key[4], char client_message[100], const int read_size, bool *isExit)
{
	char tempMessage[read_size / 2 + 1]; // 2 hex digits, +1 for null terminator
	memset(tempMessage, '\0', sizeof(tempMessage));

	for (int i = 0; i < read_size; i += 2)
	{
		char tempHex[3] = {'\0'};				 // 2 hex digits + null terminator
		strncpy(tempHex, client_message + i, 2); // Extract 2 hex digits
		SDES_decrypt(tempHex, key, tempHex);

		// Convert decrypted hex back to a character
		char tempChar = (char)strtol(tempHex, NULL, 16); // Convert hex to char
		tempMessage[i / 2] = tempChar;
	}

	tempMessage[read_size / 2] = '\0'; // Null terminate the decrypted message

	if (strncmp(tempMessage, "exit+", 5) == 0 && strcmp(tempMessage + 5, key) == 0)
	{
		*isExit = true;
		printf("INFO: Client requested to exit with correct key. Exiting...\n");
		return;
	}

	printf("=== DECRYPTED MESSAGE ===\n");
	printf("%s\n", tempMessage);
	printf("=== END OF MESSAGE ===\n\n");
}

void messageClient(char key[4], char client_message[100], bool *isExit)
{
	// Clear buffer
	memset(client_message, '\0', sizeof(*client_message));

	char tempMessage[100];
	memset(tempMessage, '\0', sizeof(tempMessage));

	printf("Enter message to send to client (type 'exit' to quit): ");
	printf(">> ");
	fgets(tempMessage, sizeof(tempMessage) - 1, stdin);

	// Remove newline character from fgets
	size_t len = strlen(tempMessage);
	if (len > 0 && tempMessage[len - 1] == '\n')
	{
		tempMessage[len - 1] = '\0';
	}

	if (strcmp(tempMessage, "exit") == 0)
	{
		*isExit = true;
		printf("INFO: Exiting...\n");
		strcpy(tempMessage, "exit+");
		strcat(tempMessage, key);						   // Send exit message with key
		tempMessage[strlen("exit+") + strlen(key)] = '\0'; // Null terminate the final message
	}

	char hexMessage[201];						  // 2 hex digits per character + null terminator
	memset(hexMessage, '\0', sizeof(hexMessage)); // Clear the buffer

	for (int i = 0; i < strlen(tempMessage); i++)
	{
		char tempHex[3];										 // 2 hex digits + null terminator
		sprintf(tempHex, "%02X", (unsigned char)tempMessage[i]); // Convert next character to hex

		SDES(tempHex, key, tempHex);

		strcat(hexMessage, tempHex); // Append the encrypted hex to the final message
	}

	strcpy(client_message, hexMessage); // Copy the encrypted hex message to client_message
	printf("INFO: Encrypted message to be sent: %s\n\n", client_message);
}