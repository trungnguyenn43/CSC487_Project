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
#include <unistd.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_addr and sockaddr_in structs

#include "DiffHellman.h"
#include "SDES.h"

static char SERVER_ADDR[26] = "10.0.0.2"; // IP address of the server by default
int SERVER_PORT = 49152;				  // Port number of the server by default

void corectKeyLength(const int, char[4]);
void messageServer(char[4], char[100], bool *);
void decipherMessage(char[4], char[100], const int, bool *);

int main(int argc, char *argv[])
{
	// getting server address and port
	char inputBuffer[100];
	printf("Enter server IP address or type '/' to use default (10.0.0.2) >> ");
	scanf("%s", inputBuffer);

	if (strncmp(inputBuffer, "/", 1) != 0)
	{
		strncpy(SERVER_ADDR, inputBuffer, 16);
	}

	printf("Enter server port number or '/' to use default (49152) >> ");
	scanf("%s", inputBuffer);
	getchar(); // clear newline character from input buffer

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

		SERVER_PORT = atoi(inputBuffer); // to int
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

	// wait for server to get server public key, prime, and exponent
	// Then generate shared key
	int prime = -1;
	int exp = -1;
	int shareKey = -1;
	memset(server_reply, '\0', 100); // Clear the buffer
	if ((read_size = recv(socket_desc, server_reply, 100, 0)) < 0)
	{
		printf("ERROR: receive failed during key exchange. Exiting...\n");
		close(socket_desc);
		return 1;
	}
	else
	{
		memset(server_reply + read_size, '\0', 1); // Null terminate the string
		int serverPublicKey;
		sscanf(server_reply, "%d %d %d", &serverPublicKey, &prime, &exp); // Extract prime and exp from the received message
		shareKey = DiffHellman_GenShareKey(serverPublicKey, exp, prime);

		printf("INFO: Using prime number: %d\n", prime);
		printf("INFO: Using private exponent: %d\n", exp);
	}

	// Diff Hellman Key Exchange
	int publicKey = DiffHellman_GenPublicKey(&exp, &prime);
	if (publicKey == -1)
	{
		printf("ERROR: Unable to generate public key. Exiting...\n");
		close(socket_desc);
		return 1;
	}

	memset(client_message, '\0', 100);		  // Clear the buffer
	sprintf(client_message, "%d", publicKey); // Convert int to string

	// Sent the public key to server
	if (send(socket_desc, client_message, strlen(client_message), 0) < 0)
	{
		printf("Send failed");
		close(socket_desc);
		return 1;
	}

	// End of Diff Hellman Key Exchange

	char plaintext[9], key[4]; // 8 bits + null terminator, 3 bits + null terminator
	corectKeyLength(shareKey, key);
	printf("INFO: Shared key: %d\n", shareKey);
	printf("INFO: Using SDES with shared key: %s\n", key);

	bool isExit = false;
	memset(client_message, '\0', 100); // Clear the buffer

	while (!isExit)
	{
		messageServer(key, client_message, &isExit);

		if (send(socket_desc, client_message, strlen(client_message), 0) < 0)
		{
			printf("ERROR: Send failed. Exiting...\n");
			close(socket_desc);
			return 1;
		}

		/*
			If the client sent an exit message with the correct key, the isExit flag will be set to true
			The exit message format is "exit+<key>", where <key> is the shared key in hexadecimal format
		*/

		if (isExit)
			break;

		printf("WAITING FOR SERVER MESSAGE...\n");
		memset(server_reply, '\0', 100); // Clear the buffer for next message

		if ((read_size = recv(socket_desc, server_reply, 100, 0)) < 0)
		{
			printf("ERROR: receive failed");
			close(socket_desc);
			return 1;
		}
		else
		{
			// print out original message
			printf("\nINFO: Server sent %d byte message:  %s\n", read_size, server_reply);
			strcpy(client_message, server_reply);
			decipherMessage(key, client_message, read_size, &isExit);
			if (isExit)
				break;

			memset(server_reply, '\0', 100); // Clear the buffer for next message
		}
	}

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
	char tempMessage[read_size / 2 + 1];			// Each character is 2 hex digits, +1 for null terminator
	memset(tempMessage, '\0', sizeof(tempMessage)); // Clear the buffer

	for (int i = 0; i < read_size; i += 2) // Process 2 hex digits at a time
	{
		char tempHex[3] = {'\0'}; // 2 hex digits + null terminator
		strncpy(tempHex, client_message + i, 2);
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

void messageServer(char key[4], char client_message[100], bool *isExit)
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
		SDES(tempHex, key, tempHex);							 // Encrypt the hex using SDES and the shared key
		strcat(hexMessage, tempHex);							 // Append the encrypted hex to the final message
	}

	strcpy(client_message, hexMessage); // Copy the encrypted hex message to client_message
	printf("INFO: Encrypted message to be sent: %s\n\n", client_message);
}