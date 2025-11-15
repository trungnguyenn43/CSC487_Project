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
#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_addr and sockaddr_in structs

#include "DiffHellman.h"
#include "SDES.h"
#include "UtilFunction.h"
#include "certs.h"

static char SERVER_ADDR[26] = "10.0.0.2"; // IP address of the server by default
int SERVER_PORT = 49152;				  // Port number of the server by default
static char CBC_Hash_KEY[4] = "CCB"; //key for CBC Hash
static char CBC_IV[3] = "1A"; // IV for CBC Hash

void correctKeyLength(const int, char[4]);
void messageServer(char[4], char[100], bool *);
void decipherMessage(char[4], char[100], const int, bool *);


int main(int argc, char *argv[])
{
	srand(time(NULL)); 
	
	printf("========= RSA KEY GEN ==========\n");

	//================
	// RSA Key Gen
	//================
	unsigned int rsa_public_key = 0, rsa_private_key = 0;
	unsigned int p, q, n, totient_n;

	//getting two distinct prime numbers
	do{
		printf("Enter two distinct prime numbers (p and q): ");
		scanf("%u %u", &p, &q);
		printf("Checking if p and q are co-prime...\n");
		getchar(); // clear newline character from input buffer

		//checking if both numbers are prime
		if(isPrime(p) == false || isPrime(q) == false){
			printf("One or both numbers are not prime. Please enter again.\n");
			continue;
		}

		if(gcd(p, q) != 1){
			printf("p and q are not co-prime. Please enter again.\n");
		} else {
			printf("p and q are co-prime. Continue...\n\n");
			break;
		}

	}while(1);

	//setting n and totient_n
	n = p * q;
	totient_n = (p - 1) * (q - 1);
	//generating public and private keys
	rsa_private_key = RSA_KeyGen(p, q, &rsa_public_key);

	printf("Generated RSA Public Key: %u\n", rsa_public_key);
	printf("Generated RSA Private Key: %u\n\n", rsa_private_key);

	printf("========= Setting up connection ==========\n");

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

	int socket_desc; // file descriptor returned by socket command
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

	printf("Connected to server %s on port %d\n\n", SERVER_ADDR, SERVER_PORT);

	//=========================
	//Share public key with server
	//=========================
	memset(client_message, '\0', 100); // Clear the buffer
	// Sent the public key to server
	sprintf(client_message, "%u %u", rsa_public_key, n); // convert to string
	if (send(socket_desc, client_message, strlen(client_message), 0) < 0)
	{
		printf("Send failed");
		close(socket_desc);
		return 1;
	}


	printf("========= Diff Hellman Key Exchange ==========\n");
	//=========================
	// Diff Hellman Key Exchange
	//=========================
	// wait for server to get server public key, prime, and exponent
	// Then generate shared key
	int prime = 0;
	int exp = 0;
	int alpha = 0;
	int shareKey = -1;
	memset(server_reply, '\0', 100); // Clear the buffer
	if ((read_size = recv(socket_desc, server_reply, 100, 0)) < 0)
	{
		printf("ERROR: receive failed during key exchange. Exiting...\n");
		close(socket_desc);
		return 1;
	}
	
	// Diff Hellman Key Exchange
	memset(server_reply + read_size, '\0', 1); // Null terminate the string
	int server_SYM_PublicKey;
	unsigned int signature;
	unsigned int server_n;
	unsigned int server_rsa_publickey;
	sscanf(server_reply, "%d %d %d %d %u %u", &server_SYM_PublicKey, &prime, &alpha, &server_rsa_publickey, &server_n, &signature);
	
	printf("INFO: Server sent public key: %d\n", server_SYM_PublicKey);
	printf("INFO: Using prime number: %d\n", prime);
	printf("INFO: Using alpha: %d\n\n", alpha);
	printf("INFO: Verifying RSA signature: %u\n", signature);

	// ==========
	// Verifying Signature
	// ===========
	printf("============ SIGNATURE VERIFICATION ============\n");
	char tempOutputBuffer[100];
	sprintf(client_message, "%d %d %d", server_SYM_PublicKey, prime, alpha);
	CBCHash(client_message, CBC_IV, CBC_Hash_KEY, tempOutputBuffer);

	// Convert hash to numeric value
	unsigned int hashValue = (int)strtol(tempOutputBuffer, NULL, 16);
	printf("INFO: CBC Hash of public key, prime, and alpha: %d\n", hashValue);
	unsigned int decryptedHash = modExp(signature, server_rsa_publickey, server_n);
	printf("INFO: Decrypted RSA signature: %u\n", decryptedHash);

	if(decryptedHash != hashValue){
		printf("WARNING: RSA signature verification failed! Be cautious...\n");
		close(socket_desc);
		return 1;
	} else {
		printf("INFO: RSA signature verification succeeded. Continuing...\n\n");
	}

	printf("============ END OF SIGNATURE VERIFICATION ============\n\n");

	//Run inside client program instead
	exp = rand() % (prime - 2) + 1; // Random integer in the range [1, prime-1]
	printf("INFO: Using private exponent: %d\n", exp);

	int publicKey = DiffHellman_GenPublicKey(&exp, &alpha, &prime);
	if (publicKey == -1)
	{
		printf("ERROR: Unable to generate public key. Exiting...\n");
		
		close(socket_desc);
		return 1;
	}
	printf("INFO: Public key: %d\n\n", publicKey);

	// Generating RSA signature for public key
	printf("============= SIGNATURE GENERATION ============\n");
	
	memset(client_message, '\0', 100);		  // Clear the buffer
	sprintf(client_message, "%d %d %d", publicKey, prime, alpha); // Convert int to string
	
	//generate signature for public key
	CBCHash(client_message, CBC_IV, CBC_Hash_KEY, tempOutputBuffer);
	
	// Convert hash to numeric value
	hashValue = strtol(tempOutputBuffer, NULL, 16);
	printf("INFO: CBC Hash of public key, prime, and alpha: %d\n", hashValue);
	
	//Encrypt the hash with RSA private key to create signature
	signature = modExp(hashValue, rsa_private_key, n);
	printf("INFO: Generated RSA signature: %u\n\n", signature);

	sprintf(client_message, "%d %d %d %u", publicKey, prime, alpha, signature);
	printf("============ END OF SIGNATURE GENERATION ============\n\n");
	
	shareKey = DiffHellman_GenShareKey(server_SYM_PublicKey, exp, prime);

	// Sent the public key to server
	if (send(socket_desc, client_message, strlen(client_message), 0) < 0)
	{
		printf("Send failed");
		close(socket_desc);
		return 1;
	}

	// End of Diff Hellman Key Exchange

	char plaintext[9], key[4]; // 8 bits + null terminator, 3 bits + null terminator
	printf("INFO: Shared key: %d\n", shareKey);
	correctKeyLength(shareKey, key);
	printf("INFO: Using SDES with shared key: %s\n", key);

	bool isExit = false;
	memset(client_message, '\0', 100); // Clear the buffer

	printf("\n===== MESSAGE EXCHANGE SESSION =====\n");

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
			printf("INFO: Server sent %d byte message:  %s\n", read_size, server_reply);
			strcpy(client_message, server_reply);
			decipherMessage(key, client_message, read_size, &isExit);
			if (isExit)
				break;

			memset(server_reply, '\0', 100); // Clear the buffer for next message
		}
	}

	return 0;
}

void correctKeyLength(const int key, char keyStr[4])
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
