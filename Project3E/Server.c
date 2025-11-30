// Essential
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>	  // For file operations
#include <sys/stat.h> // For file permissions

// Socket dependency
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr

#include "SDES.h"
#include "DiffHellman.h"
#include "UtilFunction.h"
#include "certs.h"

// Function prototypes
void correctKeyLength(const int, char[4]);
void decipherMessage(char[4], char[], const int, bool *, bool *);
void messageClient(char[4], char[], bool *, bool *);
void receiveCert(int);
void sendCert(int, const char[]);
void getKeyParamsFromCert(unsigned int *, unsigned int *);
int handleKeyExchangeRequest(int, const int, const unsigned int);
int requestKeyExchange(int, const unsigned int, const unsigned int);
void requestChangeCipher(int , char []);
void handleChangeCipherRequest(int , char []);

// Define server port
const int SERVER_PORT = 49152;		 // Port number of the server
static char CBC_Hash_KEY[4] = "CCB"; // key for CBC Hash
static char CBC_IV[3] = "1A";		 // IV for CBC Hash
const char CERT_FILE[] = "server_cert.txt";
const char CERT_TEMP_FILE[] = "SV_temp_cert_file.txt";

unsigned int rsa_public_key = 0, rsa_private_key = 0;
unsigned int p = 47, q = 83, n, totient_n;
static char SDES_KEY[4] = "000"; // SDES key placeholder
unsigned int RSA_Client_PU = 0, RSA_Client_n = 0;

int main(int argc, char *argv[])
{
	int socket_desc, new_socket, c, read_size, i;
	struct sockaddr_in server, client;
	char client_message[1024]; // to receive
	char server_message[1024]; // to send

	printf("========= RSA KEY GEN ==========\n");
	//====================================
	// RSA Key GEN
	//====================================

	// getting two distinct prime numbers
	do
	{
		// printf("Enter two distinct prime numbers (p and q): ");
		// scanf("%u %u", &p, &q);
		printf("Checking if p and q are coprime...\n");
		// getchar(); // clear newline character from input buffer

		// checking if both numbers are prime
		if (isPrime(p) == false || isPrime(q) == false)
		{
			printf("One or both numbers are not prime. Please enter again.\n");
			continue;
		}

		if (gcd(p, q) != 1)
		{
			printf("p and q are not coprime. Please enter again.\n");
		}
		else
		{
			printf("p and q are coprime. Continue...\n\n");
			break;
		}

	} while (1);

	// setting n and totient_n
	n = p * q;
	totient_n = (p - 1) * (q - 1);
	// generating public and private keys
	rsa_private_key = RSA_KeyGen(p, q, &rsa_public_key);

	printf("Generated RSA Public Key: %u\n", rsa_public_key);
	printf("Generated RSA Private Key: %u\n\n", rsa_private_key);

	// Generating cert for server
	printf("============= CERTIFICATE GENERATION ============\n");

	certGen((char *)CERT_FILE, rsa_private_key, rsa_public_key, n);

	printf("======= SOCKET SETUP =======\n");

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
	printf("INFO: Client connected from IP: %s, Port: %d\n\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

	// wait for client to send certificate signal
	recv(new_socket, client_message, sizeof(client_message), 0);
	if (strncmp(client_message, "CERT_TRANSFER", strlen("CERT_TRANSFER")) != 0)
	{
		printf("ERROR: Invalid certificate transfer request from client. Exiting...\n");
		close(socket_desc);
		return 1;
	}

	// ========== Certificate Exchange ==========
	printf("========= RECEIVING CERTIFICATE ==========\n");
	receiveCert(new_socket);

	printf("========= VERIFY CLIENT CERTIFICATE =========\n");

	if (verifyFileSignature((char *)CERT_TEMP_FILE) != 1)
	{
		printf("ERROR: Client certificate signature is invalid. Exiting...\n");
		close(socket_desc);
		return 1;
	}
	else
	{
		printf("INFO: Client certificate signature is valid.\n\n");
	}

	getKeyParamsFromCert(&RSA_Client_PU, &RSA_Client_n);

	// ========== End Receive Client Certificate ==========
	printf("===== SENDING CERTIFICATE =====\n");
	sendCert(new_socket, (char *)CERT_FILE);
	printf("===== CERTIFICATE EXCHANGE COMPLETE =====\n\n");

	// Diffie-Hellman Key Exchange
	printf("===== DIFFIE-HELLMAN KEY EXCHANGE =====\n");

	requestKeyExchange(new_socket, RSA_Client_PU, RSA_Client_n);

	// ========== End Diffie-Hellman Key Exchange ==========

	// Server will start receive first
	printf("\n===== MESSAGE EXCHANGE SESSION =====\n");
	printf("WAITING FOR CLIENT MESSAGE...\n");

	while (!isExit)
	{
		bool chCipher = false;
		// Receive a message from client
		if ((read_size = recv(new_socket, client_message, sizeof(client_message), 0)) > 0)
		{
			if (read_size == -1)
			{
				printf("ERROR: receive failed\n");
				isExit = true;
				break;
			}

			printf("INFO: Client sent %d byte message:  %s\n", read_size, client_message);

			decipherMessage(SDES_KEY, client_message, read_size, &isExit, &chCipher);

			if (chCipher)
			{
				handleChangeCipherRequest(new_socket, client_message);
			}

			/*
				If the client sent an exit message with the correct key, the isExit flag will be set to true
				The exit message format is "exit+<key>", where <key> is the shared key in hexadecimal format
			*/

			if (isExit){
				break;
			}

			chCipher = false;
			// write message back to client
			messageClient(SDES_KEY, client_message, &isExit, &chCipher);
			if (chCipher)
			{
				requestChangeCipher(new_socket, client_message);
			}
			else if (send(new_socket, client_message, strlen(client_message), 0) < 0)
			{
				printf("ERROR: Send failed. Exiting...\n");
				close(new_socket);
				return 1;
			}

			if (isExit)
			{
				break;
			}

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

void correctKeyLength(const int key, char keyStr[4])
{
	// Get the last 3 digits of the integer and convert them to hexadecimal
	int lastThreeDigits = key % 1000;
	sprintf(keyStr, "%03X", lastThreeDigits); // Convert to 3 hex digits

	keyStr[3] = '\0';
}

void decipherMessage(char key[4], char client_message[1024], const int read_size, bool *isExit, bool *chCipher)
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
	else if (strncmp(tempMessage, "chcipher", 8) == 0 && strcmp(tempMessage + 8, key) == 0)
	{
		*chCipher = true;
		printf("INFO: Client requested to change cipher suite.\n");
		return;
	}

	printf("=== DECRYPTED MESSAGE ===\n");
	printf("%s\n", tempMessage);
	printf("=== END OF MESSAGE ===\n\n");
}

void messageClient(char key[4], char client_message[1024], bool *isExit, bool *chCipher)
{
	// Clear buffer
	memset(client_message, '\0', sizeof(client_message));

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
	else if (strcmp(tempMessage, "chcipher") == 0)
	{
		*chCipher = true;
		strcpy(tempMessage, "chcipher");
		strcat(tempMessage, key);
		tempMessage[strlen("chcipher") + strlen(key)] = '\0'; // Send chcipher message with key
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

void sendCert(int socket_desc, const char certFileName[])
{

	// getting file name
	if (strlen(certFileName) == 0)
	{
		char certFileName[100];
		printf("Enter certificate file name to send to server (e.g., cert.txt): ");
		fgets(certFileName, sizeof(certFileName), stdin);
		certFileName[strcspn(certFileName, "\n")] = 0; // Remove newline character
	}

	// Open cert file to send its contents to server
	FILE *certFile = fopen(certFileName, "r");
	if (!certFile)
	{
		printf("ERROR: Cannot open certificate file '%s'.\n", certFileName);
		return;
	}

	// Notify server about certificate transfer
	send(socket_desc, "CERT_TRANSFER", strlen("CERT_TRANSFER"), 0);

	// ACK from server
	char server_reply[100];
	memset(server_reply, '\0', 100); // Clear the buffer
	if (recv(socket_desc, server_reply, 100, 0) < 0)
	{
		printf("ERROR: receive failed during certificate transfer. Exiting...\n");
		return;
	}

	if (strncmp(server_reply, "CERT_TRANSFER_ACK", strlen("CERT_TRANSFER_ACK")) != 0)
	{
		printf("ERROR: Invalid ACK from server. Exiting...\n");
		return;
	}

	printf("INFO: Sending certificate file '%s' to server...\n", certFileName);

	char buffer[1024];
	// send chunks of data to server
	while (fgets(buffer, sizeof(buffer), certFile) != NULL)
	{
		// Send each line to server
		if (send(socket_desc, buffer, strlen(buffer), 0) < 0)
		{
			printf("ERROR: Failed to send certificate file data.\n");
			fclose(certFile);
			return;
		}

		// Wait for ACK from server
		memset(server_reply, '\0', 100); // Clear the buffer
		if (recv(socket_desc, server_reply, 100, 0) < 0)
		{
			printf("ERROR: receive failed during certificate transfer. Exiting...\n");
			fclose(certFile);
			return;
		}

		if (strncmp(server_reply, "CERT_LINE_ACK", strlen("CERT_LINE_ACK")) != 0)
		{
			printf("ERROR: Invalid line ACK from server. Exiting...\n");
			fclose(certFile);
			return;
		}
	}

	fclose(certFile);

	// Send transfer end message
	send(socket_desc, "CERT_TRANSFER_END", strlen("CERT_TRANSFER_END"), 0);

	printf("INFO: Certificate file sent to server.\n");
	return;
}

void receiveCert(int socket_desc)
{

	// Acknowledge the certificate transfer request
	send(socket_desc, "CERT_TRANSFER_ACK", strlen("CERT_TRANSFER_ACK"), 0);

	char client_message[1024]; // Buffer for receiving data
	memset(client_message, '\0', sizeof(client_message));

	printf("INFO: Receiving certificate file from client...\n");

	FILE *tempFile = fopen(CERT_TEMP_FILE, "w");
	if (!tempFile)
	{
		printf("ERROR: Cannot open temp file for writing.\n");
		return;
	}

	while (1)
	{
		if (recv(socket_desc, client_message, sizeof(client_message), 0) < 0)
		{
			printf("ERROR: receive failed during certificate transfer. Exiting...\n");
			fclose(tempFile);
			return;
		}

		// Check for transfer end message
		if (strncmp(client_message, "CERT_TRANSFER_END", strlen("CERT_TRANSFER_END")) == 0)
		{
			printf("INFO: Certificate transfer complete.\n");
			break;
		}

		if (send(socket_desc, "CERT_LINE_ACK", strlen("CERT_LINE_ACK"), 0) < 0) // Send ACK for each line received
		{
			printf("ERROR: send failed during certificate transfer. Exiting...\n");
			fclose(tempFile);
			return;
		}

		// Write the received line to the temp file
		if (fwrite(client_message, 1, strlen(client_message), tempFile) < strlen(client_message))
		{
			printf("ERROR: Failed to write to temporary file.\n");
			fclose(tempFile);
			return;
		}

		memset(client_message, '\0', sizeof(client_message)); // Clear the buffer for next line
	}

	fclose(tempFile);
	printf("INFO: Certificate file saved to temp_cert_file.txt\n");
	printf("Done \n");

	return;
}

void getKeyParamsFromCert(unsigned int *publicKey, unsigned int *n)
{
	FILE *certFile = fopen(CERT_TEMP_FILE, "r");
	if (!certFile)
	{
		printf("ERROR: Cannot open certificate file '%s'.\n", CERT_TEMP_FILE);
		return;
	}

	char inputBuffer[256];
	// Read through the certificate file to find the Public Key line
	while (fgets(inputBuffer, sizeof(inputBuffer), certFile) != NULL)
	{
		if (strncmp(inputBuffer, "Public Key:", 11) == 0)
		{
			// extract public key and n
			sscanf(inputBuffer, "Public Key: %u %u", publicKey, n);
			// append to valueString
			break;
		}
	}

	fclose(certFile);
}

int handleKeyExchangeRequest(int socket_desc, const int RSA_SERVER_PU, const unsigned int RSA_SERVER_n)
{
	char server_message[1024], client_message[1024];

	// receive key params from server
	recv(socket_desc, server_message, sizeof(server_message), 0);
	unsigned int enc_SDES_prime = 0, enc_SDES_alpha = 0, enc_SDES_public = 0, signature;
	sscanf(server_message, "%u %u %u %u", &enc_SDES_public, &enc_SDES_prime, &enc_SDES_alpha, &signature);

	printf("Message: %s\n", server_message);

	// verify signature
	{
		char tempHash[3];
		sprintf(server_message, "%u %u %u", enc_SDES_public, enc_SDES_prime, enc_SDES_alpha);
		CBCHash(server_message, CBC_IV, CBC_Hash_KEY, tempHash);
		unsigned int hashValue = (unsigned int)strtol(tempHash, NULL, 16);
		unsigned int decryptedSignature = modExp(signature, RSA_SERVER_PU, RSA_SERVER_n);
		if (hashValue != decryptedSignature)
		{
			printf("ERROR: Invalid signature from server. Exiting...\n");
			close(socket_desc);
			return 1;
		}
		else
		{
			printf("INFO: Valid signature from server.\n");
		}
	}

	// decrypt key params
	int SDES_prime = modExp(enc_SDES_prime, rsa_private_key, n);
	int SDES_alpha = modExp(enc_SDES_alpha, rsa_private_key, n);
	int SDES_server_publicKey = modExp(enc_SDES_public, rsa_private_key, n);
	int SDES_private = rand() % (SDES_prime - 2) + 3; // private key in range [3, prime-2]
	printf("INFO: Received Server's Diffie-Hellman Public Key: %u\n", SDES_server_publicKey);
	printf("INFO: Using prime number: %u and alpha: %u for Diffie-Hellman Key Exchange\n", SDES_prime, SDES_alpha);
	printf("INFO: Diffie-Hellman Private Key: %u\n", SDES_private);

	int SDES_public = DiffHellman_GenPublicKey(&SDES_private, &SDES_alpha, &SDES_prime);
	printf("INFO: Generated Diffie-Hellman Public Key: %u\n\n", SDES_public);

	// send public key to server
	enc_SDES_public = modExp(SDES_public, RSA_SERVER_PU, RSA_SERVER_n);
	{
		char tempHash[3];
		sprintf(client_message, "%u", enc_SDES_public);
		CBCHash(client_message, CBC_IV, CBC_Hash_KEY, tempHash);
		unsigned int hashValue = (unsigned int)strtol(tempHash, NULL, 16);
		unsigned int signature = modExp(hashValue, rsa_private_key, n);
		sprintf(client_message, "%u %u", enc_SDES_public, signature);
	}
	printf("Sending message: %s\n", client_message);
	send(socket_desc, client_message, strlen(client_message), 0);

	// generate shared key
	unsigned int SDES_SharedKey = DiffHellman_GenShareKey(SDES_server_publicKey, SDES_private, SDES_prime);
	printf("INFO: Generated Shared Key: %u\n", SDES_SharedKey);
	// Correct key length to 3 hex digits
	correctKeyLength(SDES_SharedKey, SDES_KEY);
	printf("INFO: Using SDES Key: %s\n\n", SDES_KEY);

	return 0;
}

int requestKeyExchange(int socket_desc, const unsigned int RSA_Client_PU, const unsigned int RSA_Client_n)
{
	char server_message[1024], client_message[1024];
	int DF_prime = 0, DF_alpha = 0, DF_privateKey = 0, DF_publicKey = 0, DF_sharedKey = -1;

	DF_publicKey = DiffHellman_GenPublicKey(&DF_privateKey, &DF_alpha, &DF_prime);
	printf("INFO: Using alpha: %d and prime: %d\n", DF_alpha, DF_prime);
	printf("INFO: Private Key (exp): %d\n", DF_privateKey);
	printf("INFO: Public Key: %d\n\n", DF_publicKey);

	unsigned int enc_DF_publicKey = modExp(DF_publicKey, RSA_Client_PU, RSA_Client_n);
	unsigned int enc_DF_prime = modExp(DF_prime, RSA_Client_PU, RSA_Client_n);
	unsigned int enc_DF_alpha = modExp(DF_alpha, RSA_Client_PU, RSA_Client_n);

	sprintf(server_message, "%u %u %u", enc_DF_publicKey, enc_DF_prime, enc_DF_alpha);

	// hash the message
	{
		char tempHash[3];
		CBCHash(server_message, CBC_IV, CBC_Hash_KEY, tempHash);
		unsigned int hashValue = (unsigned int)strtol(tempHash, NULL, 16);
		unsigned int signature = modExp(hashValue, rsa_private_key, n);
		sprintf(server_message, "%u %u %u %u", enc_DF_publicKey, enc_DF_prime, enc_DF_alpha, signature);
	}

	// send to client
	printf("Sending message: %s\n", server_message);
	send(socket_desc, server_message, strlen(server_message), 0);
	printf("INFO: Sent encrypted Diffie-Hellman parameters to client.\n");

	// receive client's public key
	memset(client_message, '\0', sizeof(client_message));
	recv(socket_desc, client_message, sizeof(client_message), 0);
	{
		printf("Message: %s\n", client_message);
		unsigned int signature = 0;
		sscanf(client_message, "%u %u", &enc_DF_publicKey, &signature);

		sprintf(client_message, "%u", enc_DF_publicKey);

		char tempHash[3];
		CBCHash(client_message, CBC_IV, CBC_Hash_KEY, tempHash);
		unsigned int hashValue = (unsigned int)strtol(tempHash, NULL, 16);
		unsigned int decryptedSignature = modExp(signature, RSA_Client_PU, RSA_Client_n);

		if (hashValue != decryptedSignature)
		{
			printf("ERROR: Invalid signature from client. Exiting...\n");
			close(socket_desc);
			return 1;
		}
		else
		{
			printf("INFO: Valid signature from client.\n");
		}
	}

	int DF_client_publicKey = modExp(enc_DF_publicKey, rsa_private_key, n);
	printf("INFO: Received Client's Diffie-Hellman Public Key: %d\n", DF_client_publicKey);
	DF_sharedKey = DiffHellman_GenShareKey(DF_client_publicKey, DF_privateKey, DF_prime);

	printf("INFO: Generated Shared Secret Key: %d\n", DF_sharedKey);
	correctKeyLength(DF_sharedKey, SDES_KEY);
	printf("INFO: SDES Key (last 3 hex digits of shared key): %s\n\n", SDES_KEY);

	return 0;
}

void requestChangeCipher(int socket_desc, char message_server[1024])
{	
	//notify server about change cipher request
	send(socket_desc, message_server, strlen(message_server), 0);

	// store old key
	char old_key[4];
	strcpy(old_key, SDES_KEY);

	// generate new key
	unsigned int new_key_int = rand() % 1024 + 3; // new key in range [3, 1023]
	correctKeyLength(new_key_int, SDES_KEY);

	printf("New int SDES Key: %u. In hex: %s\n", new_key_int, SDES_KEY);

	// wait for server to ack
	recv(socket_desc, message_server, 1024, 0);
	if (strncmp(message_server, "chcipher_ack", strlen("chcipher_ack")) != 0)
	{
		printf("ERROR: Invalid change cipher ACK from server. Exiting...\n");
		close(socket_desc);
		return;
	}

	// generate new RSA key
	unsigned int new_p = 0, new_q = 0, new_n = 0;
	unsigned int new_rsa_public_key = 0, new_rsa_private_key = 0;

	// getting two distinct prime numbers
	do
	{
		printf("Enter two distinct prime numbers (p and q): ");
		fgets(message_server, sizeof(message_server), stdin);
		sscanf(message_server, "%u %u", &new_p, &new_q);
		printf("Checking if p and q are coprime...\n");

		// checking if both numbers are prime
		if (isPrime(p) == false || isPrime(q) == false)
		{
			printf("One or both numbers are not prime. Please enter again.\n");
			continue;
		}

		if (gcd(p, q) != 1)
		{
			printf("p and q are not coprime. Please enter again.\n");
		}
		else
		{
			printf("p and q are coprime. Continue...\n\n");
			break;
		}

	} while (1);

	// setting n and totient_n
	new_n = new_p * new_q;
	unsigned int new_totient_n = (new_p - 1) * (new_q - 1);

	// generating public and private keys
	new_rsa_private_key = RSA_KeyGen(new_p, new_q, &new_rsa_public_key);
	printf("Generated NEW RSA Public Key: %u\n", new_rsa_public_key);
	printf("Generated NEW RSA Private Key: %u\n\n", new_rsa_private_key);

	// sign key parameters
	char tempHash[3];
	sprintf(message_server, "%d %u %u", new_key_int, new_rsa_public_key, new_n);
	CBCHash(message_server, CBC_IV, CBC_Hash_KEY, tempHash);
	unsigned int hashValue = (unsigned int)strtol(tempHash, NULL, 16);
	unsigned int signature = modExp(hashValue, rsa_private_key, n);

	// send new key params to server
	sprintf(message_server, "%d %u %u %u", new_key_int, new_rsa_public_key, new_n, signature);
	printf("INFO: sending message: %s\n", message_server);

	// encrypt message
	char hexMessage[2049];						  // 2 hex digits per character + null terminator
	memset(hexMessage, '\0', sizeof(hexMessage)); // Clear the buffer
	for (int i = 0; i < strlen(message_server); i++)
	{
		char tempHex[3];											// 2 hex digits + null terminator
		sprintf(tempHex, "%02X", (unsigned char)message_server[i]); // Convert next character to hex
		SDES(tempHex, old_key, tempHex);							// Encrypt the hex using SDES and the old key
		strcat(hexMessage, tempHex);								// Append the encrypted hex to the final message
	}

	send(socket_desc, hexMessage, strlen(hexMessage), 0);

	return;
}

void handleChangeCipherRequest(int socket_desc, char message_server[1024])
{

	char old_key[4];
	strcpy(old_key, SDES_KEY);

	// acknowledge change cipher request
	send(socket_desc, "chcipher_ack", strlen("chcipher_ack"), 0);

	// receive new key params from client
	recv(socket_desc, message_server, 1024, 0);

	// decrypt message
	char tempMessage[strlen(message_server) / 2 + 1];	// Each character is 2 hex digits, +1 for null terminator
	memset(tempMessage, '\0', sizeof(tempMessage));		// Clear the buffer
	for (int i = 0; i < strlen(message_server); i += 2) // Process 2 hex digits at a time
	{
		char tempHex[3] = {'\0'}; // 2 hex digits + null terminator
		strncpy(tempHex, message_server + i, 2);
		SDES_decrypt(tempHex, old_key, tempHex);

		// Convert decrypted hex back to a character
		char tempChar = (char)strtol(tempHex, NULL, 16); // Convert hex to char
		tempMessage[i / 2] = tempChar;
	}
	tempMessage[strlen(message_server) / 2] = '\0'; // Null terminate the decrypted message
	strcpy(message_server, tempMessage);

	int new_key_int = 0;
	unsigned int new_rsa_public_key = 0, new_n = 0, signature = 0;
	sscanf(message_server, "%d %u %u %u", &new_key_int, &new_rsa_public_key, &new_n, &signature);

	// verify signature
	{
		char tempHash[3];
		sprintf(message_server, "%u %u %u", new_key_int, new_rsa_public_key, new_n);
		CBCHash(message_server, CBC_IV, CBC_Hash_KEY, tempHash);
		unsigned int hashValue = (unsigned int)strtol(tempHash, NULL, 16);
		unsigned int decryptedSignature = modExp(signature, RSA_Client_PU, RSA_Client_n);
		if (hashValue != decryptedSignature)
		{
			printf("ERROR: Invalid signature from client. Exiting...\n");
			close(socket_desc);
			return;
		}
		else
		{
			printf("INFO: Valid signature from client.\n");
		}
	}

	// set new key
	correctKeyLength(new_key_int, SDES_KEY);
	printf("INFO: Changed SDES Key to: %s\n", SDES_KEY);
	printf("INFO: received RSA Public Key: %u and n: %u\n", new_rsa_public_key, new_n);

	return;
}