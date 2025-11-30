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

const char CERT_FILE[] = "client_cert.txt";
const char CERT_TEMP_FILE[] = "CL_temp_cert_file.txt";

unsigned int rsa_public_key = 0, rsa_private_key = 0;
unsigned int p = 61, q = 53, n, totient_n;
static char SDES_KEY[4] = "000"; // SDES key placeholder

void correctKeyLength(const int, char[4]);
void messageServer(char[4], char[1024], bool *, bool*);
void decipherMessage(char[4], char[1024], const int, bool *, bool*);
void receiveCert(int);
void sendCert(int, const char []);
void getKeyParamsFromCert(unsigned int *, unsigned int *);
int handleKeyExchangeRequest(int , const int , const unsigned int );
int requestKeyExchange(int , const unsigned int , const unsigned int );


int main(int argc, char *argv[])
{
	srand(time(NULL)); 
	
	printf("========= RSA KEY GEN ==========\n");

	//================
	// RSA Key Gen
	//================
	

	//getting two distinct prime numbers
	do{
		// printf("Enter two distinct prime numbers (p and q): ");
		// scanf("%u %u", &p, &q);
		printf("Checking if p and q are coprime...\n");
		// getchar(); // clear newline character from input buffer

		//checking if both numbers are prime
		if(isPrime(p) == false || isPrime(q) == false){
			printf("One or both numbers are not prime. Please enter again.\n");
			continue;
		}

		if(gcd(p, q) != 1){
			printf("p and q are not coprime. Please enter again.\n");
		} else {
			printf("p and q are coprime. Continue...\n\n");
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

	// =================
	// Generating cert
	// =================
	printf("============= CERTIFICATE GENERATION ============\n");
	certGen((char*) CERT_FILE, rsa_private_key, rsa_public_key, n);
	
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

	int socket_desc; // file descripter returned by socket command
	int read_size;
	struct sockaddr_in server;					 // in arpa/inet.h
	char server_message[1024], client_message[1024]; // will need to be bigger

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

	// ========= CERTIFICATE EXCHANGE ========
	printf("========= SENDING CERTIFICATE ==========\n");
	sendCert(socket_desc, (char*) CERT_FILE);
	
	// ========= End SENDING Certificate Exchange ==========
	printf("========= RECEIVING CERTIFICATE ==========\n");

	//wait for client to send certificate signal
	recv(socket_desc, client_message, sizeof(client_message), 0);
	if (strncmp(client_message, "CERT_TRANSFER", strlen("CERT_TRANSFER")) != 0)
	{
		printf("ERROR: Invalid certificate transfer request from client. Exiting...\n");
		close(socket_desc);
		return 1;
	}

	receiveCert(socket_desc);
	printf("========= VERIFY SERVER CERTIFICATE =========\n");
	if (verifyFileSignature((char*) CERT_TEMP_FILE) != 1)
	{
		printf("ERROR: Server certificate signature is invalid. Exiting...\n");
		close(socket_desc);
		return 1;
	}
	else
	{
		printf("INFO: Server certificate signature is valid.\n\n");
	}

	unsigned int RSA_SERVER_PU = 0, RSA_SERVER_n = 0;
	getKeyParamsFromCert(&RSA_SERVER_PU, &RSA_SERVER_n);

	printf("===== CERTIFICATE EXCHANGE COMPLETE =====\n\n");

	printf("===== DIFFIE-HELLMAN KEY EXCHANGE =====\n");

	handleKeyExchangeRequest(socket_desc, RSA_SERVER_PU, RSA_SERVER_n);

	printf("\n===== MESSAGE EXCHANGE SESSION =====\n");

	bool isExit = false;
	while (!isExit)
	{	
		bool chCipher = false;
		messageServer(SDES_KEY, client_message, &isExit, &chCipher);
		
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
		memset(server_message, '\0', 100); // Clear the buffer for next message

		if ((read_size = recv(socket_desc, server_message, 1024, 0)) < 0)
		{
			printf("ERROR: receive failed");
			close(socket_desc);
			return 1;
		}
		else
		{
			// print out original message
			printf("INFO: Server sent %d byte message:  %s\n", read_size, server_message);
			strcpy(client_message, server_message);
			decipherMessage(SDES_KEY, client_message, read_size, &isExit, &chCipher);

			if (isExit)
				break;

			memset(server_message, '\0', 100); // Clear the buffer for next message
		}
	}

	close(socket_desc); // Close the socket
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

void messageServer(char key[4], char client_message[1024], bool *isExit, bool *chCipher)
{
	// Clear buffer
	memset(client_message, '\0', sizeof(*client_message));

	char tempMessage[1024];
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
	else if(strcmp(tempMessage, "chcipher") == 0){
		*chCipher = true;
		strcpy(tempMessage, "chcipher\0");
		strcat(tempMessage, key);						   // Send chcipher message with key
	}

	char hexMessage[2049];						  // 2 hex digits per character + null terminator
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

int handleKeyExchangeRequest(int socket_desc, const int RSA_SERVER_PU, const unsigned int RSA_SERVER_n)
{
	char server_message[1024], client_message[1024];
	
	//receive key params from server
	recv(socket_desc, server_message, sizeof(server_message), 0);
	unsigned int enc_SDES_prime = 0, enc_SDES_alpha = 0, enc_SDES_public = 0, signature;
	sscanf(server_message, "%u %u %u %u", &enc_SDES_public, &enc_SDES_prime, &enc_SDES_alpha, &signature);

	printf("Message: %s\n", server_message);
	
	//verify signature
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

	//decrypt key params
	int SDES_prime = modExp(enc_SDES_prime, rsa_private_key, n);
	int SDES_alpha = modExp(enc_SDES_alpha, rsa_private_key, n);
	int SDES_server_publicKey = modExp(enc_SDES_public, rsa_private_key, n);
	int SDES_private = rand() % (SDES_prime - 2) + 3; // private key in range [3, prime-2]
	printf("INFO: Received Server's Diffie-Hellman Public Key: %u\n", SDES_server_publicKey);
	printf("INFO: Using prime number: %u and alpha: %u for Diffie-Hellman Key Exchange\n", SDES_prime, SDES_alpha);
	printf("INFO: Diffie-Hellman Private Key: %u\n", SDES_private);
	
	int SDES_public = DiffHellman_GenPublicKey(&SDES_private, &SDES_alpha, &SDES_prime);
	printf("INFO: Generated Diffie-Hellman Public Key: %u\n\n", SDES_public);

	//send public key to server
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

	//generate shared key
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
	
	//send to client
	printf("Sending message: %s\n", server_message);
	send(socket_desc, server_message, strlen(server_message), 0);
	printf("INFO: Sent encrypted Diffie-Hellman parameters to client.\n");
	
	//receive client's public key
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

void sendCert(int socket_desc, const char certFileName[]){
	
	//getting file name
	if(strlen(certFileName) == 0){
		char certFileName[100];
		printf("Enter certificate file name to send to server (e.g., cert.txt): ");
		fgets(certFileName, sizeof(certFileName), stdin);
		certFileName[strcspn(certFileName, "\n")] = 0; // Remove newline character
	}

	// Open cert file to send its contents to server
	FILE *certFile = fopen(certFileName, "r");
	if (!certFile) {
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

	if(strncmp(server_reply, "CERT_TRANSFER_ACK", strlen("CERT_TRANSFER_ACK")) != 0){
		printf("ERROR: Invalid ACK from server. Exiting...\n");
		return;
	}

	printf("INFO: Sending certificate file '%s' to server...\n", certFileName);

	char buffer[1024];
	//send chunks of data to server
	while(fgets(buffer, sizeof(buffer), certFile) != NULL) {
		// Send each line to server
		if (send(socket_desc, buffer, strlen(buffer), 0) < 0) {
			printf("ERROR: Failed to send certificate file data.\n");
			fclose(certFile);
			return;
		}

		// Wait for ACK from server
		memset(server_reply, '\0', 100); // Clear the buffer
		if (recv(socket_desc, server_reply, 100, 0) < 0) {
			printf("ERROR: receive failed during certificate transfer. Exiting...\n");
			fclose(certFile);
			return;
		}

		if (strncmp(server_reply, "CERT_LINE_ACK", strlen("CERT_LINE_ACK")) != 0) {
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

void receiveCert(int socket_desc) {

    // Acknowledge the certificate transfer request
    send(socket_desc, "CERT_TRANSFER_ACK", strlen("CERT_TRANSFER_ACK"), 0);
	
    char client_message[1024]; // Buffer for receiving data
    memset(client_message, '\0', sizeof(client_message));
	
    printf("INFO: Receiving certificate file from client...\n");

	FILE *tempFile = fopen(CERT_TEMP_FILE, "w");
	if (!tempFile) {
		printf("ERROR: Cannot open temp file for writing.\n");
		return;
	}

	while(1){
		if(recv(socket_desc, client_message, sizeof(client_message), 0) < 0){
			printf("ERROR: receive failed during certificate transfer. Exiting...\n");
			fclose(tempFile);
			return;
		}

		// Check for transfer end message
		if (strncmp(client_message, "CERT_TRANSFER_END", strlen("CERT_TRANSFER_END")) == 0) {
			printf("INFO: Certificate transfer complete.\n");
			break;
		}

		if(send(socket_desc, "CERT_LINE_ACK", strlen("CERT_LINE_ACK"), 0) < 0) // Send ACK for each line received
		{
			printf("ERROR: send failed during certificate transfer. Exiting...\n");
			fclose(tempFile);
			return;
		}

		// Write the received line to the temp file
		if (fwrite(client_message, 1, strlen(client_message), tempFile) < strlen(client_message)) {
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
	if (!certFile) {
		printf("ERROR: Cannot open certificate file '%s'.\n", CERT_TEMP_FILE);
		return;
	}

	char inputBuffer[256];
	// Read through the certificate file to find the Public Key line
	while (fgets(inputBuffer, sizeof(inputBuffer), certFile) != NULL) {
		if (strncmp(inputBuffer, "Public Key:", 11) == 0) {
			// extract public key and n
            sscanf(inputBuffer, "Public Key: %u %u", publicKey, n);
            // append to valueString
			break;
		}
	}

	fclose(certFile);
}

