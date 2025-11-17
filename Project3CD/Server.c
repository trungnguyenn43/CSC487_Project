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
#include "UtilFunction.h"
#include "certs.h"

// Function prototypes
void correctKeyLength(const int, char[4]);
int clientRequest(char [100]);
void receiveCertFile(int);
void receiveCertChainFile(int);
void receiveCRLFile(int);

// Define server port
const int SERVER_PORT = 49152; // Port number of the server
static char CBC_Hash_KEY[4] = "CCB"; //key for CBC Hash
static char CBC_IV[3] = "1A"; // IV for CBC Hash
const char CRL_FILE_NAME[] = "crl_list.txt";


int main(int argc, char *argv[])
{	
	int socket_desc, new_socket, c, read_size, i;
	struct sockaddr_in server, client;
	char client_message[1024];

	printf("========= RSA KEY GEN ==========\n");
	//====================================
	// RSA Key GEN
	//====================================
	unsigned int rsa_public_key = 0, rsa_private_key = 0;
	unsigned int p, q, n, totient_n;

	//getting two distinct prime numbers
	do{
		printf("Enter two distinct prime numbers (p and q): ");
		scanf("%u %u", &p, &q);
		printf("Checking if p and q are coprime...\n");
		getchar(); // clear newline character from input buffer

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

	// ====================================
	// Get public key from client
	// ====================================
	if(recv(new_socket, client_message, 100, 0) < 0)
	{
		printf("ERROR: receive failed during RSA key exchange. Exiting...\n");
		close(new_socket);
		return 1;
	}
	int client_rsa_public_key, client_n;
	sscanf(client_message, "%u %u", &client_rsa_public_key, &client_n); // just to check if it's a valid integer
	printf("INFO: Client sent RSA public key: %s\n\n", client_message);

	printf("========= Diff Hellman Key Exchange ==========\n");
	// generate and display public key
	int prime = 0;
	int exp = 0;
	int alpha = 0;
	int SYM_publicKey = DiffHellman_GenPublicKey(&exp, &alpha, &prime);
	int shareKey = -1;
	if (SYM_publicKey == -1)
	{
		printf("ERROR: Unable to generate public key. Exiting...\n");
		close(new_socket);
		return 1;
	}
    printf("INFO: Using alpha: %d\n", alpha);
	printf("INFO: Using private exponent: %d\n", exp);
	printf("INFO: Using prime number: %d\n", prime);
	printf("INFO: Public key: %d\n\n", SYM_publicKey);

	// ====================================
	// Generating RSA signature for public key
	// ====================================
	// Hash using CTR CBC
	printf("============= SIGNATURE GENERATION ============\n");
	printf("INFO: Generating RSA signature for public key...\n");
	sprintf(client_message, "%d %d %d", SYM_publicKey, prime, alpha);
	char tempOutputBuffer[100];

	CBCHash(client_message, CBC_IV, CBC_Hash_KEY, tempOutputBuffer);

	// Convert hash to numeric value
	int hashValue = (int)strtol(tempOutputBuffer, NULL, 16);
	printf("INFO: CBC Hash of public key, prime, and alpha: %d\n", hashValue);
	
	//Encrypt the hash with RSA private key to create signature
	unsigned int signature = modExp(hashValue, rsa_private_key, n);
	printf("INFO: Generated RSA signature: %u\n", signature);
	printf("============ END OF SIGNATURE GENERATION ============\n\n");
	
	// ====================================
	// send the public key to client
	// ====================================
	sprintf(client_message, "%d %d %d %d %u %u", SYM_publicKey, prime, alpha, rsa_public_key, n, signature);
	write(new_socket, client_message, strlen(client_message));

	// wait for client to send its public key with signature
	memset(client_message, '\0', 100); // Clear the buffer
	if ((read_size = recv(new_socket, client_message, 100, 0)) < 0)
	{
		printf("ERROR: receive failed");
		close(new_socket);
		return 1;
	}

	int clientPublicKey;
	int tempPrime, tempAlpha;
	sscanf(client_message, "%d %d %d %u", &clientPublicKey, &tempPrime, &tempAlpha, &signature); // just to check if it's a valid integer
	printf("INFO: Client sent: %s\n", client_message);

	// ==========
	// Verifying Signature
	// ===========
	printf("============ SIGNATURE VERIFICATION ============\n");
	sprintf(client_message, "%d %d %d", clientPublicKey, tempPrime, tempAlpha);
	CBCHash(client_message, CBC_IV, CBC_Hash_KEY, tempOutputBuffer);
	// Convert hash to numeric value
	hashValue = (int)strtol(tempOutputBuffer, NULL, 16);
	printf("INFO: CBC Hash of public key, prime, and alpha: %d\n", hashValue);
	unsigned int decryptedHash = modExp(signature, client_rsa_public_key, client_n);
	printf("INFO: Decrypted RSA signature: %u\n", decryptedHash);

	if(decryptedHash != hashValue){
		printf("WARNING: RSA signature verification failed! Be cautious...\n");
		close(new_socket);
		return 1;
	} else {
		printf("INFO: RSA signature verification succeeded. Continuing...\n");
	}
	
	printf("============ END OF SIGNATURE VERIFICATION ============\n\n");
	
	shareKey = DiffHellman_GenShareKey(clientPublicKey, exp, prime);
	printf("INFO: Shared key: %d\n", shareKey);

	char key[4];					// 3 hex digits + null terminator
	correctKeyLength(shareKey, key); // Convert int to 3-char string with leading zeros if necessary

	printf("INFO: Using SDES with shared key: %s\n", key);

	memset(client_message, '\0', 100); // Clear the buffer

	// Server will start receive first
	printf("\n===== MESSAGE EXCHANGE SESSION =====\n");
	
	while (!isExit)
	{	
		printf("WAITING FOR CLIENT MESSAGE...\n");
		recv(new_socket, client_message, 1024, 0) > 0;
		int requestType = clientRequest(client_message);
		switch(requestType){
			case 0:
				printf("INFO: Client requested to exit the session.\n");
				isExit = true;
				break;
			case 1:
				printf("INFO: Client requested certificate transfer.\n");
				receiveCertFile(new_socket);
				break;
			case 2:
				printf("INFO: Client requested certificate chain transfer.\n");
				receiveCertChainFile(new_socket);
				break;
			case 3:
				printf("INFO: Client requested CRL transfer.\n");
				receiveCRLFile(new_socket);
				break;
			default:
				printf("WARNING: Unknown request from client: %s\n", client_message);
				break;
		}
		if(isExit){
			break;
		}
		printf("======================================\n");
	}

	// Free character arrays
	memset(client_message, '\0', 100); // Clear the buffer

	// Free the socket pointer
	close(new_socket);
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

int clientRequest(char inputMessage[100]){
	
	int requestType = -99; // default invalid request
	if (strncmp(inputMessage, "CERT_TRANSFER", strlen("CERT_TRANSFER")) == 0)
	{
		requestType = 1;
	}
	else if(strncmp(inputMessage, "CERT_CHAIN_TRANSFER", strlen("CERT_CHAIN_TRANSFER")) == 0)
	{
		requestType = 2;
	}
	else if(strncmp(inputMessage, "CRL_TRANSFER", strlen("CRL_TRANSFER")) == 0)
	{
		requestType = 3;
	}
	else if(strncmp(inputMessage, "EXIT", strlen("EXIT")) == 0)
	{
		requestType = 0; // exit request
	}
	
	return requestType;
}

void receiveCertFile(int socket_desc) {

    // Acknowledge the certificate transfer request
    send(socket_desc, "CERT_TRANSFER_ACK", strlen("CERT_TRANSFER_ACK"), 0);
	
    char client_message[1024]; // Buffer for receiving data
    memset(client_message, '\0', sizeof(client_message));
	
    printf("INFO: Receiving certificate file from client...\n");

	FILE *tempFile = fopen("SV_temp_cert_file.txt", "wb");
	if (!tempFile) {
		printf("ERROR: Cannot open temp file for writing.\n");
		return;
	}

	while (1) {
		int bytesReceived = recv(socket_desc, client_message, sizeof(client_message), 0);
		if (bytesReceived <= 0) {
			printf("ERROR: Failed to receive certificate file data.\n");
			break;
		}
		// Check for end of transfer signal
		if (bytesReceived >= strlen("CERT_TRANSFER_END") &&
			memcmp(client_message, "CERT_TRANSFER_END", strlen("CERT_TRANSFER_END")) == 0) {
			break;
		}
		fwrite(client_message, 1, bytesReceived, tempFile);
	}

	fclose(tempFile);
	printf("INFO: Certificate file saved to temp_cert_file.txt\n");
	printf("Done \n");

	return;
}

void receiveCertChainFile(int socket_desc) {
	
	// Acknowledge the chain transfer request
	send(socket_desc, "CERT_CHAIN_TRANSFER_ACK", strlen("CERT_CHAIN_TRANSFER_ACK"), 0);

	char client_message[1024];
	memset(client_message, '\0', sizeof(client_message));

	printf("INFO: Receiving certificate chain file from client...\n");

	FILE *tempFile = fopen("SV_temp_chain_file.txt", "wb");
	if (!tempFile) {
		printf("ERROR: Cannot open temp chain file for writing.\n");
		return;
	}

	while (1) {
		int bytesReceived = recv(socket_desc, client_message, sizeof(client_message), 0);
		if (bytesReceived <= 0) {
			printf("ERROR: Failed to receive certificate chain file data.\n");
			break;
		}
		// Check for end of transfer signal
		if (bytesReceived >= strlen("CERT_CHAIN_TRANSFER_END") &&
			memcmp(client_message, "CERT_CHAIN_TRANSFER_END", strlen("CERT_CHAIN_TRANSFER_END")) == 0) {
			break;
		}
		fwrite(client_message, 1, bytesReceived, tempFile);
	}

	fclose(tempFile);
	printf("INFO: Certificate chain file saved to temp_cert_chain_file.txt\n");
	printf("Done \n");
	return;
}

void receiveCRLFile(int socket_desc) {
	// Acknowledge the CRL transfer request
	send(socket_desc, "CRL_TRANSFER_ACK", strlen("CRL_TRANSFER_ACK"), 0);

	char client_message[1024];
	memset(client_message, '\0', sizeof(client_message));

	printf("INFO: Receiving CRL file from client...\n");

	FILE *tempFile = fopen("SV_temp_crl_file.txt", "wb");
	if (!tempFile) {
		printf("ERROR: Cannot open temp CRL file for writing.\n");
		return;
	}

	while (1) {
		int bytesReceived = recv(socket_desc, client_message, sizeof(client_message), 0);
		if (bytesReceived <= 0) {
			printf("ERROR: Failed to receive CRL file data.\n");
			break;
		}
		// Check for end of transfer signal
		if (bytesReceived >= strlen("CRL_TRANSFER_END") &&
			memcmp(client_message, "CRL_TRANSFER_END", strlen("CRL_TRANSFER_END")) == 0) {
			break;
		}
		fwrite(client_message, 1, bytesReceived, tempFile);
	}

	fclose(tempFile);
	printf("INFO: CRL file saved to SV_temp_crl_file.txt\n");
	printf("Done \n");
	return;
}