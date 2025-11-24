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
const char CRL_FILE_NAME[] = "crl.txt";
unsigned int rsa_public_key = 0, rsa_private_key = 0;
unsigned int p, q, n, totient_n;

void correctKeyLength(const int, char[4]);
int getAction();
void sendCertToServer(int socket_desc, char key[4]);
void sendCertChainToServer(int socket_desc, char key[4]);
void sendCRLToServer(int socket_desc);

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
		p = 53;
		q = 11;
		printf("Checking if p and q are co-prime...\n");
		// getchar(); // clear newline character from input buffer

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

	// CRL Load
	crlInfo crlFileInfo;
	strcpy(crlFileInfo.crlFileName, CRL_FILE_NAME);

	crlEntry crlEntries[100];
	printf("========= CRL LOAD ==========\n");
	if(loadCRLEntry(&crlFileInfo, crlEntries, rsa_private_key, rsa_public_key, n) != 1){
        printf("Load CRL entries failed. Exiting program!\n");
		close(socket_desc);
        return -1;
    }


	// MESSAGE SESSION

	while (!isExit)
	{
		int action = getAction();
		switch(action){
			case 1:
				certGen(rsa_private_key, rsa_public_key, n);
				break;
			case 2:
				sendCertToServer(socket_desc, key);
				break;
			case 3:
				createCertChain(rsa_private_key, rsa_public_key, n);
				break;
			case 4:
				sendCertChainToServer(socket_desc, key);
				break;
			case 5: 
				newCRLFile(crlFileInfo.crlFileName, rsa_private_key, rsa_public_key, n);
				break;
			
			case 6:
				addCRLEntry(crlEntries, &crlFileInfo.numEntries);
				saveCRL(&crlFileInfo, crlEntries, rsa_private_key, rsa_public_key, n);
				break;
			
			case 7:
				printf("Enter Certificate Serial Number to remove from CRL: ");
				fgets(inputBuffer, sizeof(inputBuffer), stdin);
				// remove newline character from fgets
				inputBuffer[strcspn(inputBuffer, "\n")] = 0;
				rmCRLEntry(crlEntries, &crlFileInfo.numEntries, inputBuffer);
				saveCRL(&crlFileInfo, crlEntries, rsa_private_key, rsa_public_key, n);
				break;
			
			case 8:
				sendCRLToServer(socket_desc);
				break;
			case 9:
				isExit = true;
				send(socket_desc, "EXIT_RQ", strlen("EXIT_RQ"), 0);
				printf("Exiting program...\n");
				break;
			default:
				printf("Invalid action. Please try again.\n");
				break;
		}
	}

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

int getAction(){
	int choice = -1;
	char inputBuffer[10];
	printf("\n===== Operation Menu =====\n");
	printf("1. Create cert\n");
	printf("2. Send cert to server\n");
	printf("3. Create chain of certs\n");
	printf("4. Send chain of certs to server\n");
	printf("5. Create new CRL file\n");
	printf("6. Add revoked cert\n");
	printf("7. Remove revoked cert\n");
	printf("8. Send CRL to server\n");
	printf("9. Exit\n");
	printf("Enter your choice: ");

	fgets(inputBuffer, sizeof(inputBuffer), stdin);
	if(sscanf(inputBuffer, "%d", &choice) != 1){
		printf("Invalid input. Please enter a number.\n");
		choice = -1; // invalid input
	}

	return choice;
}

void sendCertToServer(int socket_desc, char key[4]){
	
	//getting file name
	char certFileName[100];
	printf("Enter certificate file name to send to server (e.g., cert.txt): ");
	fgets(certFileName, sizeof(certFileName), stdin);
	certFileName[strcspn(certFileName, "\n")] = 0; // Remove newline character

	// Open cert file to send its contents to server
	FILE *certFile = fopen(certFileName, "rb");
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
	size_t bytesRead;
	while ((bytesRead = fread(buffer, 1, sizeof(buffer), certFile)) > 0) {
		if (send(socket_desc, buffer, bytesRead, 0) < 0) {
			printf("ERROR: Failed to send certificate file data.\n");
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

void sendCertChainToServer(int socket_desc, char key[4]) {
	// Get chain file name
	char chainFileName[100];
	printf("Enter certificate chain file name to send to server (e.g., chain.txt): ");
	fgets(chainFileName, sizeof(chainFileName), stdin);
	chainFileName[strcspn(chainFileName, "\n")] = 0; // Remove newline

	FILE *chainFile = fopen(chainFileName, "rb");
	if (!chainFile) {
		printf("ERROR: Cannot open certificate chain file '%s'.\n", chainFileName);
		return;
	}

	// Notify server about chain transfer
	send(socket_desc, "CERT_CHAIN_TRANSFER", strlen("CERT_CHAIN_TRANSFER"), 0);

	// Wait for ACK from server
	char server_reply[1024];
	memset(server_reply, '\0', sizeof(server_reply));
	if (recv(socket_desc, server_reply, sizeof(server_reply), 0) < 0) {
		printf("ERROR: receive failed during chain transfer. Exiting...\n");
		fclose(chainFile);
		return;
	}

	if (strncmp(server_reply, "CERT_CHAIN_TRANSFER_ACK", strlen("CERT_CHAIN_TRANSFER_ACK")) != 0) {
		printf("ERROR: Invalid ACK from server. Exiting...\n");
		fclose(chainFile);
		return;
	}

	printf("INFO: Sending certificate chain file '%s' to server...\n", chainFileName);

	char buffer[4096];
	size_t bytesRead;
	while ((bytesRead = fread(buffer, 1, sizeof(buffer), chainFile)) > 0) {
		if (send(socket_desc, buffer, bytesRead, 0) < 0) {
			printf("ERROR: Failed to send certificate chain file data.\n");
			fclose(chainFile);
			return;
		}
	}

	fclose(chainFile);

	// Send transfer end message
	send(socket_desc, "CERT_CHAIN_TRANSFER_END", strlen("CERT_CHAIN_TRANSFER_END"), 0);

	printf("INFO: Certificate chain file sent to server.\n");
	printf("Done! Waiting verification result\n");

	memset(server_reply, '\0', sizeof(server_reply));
	if (recv(socket_desc, server_reply, sizeof(server_reply), 0) > 0) {
		printf("Server response:\n%s\n", server_reply);
	} else {
		printf("ERROR: Failed to receive server response.\n");
	}

	return;
}

void sendCRLToServer(int socket_desc) {
	// Get CRL file name
	char crlFileName[256];
	printf("Enter CRL file name to send to server (e.g., crl.txt): ");
	fgets(crlFileName, sizeof(crlFileName), stdin);
	crlFileName[strcspn(crlFileName, "\n")] = 0;

	FILE *crlFile = fopen(crlFileName, "rb");
	if (!crlFile) {
		printf("ERROR: Cannot open CRL file '%s'.\n", crlFileName);
		return;
	}

	// Notify server about CRL transfer
	send(socket_desc, "CRL_TRANSFER", strlen("CRL_TRANSFER"), 0);

	// Wait for ACK from server
	char server_reply[100];
	memset(server_reply, '\0', 100);
	if (recv(socket_desc, server_reply, 100, 0) < 0) {
		printf("ERROR: receive failed during CRL transfer. Exiting...\n");
		return;
	}
	if (strncmp(server_reply, "CRL_TRANSFER_ACK", strlen("CRL_TRANSFER_ACK")) != 0) {
		printf("ERROR: Invalid ACK from server. Exiting...\n");
		return;
	}

	printf("INFO: Sending CRL file '%s' to server...\n", crlFileName);

	char buffer[1024];
	size_t bytesRead;
	while (fgets(buffer, sizeof(buffer), crlFile) != NULL) {
		send(socket_desc, buffer, strlen(buffer), 0);
	}
	fclose(crlFile);

	// Send transfer end message
	send(socket_desc, "CRL_TRANSFER_END", strlen("CRL_TRANSFER_END"), 0);

	printf("INFO: CRL file sent to server.\n");
	return;
}

