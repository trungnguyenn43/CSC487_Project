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
void receiveCRLFile(int);

//Chain functions
void receiveCertChainFile(int, const crlEntry[], const int);
void chainVerify(int, char *, const crlEntry[], const int);
int verifyCertInChain(certInfo, const crlEntry[], const int);
int getCertsInChain(certInfo [], int *);

// Define server port
const int SERVER_PORT = 49152; // Port number of the server
static char CBC_Hash_KEY[4] = "CCB"; //key for CBC Hash
static char CBC_IV[3] = "1A"; // IV for CBC Hash
const char CRL_FILE_NAME[] = "SV_temp_crl_file.txt";
unsigned int rsa_public_key = 0, rsa_private_key = 0;
unsigned int p, q, n, totient_n;

int main(int argc, char *argv[])
{	
	int socket_desc, new_socket, c, read_size, i;
	struct sockaddr_in server, client;
	char client_message[1024];

	printf("========= RSA KEY GEN ==========\n");
	//====================================
	// RSA Key GEN
	//====================================
	

	//getting two distinct prime numbers
	do{
		// printf("Enter two distinct prime numbers (p and q): ");
		// scanf("%u %u", &p, &q);
		q = 61;
		p = 53;
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
		close(socket_desc);
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
		close(socket_desc);
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
		close(socket_desc);
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
		close(socket_desc);
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
				receiveCertChainFile(new_socket, crlEntries, crlFileInfo.numEntries);
				break;
			case 3:
				printf("INFO: Client requested CRL transfer.\n");
				receiveCRLFile(new_socket);
				
				// Reload CRL entries
				//reset crl entries
				memset(crlEntries, 0, sizeof(crlEntries));
				crlFileInfo.numEntries = 0;
				loadCRLEntry(&crlFileInfo, crlEntries, rsa_private_key, rsa_public_key, n);
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
	else if(strncmp(inputMessage, "EXIT_RQ", strlen("EXIT_RQ")) == 0)
	{
		requestType = 0; // exit request
	}
	
	return requestType;
}

void receiveCertFile(int socket_desc) {
    // Acknowledge the certificate transfer request
    send(socket_desc, "CERT_TRANSFER_ACK", strlen("CERT_TRANSFER_ACK"), 0);

    char client_message[1024];
    memset(client_message, '\0', sizeof(client_message));

    printf("INFO: Receiving certificate file from client...\n");

    FILE *tempFile = fopen("SV_temp_cert_file.txt", "w");
    if (!tempFile) {
        printf("ERROR: Cannot open temp file for writing.\n");
        return;
    }

    while (1) {
        if (recv(socket_desc, client_message, sizeof(client_message), 0) <= 0) {
            printf("ERROR: Receive failed during certificate transfer. Exiting...\n");
            fclose(tempFile);
            return;
        }

        // Check for transfer end message
        if (strncmp(client_message, "CERT_TRANSFER_END", strlen("CERT_TRANSFER_END")) == 0) {
            printf("INFO: Certificate transfer complete.\n");
            break;
        }

        // Send ACK for each line received
        if (send(socket_desc, "CERT_LINE_ACK", strlen("CERT_LINE_ACK"), 0) < 0) {
            printf("ERROR: Send failed during certificate transfer. Exiting...\n");
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
    printf("INFO: Certificate file saved to SV_temp_cert_file.txt\n");
    return;
}

void receiveCRLFile(int socket_desc) {
    // Acknowledge the CRL transfer request
    send(socket_desc, "CRL_TRANSFER_ACK", strlen("CRL_TRANSFER_ACK"), 0);

    char client_message[1024];
    memset(client_message, '\0', sizeof(client_message));

    printf("INFO: Receiving CRL file from client...\n");

    FILE *tempFile = fopen("SV_temp_crl_file.txt", "w");
    if (!tempFile) {
        printf("ERROR: Cannot open temp CRL file for writing.\n");
        return;
    }

    while (1) {
        if (recv(socket_desc, client_message, sizeof(client_message), 0) < 0) {
            printf("ERROR: Receive failed during CRL transfer. Exiting...\n");
            fclose(tempFile);
            return;
        }

        // Check for transfer end message
        if (strncmp(client_message, "CRL_TRANSFER_END", strlen("CRL_TRANSFER_END")) == 0) {
            printf("INFO: CRL transfer complete.\n");
            break;
        }

        // Send ACK for each line received
        if (send(socket_desc, "CRL_LINE_ACK", strlen("CRL_LINE_ACK"), 0) < 0) {
            printf("ERROR: Send failed during CRL transfer. Exiting...\n");
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
    printf("INFO: CRL file saved to SV_temp_crl_file.txt\n");
    return;
}

void receiveCertChainFile(int socket_desc, const crlEntry crlEntries[], const int numCrlEntries) {
    // Acknowledge the chain transfer request
    send(socket_desc, "CERT_CHAIN_TRANSFER_ACK", strlen("CERT_CHAIN_TRANSFER_ACK"), 0);

    char client_message[1024];
    memset(client_message, '\0', sizeof(client_message));

    printf("INFO: Receiving certificate chain file from client...\n");

    FILE *tempFile = fopen("SV_temp_chain_file.txt", "w");
    if (!tempFile) {
        printf("ERROR: Cannot open temp chain file for writing.\n");
        return;
    }

    while (1) {
        if (recv(socket_desc, client_message, sizeof(client_message), 0) < 0) {
            printf("ERROR: Receive failed during certificate chain transfer. Exiting...\n");
            fclose(tempFile);
            return;
        }

        // Check for transfer end message
        if (strncmp(client_message, "CERT_CHAIN_TRANSFER_END", strlen("CERT_CHAIN_TRANSFER_END")) == 0) {
            printf("INFO: Certificate chain transfer complete.\n");
            break;
        }

        // Send ACK for each line received
        if (send(socket_desc, "CERT_CHAIN_LINE_ACK", strlen("CERT_CHAIN_LINE_ACK"), 0) < 0) {
            printf("ERROR: Send failed during certificate chain transfer. Exiting...\n");
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
    printf("INFO: Certificate chain file saved to SV_temp_chain_file.txt\n");

    // Verify the certificate chain
    chainVerify(socket_desc, "SV_temp_chain_file.txt", crlEntries, numCrlEntries);

	// send chain verify done
	send(socket_desc, "CERT_CHAIN_VERIFICATION_DONE", strlen("CERT_CHAIN_VERIFICATION_DONE"), 0);

    return;
}

int getCertsInChain(certInfo certs[], int *certCount) {
	//load certs from temp chain file
	FILE *chainFile = fopen("SV_temp_chain_file.txt", "r");
	if (!chainFile) {
		printf("ERROR: Cannot open certificate chain file for validation.\n");
		return -1;
	}

	*certCount = 0;

	// read begin chain line
	char inputBuffer[256];
	fgets(inputBuffer, sizeof(inputBuffer), chainFile); // Read "-----BEGIN CERTIFICATE CHAIN-----"

	while(fgets(inputBuffer, sizeof(inputBuffer), chainFile) != NULL) {
		if (strncmp(inputBuffer, "-----BEGIN CERTIFICATE-----", 27) == 0) {
			// Start reading a certificate
			certInfo cert;
			// Read certificate details
			fgets(inputBuffer, sizeof(inputBuffer), chainFile);
			sscanf(inputBuffer, "Version: %s", cert.version);
			fgets(inputBuffer, sizeof(inputBuffer), chainFile);
			sscanf(inputBuffer, "Certificate Serial Number: %s", cert.serialNumber);
			fgets(inputBuffer, sizeof(inputBuffer), chainFile);
			sscanf(inputBuffer, "Level of Trust: %d", &cert.levelOfTrust);
			fgets(inputBuffer, sizeof(inputBuffer), chainFile);
			sscanf(inputBuffer, "Algorithm: %s", cert.algorithm);
			fgets(inputBuffer, sizeof(inputBuffer), chainFile);
			sscanf(inputBuffer, "Parameters: %s", cert.parameters);
			fgets(inputBuffer, sizeof(inputBuffer), chainFile);
			sscanf(inputBuffer, "Issuer Name: %s", cert.issuerName);
			fgets(inputBuffer, sizeof(inputBuffer), chainFile);
			sscanf(inputBuffer, "Not Before: %ld", &cert.notBefore);
			fgets(inputBuffer, sizeof(inputBuffer), chainFile);
			sscanf(inputBuffer, "Not After: %ld", &cert.notAfter);
			fgets(inputBuffer, sizeof(inputBuffer), chainFile);
			sscanf(inputBuffer, "Subject Name: %s", cert.subjectName);

			fgets(inputBuffer, sizeof(inputBuffer), chainFile); //skip line

			fgets(inputBuffer, sizeof(inputBuffer), chainFile);
			sscanf(inputBuffer, "Public Key: %u %u", &cert.publicKey, &cert.n);
			fgets(inputBuffer, sizeof(inputBuffer), chainFile);
			sscanf(inputBuffer, "Signature: %u", &cert.signature);

			certs[*certCount] = cert;
			(*certCount)++;

			// Read until end of certificate
			while (fgets(inputBuffer, sizeof(inputBuffer), chainFile) != NULL) {
				if (strncmp(inputBuffer, "-----END CERTIFICATE-----", 25) == 0) {
					break;
				}
			}
		}
		else if (strncmp(inputBuffer, "-----END CERTIFICATE CHAIN-----", 30) == 0) {
			// End of chain
			break;
		}
	}

	fclose(chainFile);
	return 0;
}


void chainVerify(int socket_desc, char *crlFileName, const crlEntry crlEntries[], const int numCrlEntries) {
	certInfo certs[30];
	int certCount = 0;
	char client_message[1024];

	// Load certificates from chain file
	if(getCertsInChain(certs, &certCount) == -1){
		sprintf(client_message, "ERROR: Unable to open certificate chain file for verification.\n");
		send(socket_desc, client_message, strlen(client_message), 0);
		return;
	}

	// Root trusted issuer list (always trusted)
	const char* ROOT_TRUSTED_CA[] = {"Norman"};
	const int ROOT_TRUSTED_CA_COUNT = sizeof(ROOT_TRUSTED_CA) / sizeof(ROOT_TRUSTED_CA[0]);

	char trustedIssuerNames[30][100] = {'\0'};
	int trustedIssuerCount = 0;
	bool certValid[30] = {false};

	//intialize trustedIssuerNames with root trusted issuers
	for(int i = 0; i < ROOT_TRUSTED_CA_COUNT; i++) {
		strcpy(trustedIssuerNames[trustedIssuerCount], ROOT_TRUSTED_CA[i]);
		trustedIssuerCount++;
	}

	// First, check validity for all certs and get subject names
	for(int i = 0; i < certCount; i++) {
		int result = verifyCertInChain(certs[i], crlEntries, numCrlEntries);
		if (result == 1) {
			certValid[i] = true;
		}
		else {
			certValid[i] = false;
		}
	}

	// Get subject names and check if they are trusted by root (root trusted issuers)
	for(int i = 0; i < certCount; i++) {
		if(certValid[i] == false){
			continue; // skip invalid certs
		}

		// Check if issuer is in ROOT_TRUSTED_CA
		for(int j = 0; j < ROOT_TRUSTED_CA_COUNT; j++) {
			if(strcmp(certs[i].issuerName, ROOT_TRUSTED_CA[j]) == 0) {
				// Issuer is trusted, check if subject is already in the trusted list
				bool alreadyTrusted = false;
				for(int k = 0; k < trustedIssuerCount; k++) {
					if(strcmp(trustedIssuerNames[k], certs[i].subjectName) == 0) {
						alreadyTrusted = true;
						break;
					}
				}
				if(!alreadyTrusted) {
					strcpy(trustedIssuerNames[trustedIssuerCount], certs[i].subjectName);
					trustedIssuerCount++;
				}
				break;
			}
		}
	}

	// 2. check if issuers are trusted, if yes, add subject to trusted list
	bool addedNewTrusted = false;
	while(true) {
		addedNewTrusted = false;
		for(int i = 0; i < certCount; i++) {
			if(certValid[i] == false){
				continue; // skip invalid certs
			}

			// Check if issuer is in trustedIssuerNames
			bool isIssuerTrusted = false;
			for(int j = 0; j < trustedIssuerCount; j++) {
				if(strcmp(certs[i].issuerName, trustedIssuerNames[j]) == 0) {
					isIssuerTrusted = true;
					break;
				}
			}

			if(isIssuerTrusted) {
				// Issuer is trusted, check if subject is already in the trusted list
				bool alreadyTrusted = false;
				for(int k = 0; k < trustedIssuerCount; k++) {
					if(strcmp(trustedIssuerNames[k], certs[i].subjectName) == 0) {
						alreadyTrusted = true;
						break;
					}
				}
				if(!alreadyTrusted) {
					strcpy(trustedIssuerNames[trustedIssuerCount], certs[i].subjectName);
					trustedIssuerCount++;
					addedNewTrusted = true;
				}
			}
		}
		
		if(!addedNewTrusted) {
			break; // No new trusted issuers added, exit loop
		}
	}

	int trustLevel = -1;
	int chainBreakPoint = -1;
	// 3. check if all certs are trusted
	for(int i = 0; i < certCount; i++) {
		
		memset(client_message, '\0', sizeof(client_message));

		if(certValid[i] == false){
			sprintf(client_message, 
				"\tCertificate with Serial Number %s is invalid (expired/revoked/invalid signature).\n", 
				certs[i].serialNumber);
			send(socket_desc, client_message, strlen(client_message), 0);
			continue; // skip invalid certs
		}

		// Check if issuer is in trustedIssuerNames
		bool isTrusted = false;
		for(int j = 0; j < trustedIssuerCount; j++) {
			if(strcmp(certs[i].issuerName, trustedIssuerNames[j]) == 0) {
				isTrusted = true;
				break;
			}
		}

		if(!isTrusted) {
			if(chainBreakPoint == -1){
				chainBreakPoint = i;
			}
			sprintf(client_message, 
				"\tCertificate with Serial Number %s is not trusted. Issuer %s is not trusted.\n", 
				certs[i].serialNumber, 
				certs[i].issuerName);
			send(socket_desc, client_message, strlen(client_message), 0);
			continue;
		} else {
			// Update trust level
			if(trustLevel == -1 || certs[i].levelOfTrust < trustLevel) {
				trustLevel = certs[i].levelOfTrust;
			}
		}
	}

	// If there is a break point, report failure
	if(chainBreakPoint != -1 && trustLevel != -1) {
		sprintf(client_message, 
			"Unable to verify complete chain. Chain verified to %s with a chain TL of %d. No cert available for %s\n", 
			certs[chainBreakPoint].issuerName, 
			trustLevel,
			certs[chainBreakPoint].issuerName);
		send(socket_desc, client_message, strlen(client_message), 0);
		return;
	}
	else if(trustLevel == -1 && chainBreakPoint != -1) {
		sprintf(client_message, "No valid and trusted certificates found in the chain.\n");
		send(socket_desc, client_message, strlen(client_message), 0);
		return;
	}
	
	// If all certs are valid and trusted, report success and show trusted subjects
	sprintf(client_message, "Certificate chain verified successfully. Chain Trust Level: %d\n", trustLevel);
	send(socket_desc, client_message, strlen(client_message), 0);
	
	return;
}

// Verify individual certificate against CRL. Return 1 if valid, 0 if invalid, -1 if error
int verifyCertInChain(certInfo cert, const crlEntry crlEntries[], const int numCrlEntries) {
	// Check validity period
	time_t currentTime = time(NULL);
	if (currentTime < cert.notBefore || currentTime > cert.notAfter) {
		printf("ERROR: Certificate with Serial Number %s is expired or not yet valid.\n", cert.serialNumber);
		return 0;
	}

	// Check against CRL entries
	for (int i = 0; i < numCrlEntries; i++) {
		if (strcmp(cert.serialNumber, crlEntries[i].serialNumber) == 0) {
			printf("ERROR: Certificate with Serial Number %s is revoked.\n", cert.serialNumber);
			return -1;
		}
	}

	//check signature
	// Hash using CTR CBC
	char tempOutputBuffer[1024];
	snprintf(tempOutputBuffer, sizeof(tempOutputBuffer),
		"Version: %s\n"
		"Certificate Serial Number: %s\n"
		"Level of Trust: %d\n"
		"Algorithm: %s\n"
		"Parameters: %s\n"
		"Issuer Name: %s\n"
		"Not Before: %ld\n"
		"Not After: %ld\n"
		"Subject Name: %s\n\n"
		"Public Key: %u %u\n",
		cert.version,
		cert.serialNumber,
		cert.levelOfTrust,
		cert.algorithm,
		cert.parameters,
		cert.issuerName,
		cert.notBefore,
		cert.notAfter,
		cert.subjectName,
		cert.publicKey,
		cert.n
	);

	char computedHash[3];
	CBCHash(tempOutputBuffer, CBC_IV, CBC_Hash_KEY, computedHash);
	// Convert hash to numeric value
	unsigned int hashValue = (unsigned int)strtol(computedHash, NULL, 16); // convert hash to integer
	
	unsigned int decryptedSignature = modExp(cert.signature, cert.publicKey, cert.n);

	if(decryptedSignature != hashValue){
		printf("ERROR: Certificate with Serial Number %s has invalid signature.\n", cert.serialNumber);
		return 0;
	}

	return 1; // Certificate is valid
}