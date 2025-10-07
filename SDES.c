#include "SDES.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

//* Global Variables *//
#pragma region global variables
char textHolder[9] = ""; // 8-bit binary string + null terminator \0
char keytext[13] = "";  // 12-bit key + null terminator. The first 2 bits are ignored
char KEY1[9] = "";      // First 8-bit subkey + null terminator
char KEY2[9] = "";      // Second 8-bit subkey + null terminator
#pragma endregion


//* Entry Point of the SDES algorithm - encryption *//
char* SDES(char* plainTextInput, char* keyInput) {
    // Validate inputs
    if (plainTextInput == NULL || keyInput == NULL) {
        fprintf(stderr, "Error: Empty input (code: 1)\n");
        return NULL;
    }

    // Check if the characters of the keyInput is valid hex digits
    for(int i = 0; i < strlen(keyInput); i++) {
        if (!isxdigit(keyInput[i])) {
            fprintf(stderr, "Error: Invalid key input (code: 2)\n");
            return NULL;
        }
    }


    {   // Convert textHolder and key from hex to binary
        strcpy(textHolder, hex2Bin(plainTextInput)); // Convert textHolder
        strcpy(keytext, hex2Bin(keyInput));         // Convert key

        // Ignore the first 2 bits of the key by left-shifting twice
        strcpy(keytext, ls_block(keytext, 2));
        keytext[strlen(keytext) - 1] = '\0'; // Null terminate after ignoring first 2 bits
        keytext[strlen(keytext) - 1] = '\0'; // Ensure null termination
    }

    // Generate the two subkeys K1 and K2
    keyGen(keytext);

    //IP block
    strcpy(textHolder, ip_block(textHolder)); // Initial Permutation (IP)
    
    //1st Fk function
    char lefttextHolder[5], righttextHolder[5], temptextHolder[5]; // 4 bits each + null terminator
    strncpy(lefttextHolder, textHolder, 4);
    lefttextHolder[4] = '\0'; // Null terminate
    strncpy(righttextHolder, textHolder + 4, 4);
    righttextHolder[4] = '\0'; // Null terminate

    strcpy(lefttextHolder, fk_block(lefttextHolder, righttextHolder, KEY1));
    
    //SW block (Swap the left and right parts)
    strcpy(temptextHolder, lefttextHolder);
    strcpy(lefttextHolder, righttextHolder);
    strcpy(righttextHolder, temptextHolder);

    //2nd Fk function
    strcpy(lefttextHolder, fk_block(lefttextHolder, righttextHolder, KEY2));
    
    //Combine the left and right parts
    strcpy(textHolder, lefttextHolder);
    strcat(textHolder, righttextHolder);
    textHolder[8] = '\0'; // Null terminate

    //IP-1 block
    strcpy(textHolder, ip1_block(textHolder)); // Inverse Initial Permutation (IP-1)
    
    //Convert to hex and return
    strcpy(textHolder, bin2Hex(textHolder));

    return textHolder;
}

//* Entry Point of the SDES algorithm - decryption *//
char* SDES_decrypt(char* ciphertextInput, char* keyInput) {
    // Validate inputs
    if (ciphertextInput == NULL || keyInput == NULL) {
        fprintf(stderr, "Error: Empty input (code: 1)\n");
        return NULL;
    }

    // Check if the characters of the keyInput is valid hex digits
    for(int i = 0; i < strlen(keyInput); i++) {
        if (!isxdigit(keyInput[i])) {
            fprintf(stderr, "Error: Invalid key input (code: 2)\n");
            return NULL;
        }
    }

    // Convert ciphertext and key from hex to binary
    strcpy(textHolder, hex2Bin(ciphertextInput)); // Convert ciphertext
    strcpy(keytext, hex2Bin(keyInput));         // Convert key

    // Ignore the first 2 bits of the key by left-shifting twice
    strcpy(keytext, ls_block(keytext, 2));
    keytext[strlen(keytext) - 1] = '\0'; // Null terminate after ignoring first 2 bits
    keytext[strlen(keytext) - 1] = '\0'; // Ensure null termination

    // Generate the two subkeys K1 and K2
    keyGen(keytext);

    // IP block
    strcpy(textHolder, ip_block(textHolder)); // Initial Permutation (IP)

    // 1st Fk function with KEY2
    char lefttextHolder[5], righttextHolder[5], temptextHolder[5]; // 4 bits each + null terminator
    strncpy(lefttextHolder, textHolder, 4);
    lefttextHolder[4] = '\0'; // Null terminate
    strncpy(righttextHolder, textHolder + 4, 4);
    righttextHolder[4] = '\0'; // Null terminate

    strcpy(lefttextHolder, fk_block(lefttextHolder, righttextHolder, KEY2));

    // SW block (Swap the left and right parts)
    strcpy(temptextHolder, lefttextHolder);
    strcpy(lefttextHolder, righttextHolder);
    strcpy(righttextHolder, temptextHolder);

    // 2nd Fk function with KEY1
    strcpy(lefttextHolder, fk_block(lefttextHolder, righttextHolder, KEY1));

    // Combine the left and right parts
    strcpy(textHolder, lefttextHolder);
    strcat(textHolder, righttextHolder);
    textHolder[8] = '\0'; // Null terminate

    // IP-1 block
    strcpy(textHolder, ip1_block(textHolder));
    
    //Convert to hex and return
    strcpy(textHolder, bin2Hex(textHolder));

    return textHolder;
}

//* Convert Hexadecimal to Binary *//
char* hex2Bin(const char* hex) {
    static char output[65]; // Maximum 16 hex digits * 4 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    // Convert each hex digit to its 4-bit binary equivalent
    for (int i = 0; i < strlen(hex); i++) {
        const char* bin = hexDigitsToBin(hex[i]);
        if (bin == NULL || *bin == '\0') {
            output[0] = '\0'; // Clear output on error
            return output;
        }
        strcat(output, bin); // Append binary representation
    }

    return output;
}

const char* hexDigitsToBin(const char hex) {
    // Return a static binary string for each hex digit
    switch (toupper(hex)) {
        case '0': return "0000";
        case '1': return "0001";
        case '2': return "0010";
        case '3': return "0011";
        case '4': return "0100";
        case '5': return "0101";
        case '6': return "0110";
        case '7': return "0111";
        case '8': return "1000";
        case '9': return "1001";
        case 'A': return "1010";
        case 'B': return "1011";
        case 'C': return "1100";
        case 'D': return "1101";
        case 'E': return "1110";
        case 'F': return "1111";
        default: 
            fprintf(stderr, "Error: Invalid hex digit '%c' (code: 2)\n", hex);
            return NULL;
    }
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

//entry point for key generator
void keyGen(const char* key) {
    // Generate the two subkeys K1 and K2 from the original 10-bit key
    char* p10_output = p10_block(key); // Apply P10 permutation

    // Split the permuted key into two halves
    char left[6], right[6]; // 5 bits each + null terminator
    strncpy(left, p10_output, 5);
    left[5] = '\0'; // Null terminate
    strncpy(right, p10_output + 5, 5);
    right[5] = '\0'; // Null terminate

    // Perform left shifts
    char* ls1_left = ls_block(left, 1);
    char* ls1_right = ls_block(right, 1);

    //P8 permutation to get KEY1
    strcpy(KEY1, p8_block(ls1_left, ls1_right));

    // Perform second left shifts
    char* ls2_left = ls_block(ls1_left, 2);
    char* ls2_right = ls_block(ls1_right, 2);

    //P8 permutation to get KEY2
    strcpy(KEY2, p8_block(ls2_left, ls2_right));

}

//* Apply P10 Permutation *//
char* p10_block(const char* input) {
    static char output[11]; // 10 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    // Apply the P10 permutation
    output[0] = input[2];
    output[1] = input[4];
    output[2] = input[1];
    output[3] = input[6];
    output[4] = input[3];
    output[5] = input[9];
    output[6] = input[0];
    output[7] = input[8];
    output[8] = input[7];
    output[9] = input[6];
    output[10] = '\0'; // Null terminator

    return output;
}

//* Left Shift Block with Shift Count *//
char* ls_block(char* input, int shiftCount) {
    int size = strlen(input); // Get the input string length

    for (int i = 0; i < shiftCount; i++) {
        char first_bit = input[0]; // Store the first bit

        // Shift all bits to the left
        for (int j = 0; j < size - 1; j++) {
            input[j] = input[j + 1];
        }

        input[size - 1] = first_bit; // Place the first bit at the end
    }

    return input;
}

char* p8_block(const char* left, const char* right) {
    static char output[9]; // 8 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    char input[17]; // 16 bits from left and right + null terminator
    strcpy(input, left);
    strcat(input, right);

    output[0] = input[5]; 
    output[1] = input[2]; 
    output[2] = input[6]; 
    output[3] = input[3]; 
    output[4] = input[7]; 
    output[5] = input[4]; 
    output[6] = input[9]; 
    output[7] = input[8]; 

    return output;
}

char* fk_block(const char* left, const char* right, const char* key) {
    
    char rightPart[5];
    static char leftPart[5]; // 4 bits + null terminator -> output
    memset(rightPart, 0, sizeof(rightPart)); // Clear the rightPart array
    memset(leftPart, 0, sizeof(leftPart));   // Clear the leftPart array

    strcpy(rightPart, right); // Copy right to rightPart
    strcpy(leftPart, left);   // Copy left to leftPart
    rightPart[4] = '\0'; // Null terminate
    leftPart[4] = '\0';  // Null terminate

    //EP block
    char expandedRight[9]; // 8 bits + null terminator
    memset(expandedRight, 0, sizeof(expandedRight)); // Clear the expandedRight array
    strcpy(expandedRight, ep_block(rightPart));

    //XOR with KEY1
    for (int i = 0; i < 9; i++) {
        expandedRight[i] = XOR(expandedRight[i], key[i]);
    }
    expandedRight[8] = '\0'; // Null terminate
    
    //S1 and S2 blocks
    char S0_output[3], S1_output[3]; // 2 bits each + null terminator
    char temp[5]; // Temporary storage for splitting
    strncpy(temp, expandedRight, 4);
    temp[4] = '\0'; // Ensure null termination
    strcpy(S0_output, s0_block(temp));

    strncpy(temp, expandedRight + 4, 4);
    temp[4] = '\0'; // Ensure null termination
    strcpy(S1_output, s1_block(temp));

    //P4 block
    char P4_input[5]; // 4 bits + null terminator
    strcpy(P4_input, S0_output);
    strcat(P4_input, S1_output);
    P4_input[4] = '\0'; // Null terminate
    strcpy(temp, p4_block(P4_input));
    
    //XOR with left
    for (int i = 0; i < 4; i++) {
        leftPart[i] = XOR(leftPart[i], temp[i]);
    }

    return leftPart;
}

char* ip_block(const char* input) {
    static char output[9]; // 8 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    // Apply the IP permutation
    output[0] = input[1]; 
    output[1] = input[5]; 
    output[2] = input[2]; 
    output[3] = input[0]; 
    output[4] = input[3]; 
    output[5] = input[7]; 
    output[6] = input[4]; 
    output[7] = input[6];
    output[8] = '\0'; // Null terminator

    return output;
}

char* ip1_block(const char* input) {
    static char output[9]; // 8 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    // Apply the IP-1 permutation
    output[0] = input[3]; 
    output[1] = input[0]; 
    output[2] = input[2]; 
    output[3] = input[4]; 
    output[4] = input[6]; 
    output[5] = input[1]; 
    output[6] = input[7]; 
    output[7] = input[5];
    output[8] = '\0'; // Null terminator

    return output;
}

char* ep_block(const char* input) {
    static char output[9]; // 8 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    // Apply the EP permutation
    output[0] = input[3]; 
    output[1] = input[0]; 
    output[2] = input[1]; 
    output[3] = input[2]; 
    output[4] = input[1]; 
    output[5] = input[2]; 
    output[6] = input[3]; 
    output[7] = input[0]; 
    output[8] = '\0'; // Null terminator

    return output;
}

char* s0_block(const char* input) {
    static char output[3]; // 2 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    const char* permuteArray[4][4] = {
        {"01", "00", "11", "10"},
        {"11", "10", "01", "00"},
        {"00", "10", "01", "11"},
        {"11", "01", "11", "10"}
    };

    //convert to int
    int row = (input[0] - '0') * 2 + (input[3] - '0');
    int col = (input[1] - '0') * 2 + (input[2] - '0');

    //copy the result
    strcpy(output, permuteArray[row][col]);

    return output;
}

char* s1_block(const char* input) {
    static char output[3]; // 2 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    const char* permuteArray[4][4] = {
        {"00", "01", "10", "11"},
        {"10", "00", "01", "11"},
        {"11", "00", "01", "00"},
        {"10", "01", "00", "11"}
    };
    
    //convert to int
    int row = (input[0] - '0') * 2 + (input[3] - '0');
    int col = (input[1] - '0') * 2 + (input[2] - '0');

    //copy the result
    strcpy(output, permuteArray[row][col]);

    return output;
}

char* p4_block(const char* input) {
    static char output[5]; // 4 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    output[0] = input[1]; 
    output[1] = input[3]; 
    output[2] = input[2]; 
    output[3] = input[0];
    output[4] = '\0'; // Null terminator 

    return output;
}

char XOR(char a, char b) {
    return (a != b) ? '1' : '0';
}