#include <windows.h>
#include <stdio.h>



#define encodedSize(plaintextLen) (plaintextLen+4)/5*8

/**
 * Encode or decode the text of a buffer using base32 encoding.
 *
 * @param[in] inBuf pointer to the array containing the buffer to encode.
 * @param[out] outBuf pointer to the array that will contain the encoded content. The buffer must already been allocate, with the size computed from the macro encodedSize(inBufferLen)
 * @param[in] plainLen Length of the plaintext content.
 * @param[in] encode if true, the content of inBuf is base32 encoded, otherwise it is decoded.
 */
void base32(unsigned char* inBuf, unsigned char* outBuf, size_t plainLen, bool encode) {
	size_t toLen, fromLen, fromIdx, toIdx;
	unsigned int x = 0, z = 0;
	char toBase, fromBase, toBaseMask, fromBaseMask;

	if (encode) {
		fromLen = plainLen; 
		fromBase = 8;
		toLen = encodedSize(plainLen);
		toBase = 5; 
		toBaseMask = 0x1f; 
	}
	else {
		fromLen = encodedSize(plainLen);
		fromBase = 5;
		toLen = plainLen;
		toBase = 8;
		toBaseMask = 0xff;
	}

	fromIdx = toIdx = 0;
	while (toIdx < toLen && fromIdx < fromLen) {
		x = (x << fromBase) | inBuf[fromIdx++];
		z += fromBase;
		while (z >= toBase) {
			z -= toBase;
			outBuf[toIdx++] = (x >> z) & toBaseMask;
		}
	}

	if (toIdx > toLen)
		printf("[!] Error, toBuf overflow\n");
	
	// if is encoding, need to go with padding stuff
	while (toIdx < toLen) {
		x = (x << fromBase);
		z += fromBase;
		while (z >= toBase) {
			z -= toBase;
			outBuf[toIdx++] = (x >> z) & toBaseMask;
		}
	}
}


#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c "
#define BYTE_TO_BINARY(byte)  \
  ((byte) & 0x80 ? '1' : '0'), \
  ((byte) & 0x40 ? '1' : '0'), \
  ((byte) & 0x20 ? '1' : '0'), \
  ((byte) & 0x10 ? '1' : '0'), \
  ((byte) & 0x08 ? '1' : '0'), \
  ((byte) & 0x04 ? '1' : '0'), \
  ((byte) & 0x02 ? '1' : '0'), \
  ((byte) & 0x01 ? '1' : '0') 

// helper to print binary content of buffers
void printBinary(unsigned char* toPrint, size_t toPrintLen) {
	for (size_t i = 0; i < toPrintLen; i++) {
		printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(toPrint[i]));
	}
}


// test case 
void testEncoding() {
	unsigned char plainStr[] = "abcdefghijklmnopqrstuvwxyz";
	unsigned char encodedStr[encodedSize(sizeof(plainStr) - 1) + 1];
	unsigned char decodedStr[sizeof(plainStr)];

	size_t encodedStrLen = 0, decodedStrLen = 0;
	// encode strings with length up to 15
	for (size_t i = 0; i < 16; i++) {
		encodedStrLen = encodedSize(i);
		base32(plainStr, encodedStr, i, true);
		decodedStrLen = i;
		base32(encodedStr, decodedStr, i, false);

		printf("------------------------------------------------\n[%lu]\n............................................\n", i);
		printf("PLAIN:\n\tsize:\t%lu\n\tvalue:\t", i);
		printBinary(plainStr, i);
		printf("\n\n");
		printf("ENCODED:\n\tsize:\t%lu\n\tvalue:\t", encodedStrLen);
		printBinary(encodedStr, encodedStrLen);
		printf("\n\n");
		printf("DECODED:\n\tsize:\t%lu\n\tvalue:\t", decodedStrLen);
		printBinary(decodedStr, decodedStrLen);
		printf("\n");
		if (memcmp(plainStr, decodedStr, i) == 0)
			printf("++++++++++++++++++\n");
		else
			printf("!!!!!!!!!!!!!!!!!!\n");
		printf("------------------------------------------------\n\n\n");
	}
}

int main(int argc, char ** argv) {
	if (argc != 4 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0){
		printf("USAGE:\n\t%s <fileToEncodePath> <encodedFilePath> <decodedFilePath>\n", argv[0]);
		return 1;

	}

	HANDLE hPlainTextFile, hEncodedTextFile, hDecodedTextFile;
	unsigned char *plainText, *encodedText, *decodedText;
	size_t plainTextLen, encodedTextLen, decodedTextLen;
	
	// Open input file
	hPlainTextFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hPlainTextFile) {
		printf("[!] CreateFileW failed for file \"%s\", error: %u\n", argv[1], GetLastError());
		return 1;
	}

	// Allocate space for the plaintext, encoded and decoded buffer
	plainTextLen = decodedTextLen = GetFileSize(hPlainTextFile, NULL);
	encodedTextLen = encodedSize(plainTextLen);
	plainText = (unsigned char*) malloc(plainTextLen);
	decodedText = (unsigned char*) malloc(decodedTextLen);
	encodedText = (unsigned char*) malloc(encodedTextLen);

	// Read input file
	if (!ReadFile(hPlainTextFile, plainText, plainTextLen, NULL, NULL)) {
		printf("[!] ReadFile failed, error: %u\n", GetLastError());
		return 1;
	}
	CloseHandle(hPlainTextFile);

	// Encode the paintext
	base32(plainText, encodedText, plainTextLen, true);
	
	// Decode the encoded text
	base32(encodedText, decodedText, plainTextLen, false);

	
	// Write encoded text to output file
	hEncodedTextFile = CreateFileA(argv[2], GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hEncodedTextFile) {
		printf("[!] CreateFileW failed for file \"%s\", error: %u\n", argv[2], GetLastError());
		return 1;
	}
	if (!WriteFile(hEncodedTextFile, encodedText, encodedTextLen, NULL, NULL)) {
		printf("[!] WriteFile failed for file %s, error: %u\n", argv[2], GetLastError());
		return 1;
	}
	CloseHandle(hEncodedTextFile);

	// Write decoded text to output file
	hDecodedTextFile = CreateFileA(argv[3], GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!WriteFile(hDecodedTextFile, decodedText, decodedTextLen, NULL, NULL)) {
		printf("[!] WriteFile failed for file %s, error: %u\n", argv[3], GetLastError());
		return 1;
	}
	CloseHandle(hDecodedTextFile);

	printf("[+] OK\n");
	return 0;
}