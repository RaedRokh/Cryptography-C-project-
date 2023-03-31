#include <stdio.h>
#include <stdlib.h>

void main() {
	FILE* publicKeyFile = fopen("ec-secp256k1-pub-key.pem", "rb");
	fseek(publicKeyFile, 0, SEEK_END);
	long publicKeySize = ftell(publicKeyFile);
	rewind(publicKeyFile);
	unsigned char* publicKeyBuffer = (unsigned char*)malloc(publicKeySize);
	publicKeyBuffer[publicKeySize] = '\0';
	fread(publicKeyBuffer, publicKeySize, 1, publicKeyFile);
	fclose(publicKeyFile);
	printf(publicKeyBuffer);
	FILE* privateKeyFile = fopen("ec-secp256k1-priv-key.pem", "rb");
	fseek(privateKeyFile, 0, SEEK_END);
	long privateKeySize = ftell(privateKeyFile);
	rewind(privateKeyFile);
	unsigned char* privateKeyBuffer = (unsigned char*)malloc(privateKeySize);
	fread(privateKeyBuffer, privateKeySize, 1, privateKeyFile);
	fclose(privateKeyFile);
	printf(privateKeyBuffer);

}
