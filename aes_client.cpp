/*
 * aes_encrypt.cpp
 *
 *  Created on: Mar 3, 2015
 *      Author: travis
 */

#include "aes_client.h"


aes_context mAES;
unsigned char* mKey;
unsigned char oIV[16];
unsigned char* nIV;
int devIDLen = 0;
String devID;

void build_decoding_table();


aes_client::aes_client(){
}

void aes_client::setKey(unsigned char* key){
	mKey = key;
}

void aes_client::setID(String dID){
	devID = dID;
	devIDLen = dID.length();
}

//Only supports up to 16 bytes right now
void aes_client::ecbEncrypt(char* output){

	//Determine number of random bytes needed
	int randNum = 16 - devIDLen;

	//Generate 16 random characters for IV and combine with device ID for Init Message
	char random[16];
	memset(random, 0, 16);
	srand(Time.second());
	for(int i = 0; i < randNum; i++){
		random[i] = 'a' + rand()%26;
	}
	//Create string from random bytes.
	String mR(random);
	//Append device ID to the end of string
	mR += devID;
	//Create buffer for encryption
	unsigned char buffer[16];

	//Create byte array for string
	byte messageBytes[mR.length()+1];

	//Put message bytes into byte array
	mR.getBytes(messageBytes, sizeof messageBytes);

	//Store first 16 unencrypted bytes from message as IV for reply cbc decrypt
	nIV = messageBytes;

	//Make sure passed buffer is empty
	memset(buffer, 0, 16);

	//Copy data into buffer for encryption
	memcpy(buffer, messageBytes, sizeof messageBytes);

	//Encrypt data
	aes_setkey_enc(&mAES, mKey, 128);
	aes_crypt_ecb(&mAES, AES_ENCRYPT, buffer, buffer);

	base64_encode(buffer, 16, output);
}

void ecbDecrypt(unsigned char* data, size_t dataLength, unsigned char* key, unsigned char* buffer){
	//Make sure buffer is empty
	memset(buffer, 0, 16);
	//Copy data into buffer for decryption
	memcpy(buffer, data, dataLength);
	//Decrypt data
	aes_setkey_dec(&mAES, key, 128);
	aes_crypt_ecb(&mAES, AES_DECRYPT, buffer, buffer);
}

void aes_client::cbcEncrypt(String message, char* output){

	//Generate 16 random characters for IV to send server
	char random[16];
	for(int i = 0; i < 16; i++){
		random[i] = 'a' + rand()%26;
	}
	//Create string from random characters
	String mR(random);
	//Append device ID to the end of String
	mR += devID;
	//Append message to the end of String
	mR += message;

	//Get Round key for Encryption
	memcpy(oIV, nIV, 16);

	//Create byte array to hold message bytes
	byte messageBytes[mR.length()+1];
	memset(messageBytes, 0, sizeof messageBytes);
	//get bytes from passed string
	mR.getBytes(messageBytes, sizeof messageBytes);

	//Store unencrypted data as IV for reply decrypt
	memcpy(nIV, messageBytes, 16);

	unsigned char buffer[128];

	//Make sure buffer is empty
	memset(buffer, 0, 128);

	//Copy message bytes into input buffer
	memcpy(buffer, messageBytes, sizeof messageBytes);

	//Calculate padded size of encrypted buffer
	size_t pLength = padding(buffer, sizeof messageBytes);

	//Encrypt message into output buffer
	aes_setkey_enc(&mAES, mKey, 128);
	aes_crypt_cbc(&mAES, AES_ENCRYPT, pLength, oIV, buffer, buffer);

	base64_encode(buffer, pLength, output);
}

String aes_client::cbcDecrypt(String message, size_t len){
	//Base 64 Decode data
	const char *messageChars = message.c_str();
	int length = len/4 *3;
	if (messageChars[length - 1] == '=') (length)--;
	if (messageChars[length - 2] == '=') (length)--;

	unsigned char messageBuf[length];
	size_t* decodeLength;
	base64_decode(message.c_str(), message.length(), decodeLength, messageBuf);

	//Copy Base 64 decoded data into buffer for decryption
	unsigned char data[length];
	memset(data, 0, sizeof data);
	memcpy(data, messageBuf, length);

	//get round key for decryption
	memcpy(oIV, nIV, 16);

	//Create output buffer for decryption.
	unsigned char oBuf[length];

	//Make sure buffers are empty
	memset(oBuf, 0, length);

	//Decrypt message into output buffer
	aes_setkey_dec(&mAES, mKey, 128);
	aes_crypt_cbc(&mAES, AES_DECRYPT, length, oIV, data, oBuf);


	//Store first 16 decrypted characters as round key for next cbc encrypted send
	memcpy(nIV, oBuf, 16);

	if(validatePacket(oBuf)){
		//Get message out of packet
		char messageArray[(sizeof oBuf - (devIDLen+16))+1];
		memset(messageArray, 0, sizeof messageArray);
		for(int i = 0; i < sizeof messageArray; i++){
			messageArray[i] = oBuf[i+16+devIDLen];
		}
		String message(messageArray);
		//Extrapolate message from received data.  All messages are appended with ~ so trim off information past that symbol
		int end = message.indexOf("~");
		String trimmed = message.substring(0,end);
		return trimmed;

	}else{

		return "Fail";
	}
}

bool aes_client::validatePacket(unsigned char* data){
	//Get ID String from packet
	char idCharArray[devIDLen+1];
	memset(idCharArray, 0, sizeof idCharArray);
	for(int i = 0; i < devIDLen; i++){
		idCharArray[i] = (const char)data[i+16];
	}
	String rID(idCharArray);
	//Make sure device ID is in the packet in the proper place
	if(rID.equals(devID)){
		return true;
	}else{
		Serial.println("Device ID does not match");
		Serial.println("rID: "+rID);
		Serial.println("devID: "+devID);
		return false;
	}
}

size_t aes_client::padding(unsigned char *buf, size_t messageLength) {
  size_t paddedLength = (messageLength & ~15) + 16;
//  char pad = paddedLength - messageLength;
//  memset(buf + messageLength, pad, pad);
  return paddedLength;
}

// base 64 - Convert from a binary blob to a string.
 static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static int mod_table[] = {0, 2, 1};

void aes_client::base64_encode(unsigned char *data,
                    size_t input_length,
                    char *encoded_data) {
    // From http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c

    int  output_length = ((input_length - 1) / 3) * 4 + 4;
    encoded_data[output_length] = 0;

    for (unsigned int i = 0, j = 0; i < input_length;) {

        unsigned int octet_a = i < input_length ? data[i++] : 0;
        unsigned int octet_b = i < input_length ? data[i++] : 0;
        unsigned int octet_c = i < input_length ? data[i++] : 0;

        unsigned int triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];

    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';
}

static char *decoding_table = NULL;

void aes_client::base64_decode(const char *data, size_t input_length, size_t *output_length, unsigned char* outputData) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return;

    int inputLength = input_length / 4 * 3;

//    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (inputLength)--;
    if (data[input_length - 2] == '=') (inputLength)--;

    unsigned char t[(size_t)inputLength];
//    unsigned char *decoded_data = t;
//    if (decoded_data == NULL) return;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < inputLength) t[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < inputLength) t[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < inputLength) t[j++] = (triple >> 0 * 8) & 0xFF;
    }

    memcpy(outputData, t, inputLength);
}

void build_decoding_table() {

    static char t[256];
    decoding_table = t;

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}

void aes_client::hexPrint(const unsigned char *buf, size_t len) {
	const char hex[] = "0123456789ABCDEF";
	for (size_t i = 0; i < len; i++) {
		char c = buf[i];
		char hexDigit = hex[(c >> 4) & 0xF];
		Serial.write(hexDigit);
		hexDigit = hex[c & 0xF];
		Serial.write(hexDigit);
		Serial.write(' ');
	}
//	Serial.print("\r\n");
}


