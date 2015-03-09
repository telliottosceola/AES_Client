/*
 * aes_encrypt.h
 *
 *  Created on: Mar 3, 2015
 *      Author: travis
 */

#ifndef AES_ENCRYPT_H_
#define AES_ENCRYPT_H_

#include "tropicssl/rsa.h"
#include "tropicssl/aes.h"
#include "spark_wiring_string.h"
#include "spark_wiring.h"
#include "spark_wiring_usbserial.h"
#include "spark_wiring_eeprom.h"

//aes_context mAES;

class aes_client{
public:
	//Constructor
	aes_client(void);
	//Set Master Key
	void setKey(unsigned char* key);

	//Set device ID
	void setID(String dID);

	//ecb Encrypt
	void ecbEncrypt(char* output);

	//ecb Decrypt
	void ecbDecrypt(unsigned char* data, size_t dataLength, unsigned char* key, unsigned char* buffer);

	//cbc Encrypt
	void cbcEncrypt(String message, char* output);

	//cbc Decrypt
	String cbcDecrypt(String message, size_t len);

private:
	void base64_encode(unsigned char *data, size_t input_length, char *encoded_data);
	void base64_decode(const char *data, size_t input_length, size_t *output_length, unsigned char* outputData);
	size_t padding(unsigned char *buf, size_t messageLength);
	bool validatePacket(unsigned char* data);
	void hexPrint(const unsigned char *buf, size_t len);
};



#endif /* AES_ENCRYPT_H_ */
