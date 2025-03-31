//Header file for input output functions
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include "base58.h"
#include "common.h"
#include <stdbool.h>
#include "base32_bch.h"

#define PRIVATE_KEY_SIZE 32  // Bitcoin secp256k1 private key is 32 bytes
const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// CashAddr Alphabet (Bech32)
const char CASHADDR_ALPHABET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
// BCH-specific polymod generator
static const uint32_t bech32_polymod_gen[5] = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };

void compute_sha256(const unsigned char *data, unsigned int len, unsigned char *output);
void compute_ripemd160(const unsigned char *data, unsigned int len, unsigned char *output);
void base58(unsigned char *s, int s_size, char *out, int out_size); 
void btc_to_bch(char addrStr[35]);
char* encode(char prefix[], char tp[], uint8_t hh[]);
uint8_t* toUint5Array(uint8_t data[], int data_len);
uint8_t* prefixToUint5Array(uint8_t* prefix, int len);
uint8_t* checksumToUint5Array(uint64_t checksum);
uint8_t* toUint5Array(uint8_t data[], int data_len);
uint8_t* convertBits(uint8_t data[], int data_len, int from, int to, bool strictMode);
int getTypeBits(char tp[]);

// SHA-256
void compute_sha256(const unsigned char *data, unsigned int len, unsigned char *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();  // Create new digest context
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);  // Initialize SHA256
    EVP_DigestUpdate(mdctx, data, len);  // Process data
    EVP_DigestFinal_ex(mdctx, output, &len);  // Finalize and get the hash
    EVP_MD_CTX_free(mdctx);  // Free context
}

// RIPEMD-160
void compute_ripemd160(const unsigned char *data, unsigned int len, unsigned char *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); 
    EVP_DigestInit_ex(mdctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, output, &len);
    EVP_MD_CTX_free(mdctx);  // Free context
}

// Base58 Encode


/* See https://en.wikipedia.org/wiki/Positional_notation#Base_conversion */
void base58(unsigned char *s, int s_size, char *out, int out_size) {
    static const char *base_chars = "123456789"
                                    "ABCDEFGHJKLMNPQRSTUVWXYZ"
                                    "abcdefghijkmnopqrstuvwxyz";

    unsigned char s_cp[s_size];
    memcpy(s_cp, s, s_size);

    int c, i, n;

    out[n = out_size] = 0;
    while (n--) {
        for (c = i = 0; i < s_size; i++) {
            c = c * 256 + s_cp[i];
            s_cp[i] = c / 58;
            c %= 58;
        }
        out[n] = base_chars[c];
    }

}

void generate_keypair(unsigned char *private_key) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;

    // Generate 32 secure random bytes for the private key
    if (RAND_bytes(private_key, PRIVATE_KEY_SIZE) != 1) {
        printf("Error generating random bytes!\n");
    }

    printf("Random Bytes: ");
    for (size_t i = 0; i < PRIVATE_KEY_SIZE; i++) {
        printf("%02x", private_key[i]);  // Print each byte as 2 hex digits
    }
    printf("\n");
    

    // Verify and generate corresponding public key
    if (!secp256k1_ec_seckey_verify(ctx, private_key)) {
        printf("Invalid private key generated.\n");
        return;
    }

    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key)) {
        printf("Failed to create public key.\n");
        return;
    }
    // Serialize public key (compressed format)
    unsigned char pubkey_serialized[33];
    size_t pubkey_length = sizeof(pubkey_serialized);
    unsigned int pubkey_length1 = sizeof(pubkey_serialized);
    secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkey_length, &pubkey, SECP256K1_EC_COMPRESSED);

    printf("Public Key: ");
    for (size_t i = 0; i < pubkey_length; i++) printf("%02X", pubkey_serialized[i]);
    printf("\n");

    // Compute HASH160 (RIPEMD-160(SHA-256(pubkey)))
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];

    unsigned int sha256_digest_length = SHA256_DIGEST_LENGTH;

    compute_sha256(pubkey_serialized, pubkey_length1, sha256_hash);
    compute_ripemd160(sha256_hash, sha256_digest_length, ripemd160_hash);

    printf("PKH (RIPEMD-160 of SHA-256 of Public Key): ");
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        printf("%02x", ripemd160_hash[i]);
    }
    printf("\n");
    
    // Add Bitcoin Cash prefix (0x00)
    unsigned char address_with_prefix[21];
    address_with_prefix[0] = 0x00; // Mainnet prefix
    memcpy(address_with_prefix + 1, ripemd160_hash, 20);

    printf("PKH (RIPEMD-160 of SHA-256 of Public Key): ");
    for (int i = 0; i < 21; i++) {
        printf("%02x",address_with_prefix[i]);
    }
    printf("\n");

  
    //Compute checksum (SHA-256(SHA-256(address_with_prefix)))
    unsigned char checksum_full[SHA256_DIGEST_LENGTH];
    compute_sha256(address_with_prefix, 21, checksum_full);
    compute_sha256(checksum_full, SHA256_DIGEST_LENGTH, checksum_full);

    // Append first 4 bytes of checksum
    unsigned char final_address[25];
    memcpy(final_address, address_with_prefix, 21);
    memcpy(final_address + 21, checksum_full, 4);
    printf("Before base58:");
    for (int i = 0; i < 25; i++) {
        printf("%02x",final_address[i]);
    }
    printf("\n");
    // Encode in Base58Check
    unsigned char bch_address[34];

    base58(final_address,25, bch_address, 34);

    printf("Bitcoin Cash Address(legacy): %s\n", bch_address);
    btc_to_bch(bch_address);
}

int getHashSizeBits(int hash_len)
{
	switch (hash_len* 8) 
	{
	case 160:
		return 0;
	case 192:
		return 1;
	case 224:
		return 2;
	case 256:
		return 3;
	case 320:
		return 4;
	case 384:
		return 5;
	case 448:
		return 6;
	case 512:
		return 7;
	default:
		return -1;
	}
}

/**
* Computes a checksum from the given input data as specified for the CashAddr
* format: https://github.com/Bitcoin-UAHF/spec/blob/master/cashaddr.md.
*
* @private
* @param {Uint8Array} data Array of 5-bit integers over which the checksum is to be computed.
* @returns {BigInteger}
*/
int64_t polymod(uint8_t* data, int data_len) {
	int64_t GENERATOR[] = { 0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470 };
	int64_t checksum = 1;
	for (int i = 0; i < data_len; ++i) {
		uint8_t value = data[i];
		int64_t topBits = checksum>>35;
		checksum = ((checksum & (0x07ffffffff))<<5)^value;
		//checksum = checksum.and(0x07ffffffff).shiftLeft(5).xor(value);
		for (int j = 0; j < 5; ++j) {
			if (((topBits>>j)&1) == 1)
			{
				checksum = checksum^(GENERATOR[j]);
			}
		}
	}
	return checksum ^ (1);
}

uint8_t* convertBits(uint8_t data[], int data_len, int from, int to, bool strictMode) {
	int length = data_len * from / to;
	if((data_len * from) % to != 0)
		length = strictMode? length : length+1;
	int mask = (1 << to) - 1;
	uint8_t* result = malloc(length);
	int index = 0;
	int accumulator = 0;
	int bits = 0;
	for (int i = 0; i < data_len; ++i) 
	{
		uint8_t value = data[i];
		//validate(0 <= value && (value >> from) == = 0, 'Invalid value: ' + value + '.');
		accumulator = (accumulator << from) | value;
		bits += from;
		while (bits >= to) {
			bits -= to;
			result[index] = (accumulator >> bits) & mask;
			++index;
		}
	}
	if (!strictMode) {
		if (bits > 0) {
			result[index] = (accumulator << (to - bits)) & mask;
			++index;
		}
	}
	else {
		//validate(bits < from && ((accumulator << (to - bits)) & mask) == = 0,'Input cannot be converted to ' + to + ' bits without padding, but strict mode was used.'	);
	}
	return result;
};

/**
* Returns an array representation of the given checksum to be encoded
* within the address' payload.
*
* @private
* @param {BigInteger} checksum Computed checksum.
* @returns {Uint8Array}
*/
uint8_t* checksumToUint5Array(uint64_t checksum) {
	printf("checksum: %llu\n", (unsigned long long) checksum);
	uint8_t* result = malloc(8);
	for (int i = 0; i < 8; ++i) {
		result[7 - i] = checksum & (31);
		checksum = checksum>> (5);
	}
	return result;
}

uint8_t* toUint5Array(uint8_t data[], int data_len) {
	return convertBits(data, data_len, 8, 5, false);
}


uint8_t* prefixToUint5Array(uint8_t* prefix, int len) {
	uint8_t* result = (uint8_t*)malloc(len);
	for (int i = 0; i < len; ++i) 
	{
		result[i] = prefix[i] & 31;
	}
	return result;
}
int getTypeBits(char tp[])
{
	if (strcmp(tp, "P2PKH")==0)
		return 0;
	if (strcmp(tp, "P2SH")==0)
		return 8;
	return -1;
}
char* encode(char prefix[], char tp[], uint8_t hh[20]) 
{
	    
		//prefix
		int prefixDataLen = strlen(prefix) + 1;
		uint8_t* prefixData = malloc(strlen(prefix)+1);
		memset(prefixData, 0, strlen(prefix) + 1);
		memcpy(prefixData, prefixToUint5Array(prefix, strlen(prefix)), strlen(prefix));

		//°æ±¾×Ö½Ú 
		uint8_t payloadDataUint8[25] = { 0 };
		uint8_t versionByte = getTypeBits(tp) + getHashSizeBits(20);
		int index = 0;
		memcpy(payloadDataUint8 + index, &versionByte, sizeof(versionByte));
		index += sizeof(versionByte);
		 
		memcpy(payloadDataUint8 + index, hh, 20);
		index += 20;

		uint8_t* payloadData = toUint5Array(payloadDataUint8, index);
		int payloadDataLen = 34;
		for (int i = 0; i < 34; ++i)
		{
			printf("%d\n", payloadData[i]);
		}

		//
		int checksumDataLen = prefixDataLen + payloadDataLen + 8;
		uint8_t* checksumData = malloc(checksumDataLen);
		memset(checksumData, 0, prefixDataLen + payloadDataLen + 8);
		memcpy(checksumData, prefixData, prefixDataLen);
		memcpy(checksumData + prefixDataLen, payloadData, payloadDataLen);
		
		//var checksumData = concat(concat(prefixData, payloadData), new Uint8Array(8));
		int payloadLen = payloadDataLen + 8;
		uint8_t* payload = malloc(payloadLen);
		memset(payload, 0, payloadLen);
		memcpy(payload, payloadData, payloadDataLen);
		memcpy(payload + payloadDataLen, checksumToUint5Array(polymod(checksumData, checksumDataLen)), 8);

		for (int i = 0; i < 42; ++i)
		{
			printf("%d\n", payload[i]);
		}

		char* bchaddr = base32_encode(payload, payloadLen);
		printf("%s",bchaddr);
		return bchaddr;
}

struct btcaddr
{
	uint8_t version;
	uint8_t pubkey_hash[20];
	uint8_t checksum[4];
};

void btc_to_bch(char* addrStr)
{
    if (strlen(addrStr) != 34) {
        printf("Invalid legacy address length: %zu\n", strlen(addrStr));
        return;
    }
	int datalen = 21;
	uint8_t data[25];
	base58_decode_check(addrStr, data, datalen);
	struct btcaddr addr;
	memcpy(&addr, data, 25);

	char prefix[20] = {0};
	char type[20] = {0};
	switch (addr.version)
	{
	case 0x00:
		strncpy(prefix, "bitcoincash", strlen("bitcoincash"));
		strncpy(type, "P2PKH", strlen("P2PKH"));
		break;
	case 0x05:
		strncpy(prefix, "bitcoincash", strlen("bitcoincash"));
		strncpy(type, "P2SH", strlen("P2SH"));
		break;
	case 0x6F:
		strncpy(prefix, "bchtest", strlen("bchtest"));
		strncpy(type, "P2PKH", strlen("P2PKH"));
		break;
	default:
		break;
	}

	char* bchaddr = encode(prefix, type, addr.pubkey_hash);
	printf("%s:%s\n", prefix, bchaddr);
	free(bchaddr);
}

int main() {

    // Writing print statement to print hello world
    printf("Hello World");
    printf("\n");
    unsigned char private_key[PRIVATE_KEY_SIZE];

    generate_keypair(private_key);

    return 0;
}
