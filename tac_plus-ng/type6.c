//
// Type 6 encoder/decoder routines from
//
// https://github.com/MarcJHuber/cisco6.git
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <openssl/md5.h>
#include <openssl/aes.h>
#endif

#define TYPE6_SALT_LEN 8
#define TYPE6_MAC_LEN 4

static __inline__ int base41_decode_block(const char in[3], uint8_t out[2])
{
    uint16_t number = 0;
    for (int i = 0; i < 3; i++) {
	if (in[i] < 'A' || in[i] > 'i')
	    return -1;
	number *= 41;
	number += in[i] - 'A';
    }
    out[0] = number >> 8;
    out[1] = number & 0xFF;
    return 0;
}

static __inline__ void base41_encode_two_bytes(const uint8_t data[2], char out[3])
{
    uint16_t number = ((uint16_t) data[0] << 8) | data[1];

    out[2] = 'A' + number % 41;
    number /= 41;
    out[1] = 'A' + number % 41;
    number /= 41;
    out[0] = 'A' + number;
}

static __inline__ int base41_decode(const char *in, uint8_t *out, size_t *out_len)
{
    size_t in_len = strlen(in);
    if (in_len % 3)
	return -1;

    ssize_t j = 0;
    for (size_t i = 0; i < in_len; i += 3, j += 2)
	if (base41_decode_block(in + i, out + j))
	    return -1;

    if (j < 1)
	return -1;

    j -= out[j - 1] ? 2 : 1;

    if (j < 1 || out[j])
	return -1;

    *out_len = j;
    return 0;
}

static __inline__ char *b41_encode(const uint8_t *data, size_t len)
{
    char *out = malloc((len >> 1) * 3 + 1);
    if (out) {
	char *t = out;

	for (size_t i = 0; i < len; i += 2, t += 3)
	    base41_encode_two_bytes(data + i, t);

	*t = 0;
    }
    return out;
}


static void calculate_md5(const char *input, uint8_t *output)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000
    MD5((const unsigned char *) input, strlen(input), output);
#else
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx) {
	EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
	EVP_DigestUpdate(ctx, input, strlen(input));
	EVP_DigestFinal_ex(ctx, output, NULL);
	EVP_MD_CTX_free(ctx);
    }
#endif
}

static void aes_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(in, out, &aes_key);
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int out_len;
    EVP_EncryptUpdate(ctx, out, &out_len, in, 16);

    int final_len;
    EVP_EncryptFinal_ex(ctx, out + out_len, &final_len);

    EVP_CIPHER_CTX_free(ctx);
#endif
}

static int verify_mac(const uint8_t *data, size_t data_len, const char *master_key)
{
    if (data_len < TYPE6_SALT_LEN + TYPE6_MAC_LEN)
	return -1;

    size_t enc_len = data_len - TYPE6_SALT_LEN - TYPE6_MAC_LEN;
    const uint8_t *salt = data;
    const uint8_t *encrypted = data + TYPE6_SALT_LEN;
    const uint8_t *mac = data + TYPE6_SALT_LEN + enc_len;

    uint8_t md5_digest[16];
    calculate_md5(master_key, md5_digest);

    uint8_t ka_input[16] = { 0 };
    memcpy(ka_input, salt, TYPE6_SALT_LEN);

    uint8_t ka[16];
    aes_ecb_encrypt(md5_digest, ka_input, ka);

    unsigned int hmac_len;
    uint8_t *digest = HMAC(EVP_sha1(), ka, 16, encrypted, enc_len, NULL, &hmac_len);
    if (!digest)
	return -1;

    return memcmp(digest, mac, TYPE6_MAC_LEN);
}

static void aes_xor(const char *master_key, const uint8_t salt[TYPE6_SALT_LEN], size_t len, uint8_t *out, const uint8_t *buf)
{
    uint8_t md5_digest[16];
    calculate_md5(master_key, md5_digest);

    uint8_t ke_input[16] = { 0 };
    memcpy(ke_input, salt, TYPE6_SALT_LEN);
    ke_input[15] = 0x01;

    uint8_t ke[16];
    aes_ecb_encrypt(md5_digest, ke_input, ke);

#if OPENSSL_VERSION_NUMBER < 0x30000000
    AES_KEY aes_ke;
    AES_set_encrypt_key(ke, 128, &aes_ke);
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, ke, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
#endif

    uint8_t ke_block[16] = { 0 };

    for (size_t i = 0; i < len; i++) {
	if ((i % 16) == 0) {
	    uint8_t counter_block[16] = { 0 };
	    counter_block[3] = (uint8_t) (i / 16);
#if OPENSSL_VERSION_NUMBER < 0x30000000
	    AES_encrypt(counter_block, ke_block, &aes_ke);
#else
	    int out_len;
	    EVP_EncryptUpdate(ctx, ke_block, &out_len, counter_block, 16);
#endif
	}
	out[i] = buf[i] ^ ke_block[i % 16];
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_CIPHER_CTX_free(ctx);
#endif
}

uint8_t *decrypt_type6(const char *encoded, const char *master_key)
{
    uint8_t decoded[strlen(encoded)];
    size_t decoded_len = 0;

    if (base41_decode(encoded, decoded, &decoded_len) || verify_mac(decoded, decoded_len, master_key))
	return NULL;

    size_t len = decoded_len - TYPE6_SALT_LEN - TYPE6_MAC_LEN;
    uint8_t *output = malloc(len + 1);
    if (!output)
	return NULL;

    aes_xor(master_key, decoded, len, output, decoded + TYPE6_SALT_LEN);

    output[len] = 0;

    return output;
}

char *encrypt_type6(const char *cleartext, const char *master_key)
{
    size_t len = strlen(cleartext);

    uint8_t enc[len];

    uint8_t salt[TYPE6_SALT_LEN];
    RAND_bytes(salt, TYPE6_SALT_LEN);

    aes_xor(master_key, salt, len, enc, (const uint8_t *) cleartext);

    uint8_t md5_digest[16];
    calculate_md5(master_key, md5_digest);

    uint8_t ka_input[16] = { 0 };
    memcpy(ka_input, salt, TYPE6_SALT_LEN);

    uint8_t ka[16];
    aes_ecb_encrypt(md5_digest, ka_input, ka);

    unsigned int hmac_len;
    uint8_t *digest = HMAC(EVP_sha1(), ka, 16, enc, len, NULL, &hmac_len);
    if (digest) {
	uint8_t mac[TYPE6_MAC_LEN];
	memcpy(mac, digest, TYPE6_MAC_LEN);

	size_t pad = (len & 1) ? 0 : 1;
	uint8_t final[TYPE6_SALT_LEN + len + TYPE6_MAC_LEN + 1 + pad];
	memcpy(final, salt, TYPE6_SALT_LEN);
	memcpy(final + TYPE6_SALT_LEN, enc, len);
	memcpy(final + TYPE6_SALT_LEN + len, mac, TYPE6_MAC_LEN);
	final[TYPE6_SALT_LEN + len + TYPE6_MAC_LEN] = 0;
	if (pad)
	    final[TYPE6_SALT_LEN + len + TYPE6_MAC_LEN + 1] = 1;

	return b41_encode(final, TYPE6_SALT_LEN + len + TYPE6_MAC_LEN + 1 + pad);
    }
    return NULL;
}
