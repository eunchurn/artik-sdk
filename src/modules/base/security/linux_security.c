/*
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 */

#include <string.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/pkcs7.h>
#include <openssl/x509v3.h>
#define HEADER_CRYPTLIB_H
#include <openssl/opensslconf.h>
#include <dlfcn.h>

#include <artik_module.h>
#include <artik_security.h>
#include <artik_list.h>
#include <artik_log.h>
#include "linux_security.h"
#include "os_security.h"

#define ARTIK_SE_ENGINE_NAME	"artiksee"
#define COOKIE_SECURITY        "SEC"
#define COOKIE_SIGVERIF        "SIG"
#define PEM_BEGIN_CRT          "-----BEGIN CERTIFICATE-----"
#define PEM_END_CRT            "-----END CERTIFICATE-----"
#define PEM_BEGIN_PUBKEY       "-----BEGIN PUBLIC KEY-----"
#define PEM_BEGIN_EC_PARAMS    "-----BEGIN EC PARAMETERS-----"
#define PEM_BEGIN_EC_PRIV_KEY  "-----BEGIN EC PRIVATE KEY-----"
#define SIZE_BUFFER            100

enum PemType {
	Certificate = 0,
	PublicKey = 1,
	PrivateKey = 2
};

typedef struct {
	artik_list node;
	char cookie[4];
	ENGINE *engine;
	int refcnt;
} security_node;

typedef struct {
	artik_list node;
	char cookie[4];
	PKCS7 *p7;
	X509 *signer_cert;
	PKCS7_SIGNER_INFO *signer;
	EVP_MD_CTX *md_ctx;
} verify_node;

typedef struct {
	artik_list node;
	char *start;
	unsigned int length;
} pem_cert_node;

static const unsigned char base64_enc_map[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
	'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
	'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', '+', '/'
};

static const uint8_t rfc5114_dh1024_160[] = {
	0x30, 0x82, 0x01, 0x08, 0x02, 0x81, 0x81, 0x00,
	0xB1, 0x0B, 0x8F, 0x96, 0xA0, 0x80, 0xE0, 0x1D,
	0xDE, 0x92, 0xDE, 0x5E, 0xAE, 0x5D, 0x54, 0xEC,
	0x52, 0xC9, 0x9F, 0xBC, 0xFB, 0x06, 0xA3, 0xC6,
	0x9A, 0x6A, 0x9D, 0xCA, 0x52, 0xD2, 0x3B, 0x61,
	0x60, 0x73, 0xE2, 0x86, 0x75, 0xA2, 0x3D, 0x18,
	0x98, 0x38, 0xEF, 0x1E, 0x2E, 0xE6, 0x52, 0xC0,
	0x13, 0xEC, 0xB4, 0xAE, 0xA9, 0x06, 0x11, 0x23,
	0x24, 0x97, 0x5C, 0x3C, 0xD4, 0x9B, 0x83, 0xBF,
	0xAC, 0xCB, 0xDD, 0x7D, 0x90, 0xC4, 0xBD, 0x70,
	0x98, 0x48, 0x8E, 0x9C, 0x21, 0x9A, 0x73, 0x72,
	0x4E, 0xFF, 0xD6, 0xFA, 0xE5, 0x64, 0x47, 0x38,
	0xFA, 0xA3, 0x1A, 0x4F, 0xF5, 0x5B, 0xCC, 0xC0,
	0xA1, 0x51, 0xAF, 0x5F, 0x0D, 0xC8, 0xB4, 0xBD,
	0x45, 0xBF, 0x37, 0xDF, 0x36, 0x5C, 0x1A, 0x65,
	0xE6, 0x8C, 0xFD, 0xA7, 0x6D, 0x4D, 0xA7, 0x08,
	0xDF, 0x1F, 0xB2, 0xBC, 0x2E, 0x4A, 0x43, 0x71,
	0x02, 0x81, 0x81, 0x00, 0xA4, 0xD1, 0xCB, 0xD5,
	0xC3, 0xFD, 0x34, 0x12, 0x67, 0x65, 0xA4, 0x42,
	0xEF, 0xB9, 0x99, 0x05, 0xF8, 0x10, 0x4D, 0xD2,
	0x58, 0xAC, 0x50, 0x7F, 0xD6, 0x40, 0x6C, 0xFF,
	0x14, 0x26, 0x6D, 0x31, 0x26, 0x6F, 0xEA, 0x1E,
	0x5C, 0x41, 0x56, 0x4B, 0x77, 0x7E, 0x69, 0x0F,
	0x55, 0x04, 0xF2, 0x13, 0x16, 0x02, 0x17, 0xB4,
	0xB0, 0x1B, 0x88, 0x6A, 0x5E, 0x91, 0x54, 0x7F,
	0x9E, 0x27, 0x49, 0xF4, 0xD7, 0xFB, 0xD7, 0xD3,
	0xB9, 0xA9, 0x2E, 0xE1, 0x90, 0x9D, 0x0D, 0x22,
	0x63, 0xF8, 0x0A, 0x76, 0xA6, 0xA2, 0x4C, 0x08,
	0x7A, 0x09, 0x1F, 0x53, 0x1D, 0xBF, 0x0A, 0x01,
	0x69, 0xB6, 0xA2, 0x8A, 0xD6, 0x62, 0xA4, 0xD1,
	0x8E, 0x73, 0xAF, 0xA3, 0x2D, 0x77, 0x9D, 0x59,
	0x18, 0xD0, 0x8B, 0xC8, 0x85, 0x8F, 0x4D, 0xCE,
	0xF9, 0x7C, 0x2A, 0x24, 0x85, 0x5E, 0x6E, 0xEB,
	0x22, 0xB3, 0xB2, 0xE5
};

static const uint8_t rfc5114_dh2048_224[] = {
	0x30, 0x82, 0x02, 0x0A, 0x02, 0x82, 0x01, 0x01,
	0x00, 0xAD, 0x10, 0x7E, 0x1E, 0x91, 0x23, 0xA9,
	0xD0, 0xD6, 0x60, 0xFA, 0xA7, 0x95, 0x59, 0xC5,
	0x1F, 0xA2, 0x0D, 0x64, 0xE5, 0x68, 0x3B, 0x9F,
	0xD1, 0xB5, 0x4B, 0x15, 0x97, 0xB6, 0x1D, 0x0A,
	0x75, 0xE6, 0xFA, 0x14, 0x1D, 0xF9, 0x5A, 0x56,
	0xDB, 0xAF, 0x9A, 0x3C, 0x40, 0x7B, 0xA1, 0xDF,
	0x15, 0xEB, 0x3D, 0x68, 0x8A, 0x30, 0x9C, 0x18,
	0x0E, 0x1D, 0xE6, 0xB8, 0x5A, 0x12, 0x74, 0xA0,
	0xA6, 0x6D, 0x3F, 0x81, 0x52, 0xAD, 0x6A, 0xC2,
	0x12, 0x90, 0x37, 0xC9, 0xED, 0xEF, 0xDA, 0x4D,
	0xF8, 0xD9, 0x1E, 0x8F, 0xEF, 0x55, 0xB7, 0x39,
	0x4B, 0x7A, 0xD5, 0xB7, 0xD0, 0xB6, 0xC1, 0x22,
	0x07, 0xC9, 0xF9, 0x8D, 0x11, 0xED, 0x34, 0xDB,
	0xF6, 0xC6, 0xBA, 0x0B, 0x2C, 0x8B, 0xBC, 0x27,
	0xBE, 0x6A, 0x00, 0xE0, 0xA0, 0xB9, 0xC4, 0x97,
	0x08, 0xB3, 0xBF, 0x8A, 0x31, 0x70, 0x91, 0x88,
	0x36, 0x81, 0x28, 0x61, 0x30, 0xBC, 0x89, 0x85,
	0xDB, 0x16, 0x02, 0xE7, 0x14, 0x41, 0x5D, 0x93,
	0x30, 0x27, 0x82, 0x73, 0xC7, 0xDE, 0x31, 0xEF,
	0xDC, 0x73, 0x10, 0xF7, 0x12, 0x1F, 0xD5, 0xA0,
	0x74, 0x15, 0x98, 0x7D, 0x9A, 0xDC, 0x0A, 0x48,
	0x6D, 0xCD, 0xF9, 0x3A, 0xCC, 0x44, 0x32, 0x83,
	0x87, 0x31, 0x5D, 0x75, 0xE1, 0x98, 0xC6, 0x41,
	0xA4, 0x80, 0xCD, 0x86, 0xA1, 0xB9, 0xE5, 0x87,
	0xE8, 0xBE, 0x60, 0xE6, 0x9C, 0xC9, 0x28, 0xB2,
	0xB9, 0xC5, 0x21, 0x72, 0xE4, 0x13, 0x04, 0x2E,
	0x9B, 0x23, 0xF1, 0x0B, 0x0E, 0x16, 0xE7, 0x97,
	0x63, 0xC9, 0xB5, 0x3D, 0xCF, 0x4B, 0xA8, 0x0A,
	0x29, 0xE3, 0xFB, 0x73, 0xC1, 0x6B, 0x8E, 0x75,
	0xB9, 0x7E, 0xF3, 0x63, 0xE2, 0xFF, 0xA3, 0x1F,
	0x71, 0xCF, 0x9D, 0xE5, 0x38, 0x4E, 0x71, 0xB8,
	0x1C, 0x0A, 0xC4, 0xDF, 0xFE, 0x0C, 0x10, 0xE6,
	0x4F, 0x02, 0x82, 0x01, 0x01, 0x00, 0xAC, 0x40,
	0x32, 0xEF, 0x4F, 0x2D, 0x9A, 0xE3, 0x9D, 0xF3,
	0x0B, 0x5C, 0x8F, 0xFD, 0xAC, 0x50, 0x6C, 0xDE,
	0xBE, 0x7B, 0x89, 0x99, 0x8C, 0xAF, 0x74, 0x86,
	0x6A, 0x08, 0xCF, 0xE4, 0xFF, 0xE3, 0xA6, 0x82,
	0x4A, 0x4E, 0x10, 0xB9, 0xA6, 0xF0, 0xDD, 0x92,
	0x1F, 0x01, 0xA7, 0x0C, 0x4A, 0xFA, 0xAB, 0x73,
	0x9D, 0x77, 0x00, 0xC2, 0x9F, 0x52, 0xC5, 0x7D,
	0xB1, 0x7C, 0x62, 0x0A, 0x86, 0x52, 0xBE, 0x5E,
	0x90, 0x01, 0xA8, 0xD6, 0x6A, 0xD7, 0xC1, 0x76,
	0x69, 0x10, 0x19, 0x99, 0x02, 0x4A, 0xF4, 0xD0,
	0x27, 0x27, 0x5A, 0xC1, 0x34, 0x8B, 0xB8, 0xA7,
	0x62, 0xD0, 0x52, 0x1B, 0xC9, 0x8A, 0xE2, 0x47,
	0x15, 0x04, 0x22, 0xEA, 0x1E, 0xD4, 0x09, 0x93,
	0x9D, 0x54, 0xDA, 0x74, 0x60, 0xCD, 0xB5, 0xF6,
	0xC6, 0xB2, 0x50, 0x71, 0x7C, 0xBE, 0xF1, 0x80,
	0xEB, 0x34, 0x11, 0x8E, 0x98, 0xD1, 0x19, 0x52,
	0x9A, 0x45, 0xD6, 0xF8, 0x34, 0x56, 0x6E, 0x30,
	0x25, 0xE3, 0x16, 0xA3, 0x30, 0xEF, 0xBB, 0x77,
	0xA8, 0x6F, 0x0C, 0x1A, 0xB1, 0x5B, 0x05, 0x1A,
	0xE3, 0xD4, 0x28, 0xC8, 0xF8, 0xAC, 0xB7, 0x0A,
	0x81, 0x37, 0x15, 0x0B, 0x8E, 0xEB, 0x10, 0xE1,
	0x83, 0xED, 0xD1, 0x99, 0x63, 0xDD, 0xD9, 0xE2,
	0x63, 0xE4, 0x77, 0x05, 0x89, 0xEF, 0x6A, 0xA2,
	0x1E, 0x7F, 0x5F, 0x2F, 0xF3, 0x81, 0xB5, 0x39,
	0xCC, 0xE3, 0x40, 0x9D, 0x13, 0xCD, 0x56, 0x6A,
	0xFB, 0xB4, 0x8D, 0x6C, 0x01, 0x91, 0x81, 0xE1,
	0xBC, 0xFE, 0x94, 0xB3, 0x02, 0x69, 0xED, 0xFE,
	0x72, 0xFE, 0x9B, 0x6A, 0xA4, 0xBD, 0x7B, 0x5A,
	0x0F, 0x1C, 0x71, 0xCF, 0xFF, 0x4C, 0x19, 0xC4,
	0x18, 0xE1, 0xF6, 0xEC, 0x01, 0x79, 0x81, 0xBC,
	0x08, 0x7F, 0x2A, 0x70, 0x65, 0xB3, 0x84, 0xB8,
	0x90, 0xD3, 0x19, 0x1F, 0x2B, 0xFA
};

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* Compatibility layer between OpenSSL 1.0.2 and 1.1.0 */
static EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey)
{
	if (pkey->type != EVP_PKEY_EC)
		return NULL;

	return pkey->pkey.ec;
}
#endif


static int (*see_device_init)(const char *id, const char *pwd);
static int (*see_device_deinit)(void);
static see_dev *(*see_device_get)(void);
static void *g_dlopen_handle = NULL;
static see_dev *g_see_dev = NULL;
static artik_list *requested_node = NULL;
static artik_list *verify_nodes = NULL;
static int *dev_debug;
static bool openssl_global_init = false;
static ENGINE *openssl_engine   = NULL;
static int openssl_engine_refcnt = 0;

static char *strnstr(const char *haystack, const char *needle, size_t len)
{
	int i;
	size_t needle_len;

	needle_len = strnlen(needle, len);
	if (!needle_len)
		return (char *)haystack;

	for (i = 0; i <= (int)(len-needle_len); i++) {
		if ((haystack[0] == needle[0]) &&
				(!memcmp(haystack, needle, needle_len)))
			return (char *)haystack;

		haystack++;
	}

	return NULL;
}

static int asn1_parse_int(unsigned char **p, unsigned int n, unsigned int *res)
{
	*res = 0;

	for ( ; n > 0; --n) {
		if ((**p < '0') || (**p > '9'))
			return -1;
		*res *= 10;
		*res += (*(*p)++ - '0');
	}

	return 0;
}

static bool convert_asn1_time(ASN1_TYPE *in, artik_time *out)
{
	unsigned char *in_str;
	int len;

	if (!in || !out || (in->type != V_ASN1_UTCTIME))
		return false;

	in_str = in->value.asn1_string->data;
	len = strlen((const char *)in_str);
	memset(out, 0, sizeof(*out));

	/* Parse date */
	if (asn1_parse_int(&in_str, 2, &out->year))
		return false;
	if (asn1_parse_int(&in_str, 2, &out->month))
		return false;
	if (asn1_parse_int(&in_str, 2, &out->day))
		return false;
	if (asn1_parse_int(&in_str, 2, &out->hour))
		return false;
	if (asn1_parse_int(&in_str, 2, &out->minute))
		return false;

	/* Parse seconds if available */
	if (len > 10) {
		if (asn1_parse_int(&in_str, 2, &out->second))
			return false;
	}

	/* Check if we have 'Z' as expected */
	if ((len > 12) && (*in_str != 'Z'))
		return false;

	/* Adjust to full year */
	out->year += 100 * (out->year < 50);
	out->year += 1900;

	return true;
}

static int base64_encode(unsigned char *dst, unsigned int dlen, unsigned int *olen,
		const unsigned char *src, unsigned int slen)
{
	unsigned int i, n;
	unsigned int C1, C2, C3;
	unsigned char *p;

	if (slen == 0) {
		*olen = 0;
		return 0;
	}

	n = (slen << 3) / 6;

	switch ((slen << 3) - (n * 6)) {
	case 2:
		n += 3;
		break;
	case 4:
		n += 2;
		break;
	default:
		break;
	}

	if (dlen < n + 1) {
		*olen = n + 1;
		return -1;
	}

	n = (slen / 3) * 3;

	for (i = 0, p = dst; i < n; i += 3) {
		C1 = *src++;
		C2 = *src++;
		C3 = *src++;

		*p++ = base64_enc_map[(C1 >> 2) & 0x3F];
		*p++ = base64_enc_map[(((C1 &  3) << 4) + (C2 >> 4)) & 0x3F];
		*p++ = base64_enc_map[(((C2 & 15) << 2) + (C3 >> 6)) & 0x3F];
		*p++ = base64_enc_map[C3 & 0x3F];
	}

	if (i < slen) {
		C1 = *src++;
		C2 = ((i + 1) < slen) ? *src++ : 0;

		*p++ = base64_enc_map[(C1 >> 2) & 0x3F];
		*p++ = base64_enc_map[(((C1 & 3) << 4) + (C2 >> 4)) & 0x3F];

		if ((i + 1) < slen)
			*p++ = base64_enc_map[((C2 & 15) << 2) & 0x3F];
		else
			*p++ = '=';

		*p++ = '=';
	}

	*olen = p - dst;
	*p = 0;

	return 0;
}

static artik_error os_security_convert_der_to_pem(const unsigned char *der_data,
		unsigned int derLen, unsigned char **pem_data, unsigned int *pemLen)
{
	unsigned int ret;
	unsigned char *encodeBuf = NULL, *pBuf = NULL, *c = NULL;
	unsigned int useLen, addLen, len;

	base64_encode(NULL, 0, &useLen, der_data, derLen);
	addLen = strlen(PEM_BEGIN_CRT) + strlen(PEM_END_CRT) + (useLen / 64) + 3;

	*pemLen = useLen + addLen;
	*pem_data = (unsigned char *)malloc(sizeof(**pem_data) * (*pemLen));
	if (!(*pem_data))
		return E_NO_MEM;

	encodeBuf = calloc(1, useLen);
	if (!encodeBuf)
		return E_NO_MEM;

	ret = base64_encode(encodeBuf, useLen, &useLen, der_data, derLen);
	if (ret) {
		free(encodeBuf);
		free(*pem_data);
		return E_SECURITY_ERROR;
	}

	pBuf = *pem_data;

	memcpy(pBuf, PEM_BEGIN_CRT, strlen(PEM_BEGIN_CRT));
	pBuf += strlen(PEM_BEGIN_CRT);
	*pBuf++ = '\n';
	c = encodeBuf;

	while (useLen) {
		len = (useLen > 64) ? 64 : useLen;
		memcpy(pBuf, c, len);
		useLen -= len;
		pBuf += len;
		c += len;
		*pBuf++ = '\n';
	}

	memcpy(pBuf, PEM_END_CRT, strlen(PEM_END_CRT));
	pBuf += strlen(PEM_END_CRT);

	*pBuf++ = '\n';
	*pBuf++ = '\0';
	free(encodeBuf);

	return S_OK;
}

static int os_convert_name(const char *iname, char *oname)
{
	if (iname[SECU_LOCATION_STRLEN] != '/')
		return E_BAD_ARGS;
	if (!strncmp(iname, ARTIK_STORAGE, SECU_LOCATION_STRLEN)) {
		memcpy(oname, "ARTIK", strlen("ARTIK"));
		memcpy(oname + strlen("ARTIK"), iname + strlen(ARTIK_STORAGE),
				strlen(iname) - strlen(ARTIK_STORAGE) + 1);
	} else if (!strncmp(iname, PROVISION_STORAGE, SECU_LOCATION_STRLEN)) {
		memcpy(oname, "POSTP", strlen("POSTP"));
		memcpy(oname + strlen("POSTP"), iname + strlen(PROVISION_STORAGE),
				strlen(iname) - strlen(PROVISION_STORAGE) + 1);
	} else if (!strncmp(iname, SECURE_STORAGE_DEFAULT, SECU_LOCATION_STRLEN)) {
		memcpy(oname, iname + strlen(SECURE_STORAGE_DEFAULT) + 1,
				strlen(iname) - strlen(SECURE_STORAGE_DEFAULT));
	} else if (!strncmp(iname, SECURE_STORAGE_SE, SECU_LOCATION_STRLEN)) {
		memcpy(oname, "SE", strlen("SE"));
		memcpy(oname + strlen("SE"), iname + strlen(SECURE_STORAGE_SE),
				strlen(iname) - strlen(SECURE_STORAGE_SE) + 1);
	} else if (!strncmp(iname, SECURE_STORAGE_MEMORY, SECU_LOCATION_STRLEN)) {
		memcpy(oname, "TMP", strlen("TMP"));
		memcpy(oname + strlen("TMP"), iname + strlen(SECURE_STORAGE_MEMORY),
				strlen(iname) - strlen(SECURE_STORAGE_MEMORY) + 1);
	} else {
		return E_BAD_ARGS;
	}

	return S_OK;
}

static unsigned int os_convert_mode(unsigned int algo, unsigned int mode)
{
	switch (algo) {
	case AES_ALGORITHM:
		switch (mode) {
		case AES_ECB_NOPAD:
			return LINUX_AES_ECB_NOPAD;
		case AES_ECB_PKCS7:
			return LINUX_AES_ECB_PKCS7;
		case AES_CBC_NOPAD:
			return LINUX_AES_CBC_NOPAD;
		case AES_CBC_PKCS7:
			return LINUX_AES_CBC_PKCS7;
		case AES_CTR_NOPAD:
			return LINUX_AES_CTR;
		default:
			return mode;
		}
	case RSA_ALGORITHM:
		switch (mode) {
		case RSAES_1024_PKCS1_V1_5:
		case RSAES_2048_PKCS1_V1_5:
			return LINUX_RSAES_PKCS1_V1_5;
		case RSASSA_1024_PKCS1_V1_5_SHA160:
		case RSASSA_2048_PKCS1_V1_5_SHA160:
			return LINUX_RSASSA_PKCS1_V1_5_SHA1;
		case RSASSA_1024_PKCS1_V1_5_SHA256:
		case RSASSA_2048_PKCS1_V1_5_SHA256:
			return LINUX_RSASSA_PKCS1_V1_5_SHA256;
		case RSASSA_1024_PKCS1_V1_5_SHA384:
		case RSASSA_2048_PKCS1_V1_5_SHA384:
			return LINUX_RSASSA_PKCS1_V1_5_SHA384;
		case RSASSA_1024_PKCS1_V1_5_SHA512:
		case RSASSA_2048_PKCS1_V1_5_SHA512:
			return LINUX_RSASSA_PKCS1_V1_5_SHA512;
		case RSASSA_1024_PKCS1_PSS_MGF1_SHA160:
		case RSASSA_2048_PKCS1_PSS_MGF1_SHA160:
			return LINUX_RSASSA_PKCS1_PSS_MGF1_SHA1;
		case RSASSA_1024_PKCS1_PSS_MGF1_SHA256:
		case RSASSA_2048_PKCS1_PSS_MGF1_SHA256:
			return LINUX_RSASSA_PKCS1_PSS_MGF1_SHA256;
		case RSASSA_1024_PKCS1_PSS_MGF1_SHA384:
		case RSASSA_2048_PKCS1_PSS_MGF1_SHA384:
			return LINUX_RSASSA_PKCS1_PSS_MGF1_SHA384;
		case RSASSA_1024_PKCS1_PSS_MGF1_SHA512:
		case RSASSA_2048_PKCS1_PSS_MGF1_SHA512:
			return LINUX_RSASSA_PKCS1_PSS_MGF1_SHA512;
		default:
			return mode;
		}
	case ECC_ALGORITHM:
		switch (mode) {
		case ECC_BRAINPOOL_P256R1:
			return LINUX_ECDSA_BRAINPOOL_P256R1;
		case ECC_SEC_P256R1:
			return LINUX_ECDSA_SEC_P256R1;
		case ECC_SEC_P384R1:
			return LINUX_ECDSA_SEC_P384R1;
		case ECC_SEC_P521R1:
			return LINUX_ECDSA_SEC_P521R1;
		default:
			return mode;
		}
	case HMAC_ALGORITHM:
		switch (mode) {
		case HASH_SHA1_160:
			return LINUX_HMAC_SHA1;
		case HASH_SHA2_256:
			return LINUX_HMAC_SHA256;
		case HASH_SHA2_384:
			return LINUX_HMAC_SHA384;
		case HASH_SHA2_512:
			return LINUX_HMAC_SHA512;
		default:
			return mode;
		}
	default:
		return mode;
	}
}

static unsigned int os_convert_algo(unsigned int algo)
{
	switch (algo) {
	case AES_128:
		return LINUX_AES_128;
	case AES_192:
		return LINUX_AES_192;
	case AES_256:
		return LINUX_AES_256;
	case RSA_1024:
		return LINUX_RSA_1024;
	case RSA_2048:
		return LINUX_RSA_2048;
	case ECC_BRAINPOOL_P256R1:
		return LINUX_ECC_BRAINPOOL_P256R1;
	case ECC_SEC_P256R1:
		return LINUX_ECC_SEC_P256R1;
	case ECC_SEC_P384R1:
		return LINUX_ECC_SEC_P384R1;
	case ECC_SEC_P521R1:
		return LINUX_ECC_SEC_P521R1;
	case HMAC_ALGORITHM:
		return LINUX_HMAC_ALGORITHM;
	case DH_1024:
		return LINUX_DH_1024;
	case DH_1024_5114:
		return LINUX_DH_1024_5114;
	case DH_2048:
		return LINUX_DH_2048;
	case DH_2048_5114:
		return LINUX_DH_2048_5114;
	case HASH_SHA1_160:
		return LINUX_HASH_SHA1;
	case HASH_SHA2_256:
		return LINUX_HASH_SHA256;
	case HASH_SHA2_384:
		return LINUX_HASH_SHA384;
	case HASH_SHA2_512:
		return LINUX_HASH_SHA512;
	default:
		return algo;
	}
}

artik_error os_security_request(artik_security_handle *handle)
{
	security_node *node = (security_node *) artik_list_add(&requested_node,
						0, sizeof(security_node));
	char *error;
	void *dlopen_handle;

	if (!node)
		return E_NO_MEM;

	node->node.handle = (ARTIK_LIST_HANDLE) node;
	*handle = (artik_security_handle)node;

	if (g_dlopen_handle == NULL && artik_list_size(requested_node) == 1) {
		dlopen_handle = dlopen("libsee-linux.so.0", RTLD_NOW);
		error = dlerror();
		if (error) {
			log_err("failed to open libsee-linux.so.0 : %s", error);
			return E_NOT_INITIALIZED;
		}

		*(void **)(&see_device_init) = dlsym(dlopen_handle, "see_device_init");
		error = dlerror();
		if (error) {
			log_err("failed to dlsym see_device_init : %s", error);
			goto ERROR;
		}

		*(void **)(&see_device_deinit) = dlsym(dlopen_handle, "see_device_deinit");
		error = dlerror();
		if (error) {
			log_err("failed to dlsym see_device_deinit : %s", error);
			goto ERROR;
		}

		*(void **)(&see_device_get) = dlsym(dlopen_handle, "see_device_get");
		error = dlerror();
		if (error) {
			log_err("failed to dlsym see_device_get : %s", error);
			goto ERROR;
		}

		dev_debug = dlsym(dlopen_handle, "dev_debug");
		error = dlerror();
		if (error) {
			log_err("failed to dlsym dev_debug : %s", error);
			goto ERROR;
		}

		*dev_debug = 2;
		if (see_device_init("ARTIK SDK", "ARTIK SDK") < 0) {
			log_err("failed to initialize device");
			goto ERROR;
		}

		g_see_dev = see_device_get();
		if (!g_see_dev) {
			log_err("failed to get device");
			goto ERROR;
		}

		g_dlopen_handle = dlopen_handle;
	}
	return S_OK;

ERROR:
	g_see_dev = NULL;
	if (dlopen_handle)
		dlclose(dlopen_handle);
	return E_NOT_INITIALIZED;
}

artik_error os_security_release(artik_security_handle handle)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);

	artik_list_delete_node(&requested_node, (artik_list *)node);

	if (g_dlopen_handle != NULL && artik_list_size(requested_node) == 0) {
		g_see_dev = NULL;
		see_device_deinit();
		if (g_dlopen_handle)
			dlclose(g_dlopen_handle);
		g_dlopen_handle = NULL;
	}

	return S_OK;
}

artik_error os_security_get_random_bytes(artik_security_handle handle,
		unsigned int rand_size, unsigned char **rand)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data random;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!rand) {
		log_err("Invalid random buffer");
		return E_BAD_ARGS;
	}
	if (rand_size == 0) {
		log_err("Invalid random size: %d", rand_size);
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->generate_random) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	random.data = NULL;
	random.length = 0;

	if (g_see_dev->generate_random(rand_size, &random) < 0) {
		log_err("generate random error");
		return E_SECURITY_ERROR;
	}

	if (rand_size != random.length) {
		log_err("generate random error");
		return E_SECURITY_ERROR;
	}

	*rand = random.data;

	return S_OK;
}

artik_error os_security_get_ec_pubkey_from_cert(const char *cert, char **key)
{
	artik_error ret = S_OK;
	X509 *x509 = NULL;
	EC_KEY *ec_pub = NULL;
	EVP_PKEY *evp_pub = NULL;
	BIO *ibio = NULL;
	BUF_MEM *bptr = NULL;

	if (!cert || !key || *key)
		return E_BAD_ARGS;

	ibio = BIO_new(BIO_s_mem());

	if (!ibio) {
		ret = E_NO_MEM;
		goto exit;
	}

	BIO_write(ibio, cert, strlen(cert));

	x509 = PEM_read_bio_X509(ibio, NULL, NULL, NULL);

	if (!x509) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	evp_pub = X509_get_pubkey(x509);

	if (!evp_pub) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	ec_pub = EVP_PKEY_get0_EC_KEY(evp_pub);

	if (!ec_pub) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	if (ibio)
		BIO_free(ibio);

	ibio = BIO_new(BIO_s_mem());
	PEM_write_bio_EC_PUBKEY(ibio, ec_pub);
	BIO_write(ibio, "\0", 1);
	BIO_get_mem_ptr(ibio, &bptr);

	if (!bptr) {
		ret = E_NO_MEM;
		goto exit;
	}

	*key = (char *)malloc(sizeof(**key) * bptr->length);
	if (!(*key)) {
		ret = E_NO_MEM;
		goto exit;
	}

	BIO_read(ibio, (void *)(*key), bptr->length);

exit:
	if (x509)
		X509_free(x509);
	if (ibio)
		BIO_free(ibio);
	if (evp_pub)
		EVP_PKEY_free(evp_pub);
	return ret;
}

artik_error os_security_set_certificate(artik_security_handle handle,
		const char *cert_name, const unsigned char *cert,
		unsigned int cert_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data certificate;
	char name[20] = { 0, };

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!cert_name) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}
	if (!cert) {
		log_err("Invalid certificate buffer");
		return E_BAD_ARGS;
	}
	if (cert_size == 0) {
		log_err("Invalid certificate size: %d", cert_size);
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->set_certificate) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(cert_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	certificate.data = (unsigned char *)cert;
	certificate.length = cert_size;
	if (g_see_dev->set_certificate(name, &certificate) < 0) {
		log_err("set certificate error");
		return E_SECURITY_ERROR;
	}

	return S_OK;
}

artik_error os_security_get_certificate(artik_security_handle handle,
		const char *cert_name, artik_security_cert_type_t type,
		unsigned char **cert, unsigned int *cert_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data certificate;
	char name[20] = { 0, };
	char *cert_pem = NULL;
	char *artik_pem = NULL;
	int num;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!cert_name) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}
	if (!cert || !cert_size) {
		log_err("Invalid certificate buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->get_certificate) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(cert_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	if (!strncmp(ARTIK_STORAGE, name, strlen(ARTIK_STORAGE))) {
		if (g_see_dev->get_certificate("ARTIK/0", &certificate) < 0) {
			log_err("get certificate error");
			return E_SECURITY_ERROR;
		}

		num = name[strlen(ARTIK_STORAGE) + 1] - '0';
		if (num >= ARTIK_CERTS_NUM) {
			log_err("Invalid certificate name");
			return E_BAD_ARGS;
		}
		cert_pem = certificate.data;
		while (num != ARTIK_CERTS_NUM - 1) {
			cert_pem += strlen(PEM_BEGIN_CRT);
			cert_pem = strstr(cert_pem, PEM_BEGIN_CRT);
			num++;
		}
		artik_pem = strstr(cert_pem, PEM_END_CRT) + strlen(PEM_END_CRT);
		num = artik_pem - cert_pem + 1;
		artik_pem = (char *)malloc(sizeof(char) * num);
		memcpy(artik_pem, cert_pem, num - 1);
		artik_pem[num - 1] = '\0';
		free(certificate.data);
		certificate.data = artik_pem;
		certificate.length = num;
	} else {
		if (g_see_dev->get_certificate(name, &certificate) < 0) {
			log_err("get certificate error");
			return E_SECURITY_ERROR;
		}
	}

	if (!strncmp(certificate.data, PEM_BEGIN_CRT, strlen(PEM_BEGIN_CRT) - 1)) {
		switch (type) {
		case ARTIK_SECURITY_CERT_TYPE_PEM:
			*cert = certificate.data;
			*cert_size = certificate.length;
			break;
		case ARTIK_SECURITY_CERT_TYPE_DER:
			cert_pem = strndup(certificate.data, certificate.length);
			os_security_convert_pem_to_der(cert_pem, cert, cert_size);
			free(cert_pem);
			break;
		default:
			return E_BAD_ARGS;
		}
	} else {
		switch (type) {
		case ARTIK_SECURITY_CERT_TYPE_PEM:
			os_security_convert_der_to_pem(certificate.data, certificate.length,
					cert, cert_size);
			free(certificate.data);
			break;
		case ARTIK_SECURITY_CERT_TYPE_DER:
			*cert = certificate.data;
			*cert_size = certificate.length;
			break;
		default:
			return E_BAD_ARGS;
		}
	}

	return S_OK;
}

artik_error os_security_get_certificate_sn(const char *cert, unsigned char *sn,
		unsigned int *len)
{
	X509            *x509 = NULL;
	BIO             *ibio = NULL;
	ASN1_INTEGER    *serial = NULL;
	BIGNUM          *serialBN = NULL;
	artik_error     ret = S_OK;

	if (!sn || !len || (*len == 0))
		return E_BAD_ARGS;

	ibio = BIO_new(BIO_s_mem());
	if (BIO_puts(ibio, cert) < 0) {
		ret = E_INVALID_VALUE;
		goto exit;
	}

	x509 = PEM_read_bio_X509_AUX(ibio, NULL, NULL, NULL);
	if (!x509) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	serial = X509_get_serialNumber(x509);
	if (!serial) {
		ret = E_INVALID_VALUE;
		goto exit;
	}

	serialBN = ASN1_INTEGER_to_BN(serial, NULL);
	if (BN_num_bytes(serialBN) > *len) {
		ret = E_BAD_ARGS;
		goto exit;
	}
	*len = BN_bn2bin(serialBN, sn);
exit:
	if (serialBN)
		BN_free(serialBN);
	if (x509)
		X509_free(x509);
	if (ibio)
		BIO_free(ibio);
	return ret;
}

static void pem_chain_list_clear(artik_list *elm)
{
	/* It should be a string allocated with strndup, free it */
	free(elm->data);
}

artik_error os_security_get_certificate_pem_chain(artik_security_handle handle,
		const char *cert_name, artik_list **chain)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	artik_error ret = S_OK;
	see_data certificate;
	int i = 0;
	char *finger = NULL;
	char *begin = NULL;
	char *end = NULL;
	int remaining = 0;
	artik_list *pem_certs = NULL;
	pem_cert_node *pem_cert = NULL;
	BIO *cbio = NULL;
	X509 *x509 = NULL;
	BUF_MEM *bptr = NULL;
	artik_list *cpem = NULL;
	char name[20] = { 0, };

	if (!node || !cert_name || !chain)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->get_certificate)
		return E_NOT_SUPPORTED;

	if (os_convert_name(cert_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	if (g_see_dev->get_certificate(name, &certificate) < 0)
		return E_SECURITY_ERROR;

	/* Count number of certs and store boundaries */
	finger = (char *)certificate.data;
	while (1) {
		remaining = certificate.length - (finger - (char *)certificate.data);

		begin = strnstr(finger, PEM_BEGIN_CRT, remaining);
		if (!begin)
			break;

		remaining = certificate.length - (begin - (char *)certificate.data);
		end = strnstr(begin, PEM_END_CRT, remaining);
		if (!end)
			break;

		end += strlen(PEM_END_CRT);
		pem_cert = (pem_cert_node *) artik_list_add(&pem_certs, 0,
				sizeof(pem_cert_node));
		pem_cert->start = begin;
		pem_cert->length = end - begin;

		finger = end;

		if (finger >= ((char *)certificate.data + certificate.length))
			break;
	}

	log_dbg("read %d PEM certificates\n", artik_list_size(pem_certs));

	if (!artik_list_size(pem_certs)) {
		/* No PEM certificates were detected, try DER parsing */
		cbio = BIO_new_mem_buf((void *)certificate.data, certificate.length);
		if (!cbio) {
			log_err("Failed to allocate memory\n");
			ret = E_NO_MEM;
			goto exit;
		}

		x509 = d2i_X509_bio(cbio, NULL);
		if (!x509) {
			log_err("Failed to parse DER certificate\n");
			ret = E_SECURITY_INVALID_X509;
			goto exit;
		}

		BIO_free(cbio);

		/* Convert X509 into a PEM string */
		cbio = BIO_new(BIO_s_mem());
		PEM_write_bio_X509(cbio, x509);
		BIO_write(cbio, "\0", 1);
		BIO_get_mem_ptr(cbio, &bptr);
		if (!bptr) {
			BIO_free(cbio);
			log_err("Failed to convert to PEM string\n");
			ret = E_SECURITY_INVALID_X509;
			goto exit;
		}

		cpem = artik_list_add(chain, NULL, sizeof(artik_list));
		if (!cpem) {
			BIO_free(cbio);
			log_err("Failed to allocate memory\n");
			ret = E_NO_MEM;
			goto exit;
		}

		cpem->data = malloc(bptr->length);
		if (!cpem->data) {
			artik_list_delete_node(chain, cpem);
			BIO_free(cbio);
			log_err("Failed to allocate memory\n");
			ret = E_NO_MEM;
			goto exit;
		}

		BIO_read(cbio, (void *)cpem->data, bptr->length);
		BIO_free(cbio);

		goto exit;
	}

	/* Extract PEM strings for each certificate found */
	for (i = 0; i < artik_list_size(pem_certs); i++) {
		pem_cert = (pem_cert_node *)artik_list_get_by_pos(pem_certs, i);
		if (!pem_cert)
			break;

		cpem = artik_list_add(chain, NULL, sizeof(artik_list));
		if (!cpem)
			break;

		cpem->data = (void *)strndup(pem_cert->start, pem_cert->length);
		if (!cpem->data) {
			artik_list_delete_node(chain, cpem);
			break;
		}

		cpem->clear = pem_chain_list_clear;
	}

	artik_list_delete_all(&pem_certs);

exit:
	return ret;
}

artik_error os_security_remove_certificate(artik_security_handle handle,
		const char *cert_name)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	char name[20] = { 0, };

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!cert_name) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->remove_certificate) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(cert_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	if (g_see_dev->remove_certificate(name) < 0) {
		log_err("remove certificate error");
		return E_SECURITY_ERROR;
	}

	return S_OK;
}

artik_error os_security_get_hash(artik_security_handle handle,
		unsigned int hash_algo, const unsigned char *input,
		unsigned int input_size, unsigned char **hash, unsigned int *hash_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data input_data;
	see_data hash_data;

	unsigned int linux_hash_algo;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!input) {
		log_err("Invalid input buffer");
		return E_BAD_ARGS;
	}
	if (input_size == 0) {
		log_err("Invalid input size");
		return E_BAD_ARGS;
	}
	if (!hash || !hash_size) {
		log_err("Invalid hash buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->get_hash) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	linux_hash_algo = os_convert_algo(hash_algo);

	input_data.data = (unsigned char *)input;
	input_data.length = input_size;

	if (g_see_dev->get_hash(linux_hash_algo, &input_data, &hash_data) < 0) {
		log_err("get hash error");
		return E_SECURITY_ERROR;
	}

	*hash = hash_data.data;
	*hash_size = hash_data.length;

	return S_OK;
}

artik_error os_security_get_hmac(artik_security_handle handle,
		unsigned int hmac_algo, const char *key_name,
		const unsigned char *input, unsigned int input_size,
		unsigned char **hmac, unsigned int *hmac_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data input_data;
	see_data hmac_data;
	char name[20] = { 0, };

	unsigned int linux_hmac_algo;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!input) {
		log_err("Invalid input buffer");
		return E_BAD_ARGS;
	}
	if (input_size == 0) {
		log_err("Invalid input size");
		return E_BAD_ARGS;
	}
	if (!hmac || !hmac_size) {
		log_err("Invalid hmac buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->get_hmac) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_hmac_algo = os_convert_mode(HMAC_ALGORITHM, hmac_algo);

	input_data.data = (unsigned char *)input;
	input_data.length = input_size;

	if (g_see_dev->get_hmac(linux_hmac_algo, name, &input_data, &hmac_data) < 0) {
		log_err("get hmac error");
		return E_SECURITY_ERROR;
	}

	*hmac = hmac_data.data;
	*hmac_size = hmac_data.length;

	return S_OK;
}

artik_error os_security_get_rsa_signature(artik_security_handle handle,
		unsigned int rsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		unsigned int salt_size,
		unsigned char **sig, unsigned int *sig_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data hash_data;
	see_data sig_data;
	char name[20] = { 0, };

	unsigned int linux_rsa_algo;
	unsigned int linux_rsa_mode;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!hash) {
		log_err("Invalid hash buffer");
		return E_BAD_ARGS;
	}
	if (hash_size == 0) {
		log_err("Invalid hash size");
		return E_BAD_ARGS;
	}
	if (!sig || !sig_size) {
		log_err("Invalid signature buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->get_signature) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_rsa_algo = os_convert_algo(RSA_ALGORITHM);
	linux_rsa_mode = os_convert_mode(RSA_ALGORITHM, rsa_algo);

	hash_data.data = (unsigned char *)hash;
	hash_data.length = hash_size;

	if (g_see_dev->get_signature(linux_rsa_algo, linux_rsa_mode, name, &hash_data,
			&sig_data) < 0) {
		log_err("get signature error");
		return E_SECURITY_ERROR;
	}

	*sig = sig_data.data;
	*sig_size = sig_data.length;

	return S_OK;
}

artik_error os_security_verify_rsa_signature(artik_security_handle handle,
		unsigned int rsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		unsigned int salt_size,
		const unsigned char *sig, unsigned int sig_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data hash_data;
	see_data sig_data;
	char name[20] = { 0, };

	unsigned int linux_rsa_algo;
	unsigned int linux_rsa_mode;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!hash) {
		log_err("Invalid hash buffer");
		return E_BAD_ARGS;
	}
	if (hash_size == 0) {
		log_err("Invalid hash size");
		return E_BAD_ARGS;
	}
	if (!sig) {
		log_err("Invalid signature buffer");
		return E_BAD_ARGS;
	}
	if (sig_size == 0) {
		log_err("Invalid signature size");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->verify_signature) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_rsa_algo = os_convert_algo(RSA_ALGORITHM);
	linux_rsa_mode = os_convert_mode(RSA_ALGORITHM, rsa_algo);

	hash_data.data = (unsigned char *)hash;
	hash_data.length = hash_size;
	sig_data.data = (unsigned char *)sig;
	sig_data.length = sig_size;

	if (g_see_dev->verify_signature(linux_rsa_algo, linux_rsa_mode, name,
			&hash_data, &sig_data) < 0) {
		log_err("verify signature error");
		return E_SECURITY_ERROR;
	}

	return S_OK;
}

artik_error os_security_get_ecdsa_signature(artik_security_handle handle,
		unsigned int ecdsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		unsigned char **sig, unsigned int *sig_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data hash_data;
	see_data sig_data;
	char name[20] = { 0, };

	unsigned int linux_ecdsa_algo;
	unsigned int linux_ecdsa_mode;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!hash) {
		log_err("Invalid hash buffer");
		return E_BAD_ARGS;
	}
	if (hash_size == 0) {
		log_err("Invalid hash size");
		return E_BAD_ARGS;
	}
	if (!sig || !sig_size) {
		log_err("Invalid signature buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->get_signature) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_ecdsa_algo = os_convert_algo(ECC_ALGORITHM);
	linux_ecdsa_mode = os_convert_mode(ECC_ALGORITHM, ecdsa_algo);

	hash_data.data = (unsigned char *)hash;
	hash_data.length = hash_size;

	if (g_see_dev->get_signature(linux_ecdsa_algo, linux_ecdsa_mode, name,
			&hash_data, &sig_data) < 0) {
		log_err("get signature error");
		return E_SECURITY_ERROR;
	}

	*sig = sig_data.data;
	*sig_size = sig_data.length;

	return S_OK;
}

artik_error os_security_verify_ecdsa_signature(artik_security_handle handle,
		unsigned int ecdsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		const unsigned char *sig, unsigned int sig_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data hash_data;
	see_data sig_data;
	char name[20] = { 0, };

	unsigned int linux_ecdsa_algo;
	unsigned int linux_ecdsa_mode;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!hash) {
		log_err("Invalid hash buffer");
		return E_BAD_ARGS;
	}
	if (hash_size == 0) {
		log_err("Invalid hash size");
		return E_BAD_ARGS;
	}
	if (!sig) {
		log_err("Invalid signature buffer");
		return E_BAD_ARGS;
	}
	if (sig_size == 0) {
		log_err("Invalid signature size");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->verify_signature) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_ecdsa_algo = os_convert_algo(ECC_ALGORITHM);
	linux_ecdsa_mode = os_convert_mode(ECC_ALGORITHM, ecdsa_algo);

	hash_data.data = (unsigned char *)hash;
	hash_data.length = hash_size;
	sig_data.data = (unsigned char *)sig;
	sig_data.length = sig_size;

	if (g_see_dev->verify_signature(linux_ecdsa_algo, linux_ecdsa_mode, name,
			&hash_data, &sig_data) < 0) {
		log_err("verify signature error");
		return E_SECURITY_ERROR;
	}

	return S_OK;
}

artik_error os_security_generate_dhm_params(artik_security_handle handle,
		unsigned int key_algo, const char *key_name, unsigned char **pubkey,
		unsigned int *pubkey_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data params_data;
	see_data pubkey_data;
	char name[20] = { 0, };

	unsigned int linux_key_algo;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!pubkey || !pubkey_size) {
		log_err("Invalid public key buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->generate_dhparams || !g_see_dev->set_dhparams) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_key_algo = os_convert_algo(key_algo);

	if (linux_key_algo == LINUX_DH_1024 || linux_key_algo == LINUX_DH_2048) {
		if (g_see_dev->generate_dhparams(linux_key_algo, name, &pubkey_data) < 0) {
			log_err("generate dhparams error");
			return E_SECURITY_ERROR;
		}
	} else if (linux_key_algo == LINUX_DH_1024_5114) {
		params_data.data = (void *)rfc5114_dh1024_160;
		params_data.length = sizeof(rfc5114_dh1024_160);
		if (g_see_dev->set_dhparams(linux_key_algo, name, &params_data, &pubkey_data) < 0) {
			log_err("set dhparams error");
			return E_SECURITY_ERROR;
		}
	} else if (linux_key_algo == LINUX_DH_2048_5114) {
		params_data.data = (void *)rfc5114_dh2048_224;
		params_data.length = sizeof(rfc5114_dh2048_224);
		if (g_see_dev->set_dhparams(linux_key_algo, name, &params_data, &pubkey_data) < 0) {
			log_err("set dhparams error");
			return E_SECURITY_ERROR;
		}
	} else {
		log_err("Invalid algorithm");
		return E_BAD_ARGS;
	}

	*pubkey = pubkey_data.data;
	*pubkey_size = pubkey_data.length;

	return S_OK;
}

artik_error os_security_set_dhm_params(artik_security_handle handle,
		const char *key_name,
		const unsigned char *params, unsigned int params_size,
		unsigned char **pubkey, unsigned int *pubkey_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data params_data;
	see_data pubkey_data;
	char name[20] = { 0, };

	unsigned int linux_key_algo;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!params) {
		log_err("Invalid params buffer");
		return E_BAD_ARGS;
	}
	if (params_size == 0) {
		log_err("Invalid params size");
		return E_BAD_ARGS;
	}
	if (!pubkey || !pubkey_size) {
		log_err("Invalid public key buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->set_dhparams) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_key_algo = os_convert_algo(DH_ALGORITHM);

	params_data.data = (unsigned char *)params;
	params_data.length = params_size;
	if (g_see_dev->set_dhparams(linux_key_algo, name, &params_data, &pubkey_data) < 0) {
		log_err("set dhparams error");
		return E_SECURITY_ERROR;
	}

	*pubkey = pubkey_data.data;
	*pubkey_size = pubkey_data.length;

	return S_OK;
}

artik_error os_security_compute_dhm_params(artik_security_handle handle,
		const char *key_name, const unsigned char *pubkey,
		unsigned int pubkey_size, unsigned char **secret,
		unsigned int *secret_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data pubkey_data;
	see_data secret_data;
	char name[20] = { 0, };

	unsigned int linux_key_algo;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!pubkey) {
		log_err("Invalid public key buffer");
		return E_BAD_ARGS;
	}
	if (pubkey_size == 0) {
		log_err("Invalid public key size");
		return E_BAD_ARGS;
	}
	if (!secret || !secret_size) {
		log_err("Invalid secret buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->compute_dhparams) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_key_algo = os_convert_algo(DH_ALGORITHM);

	pubkey_data.data = (unsigned char *)pubkey;
	pubkey_data.length = pubkey_size;
	if (g_see_dev->compute_dhparams(linux_key_algo, name, &pubkey_data, &secret_data) < 0) {
		log_err("compute dhparams error");
		return E_SECURITY_ERROR;
	}

	*secret = secret_data.data;
	*secret_size = secret_data.length;

	return S_OK;
}

artik_error os_security_generate_ecdh_params(artik_security_handle handle,
		unsigned int key_algo, const char *key_name, unsigned char **pubkey,
		unsigned int *pubkey_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data pubkey_data;
	char name[20] = { 0, };

	unsigned int linux_key_algo;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!pubkey || !pubkey_size) {
		log_err("Invalid public key buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->generate_ecdhkey) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_key_algo = os_convert_algo(key_algo);

	if (g_see_dev->generate_ecdhkey(linux_key_algo, name, &pubkey_data) < 0) {
		log_err("generate ecdhkey error");
		return E_SECURITY_ERROR;
	}

	*pubkey = pubkey_data.data;
	*pubkey_size = pubkey_data.length;

	return S_OK;
}

artik_error os_security_compute_ecdh_params(artik_security_handle handle,
		const char *key_name, const unsigned char *pubkey,
		unsigned int pubkey_size, unsigned char **secret,
		unsigned int *secret_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data pubkey_data;
	see_data secret_data;
	char name[20] = { 0, };

	unsigned int linux_key_algo;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!pubkey) {
		log_err("Invalid public key buffer");
		return E_BAD_ARGS;
	}
	if (pubkey_size == 0) {
		log_err("Invalid public key size");
		return E_BAD_ARGS;
	}
	if (!secret || !secret_size) {
		log_err("Invalid secret buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->compute_ecdhkey) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_key_algo = os_convert_algo(ECC_ALGORITHM);

	pubkey_data.data = (unsigned char *)pubkey;
	pubkey_data.length = pubkey_size;
	if (g_see_dev->compute_ecdhkey(linux_key_algo, name, &pubkey_data, &secret_data) < 0) {
		log_err("compute ecdhkey error");
		return E_SECURITY_ERROR;
	}

	*secret = secret_data.data;
	*secret_size = secret_data.length;

	return S_OK;
}

artik_error os_security_generate_key(artik_security_handle handle,
		unsigned int key_algo, const char *key_name, const void *key_param)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);

	see_data param_data;
	see_data pubkey_data;
	struct hmac_key_param *hmac_key = (struct hmac_key_param *)key_param;
	struct rsa_key_param *rsa_key = (struct rsa_key_param *)key_param;
	unsigned char rsa_pub[3] = { 0x01, 0x00, 0x01 };
	char name[20] = { 0, };
	int ret;

	unsigned int linux_key_algo;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->generate_key || !g_see_dev->generate_key_with_params) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_key_algo = os_convert_algo(key_algo);

	pubkey_data.length = 0;
	param_data.data = NULL;
	param_data.length = 0;
	switch (key_algo & 0xF000) {
	case HMAC_ALGORITHM:
		if (key_param)
			param_data.length = hmac_key->key_size;
		else
			param_data.length = 64;
		ret = g_see_dev->generate_key_with_params(linux_key_algo, name, &param_data, &pubkey_data);
		if (ret < 0) {
			log_err("generate key with params error: %d", ret);
			return E_SECURITY_ERROR;
		}
		break;
	case RSA_ALGORITHM:
		if (key_param) {
			param_data.data = rsa_key->exponent;
			param_data.length = rsa_key->exponent_size;
		} else {
			param_data.data = rsa_pub;
			param_data.length = 3;
		}
		ret = g_see_dev->generate_key_with_params(linux_key_algo, name, &param_data, &pubkey_data);
		if (ret < 0) {
			log_err("generate key with params error");
			return E_SECURITY_ERROR;
		}
		break;
	default:
		ret = g_see_dev->generate_key(linux_key_algo, name, &pubkey_data);
		if (ret < 0) {
			log_err("generate key error");
			return E_SECURITY_ERROR;
		}
		break;
	}

	if (pubkey_data.length > 0)
		free(pubkey_data.data);

	return S_OK;
}

artik_error os_security_set_key(artik_security_handle handle,
		unsigned int key_algo, const char *key_name,
		const unsigned char *key, unsigned int key_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data key_data;
	char name[20] = { 0, };

	unsigned int linux_key_algo;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!key) {
		log_err("Invalid key buffer");
		return E_BAD_ARGS;
	}
	if (key_size == 0) {
		log_err("Invalid key size");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->set_key) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_key_algo = os_convert_algo(key_algo);

	key_data.data = (unsigned char *)key;
	key_data.length = key_size;
	if (g_see_dev->set_key(linux_key_algo, name, &key_data) < 0) {
		log_err("set key error");
		return E_SECURITY_ERROR;
	}

	return S_OK;
}

artik_error os_security_get_publickey(artik_security_handle handle,
		unsigned int key_algo, const char *key_name,
		unsigned char **pubkey, unsigned int *pubkey_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data public_data;
	char name[20] = { 0, };

	unsigned int linux_key_algo;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!pubkey || !pubkey_size) {
		log_err("Invalid public key buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->get_pubkey) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_key_algo = os_convert_algo(key_algo);

	if (g_see_dev->get_pubkey(linux_key_algo, name, &public_data) < 0) {
		log_err("get pubkey error");
		return E_SECURITY_ERROR;
	}

	*pubkey = public_data.data;
	*pubkey_size = public_data.length;

	return S_OK;
}

artik_error os_security_remove_key(artik_security_handle handle,
		unsigned int key_algo, const char *key_name)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	char name[20] = { 0, };

	unsigned int linux_key_algo;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->remove_key) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_key_algo = os_convert_algo(key_algo);

	if (g_see_dev->remove_key(linux_key_algo, name) < 0) {
		log_err("remove key error");
		return E_SECURITY_ERROR;
	}

	return S_OK;
}

artik_error os_security_write_secure_storage(artik_security_handle handle,
		const char *data_name, unsigned int offset, const unsigned char *data,
		unsigned int data_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data storage_data;
	char name[20] = { 0, };

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!data_name) {
		log_err("Invalid data name");
		return E_BAD_ARGS;
	}
	if (!data) {
		log_err("Invalid data buffer");
		return E_BAD_ARGS;
	}
	if (data_size == 0) {
		log_err("Invalid data size");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->write_secure_storage) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(data_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	storage_data.data = (unsigned char *)data;
	storage_data.length = data_size;
	if (g_see_dev->write_secure_storage(name, offset, &storage_data) < 0) {
		log_err("write secure storage error");
		return E_SECURITY_ERROR;
	}

	return S_OK;
}

artik_error os_security_read_secure_storage(artik_security_handle handle,
		const char *data_name, unsigned int offset, unsigned int read_size,
		unsigned char **data, unsigned int *data_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data storage_data;
	char name[20] = { 0, };

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!data_name) {
		log_err("Invalid data name");
		return E_BAD_ARGS;
	}
	if (!data || !data_size) {
		log_err("Invalid data buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->read_secure_storage) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(data_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	if (g_see_dev->read_secure_storage(name, offset, read_size,
			&storage_data) < 0) {
		log_err("read secure storage error");
		return E_SECURITY_ERROR;
	}

	*data = storage_data.data;
	*data_size = storage_data.length;

	return S_OK;
}

artik_error os_security_remove_secure_storage(artik_security_handle handle,
		const char *data_name)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	char name[20] = { 0, };

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!data_name) {
		log_err("Invalid data name");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->delete_secure_storage) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(data_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	if (g_see_dev->delete_secure_storage(name) < 0) {
		log_err("delete secure storage error");
		return E_SECURITY_ERROR;
	}

	return S_OK;
}

artik_error os_security_aes_encryption(artik_security_handle handle,
		unsigned int aes_mode, const char *key_name,
		const unsigned char *iv, unsigned int iv_size,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data input_data;
	see_data output_data;
	see_data iv_data;
	char name[20] = { 0, };

	unsigned int linux_aes_algo;
	unsigned int linux_aes_mode;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!input) {
		log_err("Invalid input buffer");
		return E_BAD_ARGS;
	}
	if (input_size == 0) {
		log_err("Invalid input size");
		return E_BAD_ARGS;
	}
	if (!output || !output_size) {
		log_err("Invalid output buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->encryption) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_aes_algo = os_convert_algo(AES_ALGORITHM);
	linux_aes_mode = os_convert_mode(AES_ALGORITHM, aes_mode);

	iv_data.data = (unsigned char *)iv;
	iv_data.length = iv_size;
	input_data.data = (unsigned char *)input;
	input_data.length = input_size;
	if (g_see_dev->encryption(linux_aes_algo, linux_aes_mode, name, &iv_data,
			&input_data, &output_data) < 0) {
		log_err("encryption error");
		return E_SECURITY_ERROR;
	}

	*output = output_data.data;
	*output_size = output_data.length;

	return S_OK;
}

artik_error os_security_aes_decryption(artik_security_handle handle,
		unsigned int aes_mode, const char *key_name,
		const unsigned char *iv, unsigned int iv_size,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data input_data;
	see_data output_data;
	see_data iv_data;
	char name[20] = { 0, };

	unsigned int linux_aes_algo;
	unsigned int linux_aes_mode;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!input) {
		log_err("Invalid input buffer");
		return E_BAD_ARGS;
	}
	if (input_size == 0) {
		log_err("Invalid input size");
		return E_BAD_ARGS;
	}
	if (!output || !output_size) {
		log_err("Invalid output buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->encryption) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_aes_algo = os_convert_algo(AES_ALGORITHM);
	linux_aes_mode = os_convert_mode(AES_ALGORITHM, aes_mode);

	iv_data.data = (unsigned char *)iv;
	iv_data.length = iv_size;
	input_data.data = (unsigned char *)input;
	input_data.length = input_size;
	if (g_see_dev->decryption(linux_aes_algo, linux_aes_mode, name, &iv_data,
			&input_data, &output_data) < 0) {
		log_err("decryption error");
		return E_SECURITY_ERROR;
	}

	*output = output_data.data;
	*output_size = output_data.length;

	return S_OK;
}

artik_error os_security_rsa_encryption(artik_security_handle handle,
		unsigned int rsa_mode, const char *key_name,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data input_data;
	see_data output_data;
	char name[20] = { 0, };

	unsigned int linux_rsa_algo;
	unsigned int linux_rsa_mode;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!input) {
		log_err("Invalid input buffer");
		return E_BAD_ARGS;
	}
	if (input_size == 0) {
		log_err("Invalid input size");
		return E_BAD_ARGS;
	}
	if (!output || !output_size) {
		log_err("Invalid output buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->encryption) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_rsa_algo = os_convert_algo(RSA_ALGORITHM);
	linux_rsa_mode = os_convert_mode(RSA_ALGORITHM, rsa_mode);

	input_data.data = (unsigned char *)input;
	input_data.length = input_size;
	if (g_see_dev->encryption(linux_rsa_algo, linux_rsa_mode, name, NULL,
			&input_data, &output_data) < 0) {
		log_err("get encryption error");
		return E_SECURITY_ERROR;
	}

	*output = output_data.data;
	*output_size = output_data.length;

	return S_OK;
}

artik_error os_security_rsa_decryption(artik_security_handle handle,
		unsigned int rsa_mode, const char *key_name,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size)
{
	security_node *node = (security_node *)
		artik_list_get_by_handle(requested_node,
						(ARTIK_LIST_HANDLE) handle);
	see_data input_data;
	see_data output_data;
	char name[20] = { 0, };

	unsigned int linux_rsa_algo;
	unsigned int linux_rsa_mode;

	if (!node) {
		log_err("security node error");
		return E_BAD_ARGS;
	}
	if (!key_name) {
		log_err("Invalid key name");
		return E_BAD_ARGS;
	}
	if (!input) {
		log_err("Invalid input buffer");
		return E_BAD_ARGS;
	}
	if (input_size == 0) {
		log_err("Invalid input size");
		return E_BAD_ARGS;
	}
	if (!output || !output_size) {
		log_err("Invalid output buffer");
		return E_BAD_ARGS;
	}
	if (!g_see_dev) {
		log_err("Device error");
		return E_NOT_SUPPORTED;
	}
	if (!g_see_dev->decryption) {
		log_err("Security API not supported");
		return E_NOT_SUPPORTED;
	}

	if (os_convert_name(key_name, name)) {
		log_err("Invalid certificate name");
		return E_BAD_ARGS;
	}

	linux_rsa_algo = os_convert_algo(RSA_ALGORITHM);
	linux_rsa_mode = os_convert_mode(RSA_ALGORITHM, rsa_mode);

	input_data.data = (unsigned char *)input;
	input_data.length = input_size;
	if (g_see_dev->decryption(linux_rsa_algo, linux_rsa_mode, name, NULL,
			&input_data, &output_data) < 0) {
		log_err("get decryption error");
		return E_SECURITY_ERROR;
	}

	*output = output_data.data;
	*output_size = output_data.length;

	return S_OK;
}

artik_error os_security_verify_signature_init(artik_security_handle *handle,
		const char *signature_pem, const char *root_ca,
		const artik_time *signing_time_in, artik_time *signing_time_out)
{
	verify_node *node = NULL;
	BIO *sigbio = NULL;
	BIO *cabio = NULL;
	X509 *ca_cert = NULL;
	X509_STORE_CTX *store_ctx = NULL;
	X509_STORE *store = NULL;
	artik_error ret = S_OK;

	STACK_OF(PKCS7_SIGNER_INFO) * sinfos = NULL;

	if (!handle || !signature_pem || !root_ca)
		return E_BAD_ARGS;

	node = (verify_node *)artik_list_add(&verify_nodes, 0, sizeof(verify_node));
	if (!node)
		return E_NO_MEM;

	/* Do OpenSSL one-time global initialization stuff */
	if (!openssl_global_init) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		CRYPTO_malloc_init();
#else
		OPENSSL_malloc_init();
#endif
		OpenSSL_add_all_algorithms();
		openssl_global_init = true;
	}

	/* Parse root CA */
	cabio = BIO_new(BIO_s_mem());
	if (!cabio) {
		log_dbg("Failed to create bio for root CA");
		ret = E_NO_MEM;
		goto exit;
	}

	BIO_write(cabio, root_ca, strlen(root_ca));
	ca_cert = PEM_read_bio_X509_AUX(cabio, NULL, 0, NULL);
	if (!ca_cert) {
		log_dbg("Failed to parse bio for root CA certificate");
		ret = E_SECURITY_INVALID_X509;
		goto exit;
	}

	/* Parse PKCS7 signature */
	sigbio = BIO_new(BIO_s_mem());
	if (!sigbio) {
		log_dbg("Failed to create bio for PKCS7 signature");
		ret = E_NO_MEM;
		goto exit;
	}

	BIO_write(sigbio, signature_pem, strlen(signature_pem));
	node->p7 = PEM_read_bio_PKCS7(sigbio, NULL, 0, NULL);
	if (!node->p7) {
		log_dbg("Could not parse PKCS7 signature form PEM");
		ret = E_SECURITY_INVALID_PKCS7;
		goto exit;
	}

	/* Perform some checkng on the PKCS7 signature */
	if (!PKCS7_type_is_signed(node->p7)) {
		log_dbg("Wrong type of PKCS7, should be signed");
		ret = E_SECURITY_INVALID_PKCS7;
		goto exit;
	}

	sinfos = PKCS7_get_signer_info(node->p7);
	if (!sinfos || !sk_PKCS7_SIGNER_INFO_num(sinfos)) {
		log_dbg("No signers found in the PKCS7 structure");
		ret = E_SECURITY_INVALID_PKCS7;
		goto exit;
	}

	if (sk_PKCS7_SIGNER_INFO_num(sinfos) > 1) {
		log_err("Only verification for one signer is supported");
		ret = E_NOT_SUPPORTED;
		goto exit;
	}

	/* Verify signer certificate against ca chain */
	node->signer = sk_PKCS7_SIGNER_INFO_value(sinfos, 0);
	node->signer_cert = X509_find_by_issuer_and_serial(node->p7->d.sign->cert,
			node->signer->issuer_and_serial->issuer,
			node->signer->issuer_and_serial->serial);

	if (!node->signer_cert) {
		log_dbg("Failed to find the signer certificate in the PKCS7 structure");
		ret = E_SECURITY_INVALID_PKCS7;
		goto exit;
	}

	store = X509_STORE_new();
	if (!store) {
		log_dbg("Failed to allocate store");
		ret = E_SECURITY_CA_VERIF_FAILED;
		goto exit;
	}

	X509_STORE_add_cert(store, ca_cert);

	store_ctx = X509_STORE_CTX_new();
	if (!store_ctx) {
		log_dbg("Failed to allocate store context");
		ret = E_SECURITY_CA_VERIF_FAILED;
		X509_STORE_free(store);
		goto exit;
	}

	if (!X509_STORE_CTX_init(store_ctx, store, node->signer_cert,
				node->p7->d.sign->cert)) {
		log_dbg("Failed to initialize verification context");
		X509_STORE_free(store);
		X509_STORE_CTX_free(store_ctx);
	}

	X509_STORE_CTX_set_purpose(store_ctx, X509_PURPOSE_CRL_SIGN);
	if (X509_verify_cert(store_ctx) <= 0) {
		log_dbg("Signer certificate verification failed (err=%d)",
				X509_STORE_CTX_get_error(store_ctx));
		X509_STORE_CTX_cleanup(store_ctx);
		X509_STORE_free(store);
		X509_STORE_CTX_free(store_ctx);
		ret = E_SECURITY_CA_VERIF_FAILED;
		goto exit;
	}

	X509_STORE_CTX_cleanup(store_ctx);
	X509_STORE_free(store);
	X509_STORE_CTX_free(store_ctx);

	/* Verify signer attributes */
	if (!node->signer->auth_attr ||
			!sk_X509_ATTRIBUTE_num(node->signer->auth_attr)) {
		log_dbg("Signer does not have attributes");
		ret = E_SECURITY_INVALID_PKCS7;
		goto exit;
	}

	if (signing_time_in || signing_time_out) {
		artik_time pkcs7_signing_time;
		ASN1_TYPE *signing_time_attr = PKCS7_get_signed_attribute(node->signer,
				NID_pkcs9_signingTime);
		if (!signing_time_attr) {
			log_dbg("Signer does not have signing time");
			ret = E_SECURITY_INVALID_PKCS7;
			goto exit;
		}

		if (!convert_asn1_time(signing_time_attr, &pkcs7_signing_time)) {
			log_dbg("Could not parse signing time from PKCS7");
			ret = E_SECURITY_INVALID_PKCS7;
			goto exit;
		}

		log_info("SigningTime: %02d/%02d/%d %02d:%02d:%02d\n",
				pkcs7_signing_time.month, pkcs7_signing_time.day,
				pkcs7_signing_time.year, pkcs7_signing_time.hour,
				pkcs7_signing_time.minute, pkcs7_signing_time.second);

		if (signing_time_out)
			memcpy(signing_time_out, &pkcs7_signing_time, sizeof(artik_time));

		if (signing_time_in) {
			artik_time_module *time =
				(artik_time_module *)artik_request_api_module("time");

			if (time->compare_dates(&pkcs7_signing_time,
					signing_time_in) == -1) {
				log_dbg("Signing time happened before current signing time");
				ret = E_SECURITY_SIGNING_TIME_ROLLBACK;
				goto exit;
			}
		}
	}

	/* Prepare context for message digest computation */
	node->md_ctx = EVP_MD_CTX_create();
	if (!node->md_ctx) {
		log_dbg("Failed to create digest context");
		ret = E_NO_MEM;
		goto exit;
	}

	if (!EVP_DigestInit_ex(node->md_ctx,
			EVP_get_digestbynid(
				OBJ_obj2nid(node->signer->digest_alg->algorithm)),
			NULL)) {
		log_dbg("Failed to initialize digest context");
		EVP_MD_CTX_destroy(node->md_ctx);
		ret = E_BAD_ARGS;
		goto exit;
	}

	strncpy(node->cookie, COOKIE_SIGVERIF, sizeof(node->cookie));
	node->node.handle = (ARTIK_LIST_HANDLE) node;
	*handle = (artik_security_handle)node;

exit:
	if (cabio)
		BIO_free(cabio);
	if (sigbio)
		BIO_free(sigbio);
	if (ca_cert)
		X509_free(ca_cert);

	if (ret != S_OK)
		artik_list_delete_node(&verify_nodes, (artik_list *)node);

	return ret;
}

artik_error os_security_verify_signature_update(artik_security_handle handle,
		const unsigned char *data, unsigned int data_len)
{
	verify_node *node = (verify_node *)artik_list_get_by_handle(verify_nodes,
		(ARTIK_LIST_HANDLE)handle);

	if (!node || !data || !data_len ||
			strncmp(node->cookie, COOKIE_SIGVERIF, sizeof(node->cookie)))
		return E_BAD_ARGS;

	if (!EVP_DigestUpdate(node->md_ctx, data, data_len)) {
		log_dbg("Failed to update data for digest computation");
		return E_BAD_ARGS;
	}

	return S_OK;
}

artik_error os_security_verify_signature_final(artik_security_handle handle)
{
	artik_error ret = S_OK;
	ASN1_OCTET_STRING *data_digest = NULL;
	EVP_PKEY *pkey = NULL;
	unsigned char md_dat[EVP_MAX_MD_SIZE], *abuf = NULL;
	unsigned int md_len = 0;
	int alen = 0;
	verify_node *node = (verify_node *)artik_list_get_by_handle(verify_nodes,
		(ARTIK_LIST_HANDLE)handle);

	if (!node || strncmp(node->cookie, COOKIE_SIGVERIF, sizeof(node->cookie)))
		return E_BAD_ARGS;

	if (!EVP_DigestFinal_ex(node->md_ctx, md_dat, &md_len)) {
		log_dbg("Failed to finalize digest computation");
		ret = E_BAD_ARGS;
		goto exit;
	}

	/* Extract digest from the signer info */
	data_digest = PKCS7_digest_from_attributes(node->signer->auth_attr);
	if (!data_digest) {
		log_dbg("Failed to get digest from signer's attributes");
		ret = E_SECURITY_INVALID_PKCS7;
		goto exit;
	}

	/* Compare with the signature digest */
	if ((data_digest->length != (int)md_len) ||
			memcmp(data_digest->data, md_dat, md_len)) {
		log_dbg("Computed data digest mismatch");
		ret = E_SECURITY_DIGEST_MISMATCH;
		goto exit;
	}

	/* Verify Signature */
	if (!EVP_VerifyInit_ex(node->md_ctx,
			EVP_get_digestbynid(
					OBJ_obj2nid(node->signer->digest_alg->algorithm)),
			NULL)) {
		log_dbg("Failed to initialize signature verification");
		ret = E_SECURITY_INVALID_PKCS7;
		goto exit;
	}

	alen = ASN1_item_i2d((ASN1_VALUE *)node->signer->auth_attr, &abuf,
			ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));
	if (alen <= 0) {
		log_dbg("Failed to get signature from signer info");
		ret = E_SECURITY_INVALID_PKCS7;
		goto exit;
	}

	if (!EVP_VerifyUpdate(node->md_ctx, abuf, alen)) {
		log_dbg("Failed to feed signature for verification");
		ret = E_BAD_ARGS;
		goto exit;
	}

	/* Extract public key from signer certificate */
	pkey = X509_get_pubkey(node->signer_cert);
	if (!pkey) {
		log_dbg("Failed to get public key from signer certificate");
		ret = E_SECURITY_INVALID_X509;
		goto exit;
	}

	/* Perform the final verification */
	if (EVP_VerifyFinal(node->md_ctx, node->signer->enc_digest->data,
			node->signer->enc_digest->length, pkey) <= 0) {
		log_dbg("Signature verification failed (err=%lu)", ERR_get_error());
		ret = E_SECURITY_SIGNATURE_MISMATCH;
		goto exit;
	}

exit:
	if (abuf)
		OPENSSL_free(abuf);
	if (pkey)
		EVP_PKEY_free(pkey);
	PKCS7_free(node->p7);
	EVP_MD_CTX_destroy(node->md_ctx);
	artik_list_delete_node(&verify_nodes, (artik_list *)node);

	return ret;
}

artik_error os_security_convert_pem_to_der(const char *pem_data,
		unsigned char **der_data, unsigned int *length)
{
	artik_error ret = S_OK;
	X509 *x509 = NULL;
	EC_KEY *ec_key = NULL;
	BIO *ibio = NULL;
	char buf[SIZE_BUFFER];
	const char *p;
	int i;
	enum PemType pemType;
	int len;

	if (!pem_data || !der_data || *der_data || !length)
		return E_BAD_ARGS;

	p = pem_data;

	for (i = 0; i < SIZE_BUFFER && *p != '\0' && *p != '\n'; i++, p++)
		buf[i] = *p;

	if (i == SIZE_BUFFER)
		buf[i-1] = '\0';
	else
		buf[i] = '\0';

	if (strstr(buf, PEM_BEGIN_CRT)) {
		log_dbg("The PEM is a certificate");
		pemType = Certificate;
	} else if (strstr(buf, PEM_BEGIN_PUBKEY)) {
		log_dbg("The PEM is a public key");
		pemType = PublicKey;
	} else if (
			strstr(buf, PEM_BEGIN_EC_PARAMS) ||
			strstr(buf, PEM_BEGIN_EC_PRIV_KEY)) {
		log_dbg("The PEM is an EC private key");
		pemType = PrivateKey;
	} else {
		log_err("Uknown PEM or wrong format");
		return E_SECURITY_ERROR;
	}

	ibio = BIO_new(BIO_s_mem());

	if (!ibio) {
		log_err("Fail to create bio");
		ret = E_NO_MEM;
		goto exit;
	}

	BIO_write(ibio, pem_data, strlen(pem_data));

	if (pemType == Certificate) {

		x509 = PEM_read_bio_X509(ibio, NULL, NULL, NULL);

		if (!x509) {
			log_err("Fail to create x509");
			ret = E_BAD_ARGS;
			goto exit;
		}

		len = i2d_X509(x509, der_data);
		if (len < 0) {
			log_err("Fail to convert certificate");
			ret = E_SECURITY_ERROR;
			goto exit;
		}

	} else if (pemType == PublicKey) {

		ec_key = PEM_read_bio_EC_PUBKEY(ibio, NULL, NULL, NULL);

		if (!ec_key) {
			log_err("Fail to create ec key");
			ret = E_BAD_ARGS;
			goto exit;
		}

		len = i2d_EC_PUBKEY(ec_key, der_data);
		if (len < 0) {
			log_err("Fail to convert EC public key");
			ret = E_SECURITY_ERROR;
			goto exit;
		}

	} else if (pemType == PrivateKey) {

		ec_key = PEM_read_bio_ECPrivateKey(ibio, NULL, NULL, NULL);

		if (!ec_key) {
			log_err("Fail to create ec key");
			ret = E_BAD_ARGS;
			goto exit;
		}

		len = i2d_ECPrivateKey(ec_key, der_data);
		if (len < 0) {
			log_err("Fail to convert EC private key");
			ret = E_SECURITY_ERROR;
			goto exit;
		}
	}

	*length = len;

exit:
	if (x509)
		X509_free(x509);
	if (ibio)
		BIO_free(ibio);
	if (ec_key)
		EC_KEY_free(ec_key);
	return ret;
}

artik_error os_security_load_openssl_engine(void)
{
	char *load_dir = NULL;

	openssl_engine_refcnt++;

	if (openssl_engine != NULL)
		return S_OK;

	/* First try to load and init the OpenSSL SE engine */
	ENGINE_load_dynamic();

	load_dir = getenv("OPENSSL_ENGINES");
	if (!load_dir)
		load_dir = ENGINESDIR;

	openssl_engine = ENGINE_by_id("dynamic");
	ENGINE_ctrl_cmd_string(openssl_engine, "ID", ARTIK_SE_ENGINE_NAME, 0);
	ENGINE_ctrl_cmd_string(openssl_engine, "DIR_LOAD", "2", 0);
	ENGINE_ctrl_cmd_string(openssl_engine, "DIR_ADD", load_dir, 0);
	ENGINE_ctrl_cmd_string(openssl_engine, "LIST_ADD", "1", 0);
	ENGINE_ctrl_cmd_string(openssl_engine, "LOAD", NULL, 0);

	if (!openssl_engine || !ENGINE_init(openssl_engine)) {
		if (openssl_engine)
			ENGINE_free(openssl_engine);
		openssl_engine = NULL;
		log_err("openssl engine init failed");
		openssl_engine_refcnt--;
		return E_ACCESS_DENIED;
	}
	if (!ENGINE_set_default(openssl_engine, ENGINE_METHOD_RAND |
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			ENGINE_METHOD_ECDSA)) {
#else
			ENGINE_METHOD_EC)) {
#endif
			ENGINE_finish(openssl_engine);
			ENGINE_free(openssl_engine);
			openssl_engine = NULL;
			openssl_engine_refcnt--;
			log_err("openssl set default engine failed");
			return E_ACCESS_DENIED;
		}

	return S_OK;
}

artik_error os_security_unload_openssl_engine(void)
{
	/* Unload the engine and clean up */
	openssl_engine_refcnt--;

	if (openssl_engine && !openssl_engine_refcnt) {
		OBJ_cleanup();
		EVP_cleanup();
		ENGINE_unregister_ciphers(openssl_engine);
		ENGINE_unregister_digests(openssl_engine);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		ENGINE_unregister_ECDSA(openssl_engine);
		ENGINE_unregister_ECDH(openssl_engine);
#else
		ENGINE_unregister_EC(openssl_engine);
#endif
		ENGINE_unregister_pkey_meths(openssl_engine);
		ENGINE_unregister_RAND(openssl_engine);
		ENGINE_remove(openssl_engine);
		ENGINE_cleanup();
		ENGINE_finish(openssl_engine);
		ENGINE_free(openssl_engine);
		openssl_engine = NULL;
	}

	return S_OK;
}

