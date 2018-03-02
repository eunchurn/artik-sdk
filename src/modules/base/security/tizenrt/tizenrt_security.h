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

#ifndef __TIZENRT_SECURITY_H__
#define __TIZENRT_SECURITY_H__

#include <artik_security.h>
#include <artik_list.h>

#include <tls/asn1.h>
#include <tls/x509_crt.h>

typedef struct {
	mbedtls_x509_time signing_time;
	mbedtls_asn1_buf digest;
	mbedtls_asn1_buf raw;
} authenticated_attributes;

typedef struct {
	mbedtls_x509_name issuer;
	mbedtls_x509_buf serial;
	mbedtls_md_type_t digest_alg_id;
	authenticated_attributes authenticated_attributes;
	mbedtls_asn1_buf encrypted_digest;
} signer_info;

typedef struct {
	artik_list node;
	mbedtls_md_type_t md_alg_id;
} digest_algo_id;

typedef struct {
	mbedtls_x509_crt *chain;
	mbedtls_x509_crt *cert;
	signer_info signer;
} signed_data;

artik_error pkcs7_get_signed_data(mbedtls_asn1_buf *buf, mbedtls_x509_crt *rootCA, signed_data *sig_data);

/**
 * @brief Common Data for input and output at SEE
 */
typedef struct {
	void *data; /**< data pointer*/
	unsigned int length; /**< data length */
} see_data;

/**
 * @brief File Information in secure storage
 */
typedef struct {
	char name[20]; /**< file name */
	unsigned int attr; /**< data type */
} see_storage_file;

/**
 * @brief File List of secure storage
 */
typedef see_storage_file * see_storage_list;

typedef struct {
	int (*generate_random)(unsigned int size, see_data *random);
	int (*set_certificate)(const char *cert_name, see_data *certificate);
	int (*get_certificate)(const char *cert_name, unsigned int type, see_data *certificate);
	int (*remove_certificate)(const char *cert_name);

	int (*get_rsa_signature)(unsigned int mode,
			const char *key_name, see_data *hash, unsigned int salt_size, see_data *sign);
	int (*verify_rsa_signature)(unsigned int mode,
			const char *key_name, see_data *hash, unsigned int salt_size, see_data *sign);
	int (*get_ecdsa_signature)(unsigned int mode,
			const char *key_name, see_data *hash, see_data *sign);
	int (*verify_ecdsa_signature)(unsigned int mode,
			const char *key_name, see_data *hash, see_data *sign);

	int (*get_hash)(unsigned int algo, see_data *data, see_data *hash);
	int (*get_hmac)(unsigned int algo, const char *key_name, see_data *data,
			see_data *hmac);

	int (*generate_dhparams)(see_algorithm algo, const char *key_name, see_data *public);
	int (*set_dhparams)(const char *key_name, see_data *params, see_data *public);
	int (*compute_dhparams)(const char *key_name, see_data *public, see_data *secret);

	int (*generate_ecdhkey)(see_algorithm algo, const char *key_name, see_data *public);
	int (*compute_ecdhkey)(const char *key_name, see_data *public, see_data *secret);

	int (*read_secure_storage)(const char *name, unsigned int offset,
			unsigned int size, see_data *data);
	int (*write_secure_storage)(const char *name, unsigned int offset,
			see_data *data);
	int (*delete_secure_storage)(const char *name);

	int (*post_provision)(const char *admin_id, const char *admin_key,
			see_data *pp_data, unsigned int lock);
	int (*generate_key)(see_algorithm algo, const char *name, void *key_param);
	int (*set_key)(see_algorithm algo, const char *name, see_data *key);
	int (*get_pubkey)(see_algorithm algo, const char *name, see_data *key);
	int (*remove_key)(see_algorithm algo, const char *name);

	int (*aes_encryption)(unsigned int mode,
			const char *key_name, see_data *iv, see_data *input,
			see_data *output);
	int (*aes_decryption)(unsigned int mode,
			const char *key_name, see_data *iv, see_data *input,
			see_data *output);
	int (*rsa_encryption)(unsigned int mode,
			const char *key_name, see_data *input,
			see_data *output);
	int (*rsa_decryption)(unsigned int mode,
			const char *key_name, see_data *input,
			see_data *output);
} see_dev;

int see_device_init(const char *id, const char *pwd);
int see_device_deinit(void);
see_dev *see_device_get(void);

#endif /* __TIZENRT_SECURITY_H__ */
