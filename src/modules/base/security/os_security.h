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

#ifndef	__OS_SECURITY_H__
#define	__OS_SECURITY_H__

#include "artik_error.h"

artik_error os_security_request(artik_security_handle *handle);
artik_error os_security_release(artik_security_handle handle);
artik_error os_security_get_random_bytes(artik_security_handle handle,
		unsigned int rand_size, unsigned char **rand);
artik_error os_security_get_certificate_sn(const char *cert, unsigned char *sn,
		unsigned int *len);
artik_error os_security_get_ec_pubkey_from_cert(const char *cert, char **key);
artik_error os_security_set_certificate(artik_security_handle handle,
		const char *cert_name, const unsigned char *cert,
		unsigned int cert_size);
artik_error os_security_get_certificate(artik_security_handle handle,
		const char *cert_name, artik_security_cert_type_t type,
		unsigned char **cert, unsigned int *cert_size);
artik_error os_security_get_certificate_pem_chain(artik_security_handle handle,
		const char *cert_name, artik_list **chain);
artik_error os_security_remove_certificate(artik_security_handle handle,
		const char *cert_name);
artik_error os_security_get_hash(artik_security_handle handle,
		unsigned int hash_algo, const unsigned char *input,
		unsigned int input_size, unsigned char **hash, unsigned int *hash_size);
artik_error os_security_get_hmac(artik_security_handle handle,
		unsigned int hmac_algo, const char *key_name,
		const unsigned char *input, unsigned int input_size,
		unsigned char **hmac, unsigned int *hmac_size);
artik_error os_security_get_rsa_signature(artik_security_handle handle,
		unsigned int rsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		unsigned int salt_size,
		unsigned char **sig, unsigned int *sig_size);
artik_error os_security_verify_rsa_signature(artik_security_handle handle,
		unsigned int rsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		unsigned int salt_size,
		const unsigned char *sig, unsigned int sig_size);
artik_error os_security_get_ecdsa_signature(artik_security_handle handle,
		unsigned int ecdsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		unsigned char **sig, unsigned int *sig_size);
artik_error os_security_verify_ecdsa_signature(artik_security_handle handle,
		unsigned int ecdsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		const unsigned char *sig, unsigned int sig_size);
artik_error os_security_generate_dhm_params(artik_security_handle handle,
		unsigned int key_algo, const char *key_name, unsigned char **pubkey,
		unsigned int *pubkey_size);
artik_error os_security_set_dhm_params(artik_security_handle handle,
		const char *key_name,
		const unsigned char *params, unsigned int params_size,
		unsigned char **pubkey, unsigned int *pubkey_size);
artik_error os_security_compute_dhm_params(artik_security_handle handle,
		const char *key_name, const unsigned char *pubkey,
		unsigned int pubkey_size, unsigned char **secret,
		unsigned int *secret_size);
artik_error os_security_generate_ecdh_params(artik_security_handle handle,
		unsigned int key_algo, const char *key_name,
		unsigned char **pubkey, unsigned int *pubkey_size);
artik_error os_security_set_ecdh_params(artik_security_handle handle,
		const char *key_name,
		const unsigned char *params, unsigned int params_size,
		unsigned char **pubkey, unsigned int *pubkey_size);
artik_error os_security_compute_ecdh_params(artik_security_handle handle,
		const char *key_name,
		const unsigned char *pubkey, unsigned int pubkey_size,
		unsigned char **secret, unsigned int *secret_size);
artik_error os_security_generate_key(artik_security_handle handle,
		unsigned int key_algo, const char *key_name, const void *key_param);
artik_error os_security_set_key(artik_security_handle handle,
		unsigned int key_algo, const char *key_name,
		const unsigned char *key, unsigned int key_size);
artik_error os_security_get_publickey(artik_security_handle handle,
		unsigned int key_algo, const char *key_name,
		unsigned char **pubkey, unsigned int *pubkey_size);
artik_error os_security_remove_key(artik_security_handle handle,
		unsigned int key_algo, const char *key_name);
artik_error os_security_write_secure_storage(artik_security_handle handle,
		const char *data_name, unsigned int offset,
		const unsigned char *data, unsigned int data_size);
artik_error os_security_read_secure_storage(artik_security_handle handle,
		const char *data_name, unsigned int offset, unsigned int read_size,
		unsigned char **data, unsigned int *data_size);
artik_error os_security_remove_secure_storage(artik_security_handle handle,
		const char *data_name);
artik_error os_security_aes_encryption(artik_security_handle handle,
		unsigned int aes_mode, const char *key_name,
		const unsigned char *iv, unsigned int iv_size,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size);
artik_error os_security_aes_decryption(artik_security_handle handle,
		unsigned int aes_mode, const char *key_name,
		const unsigned char *iv, unsigned int iv_size,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size);
artik_error os_security_rsa_encryption(artik_security_handle handle,
		unsigned int rsa_mode, const char *key_name,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size);
artik_error os_security_rsa_decryption(artik_security_handle handle,
		unsigned int rsa_mode, const char *key_name,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size);
artik_error os_security_verify_signature_init(artik_security_handle *handle,
		const char *signature_pem, const char *root_ca,
		const artik_time *signing_time_in, artik_time *signing_time_out);
artik_error os_security_verify_signature_update(artik_security_handle handle,
		const unsigned char *data, unsigned int data_len);
artik_error os_security_verify_signature_final(artik_security_handle handle);
artik_error os_security_convert_pem_to_der(const char *pem_data,
		unsigned char **der_data, unsigned int *length);

#endif  /* __OS_SECURITY_H__ */
