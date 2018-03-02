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

#include <artik_security.h>
#include "os_security.h"

static artik_error request(artik_security_handle *handle)
{
	return os_security_request(handle);
}

static artik_error release(artik_security_handle handle)
{
	return os_security_release(handle);
}

static artik_error get_random_bytes(artik_security_handle handle,
		unsigned int len, unsigned char **rand)
{
	return os_security_get_random_bytes(handle, len, rand);
}

static artik_error get_certificate_sn(const char *cert, unsigned char *sn,
		unsigned int *len)
{
	return os_security_get_certificate_sn(cert, sn, len);
}

static artik_error get_ec_pubkey_from_cert(const char *cert, char **key)
{
	return os_security_get_ec_pubkey_from_cert(cert, key);
}

static artik_error set_certificate(artik_security_handle handle,
		const char *cert_name, const unsigned char *cert,
		unsigned int cert_size)
{
	return os_security_set_certificate(handle, cert_name, cert, cert_size);
}

static artik_error get_certificate(artik_security_handle handle,
		const char *cert_name, artik_security_cert_type_t type,
		unsigned char **cert, unsigned int *cert_size)
{
	return os_security_get_certificate(handle, cert_name, type, cert, cert_size);
}

artik_error get_certificate_pem_chain(artik_security_handle handle,
		const char *cert_name, artik_list **chain)
{
	return os_security_get_certificate_pem_chain(handle, cert_name, chain);
}

static artik_error remove_certificate(artik_security_handle handle,
		const char *cert_name)
{
	return os_security_remove_certificate(handle, cert_name);
}

static artik_error get_hash(artik_security_handle handle,
		see_hash_mode hash_algo, const unsigned char *input,
		unsigned int input_size, unsigned char **hash, unsigned int *hash_size)
{
	return os_security_get_hash(handle, hash_algo, input, input_size, hash,
			hash_size);
}

static artik_error get_hmac(artik_security_handle handle,
		see_hash_mode hmac_algo, const char *key_name,
		const unsigned char *input, unsigned int input_size,
		unsigned char **hmac, unsigned int *hmac_size)
{
	return os_security_get_hmac(handle, hmac_algo, key_name, input, input_size,
			hmac, hmac_size);
}

static artik_error get_rsa_signature(artik_security_handle handle,
		see_rsa_mode rsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		unsigned int salt_size,
		unsigned char **sig, unsigned int *sig_size)
{
	return os_security_get_rsa_signature(handle, rsa_algo, key_name, hash,
			hash_size, salt_size, sig, sig_size);
}

static artik_error verify_rsa_signature(artik_security_handle handle,
		see_rsa_mode rsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		unsigned int salt_size,
		const unsigned char *sig, unsigned int sig_size)
{
	return os_security_verify_rsa_signature(handle, rsa_algo, key_name, hash,
			hash_size, salt_size, sig, sig_size);
}

static artik_error get_ecdsa_signature(artik_security_handle handle,
		see_algorithm ecdsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		unsigned char **sig, unsigned int *sig_size)
{
	return os_security_get_ecdsa_signature(handle, ecdsa_algo, key_name, hash,
			hash_size, sig, sig_size);
}

static artik_error verify_ecdsa_signature(artik_security_handle handle,
		see_algorithm ecdsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		const unsigned char *sig, unsigned int sig_size)
{
	return os_security_verify_ecdsa_signature(handle, ecdsa_algo, key_name,
			hash, hash_size, sig, sig_size);
}

static artik_error generate_dhm_params(artik_security_handle handle,
		see_algorithm key_algo, const char *key_name,
		unsigned char **pubkey, unsigned int *pubkey_size)
{
	return os_security_generate_dhm_params(handle, key_algo, key_name,
			pubkey, pubkey_size);
}

static artik_error set_dhm_params(artik_security_handle handle,
		const char *key_name,
		const unsigned char *params, unsigned int params_size,
		unsigned char **pubkey, unsigned int *pubkey_size)
{
	return os_security_set_dhm_params(handle, key_name, params, params_size,
			pubkey, pubkey_size);
}

static artik_error compute_dhm_params(artik_security_handle handle,
		const char *key_name,
		const unsigned char *pubkey, unsigned int pubkey_size,
		unsigned char **secret, unsigned int *secret_size)
{
	return os_security_compute_dhm_params(handle, key_name, pubkey, pubkey_size,
			secret, secret_size);
}

static artik_error generate_ecdh_params(artik_security_handle handle,
		see_algorithm key_algo, const char *key_name,
		unsigned char **pubkey, unsigned int *pubkey_size)
{
	return os_security_generate_ecdh_params(handle, key_algo, key_name,
			pubkey, pubkey_size);
}

static artik_error compute_ecdh_params(artik_security_handle handle,
		const char *key_name, const unsigned char *pubkey,
		unsigned int pubkey_size, unsigned char **secret,
		unsigned int *secret_size)
{
	return os_security_compute_ecdh_params(handle, key_name,
			pubkey, pubkey_size, secret, secret_size);
}

static artik_error generate_key(artik_security_handle handle,
		see_algorithm key_algo, const char *key_name, const void *key_param)
{
	return os_security_generate_key(handle, key_algo, key_name, key_param);
}

static artik_error set_key(artik_security_handle handle, see_algorithm key_algo,
		const char *key_name, const unsigned char *key, unsigned int key_size)
{
	return os_security_set_key(handle, key_algo, key_name, key, key_size);
}

static artik_error get_publickey(artik_security_handle handle,
		see_algorithm key_algo, const char *key_name,
		unsigned char **pubkey, unsigned int *pubkey_size)
{
	return os_security_get_publickey(handle, key_algo, key_name, pubkey,
			pubkey_size);
}

static artik_error remove_key(artik_security_handle handle,
		see_algorithm key_algo, const char *key_name)
{
	return os_security_remove_key(handle, key_algo, key_name);
}

static artik_error write_secure_storage(artik_security_handle handle,
		const char *data_name, unsigned int offset,
		const unsigned char *data, unsigned int data_size)
{
	return os_security_write_secure_storage(handle, data_name, offset, data,
			data_size);
}

static artik_error read_secure_storage(artik_security_handle handle,
		const char *data_name, unsigned int offset, unsigned int read_size,
		unsigned char **data, unsigned int *data_size)
{
	return os_security_read_secure_storage(handle, data_name, offset, read_size,
			data, data_size);
}

static artik_error remove_secure_storage(artik_security_handle handle,
		const char *data_name)
{
	return os_security_remove_secure_storage(handle, data_name);
}

static artik_error aes_encryption(artik_security_handle handle,
		see_aes_mode aes_mode, const char *key_name,
		const unsigned char *iv, unsigned int iv_size,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size)
{
	return os_security_aes_encryption(handle, aes_mode, key_name, iv, iv_size,
			input, input_size, output, output_size);
}

static artik_error aes_decryption(artik_security_handle handle,
		see_aes_mode aes_mode, const char *key_name,
		const unsigned char *iv, unsigned int iv_size,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size)
{
	return os_security_aes_decryption(handle, aes_mode, key_name, iv, iv_size,
			input, input_size, output, output_size);
}

static artik_error rsa_encryption(artik_security_handle handle,
		see_rsa_mode rsa_mode, const char *key_name,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size)
{
	return os_security_rsa_encryption(handle, rsa_mode, key_name, input,
			input_size, output, output_size);
}

static artik_error rsa_decryption(artik_security_handle handle,
		see_rsa_mode rsa_mode, const char *key_name,
		const unsigned char *input, unsigned int input_size,
		unsigned char **output, unsigned int *output_size)
{
	return os_security_rsa_decryption(handle, rsa_mode, key_name, input,
			input_size, output, output_size);
}

static artik_error verify_signature_init(artik_security_handle *handle,
		const char *signature_pem, const char *root_ca,
		const artik_time *signing_time_in, artik_time *signing_time_out)
{
	return os_security_verify_signature_init(handle, signature_pem, root_ca,
			signing_time_in, signing_time_out);
}

static artik_error verify_signature_update(artik_security_handle handle,
		const unsigned char *data, unsigned int data_len)
{
	return os_security_verify_signature_update(handle, data, data_len);
}

static artik_error verify_signature_final(artik_security_handle handle)
{
	return os_security_verify_signature_final(handle);
}

static artik_error convert_pem_to_der(const char *pem_data,
		unsigned char **der_data, unsigned int *length)
{
	return os_security_convert_pem_to_der(pem_data, der_data, length);
}

EXPORT_API const artik_security_module security_module = {
	.request                    = request,
	.release                    = release,
	.get_random_bytes           = get_random_bytes,
	.get_certificate_sn         = get_certificate_sn,
	.get_ec_pubkey_from_cert    = get_ec_pubkey_from_cert,
	.set_certificate            = set_certificate,
	.get_certificate            = get_certificate,
	.get_certificate_pem_chain  = get_certificate_pem_chain,
	.remove_certificate         = remove_certificate,
	.get_hash                   = get_hash,
	.get_hmac                   = get_hmac,
	.get_rsa_signature          = get_rsa_signature,
	.verify_rsa_signature       = verify_rsa_signature,
	.get_ecdsa_signature        = get_ecdsa_signature,
	.verify_ecdsa_signature     = verify_ecdsa_signature,
	.generate_dhm_params        = generate_dhm_params,
	.set_dhm_params             = set_dhm_params,
	.compute_dhm_params         = compute_dhm_params,
	.generate_ecdh_params		= generate_ecdh_params,
	.compute_ecdh_params		= compute_ecdh_params,
	.set_key                    = set_key,
	.generate_key               = generate_key,
	.get_publickey              = get_publickey,
	.remove_key                 = remove_key,
	.write_secure_storage       = write_secure_storage,
	.read_secure_storage        = read_secure_storage,
	.remove_secure_storage      = remove_secure_storage,
	.aes_encryption             = aes_encryption,
	.aes_decryption             = aes_decryption,
	.rsa_encryption             = rsa_encryption,
	.rsa_decryption             = rsa_decryption,
	.verify_signature_init      = verify_signature_init,
	.verify_signature_update    = verify_signature_update,
	.verify_signature_final     = verify_signature_final,
	.convert_pem_to_der         = convert_pem_to_der
};
