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
#include <tls/see_api.h>
#include <tls/x509_crt.h>
#include <tls/pk.h>
#include <tls/pem.h>
#include <tls/oid.h>
#include <artik_log.h>
#include <artik_security.h>

#include "tizenrt/tizenrt_security.h"
#include "os_security.h"

static see_dev * g_see_dev = NULL;

typedef struct {
	artik_list node;
} security_node;

typedef struct {
	artik_list node;
	mbedtls_md_context_t md_ctx;
	mbedtls_asn1_buf data_digest;
	mbedtls_asn1_buf signed_digest;
	mbedtls_asn1_buf message_data;
	mbedtls_md_type_t digest_alg_id;

	mbedtls_x509_crt *chain;
	mbedtls_x509_crt *cert;
} verify_node;

static artik_list *requested_nodes = NULL;
static artik_list *verify_nodes = NULL;

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"
#define PEM_BEGIN_PUBKEY        "-----BEGIN PUBLIC KEY-----"
#define PEM_END_PUBKEY          "-----END PUBLIC KEY-----"
#define PEM_BEGIN_EC_PRIV_KEY   "-----BEGIN EC PRIVATE KEY-----"
#define PEM_END_EC_PRIV_KEY     "-----END EC PRIVATE KEY-----"

artik_error os_security_request(artik_security_handle *handle)
{
	security_node *node = (security_node *) artik_list_add(&requested_nodes,
			0, sizeof(security_node));

	if (!node)
		return E_NO_MEM;

	node->node.handle = (ARTIK_LIST_HANDLE) node;
	*handle = (artik_security_handle) node;

	if (g_see_dev == NULL && artik_list_size(requested_nodes) == 1) {
		if (see_device_init("ARTIK SDK", "ARTIK SDK") != 0) {
			delay(10);
			log_dbg("failed to initialize device");
			goto error;
		}

		see_set_debug_level(2);

		g_see_dev = see_device_get();
		if (!g_see_dev) {
			log_dbg("failed to get device");
			goto error;
		}

	}
	return S_OK;

error:
	if (g_see_dev)
		see_device_deinit();

	g_see_dev = NULL;

	return E_NOT_INITIALIZED;
}

artik_error os_security_release(artik_security_handle handle)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);

	artik_list_delete_node(&requested_nodes, (artik_list *) node);

	if (g_see_dev && artik_list_size(requested_nodes) == 0) {
		see_device_deinit();
		g_see_dev = NULL;
	}

	return S_OK;
}

artik_error os_security_get_random_bytes(artik_security_handle handle,
		unsigned int rand_size, unsigned char **rand)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data random;
	int ret = 0;

	if (!node || !rand || rand_size == 0)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->generate_random)
		return E_NOT_SUPPORTED;

	random.data = NULL;
	random.length = 0;

	ret = g_see_dev->generate_random(rand_size, &random);
	if (ret) {
		log_dbg("Failed to generate random bytes from SE (%d)", ret);
		return E_SECURITY_ERROR;
	}

	if (rand_size != random.length)
		return E_SECURITY_ERROR;

	*rand = random.data;

	return S_OK;
}

artik_error os_security_get_certificate_sn(const char *pem_cert,
		unsigned char *sn, unsigned int *len)
{
	int ret = 0;
	mbedtls_x509_crt cert;

	if (!pem_cert || !sn || !len || (*len == 0))
		return E_BAD_ARGS;

	mbedtls_x509_crt_init(&cert);
	ret = mbedtls_x509_crt_parse(&cert, (unsigned char *)pem_cert,
			strlen(pem_cert) + 1);
	if (ret) {
		fprintf(stderr, "Failed to parse certificate (err=%d)", ret);
		mbedtls_x509_crt_free(&cert);
		return E_ACCESS_DENIED;
	}

	if (cert.serial.len > *len) {
		fprintf(stderr, "Buffer is too small");
		mbedtls_x509_crt_free(&cert);
		return E_BAD_ARGS;
	}

	memcpy(sn, cert.serial.p, cert.serial.len);
	*len = cert.serial.len;

	mbedtls_x509_crt_free(&cert);

	return S_OK;
}

static void pem_chain_list_clear(artik_list *elm)
{
	/* It should be a string allocated with strndup, free it */
	free(elm->data);
}

artik_error os_security_get_certificate_pem_chain(artik_security_handle handle,
		const char *cert_name, artik_list **chain)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data certificate;
	artik_list *cpem = NULL;
	char cert_id[16] = "";

	if (!node || !cert_name || !chain)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->get_certificate)
		return E_NOT_SUPPORTED;

	memset(&certificate, 0, sizeof(see_data));
	strncpy(cert_id, cert_name, SECU_LOCATION_STRLEN);
	strncat(cert_id, "/0", 2);

	while (g_see_dev->get_certificate(cert_id, ARTIK_SECURITY_CERT_TYPE_PEM,
			&certificate) == 0) {
		cpem = artik_list_add(chain, NULL, sizeof(artik_list));
		if (!cpem) {
			free(certificate.data);
			return E_NO_MEM;
		}

		cpem->data = (void *)strndup((const char *)certificate.data,
				certificate.length);
		free(certificate.data);
		if (!cpem->data)
			return E_NO_MEM;

		cpem->clear = pem_chain_list_clear;

		cert_id[SECU_LOCATION_STRLEN + 1]++;
		if (cert_id[SECU_LOCATION_STRLEN + 1] > '9')
			break;
	}

	return S_OK;
}

artik_error os_security_set_certificate(artik_security_handle handle,
		const char *cert_name, const unsigned char *cert,
		unsigned int cert_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data certificate;
	artik_error err = S_OK;
	char *cert_pem = NULL;
	int ret = 0;

	if (!node || !cert_name || !cert || !cert_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->get_certificate)
		return E_NOT_SUPPORTED;

	/* If input is in PEM format, convert it to DER */
	if (strstr((const char *)cert, PEM_BEGIN_CRT)) {
		cert_pem = strndup((const char *)cert, cert_size);
		if (!cert_pem)
			return E_NO_MEM;

		memset(&certificate, 0, sizeof(certificate));
		err = os_security_convert_pem_to_der((const char *)cert,
				(unsigned char **)(&certificate.data), &certificate.length);
		if (err != S_OK)
			goto exit;
	} else {
		certificate.data = (void *)cert;
		certificate.length = cert_size;
	}

	ret = g_see_dev->set_certificate(cert_name, &certificate);
	if (ret) {
		log_dbg("Failed to set certificate into SE (%d)", ret);
		err = E_SECURITY_ERROR;
		goto exit;
	}

exit:
	if (cert_pem)
		free(cert_pem);

	return err;
}

artik_error os_security_get_certificate(artik_security_handle handle,
		const char *cert_name, artik_security_cert_type_t type,
		unsigned char **cert, unsigned int *cert_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data certificate;
	int ret = 0;

	if (!node || !cert_name || !cert || !cert_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->get_certificate)
		return E_NOT_SUPPORTED;

	memset(&certificate, 0, sizeof(see_data));
	ret = g_see_dev->get_certificate(cert_name, type, &certificate);
	if (ret) {
		log_dbg("Failed to get certificate from SE (%d)", ret);
		return E_SECURITY_ERROR;
	}

	*cert = certificate.data;
	*cert_size = certificate.length;

	return S_OK;
}

artik_error os_security_remove_certificate(artik_security_handle handle,
		const char *cert_name)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	int ret = 0;

	if (!node || !cert_name)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->remove_certificate)
		return E_NOT_SUPPORTED;

	ret = g_see_dev->remove_certificate(cert_name);
	if (ret) {
		log_dbg("Failed to remove certificate from SE (%d)", ret);
		return E_SECURITY_ERROR;
	}

	return S_OK;
}

artik_error os_security_get_hash(artik_security_handle handle,
		unsigned int hash_algo, const unsigned char *input,
		unsigned int input_size, unsigned char **hash, unsigned int *hash_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data input_data;
	see_data hash_data;

	if (!node || !input)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->get_hash)
		return E_NOT_SUPPORTED;

	input_data.data = (unsigned char *)input;
	input_data.length = input_size;

	if (g_see_dev->get_hash(hash_algo, &input_data, &hash_data) != 0)
		return E_SECURITY_ERROR;

	*hash = hash_data.data;
	*hash_size = hash_data.length;

	return S_OK;
}

artik_error os_security_get_hmac(artik_security_handle handle,
		unsigned int hmac_algo, const char *key_name,
		const unsigned char *input, unsigned int input_size,
		unsigned char **hmac, unsigned int *hmac_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data input_data;
	see_data hmac_data;

	if (!node || !key_name || !input || input_size == 0 || !hmac || !hmac_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->get_hmac)
		return E_NOT_SUPPORTED;

	input_data.data = (unsigned char *)input;
	input_data.length = input_size;

	if (g_see_dev->get_hmac(hmac_algo, key_name, &input_data, &hmac_data) != 0)
		return E_SECURITY_ERROR;

	*hmac = hmac_data.data;
	*hmac_size = hmac_data.length;

	return S_OK;
}

artik_error os_security_get_rsa_signature(artik_security_handle handle,
		unsigned int rsa_algo, const char *key_name, const unsigned char *hash,
		unsigned int hash_size, unsigned int salt_size,
		unsigned char **sig, unsigned int *sig_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data hash_data;
	see_data sig_data;
	int ret = 0;

	if (!node || !key_name || !hash || hash_size == 0 || !sig || !sig_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->get_rsa_signature)
		return E_NOT_SUPPORTED;

	hash_data.data = (unsigned char *)hash;
	hash_data.length = hash_size;

	ret = g_see_dev->get_rsa_signature(rsa_algo, key_name, &hash_data,
			salt_size, &sig_data);
	if (ret) {
		log_err("Failed to RSA sign (0x%08x)", ret);
		return E_SECURITY_ERROR;
	}

	*sig = sig_data.data;
	*sig_size = sig_data.length;

	return S_OK;
}

artik_error os_security_verify_rsa_signature(artik_security_handle handle,
		unsigned int rsa_algo, const char *key_name, const unsigned char *hash,
		unsigned int hash_size, unsigned int salt_size,
		const unsigned char *sig, unsigned int sig_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data hash_data;
	see_data sig_data;

	if (!node || !key_name || !hash || hash_size == 0 || !sig || !sig_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->verify_rsa_signature)
		return E_NOT_SUPPORTED;

	hash_data.data = (unsigned char *)hash;
	hash_data.length = hash_size;
	sig_data.data = (unsigned char *)sig;
	sig_data.length = sig_size;

	if (g_see_dev->verify_rsa_signature(rsa_algo, key_name, &hash_data,
			salt_size, &sig_data) != 0)
		return E_SECURITY_ERROR;

	return S_OK;
}

artik_error os_security_get_ecdsa_signature(artik_security_handle handle,
		unsigned int ecdsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size, unsigned char **sig,
		unsigned int *sig_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data hash_data;
	see_data sig_data;

	if (!node || !key_name || !hash || hash_size == 0 || !sig || !sig_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->get_ecdsa_signature)
		return E_NOT_SUPPORTED;

	hash_data.data = (unsigned char *)hash;
	hash_data.length = hash_size;

	if (g_see_dev->get_ecdsa_signature(ecdsa_algo, key_name, &hash_data,
			&sig_data) != 0)
		return E_SECURITY_ERROR;

	*sig = sig_data.data;
	*sig_size = sig_data.length;

	return S_OK;
}

artik_error os_security_verify_ecdsa_signature(artik_security_handle handle,
		unsigned int ecdsa_algo, const char *key_name,
		const unsigned char *hash, unsigned int hash_size,
		const unsigned char *sig, unsigned int sig_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data hash_data;
	see_data sig_data;

	if (!node || !key_name || !hash || hash_size == 0 || !sig || !sig_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->verify_ecdsa_signature)
		return E_NOT_SUPPORTED;

	hash_data.data = (unsigned char *)hash;
	hash_data.length = hash_size;
	sig_data.data = (unsigned char *)sig;
	sig_data.length = sig_size;

	if (g_see_dev->verify_ecdsa_signature(ecdsa_algo, key_name, &hash_data,
			&sig_data) != 0)
		return E_SECURITY_ERROR;

	return S_OK;
}

artik_error os_security_generate_dhm_params(artik_security_handle handle,
		unsigned int key_algo, const char *key_name, unsigned char **pubkey,
		unsigned int *pubkey_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data pubkey_data;

	if (!node || !key_name || !pubkey || !pubkey_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->generate_dhparams)
		return E_NOT_SUPPORTED;

	if (g_see_dev->generate_dhparams(key_algo, key_name, &pubkey_data) != 0)
		return E_SECURITY_ERROR;

	*pubkey = pubkey_data.data;
	*pubkey_size = pubkey_data.length;

	return S_OK;
}

artik_error os_security_set_dhm_params(artik_security_handle handle,
		const char *key_name, const unsigned char *params,
		unsigned int params_size, unsigned char **pubkey,
		unsigned int *pubkey_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data params_data;
	see_data pubkey_data;

	if (!node || !key_name || !params || params_size == 0 || !pubkey ||
			!pubkey_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->set_dhparams)
		return E_NOT_SUPPORTED;

	params_data.data = (unsigned char *)params;
	params_data.length = params_size;
	if (g_see_dev->set_dhparams(key_name, &params_data, &pubkey_data) != 0)
		return E_SECURITY_ERROR;

	*pubkey = pubkey_data.data;
	*pubkey_size = pubkey_data.length;

	return S_OK;
}

artik_error os_security_compute_dhm_params(artik_security_handle handle,
		const char *key_name, const unsigned char *pubkey,
		unsigned int pubkey_size, unsigned char **secret,
		unsigned int *secret_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data pubkey_data;
	see_data secret_data;

	if (!node || !key_name || !pubkey || pubkey_size == 0 || !secret ||
			!secret_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->compute_dhparams)
		return E_NOT_SUPPORTED;

	pubkey_data.data = (unsigned char *)pubkey;
	pubkey_data.length = pubkey_size;
	if (g_see_dev->compute_dhparams(key_name, &pubkey_data, &secret_data) != 0)
		return E_SECURITY_ERROR;

	*secret = secret_data.data;
	*secret_size = secret_data.length;

	return S_OK;
}


artik_error os_security_generate_ecdh_params(artik_security_handle handle,
		unsigned int key_algo, const char *key_name, unsigned char **pubkey,
		unsigned int *pubkey_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data pubkey_data;

	if (!node || !key_name || !pubkey || !pubkey_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->generate_ecdhkey)
		return E_NOT_SUPPORTED;

	if (g_see_dev->generate_ecdhkey(key_algo, key_name, &pubkey_data) != 0)
		return E_SECURITY_ERROR;

	*pubkey = pubkey_data.data;
	*pubkey_size = pubkey_data.length;

	return S_OK;
}

artik_error os_security_compute_ecdh_params(artik_security_handle handle,
		const char *key_name, const unsigned char *pubkey,
		unsigned int pubkey_size, unsigned char **secret,
		unsigned int *secret_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data pubkey_data;
	see_data secret_data;

	if (!node || !key_name || !pubkey || pubkey_size == 0 || !secret ||
			!secret_size)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->compute_ecdhkey)
		return E_NOT_SUPPORTED;

	pubkey_data.data = (unsigned char *)pubkey;
	pubkey_data.length = pubkey_size;
	if (g_see_dev->compute_ecdhkey(key_name, &pubkey_data, &secret_data) != 0)
		return E_SECURITY_ERROR;

	*secret = secret_data.data;
	*secret_size = secret_data.length;

	return S_OK;
}

artik_error os_security_generate_key(artik_security_handle handle,
		unsigned int key_algo, const char *key_name, const void *key_param)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);

	if (!node || !key_name)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->generate_key)
		return E_NOT_SUPPORTED;

	if (g_see_dev->generate_key(key_algo, key_name, (void *)key_param) != 0)
		return E_SECURITY_ERROR;

	return S_OK;
}

artik_error os_security_set_key(artik_security_handle handle,
		unsigned int key_algo, const char *key_name, const unsigned char *key,
		unsigned int key_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data key_data;

	if (!node || !key_name || !key || key_size == 0)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->set_key)
		return E_NOT_SUPPORTED;

	key_data.data = (unsigned char *)key;
	key_data.length = key_size;
	if (g_see_dev->set_key(key_algo, key_name, &key_data) != 0)
		return E_SECURITY_ERROR;

	return S_OK;
}

artik_error os_security_get_publickey(artik_security_handle handle,
		unsigned int key_algo, const char *key_name, unsigned char **pubkey,
		unsigned int *pubkey_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data public_data;

	if (!node || !pubkey)
		return E_BAD_ARGS;

	if (g_see_dev == NULL || g_see_dev->get_pubkey == NULL)
		return E_NOT_SUPPORTED;

	if (g_see_dev->get_pubkey(key_algo, key_name, &public_data) != 0)
		return E_SECURITY_ERROR;

	*pubkey = public_data.data;
	*pubkey_size = public_data.length;

	return S_OK;
}

artik_error os_security_remove_key(artik_security_handle handle,
		unsigned int key_algo, const char *key_name)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);

	if (!node || !key_name)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->remove_key)
		return E_NOT_SUPPORTED;

	if (g_see_dev->remove_key(key_algo, key_name) != 0)
		return E_SECURITY_ERROR;

	return S_OK;
}

artik_error os_security_write_secure_storage(artik_security_handle handle,
		const char *data_name, unsigned int offset, const unsigned char *data,
		unsigned int data_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data storage_data;

	if (!node || !data_name || !data || data_size == 0)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->write_secure_storage)
		return E_NOT_SUPPORTED;

	storage_data.data = (unsigned char *)data;
	storage_data.length = data_size;
	if (g_see_dev->write_secure_storage(data_name, offset, &storage_data) != 0)
		return E_SECURITY_ERROR;

	return S_OK;
}

artik_error os_security_read_secure_storage(artik_security_handle handle,
		const char *data_name, unsigned int offset, unsigned int read_size,
		unsigned char **data, unsigned int *data_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data storage_data;
	artik_error err = S_OK;
	int ret = 0;

	if (!node || !data_name || !data || !data_size ||
			(offset + read_size > SEE_MAX_DATA_SIZE))
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->read_secure_storage)
		return E_NOT_SUPPORTED;

	memset(&storage_data, 0, sizeof(storage_data));
	ret = g_see_dev->read_secure_storage(data_name, 0, SEE_MAX_DATA_SIZE,
			&storage_data);
	if (ret) {
		log_err("Failed to read secure storage (0x%08x)\n", ret);
		err = E_SECURITY_ERROR;
		goto exit;
	}

	if ((offset + read_size) > storage_data.length) {
		read_size = storage_data.length - offset;
	}

	*data = malloc(read_size);
	if (!data) {
		err = E_NO_MEM;
		goto exit;
	}

	memcpy(*data, storage_data.data + offset, read_size);
	*data_size = read_size;

exit:
	if (storage_data.data)
		free(storage_data.data);

	return err;
}

artik_error os_security_remove_secure_storage(artik_security_handle handle,
		const char *data_name)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);

	if (!node || !data_name)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->delete_secure_storage)
		return E_NOT_SUPPORTED;

	if (g_see_dev->delete_secure_storage(data_name) != 0)
		return E_SECURITY_ERROR;

	return S_OK;
}

artik_error os_security_aes_encryption(artik_security_handle handle,
		unsigned int aes_mode, const char *key_name, const unsigned char *iv,
		unsigned int iv_size, const unsigned char *input,
		unsigned int input_size, unsigned char **output,
		unsigned int *output_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data input_data;
	see_data output_data;
	see_data iv_data;
	int ret = 0;

	if (!node || !key_name || !input || input_size == 0 || !output ||
			output_size == 0)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->aes_encryption)
		return E_NOT_SUPPORTED;

	iv_data.data = (unsigned char *)iv;
	iv_data.length = iv_size;
	input_data.data = (unsigned char *)input;
	input_data.length = input_size;
	ret = g_see_dev->aes_encryption(aes_mode, key_name, &iv_data, &input_data,
			&output_data);
	if (ret) {
		log_err("Failed to AES encrypt (0x%08x)", ret);
		return E_SECURITY_ERROR;
	}

	*output = output_data.data;
	*output_size = output_data.length;

	return S_OK;
}

artik_error os_security_aes_decryption(artik_security_handle handle,
		unsigned int aes_mode, const char *key_name, const unsigned char *iv,
		unsigned int iv_size, const unsigned char *input,
		unsigned int input_size, unsigned char **output,
		unsigned int *output_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data input_data;
	see_data output_data;
	see_data iv_data;
	int ret = 0;

	if (!node || !key_name || !input || input_size == 0 || !output ||
			output_size == 0)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->aes_encryption)
		return E_NOT_SUPPORTED;

	iv_data.data = (unsigned char *)iv;
	iv_data.length = iv_size;
	input_data.data = (unsigned char *)input;
	input_data.length = input_size;
	ret = g_see_dev->aes_decryption(aes_mode, key_name, &iv_data, &input_data,
			&output_data);
	if (ret) {
		log_err("Failed to AES decrypt (0x%08x)", ret);
		return E_SECURITY_ERROR;
	}

	*output = output_data.data;
	*output_size = output_data.length;

	return S_OK;
}

artik_error os_security_rsa_encryption(artik_security_handle handle,
		unsigned int rsa_mode, const char *key_name, const unsigned char *input,
		unsigned int input_size, unsigned char **output,
		unsigned int *output_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data input_data, output_data;
	int ret = 0;

	if (!node || !key_name || !input || input_size == 0 || !output ||
			output_size == 0)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->rsa_encryption)
		return E_NOT_SUPPORTED;

	input_data.data = (unsigned char *)input;
	input_data.length = input_size;
	ret = g_see_dev->rsa_encryption(rsa_mode, key_name, &input_data,
			&output_data);
	if (ret) {
		log_err("Failed to RSA encrypt (0x%08x)", ret);
		return E_SECURITY_ERROR;
	}

	*output = output_data.data;
	*output_size = output_data.length;

	return S_OK;
}

artik_error os_security_rsa_decryption(artik_security_handle handle,
		unsigned int rsa_mode, const char *key_name, const unsigned char *input,
		unsigned int input_size, unsigned char **output,
		unsigned int *output_size)
{
	security_node *node = (security_node *)artik_list_get_by_handle(
			requested_nodes, (ARTIK_LIST_HANDLE) handle);
	see_data input_data;
	see_data output_data;

	if (!node || !key_name || !input || input_size == 0 || !output ||
			output_size == 0)
		return E_BAD_ARGS;

	if (!g_see_dev || !g_see_dev->rsa_encryption)
		return E_NOT_SUPPORTED;

	input_data.data = (unsigned char *)input;
	input_data.length = input_size;
	if (g_see_dev->rsa_decryption(rsa_mode, key_name, &input_data,
			&output_data) != 0)
		return E_SECURITY_ERROR;

	*output = output_data.data;
	*output_size = output_data.length;

	return S_OK;
}

/*
 * Compare two X.509 Names (aka rdnSequence).
 *
 * See RFC 5280 section 7.1, though we don't implement the whole algorithm:
 * we sometimes return unequal when the full algorithm would return equal,
 * but never the other way. (In particular, we don't do Unicode normalisation
 * or space folding.)
 *
 * Return 0 if equal, -1 otherwise.
 */
static int x509_name_cmp(const mbedtls_x509_name *a, const mbedtls_x509_name *b)
{
	/* Avoid recursion, it might not be optimised by the compiler */
	while (a != NULL || b != NULL) {
		if (a == NULL || b == NULL)
			return -1;

		/* type */
		if (a->oid.tag != b->oid.tag || a->oid.len != b->oid.len ||
				memcmp(a->oid.p, b->oid.p, b->oid.len) != 0) {
			return -1;
		}

		/* value */
		if (a->val.tag != b->val.tag || a->val.len != b->val.len ||
				memcmp(a->val.p, b->val.p, b->val.len) != 0) {
			return -1;
		}

		/* structure of the list of sets */
		if (a->next_merged != b->next_merged)
			return -1;

		a = a->next;
		b = b->next;
	}

	/* a == NULL == b */
	return 0;
}

static artik_error check_pkcs7_validity(signed_data *sig_data)
{
	mbedtls_x509_crt *cert = sig_data->chain;

	while (cert != NULL) {
		if (x509_name_cmp(&sig_data->signer.issuer, &cert->issuer) != 0) {
			char info[1024];

			mbedtls_x509_dn_gets(info, 1024, &cert->issuer);
			log_dbg("Issuer is: %s", info);

			mbedtls_x509_dn_gets(info, 1024, &sig_data->signer.issuer);
			log_dbg("Expected issuer is: %s", info);
			cert = cert->next;
			continue;
		}

		if (sig_data->signer.serial.len == cert->issuer_id.len &&
				memcmp(sig_data->signer.serial.p, cert->issuer_id.p,
					cert->issuer_id.len) == 0) {
			log_dbg("Issuer serial number does not match.");
			cert = cert->next;
			continue;
		}

		if ((cert->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE) == 0) {
			log_dbg("Extended key usage extension not found.");
			cert = cert->next;
			continue;
		}

		if (mbedtls_x509_crt_check_extended_key_usage(cert,
					MBEDTLS_OID_CODE_SIGNING,
					MBEDTLS_OID_SIZE(MBEDTLS_OID_CODE_SIGNING)) != 0) {
			log_dbg("Signer certificate verification failed: The purpose of the certificate is not digitalSignature.");
			cert = cert->next;
			continue;
		}

		break;
	}

	if (cert == NULL) {
		log_dbg("Issuer certificate not found.");
		return E_SECURITY_INVALID_PKCS7;
	}

	if (sig_data->signer.digest_alg_id != MBEDTLS_MD_SHA256) {
		log_dbg("Only verification with SHA256 is supported.");
		return E_NOT_SUPPORTED;
	}

	sig_data->cert = cert;
	return S_OK;
}

static artik_error initialize_md_context(verify_node *node,
		signed_data *sig_data)
{
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(
			sig_data->signer.digest_alg_id);

	if (!md_info) {
		log_dbg("SHA256 is not supported by mbedtls.");
		return E_SECURITY_INVALID_PKCS7;
	}

	mbedtls_md_init(&node->md_ctx);
	if (mbedtls_md_setup(&node->md_ctx, md_info, 0) != 0) {
		log_dbg("Failed to initialize digest context.");
		return E_BAD_ARGS;
	}

	if (mbedtls_md_starts(&node->md_ctx) != 0) {
		log_dbg("Failed to prepare digest context.");
		mbedtls_md_free(&node->md_ctx);
		return E_BAD_ARGS;
	}

	return S_OK;
}

static artik_error copy_node_data(verify_node *node, signed_data *sig_data)
{
	size_t data_digest_len = sig_data->signer.authenticated_attributes.digest.len;
	size_t signed_digest_len = sig_data->signer.encrypted_digest.len;
	size_t message_data_len = sig_data->signer.authenticated_attributes.raw.len;

	node->data_digest.p = malloc(sizeof(unsigned char) * data_digest_len);
	node->signed_digest.p = malloc(sizeof(unsigned char) * signed_digest_len);
	node->message_data.p = malloc(sizeof(unsigned char) * message_data_len);

	if (!node->data_digest.p || !node->signed_digest.p || !node->message_data.p) {
		if (node->data_digest.p)
			free(node->data_digest.p);

		if (node->signed_digest.p)
			free(node->signed_digest.p);

		if (node->message_data.p)
			free(node->message_data.p);

		return E_NO_MEM;
	}

	node->data_digest.len = data_digest_len;
	node->signed_digest.len = signed_digest_len;
	node->message_data.len = message_data_len;

	memcpy(node->data_digest.p,
			sig_data->signer.authenticated_attributes.digest.p, data_digest_len);
	memcpy(node->signed_digest.p,
			sig_data->signer.encrypted_digest.p, signed_digest_len);
	memcpy(node->message_data.p,
			sig_data->signer.authenticated_attributes.raw.p, message_data_len);
	*(node->message_data.p) = 0x31;

	return S_OK;
}

artik_error os_security_verify_signature_init(artik_security_handle *handle,
		const char *signature_pem, const char *root_ca,
		const artik_time *signing_time_in, artik_time *signing_time_out)
{
	artik_error err = S_OK;
	int ret;
	mbedtls_asn1_buf buf_pkcs7;
	signed_data sig_data;
	mbedtls_x509_crt x509_crt_root_ca;
	mbedtls_pem_context pem_ctx;
	artik_time signing_time;
	mbedtls_x509_time *x509_signing_time;

	if (!handle)
		return E_BAD_ARGS;

	verify_node *node = (verify_node *) artik_list_add(&verify_nodes, 0,
			sizeof(verify_node));

	if (!node)
		return E_NO_MEM;

	mbedtls_pem_init(&pem_ctx);

	if (mbedtls_pem_read_buffer(&pem_ctx, "-----BEGIN PKCS7-----",
				"-----END PKCS7-----", (unsigned char *)signature_pem, NULL, 0,
				&buf_pkcs7.len) != 0) {
		log_dbg("failed to parse signature_pem.");
		err = E_SECURITY_INVALID_PKCS7;
		goto cleanup_node;
	}

	buf_pkcs7.p = pem_ctx.buf;
	buf_pkcs7.len = pem_ctx.buflen;

	mbedtls_x509_crt_init(&x509_crt_root_ca);
	ret = mbedtls_x509_crt_parse(&x509_crt_root_ca, (unsigned char *)root_ca,
			strlen(root_ca) + 1);
	if (ret != 0) {
		log_dbg("Failed to parse root ca certificate (err %d).", ret);
		err = E_SECURITY_INVALID_X509;
		goto cleanup_pem;
	}

	err = pkcs7_get_signed_data(&buf_pkcs7, &x509_crt_root_ca, &sig_data);
	if (err != S_OK)
		goto cleanup;

	x509_signing_time = &sig_data.signer.authenticated_attributes.signing_time;
	signing_time.second = x509_signing_time->sec;
	signing_time.minute = x509_signing_time->min;
	signing_time.hour = x509_signing_time->hour;
	signing_time.day = x509_signing_time->day;
	signing_time.month = x509_signing_time->mon;
	signing_time.year = x509_signing_time->year;
	signing_time.day_of_week = -1;
	signing_time.msecond = 0;

	log_info("SigningTime: %02d/%02d/%d %02d:%02d:%02d\n", signing_time.month,
			signing_time.day, signing_time.year, signing_time.hour,
			signing_time.minute, signing_time.second);

	if (signing_time_out)
		memcpy(signing_time_out, &signing_time, sizeof(artik_time));

	if (signing_time_in) {
		artik_time_module *time = (artik_time_module *)artik_request_api_module("time");

		if (time->compare_dates(signing_time_in, &signing_time) > 0) {
			log_dbg("Signing time happened before current signing time");
			err = E_SECURITY_SIGNING_TIME_ROLLBACK;
			goto cleanup;
		}
	}

	err = check_pkcs7_validity(&sig_data);
	if (err != S_OK)
		goto cleanup;

	err = initialize_md_context(node, &sig_data);
	if (err != S_OK)
		goto cleanup;

	err = copy_node_data(node, &sig_data);
	if (err != S_OK)
		goto cleanup;

	node->cert = sig_data.cert;
	node->chain = sig_data.chain;
	node->digest_alg_id = sig_data.signer.digest_alg_id;
	node->node.handle = (ARTIK_LIST_HANDLE) node;
	*handle = (artik_security_handle) node;

cleanup:
	mbedtls_x509_crt_free(&x509_crt_root_ca);
cleanup_pem:
	mbedtls_pem_free(&pem_ctx);
cleanup_node:
	if (err != S_OK)
		artik_list_delete_node(&verify_nodes, (artik_list *) node);

	return err;
}

artik_error os_security_verify_signature_update(artik_security_handle handle,
		const unsigned char *data, unsigned int data_len)
{
	verify_node *node = (verify_node *) artik_list_get_by_handle(verify_nodes,
			(ARTIK_LIST_HANDLE) handle);

	if (!node || !data || !data_len)
		return E_BAD_ARGS;

	if (mbedtls_md_update(&node->md_ctx, data, data_len) != 0) {
		log_dbg("Failed to update data for digest computation.");
		return E_BAD_ARGS;
	}

	return S_OK;
}

artik_error os_security_verify_signature_final(artik_security_handle handle)
{
	artik_error err = S_OK;
	int ret = 0;
	unsigned char md_dat[MBEDTLS_MD_MAX_SIZE];
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	unsigned char md_len;
	verify_node *node = (verify_node *) artik_list_get_by_handle(verify_nodes,
			(ARTIK_LIST_HANDLE) handle);

	if (!node)
		return E_BAD_ARGS;

	/* Compute final hash */
	if (mbedtls_md_finish(&node->md_ctx, md_dat) != 0) {
		log_dbg("Failed to finalize digest computation");
		err = E_BAD_ARGS;
		goto cleanup;
	}

	md_len = mbedtls_md_get_size(node->md_ctx.md_info);

	/* Compare with the signer info digest */
	if (md_len != node->data_digest.len ||
			memcmp(node->data_digest.p, md_dat, md_len)) {
		log_dbg("Computed digest mismatch.");
		err = E_SECURITY_DIGEST_MISMATCH;
		goto cleanup;
	}

	/* Compute hash of the message */
	if (mbedtls_md(node->md_ctx.md_info, node->message_data.p,
				node->message_data.len, hash) != 0) {
		log_dbg("Failed to compute hash of AuthenticatedAttribute.");
		err = E_SECURITY_SIGNATURE_MISMATCH;
		goto cleanup;
	}

	/* Verify signature of the message */
	ret = mbedtls_pk_verify(&node->cert->pk, node->digest_alg_id, hash, 0,
			node->signed_digest.p, node->signed_digest.len);
	if (ret != 0) {
		log_dbg("Signature verification failed. (err %d)", ret);
		err = E_SECURITY_SIGNATURE_MISMATCH;
		goto cleanup;
	}

cleanup:
	mbedtls_md_free(&node->md_ctx);
	free(node->data_digest.p);
	free(node->signed_digest.p);
	free(node->message_data.p);

	mbedtls_x509_crt_free(node->chain);
	artik_list_delete_node(&verify_nodes, (artik_list *) node);

	return err;
}

artik_error os_security_convert_pem_to_der(const char *pem_data,
		unsigned char **der_data, unsigned int *length)
{
	int ret = 0;
	char *begin_tag = NULL;
	char *end_tag = NULL;
	mbedtls_pem_context pem;
	size_t len;

	if (!pem_data || !der_data || *der_data || !length)
		return E_BAD_ARGS;

	if (strstr(pem_data, PEM_BEGIN_CRT)) {
		log_dbg("The PEM is a certificate");
		begin_tag = PEM_BEGIN_CERT;
		end_tag = PEM_END_CERT;
	} else if (strstr(pem_data, PEM_BEGIN_PUBKEY)) {
		log_dbg("The PEM is a public key");
		begin_tag = PEM_BEGIN_PUBKEY;
		end_tag = PEM_END_PUBKEY;

	} else if (strstr(pem_data, PEM_BEGIN_EC_PRIV_KEY)) {
		log_dbg("The PEM is an EC private key");
		begin_tag = PEM_BEGIN_EC_PRIV_KEY;
		end_tag = PEM_END_EC_PRIV_KEY;
	} else {
		log_dbg("Unknown PEM or wrong format");
		return E_SECURITY_ERROR;
	}

	mbedtls_pem_init(&pem);
	ret = mbedtls_pem_read_buffer(&pem, begin_tag, end_tag,
			(const unsigned char *)pem_data, NULL, 0, &len);
	if (ret) {
		log_dbg("Failed to convert PEM to DER (err = %X)", ret);
		mbedtls_pem_free(&pem);
		return E_SECURITY_ERROR;
	}

	if (pem.buflen <= 0) {
		log_dbg("Wrong size of pem");
		mbedtls_pem_free(&pem);
		return E_SECURITY_ERROR;
	}

	*der_data = malloc(pem.buflen);

	if (!*der_data) {
		log_dbg("Not enough memory to allocate der_data");
		mbedtls_pem_free(&pem);
		return E_NO_MEM;
	}

	memcpy(*der_data, pem.buf, pem.buflen);
	*length = pem.buflen;
	mbedtls_pem_free(&pem);

	return S_OK;
}

artik_error os_security_get_ec_pubkey_from_cert(const char *cert, char **key)
{
	int ret = 0;
	mbedtls_x509_crt x509_cert;
	unsigned char buf[2048];
	size_t key_len = 0;

	if (!cert || !key || *key)
		return E_BAD_ARGS;

	log_dbg("");

	mbedtls_x509_crt_init(&x509_cert);

	ret = mbedtls_x509_crt_parse(&x509_cert, (unsigned char *)cert,
			strlen(cert) + 1);
	if (ret) {
		log_err("Failed to parse certificate (err=%d)", ret);
		mbedtls_x509_crt_free(&x509_cert);
		return E_ACCESS_DENIED;
	}

	memset(&buf, 0, sizeof(buf));

	ret = mbedtls_pk_write_pubkey_pem(&x509_cert.pk, buf, 2048);
	if (ret) {
		log_err("Failed to write pubkey PEM (err=%d)", ret);
		mbedtls_x509_crt_free(&x509_cert);
		return E_ACCESS_DENIED;
	}

	key_len = strlen((char *)buf) + 1;
	if (key_len <= 0) {
		log_err("Wrong size of key");
		mbedtls_x509_crt_free(&x509_cert);
		return E_SECURITY_ERROR;
	}

	*key = malloc(key_len);
	if (!*key) {
		log_err("Not enough memory to allocate key");
		mbedtls_x509_crt_free(&x509_cert);
		return E_NO_MEM;
	}

	memcpy(*key, buf, key_len);

	mbedtls_x509_crt_free(&x509_cert);
	return S_OK;
}

artik_error os_security_load_openssl_engine(void)
{
	return E_NOT_SUPPORTED;
}

artik_error os_security_unload_openssl_engine(void)
{
	return E_NOT_SUPPORTED;
}
