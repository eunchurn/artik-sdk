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

#include "artik_security.hh"

artik::Security::Security() {
  m_module = reinterpret_cast<artik_security_module*>(
      artik_request_api_module("security"));
  if (!m_module || m_module->request(&m_handle) != S_OK)
    artik_throw(artik::ArtikInitException());
  m_sig_handle = NULL;
}

artik::Security::~Security() {
  m_module->release(m_handle);
}

artik_error artik::Security::get_random_bytes(unsigned int len,
  unsigned char** rand) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_random_bytes(m_handle, len, rand);
}

artik_error artik::Security::get_certificate_sn(const char *cert,
    unsigned char *sn, unsigned int *len) {
  return m_module->get_certificate_sn(cert, sn, len);
}

artik_error artik::Security::get_ec_pubkey_from_cert(const char *cert,
    char **key) {
  return m_module->get_ec_pubkey_from_cert(cert, key);
}

artik_error artik::Security::get_certificate_pem_chain(const char *cert_name,
    artik_list **chain) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_certificate_pem_chain(m_handle, cert_name, chain);
}

artik_error artik::Security::set_certificate(const char *cert_name,
    const unsigned char *cert, unsigned int cert_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->set_certificate(m_handle, cert_name, cert, cert_size);
}

artik_error artik::Security::get_certificate(const char *cert_name,
    artik_security_cert_type_t type, unsigned char **cert,
    unsigned int *cert_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_certificate(m_handle, cert_name, type, cert, cert_size);
}

artik_error artik::Security::remove_certificate(const char *cert_name) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->remove_certificate(m_handle, cert_name);
}

artik_error artik::Security::get_hash(see_hash_mode hash_algo,
    const unsigned char *input, unsigned int input_size,
    unsigned char **hash, unsigned int *hash_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_hash(m_handle, hash_algo, input, input_size, hash,
      hash_size);
}

artik_error artik::Security::get_hmac(see_hash_mode hmac_algo,
    const char *key_name, const unsigned char *input, unsigned int input_size,
    unsigned char **hmac, unsigned int *hmac_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_hmac(m_handle, hmac_algo, key_name, input, input_size,
      hmac, hmac_size);
}

artik_error artik::Security::get_rsa_signature(see_rsa_mode rsa_algo,
    const char *key_name, const unsigned char *hash, unsigned int hash_size,
    unsigned int salt_size, unsigned char **sig, unsigned int *sig_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_rsa_signature(m_handle, rsa_algo, key_name, hash,
      hash_size, salt_size, sig, sig_size);
}

artik_error artik::Security::verify_rsa_signature(see_rsa_mode rsa_algo,
    const char *key_name, const unsigned char *hash, unsigned int hash_size,
    unsigned int salt_size, const unsigned char *sig, unsigned int sig_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->verify_rsa_signature(m_handle, rsa_algo, key_name, hash,
      hash_size, salt_size, sig, sig_size);
}

artik_error artik::Security::get_ecdsa_signature(see_algorithm ecdsa_algo,
    const char *key_name, const unsigned char *hash, unsigned int hash_size,
    unsigned char **sig, unsigned int *sig_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_ecdsa_signature(m_handle, ecdsa_algo, key_name, hash,
      hash_size, sig, sig_size);
}

artik_error artik::Security::verify_ecdsa_signature(see_algorithm ecdsa_algo,
    const char *key_name, const unsigned char *hash, unsigned int hash_size,
    const unsigned char *sig, unsigned int sig_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->verify_ecdsa_signature(m_handle, ecdsa_algo, key_name, hash,
      hash_size, sig, sig_size);
}

artik_error artik::Security::generate_dhm_params(see_algorithm key_algo,
    const char *key_name, unsigned char **pubkey, unsigned int *pubkey_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->generate_dhm_params(m_handle, key_algo, key_name, pubkey,
      pubkey_size);
}

artik_error artik::Security::set_dhm_params(const char *key_name,
    const unsigned char *params, unsigned int params_size,
    unsigned char **pubkey, unsigned int *pubkey_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->set_dhm_params(m_handle, key_name, params, params_size,
      pubkey, pubkey_size);
}

artik_error artik::Security::compute_dhm_params(const char *key_name,
    const unsigned char *pubkey, unsigned int pubkey_size,
    unsigned char **secret, unsigned int *secret_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->compute_dhm_params(m_handle, key_name, pubkey,
      pubkey_size, secret, secret_size);
}

artik_error artik::Security::generate_ecdh_params(see_algorithm key_algo,
    const char *key_name, unsigned char **pubkey, unsigned int *pubkey_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->generate_ecdh_params(m_handle, key_algo, key_name, pubkey,
      pubkey_size);
}

artik_error artik::Security::compute_ecdh_params(const char *key_name,
    const unsigned char *pubkey, unsigned int pubkey_size,
    unsigned char **secret, unsigned int *secret_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->compute_ecdh_params(m_handle, key_name, pubkey,
      pubkey_size, secret, secret_size);
}

artik_error artik::Security::generate_key(see_algorithm key_algo,
    const char *key_name, const void *key_param) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->generate_key(m_handle, key_algo, key_name, key_param);
}

artik_error artik::Security::set_key(see_algorithm key_algo,
    const char *key_name, const unsigned char *key, unsigned int key_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->set_key(m_handle, key_algo, key_name, key, key_size);
}

artik_error artik::Security::get_publickey(see_algorithm key_algo,
    const char *key_name, unsigned char **key, unsigned int *key_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_publickey(m_handle, key_algo, key_name, key, key_size);
}

artik_error artik::Security::remove_key(see_algorithm key_algo,
    const char *key_name) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->remove_key(m_handle, key_algo, key_name);
}

artik_error artik::Security::write_secure_storage(const char *data_name,
    unsigned int offset, const unsigned char *data, unsigned int data_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->write_secure_storage(m_handle, data_name, offset, data,
      data_size);
}

artik_error artik::Security::read_secure_storage(const char *data_name,
    unsigned int offset, unsigned int read_size, unsigned char **data,
    unsigned int *data_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->read_secure_storage(m_handle, data_name, offset, read_size,
      data, data_size);
}

artik_error artik::Security::remove_secure_storage(const char *data_name) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->remove_secure_storage(m_handle, data_name);
}

artik_error artik::Security::aes_encryption(see_aes_mode aes_mode,
    const char *key_name, const unsigned char *iv, unsigned int iv_size,
    const unsigned char *input, unsigned int input_size, unsigned char **output,
    unsigned int *output_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->aes_encryption(m_handle, aes_mode, key_name, iv, iv_size,
      input, input_size, output, output_size);
}

artik_error artik::Security::aes_decryption(see_aes_mode aes_mode,
    const char *key_name, const unsigned char *iv, unsigned int iv_size,
    const unsigned char *input, unsigned int input_size, unsigned char **output,
    unsigned int *output_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->aes_decryption(m_handle, aes_mode, key_name, iv, iv_size,
      input, input_size, output, output_size);
}

artik_error artik::Security::rsa_encryption(see_rsa_mode rsa_mode,
    const char *key_name, const unsigned char *input, unsigned int input_size,
    unsigned char **output, unsigned int *output_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->rsa_encryption(m_handle, rsa_mode, key_name, input,
      input_size, output, output_size);
}

artik_error artik::Security::rsa_decryption(see_rsa_mode rsa_mode,
    const char *key_name, const unsigned char *input, unsigned int input_size,
    unsigned char **output, unsigned int *output_size) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->rsa_decryption(m_handle, rsa_mode, key_name, input,
      input_size, output, output_size);
}

artik_error artik::Security::convert_pem_to_der(const char *pem_data,
    unsigned char **der_data, unsigned int *length) {
  return m_module->convert_pem_to_der(pem_data, der_data, length);
}

artik_error artik::Security::verify_signature_init(
  const char *signature_pem, const char *root_ca,
  const artik_time *signing_time_in, artik_time *signing_time_out) {
  if (m_sig_handle)
    return E_BUSY;
  return m_module->verify_signature_init(&m_sig_handle, signature_pem,
    root_ca, signing_time_in, signing_time_out);
}

artik_error artik::Security::verify_signature_update(
  const unsigned char *data, unsigned int data_len) {
  if (!m_sig_handle)
    return E_NOT_INITIALIZED;
  return m_module->verify_signature_update(m_sig_handle, data, data_len);
}

artik_error artik::Security::verify_signature_final(void) {
  artik_error ret = S_OK;
  if (!m_sig_handle)
    return E_NOT_INITIALIZED;

  ret = m_module->verify_signature_final(m_sig_handle);
  m_sig_handle = NULL;

  return ret;
}
