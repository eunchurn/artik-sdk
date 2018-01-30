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

artik_error artik::Security::get_certificate(
    artik_security_certificate_id cert_id,
    char **cert) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_certificate(m_handle, cert_id, cert);
}

artik_error artik::Security::get_ca_chain(
    artik_security_certificate_id cert_id,
    char **chain) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_ca_chain(m_handle, cert_id, chain);
}

artik_error artik::Security::get_key_from_cert(const char *cert, char **key) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_key_from_cert(m_handle, cert, key);
}

artik_error artik::Security::get_random_bytes(unsigned char *rand, int len) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_random_bytes(m_handle, rand, len);
}

artik_error artik::Security::get_certificate_sn(
    artik_security_certificate_id cert_id,
    unsigned char *sn, unsigned int *len) {
  if (!m_handle)
    return E_NOT_INITIALIZED;
  return m_module->get_certificate_sn(m_handle, cert_id, sn, len);
}

artik_error artik::Security::get_ec_pubkey_from_cert(const char *cert,
    char **key) {
  return m_module->get_ec_pubkey_from_cert(cert, key);
}

artik_error artik::Security::convert_pem_to_der(const char *pem_data,
    unsigned char **der_data) {
  return m_module->convert_pem_to_der(pem_data, der_data);
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
  unsigned char *data, unsigned int data_len) {
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
