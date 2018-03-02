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

#ifndef BASE_CPP_ARTIK_SECURITY_HH_
#define BASE_CPP_ARTIK_SECURITY_HH_

#include <artik_security.h>
#include <artik_module.h>
#include <artik_error.hh>

/*! \file artik_security.hh
 *
 *  \brief C++ Wrapper to the Security module
 *
 *  This is a class encapsulation of the C
 *  Security module API \ref artik_security.h
 */
namespace artik {
/*!
 * \brief Security module C++ class
 */
class Security {
 private:
  artik_security_module *m_module;
  artik_security_handle m_handle;
  artik_security_handle m_sig_handle;

 public:
  Security();
  ~Security();

  artik_error get_random_bytes(unsigned int, unsigned char**);
  artik_error get_certificate_sn(const char *, unsigned char*, unsigned int *);
  artik_error get_ec_pubkey_from_cert(const char*, char **);
  artik_error get_certificate_pem_chain(const char *, artik_list**);
  artik_error set_certificate(const char *, const unsigned char *,
      unsigned int);
  artik_error get_certificate(const char *, artik_security_cert_type_t,
      unsigned char **, unsigned int *);
  artik_error remove_certificate(const char *);
  artik_error get_hash(see_hash_mode, const unsigned char *, unsigned int,
      unsigned char **, unsigned int *);
  artik_error get_hmac(see_hash_mode, const char *, const unsigned char *,
      unsigned int, unsigned char **, unsigned int *);
  artik_error get_rsa_signature(see_rsa_mode, const char *,
      const unsigned char *, unsigned int, unsigned int, unsigned char **,
      unsigned int *);
  artik_error verify_rsa_signature(see_rsa_mode, const char *,
      const unsigned char *, unsigned int, unsigned int, const unsigned char *,
      unsigned int);
  artik_error get_ecdsa_signature(see_algorithm, const char *,
      const unsigned char *, unsigned int, unsigned char **, unsigned int *);
  artik_error verify_ecdsa_signature(see_algorithm, const char *,
      const unsigned char *, unsigned int, const unsigned char *, unsigned int);
  artik_error generate_dhm_params(see_algorithm, const char *,
      unsigned char **, unsigned int *);
  artik_error set_dhm_params(const char *, const unsigned char *, unsigned int ,
      unsigned char **, unsigned int *);
  artik_error compute_dhm_params(const char *, const unsigned char *,
      unsigned int, unsigned char **, unsigned int *);
  artik_error generate_ecdh_params(see_algorithm , const char *,
      unsigned char **, unsigned int *);
  artik_error compute_ecdh_params(const char *, const unsigned char *,
      unsigned int, unsigned char **, unsigned int *);
  artik_error generate_key(see_algorithm, const char *, const void *);
  artik_error set_key(see_algorithm, const char *, const unsigned char *,
      unsigned int);
  artik_error get_publickey(see_algorithm, const char *, unsigned char **,
      unsigned int *);
  artik_error remove_key(see_algorithm, const char *);
  artik_error write_secure_storage(const char *, unsigned int,
      const unsigned char *, unsigned int);
  artik_error read_secure_storage(const char *, unsigned int, unsigned int,
      unsigned char **, unsigned int *);
  artik_error remove_secure_storage(const char *);
  artik_error aes_encryption(see_aes_mode, const char *, const unsigned char *,
      unsigned int, const unsigned char *, unsigned int, unsigned char **,
      unsigned int *);
  artik_error aes_decryption(see_aes_mode, const char *, const unsigned char *,
      unsigned int, const unsigned char *, unsigned int, unsigned char **,
      unsigned int *);
  artik_error rsa_encryption(see_rsa_mode, const char *, const unsigned char *,
      unsigned int , unsigned char **, unsigned int *);
  artik_error rsa_decryption(see_rsa_mode, const char *, const unsigned char *,
      unsigned int, unsigned char **, unsigned int *);
  artik_error convert_pem_to_der(const char *, unsigned char **,
      unsigned int *);
  artik_error verify_signature_init(const char *, const char *,
      const artik_time *, artik_time *);
  artik_error verify_signature_update(
      const unsigned char *, unsigned int);
  artik_error verify_signature_final(void);
};

}  // namespace artik

#endif  // BASE_CPP_ARTIK_SECURITY_HH_
