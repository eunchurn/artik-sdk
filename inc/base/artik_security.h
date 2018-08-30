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

#ifndef	__ARTIK_SECURITY_H__
#define	__ARTIK_SECURITY_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "artik_time.h"
#include "artik_error.h"
#include "artik_types.h"
#include "artik_time.h"
#include "artik_list.h"

/*! \file artik_security.h
 *
 *  \brief Security module definition
 *
 *  Definitions and functions for accessing
 *  the Security module and make use of the
 *  hardware Secure Element for cryptographic
 *  and signing features.
 *
 * \example security_test/artik_security_test.c
 */

/*!
 *  \brief Maximum length for the serial number strings
 *
 *  Maximum length allowed for string
 *  containing an serial number
 *  from a certificate of artik secure element
 */
#define ARTIK_CERT_SN_MAXLEN 20

/*!
 *  \brief Security handle type
 *
 *  Handle type used to carry instance specific
 *  information for a security object
 */
typedef void *artik_security_handle;

/*!
 *  \brief Certificate type
 *
 *  Type for specifying the certificate format.
 */
typedef enum {
	ARTIK_SECURITY_CERT_TYPE_PEM,
	ARTIK_SECURITY_CERT_TYPE_DER,
	ARTIK_SECURITY_CERT_TYPE_INVALID
} artik_security_cert_type_t;

#define SECU_LOCATION_STRLEN   5
#define ARTIK_STORAGE          "ARTIK"
#define PROVISION_STORAGE      "PROVI"
#define SECURE_STORAGE_DEFAULT "SSDEF"
#define SECURE_STORAGE_SE      "SSTSE"
#define SECURE_STORAGE_MEMORY  "SSMEM"
#define MEMORY_STORAGE         "TEMPM"

#define ARTIK_HMAC_KEY_ID      ARTIK_STORAGE"/0"
#define ARTIK_DEVICE_KEY_ID    ARTIK_STORAGE"/0"
#define ARTIK_DEVICE_CERT_ID   ARTIK_STORAGE"/0"
#define ARTIK_DEVICECA_CERT_ID ARTIK_STORAGE"/1"
#define ARTIK_ROOTCA_CERT_ID   ARTIK_STORAGE"/2"
#define ARTIK_CERTS_NUM        3

/*!
 * \brief hash mode
 */
typedef enum {
	HASH_ALGO = 0x00110000,
	HASH_SHA1_160 = HASH_ALGO,  /*!< sha1 hash algorithm */
	HASH_SHA2_256 = 0x00230000, /*!< sha256 hash algorithm */
	HASH_SHA2_384 = 0x00240000, /*!< sha384 hash algorithm */
	HASH_SHA2_512 = 0x00250000  /*!< sha512 hash algorithm */
} see_hash_mode;

/*!
 * \brief Cryptography key algorithm
 */
typedef enum {
	AES_ALGORITHM = 0x0000,
	AES_128 = AES_ALGORITHM,  /*!< 128 bits aes algorithm */
	AES_192,                  /*!< 192 bits aes algorithm */
	AES_256,                  /*!< 256 bits aes algorithm */

	RSA_ALGORITHM = 0x1000,
	RSA_1024 = RSA_ALGORITHM, /*!< 1024 bits rsa algorithm */
	RSA_2048,                 /*!< 2048 bits rsa algorithm */

	ECC_ALGORITHM = 0x2000,
	ECC_BRAINPOOL_ALGORITHM = ECC_ALGORITHM,
	ECC_BRAINPOOL_P256R1 = ECC_BRAINPOOL_ALGORITHM, /*!< ecc brainpool curve for p256r1 */
	ECC_SEC_ALGORITHM = 0x2010,
	ECC_SEC_P256R1 = ECC_SEC_ALGORITHM, /*!< nist curve for p256r1 */
	ECC_SEC_P384R1,                     /*!< nist curve for p384r1 */
	ECC_SEC_P521R1,                     /*!< nist curve for p521r1 */

	HMAC_ALGORITHM = 0x4000,

	DH_ALGORITHM = 0x5000,
	DH_1024 = DH_ALGORITHM,    /*!< dh 1024 */
	DH_1024_5114,              /*!< dh 1024 rfc5114*/
	DH_2048,                   /*!< dh 2048 */
	DH_2048_5114,              /*!< dh 2048 rfc5114*/
} see_algorithm;

/*!
 * \brief aes mode
 */
typedef enum {
	AES_ECB_NOPAD = 0,  /*!< aes128 ecb nopad mode */
	AES_ECB_PKCS7,      /*!< aes128 ecb pkcs7 mode */
	AES_CBC_NOPAD,      /*!< aes128 cbc nopad mode */
	AES_CBC_PKCS7,      /*!< aes128 cbc pkcs7 mode */
	AES_CTR_NOPAD       /*!< aes128 ctr nopad mode */
} see_aes_mode;

/*!
 * \brief rsa mode
 */
typedef enum {
	/*!< rsaes pkcs1 v1_5 for enc/dec */
	RSAES_1024_PKCS1_V1_5 = RSA_1024,
	/*!< rsaes pkcs1 v1_5 for enc/dec */
	RSAES_2048_PKCS1_V1_5 = RSA_2048,
	/*!< rsaes pkcs1 v1_5 sha1 for enc/dec */
	RSASSA_1024_PKCS1_V1_5_SHA160 = RSA_1024 | HASH_SHA1_160,
	/*!< rsaes pkcs1 v1_5 sha256 for sign/verify */
	RSASSA_1024_PKCS1_V1_5_SHA256 = RSA_1024 | HASH_SHA2_256,
	/*!< rsaes pkcs1 v1_5 sha384 for sign/verify */
	RSASSA_1024_PKCS1_V1_5_SHA384 = RSA_1024 | HASH_SHA2_384,
	/*!< rsaes pkcs1 v1_5 sha512 for sign/verify */
	RSASSA_1024_PKCS1_V1_5_SHA512 = RSA_1024 | HASH_SHA2_512,
	/*!< rsaes pkcs1 v1_5 sha1 for sign/verify */
	RSASSA_2048_PKCS1_V1_5_SHA160 = RSA_2048 | HASH_SHA1_160,
	/*!< rsaes pkcs1 v1_5 sha256 for sign/verify */
	RSASSA_2048_PKCS1_V1_5_SHA256 = RSA_2048 | HASH_SHA2_256,
	/*!< rsaes pkcs1 v1_5 sha384 for sign/verify */
	RSASSA_2048_PKCS1_V1_5_SHA384 = RSA_2048 | HASH_SHA2_384,
	/*!< rsaes pkcs1 v1_5 sha512 for sign/verify */
	RSASSA_2048_PKCS1_V1_5_SHA512 = RSA_2048 | HASH_SHA2_512,
	/*!< rsassa pkcs1 pss mgf1 sha1 for sign/verify */
	RSASSA_1024_PKCS1_PSS_MGF1_SHA160 = 0x01000000 | RSA_1024 | HASH_SHA1_160,
	/*!< rsassa pkcs1 pss mgf1 sha256 for sign/verify */
	RSASSA_1024_PKCS1_PSS_MGF1_SHA256 = 0x01000000 | RSA_1024 | HASH_SHA2_256,
	/*!< rsassa pkcs1 pss mgf1 sha384 for sign/verify */
	RSASSA_1024_PKCS1_PSS_MGF1_SHA384 = 0x01000000 | RSA_1024 | HASH_SHA2_384,
	/*!< rsassa pkcs1 pss mgf1 sha512 for sign/verify, recommended not to use this */
	RSASSA_1024_PKCS1_PSS_MGF1_SHA512 = 0x01000000 | RSA_1024 | HASH_SHA2_512,
	/*!< rsassa pkcs1 pss mgf1 sha1 for sign/verify */
	RSASSA_2048_PKCS1_PSS_MGF1_SHA160 = 0x01000000 | RSA_2048 | HASH_SHA1_160,
	/*!< rsassa pkcs1 pss mgf1 sha256 for sign/verify */
	RSASSA_2048_PKCS1_PSS_MGF1_SHA256 = 0x01000000 | RSA_2048 | HASH_SHA2_256,
	/*!< rsassa pkcs1 pss mgf1 sha384 for sign/verify */
	RSASSA_2048_PKCS1_PSS_MGF1_SHA384 = 0x01000000 | RSA_2048 | HASH_SHA2_384,
	/*!< rsassa pkcs1 pss mgf1 sha512 for sign/verify */
	RSASSA_2048_PKCS1_PSS_MGF1_SHA512 = 0x01000000 | RSA_2048 | HASH_SHA2_512,
} see_rsa_mode;

/*!
 * \brief HMAC key size parameter
 *
 * This is used for hmac key size when generating hmac key.
 *
 * \see generate_key
 */
struct hmac_key_param {
	unsigned int key_size;
};

/*!
 * \brief RSA key exponent parameter
 *
 * This is used for RSA key exponent value when generating RSA key.
 * exponent shall be only prime number.
 *
 * \see generate_key
 */
struct rsa_key_param {
	unsigned int exponent_size;
	unsigned char *exponent;
};

/*! \struct artik_security_module
 *
 *  \brief Security module operations
 *
 *  Structure containing all the exposed operations exposed
 *  by the Security module
 */
typedef struct {
	/*!
	 *  \brief Request a security instance
	 *
	 *  \param[out] handle Handle tied to the requested security
	 *              instance returned by the function.
	 *
	 *  This function loads the 'artiksee' OpenSSL engine. Loading this engine
	 *  allows performing TLS handshake with the client certificate stored in
	 *  SE. You can change the certificate used in the handshake by calling
	 *  \ref get_certificate. By default the ARTIK certificate is used.
	 *
	 *  \return S_OK on success, error code otherwise
	 *  \see artik_error artik_security_handle
	 */
	artik_error(*request) (artik_security_handle * handle);
	/*!
	 *  \brief Release a security instance
	 *
	 *  \param[in] handle Handle tied to the requested security
	 *             instance to be released.
	 *             This handle is returned by the request
	 *             function.
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*release) (artik_security_handle handle);
	/*!
	 *  \brief Generate true random bytes
	 *
	 *  \param[in] handle Handle tied to a requested security
	 *             instance.
	 *             This handle is returned by the request function.
	 *  \param[out] rand Pointer to a preallocated array that will
	 *              be filled with the
	 *              generated random bytes
	 *  \param[in] len Number of random bytes to generate
	 *
	 *  \return S_OK on success, error code otherwise
	 *  \see artik_error artik_security_handle
	 */
	artik_error(*get_random_bytes) (artik_security_handle handle,
			unsigned int len, unsigned char **rand);
	/*!
	 *  \brief Set the certificate
	 *
	 *  \param[in] handle : Handle tied to a requested security
	 *             instance.
	 *             This handle is returned by the request
	 *             function.
	 *  \param[in] cert_name : certificate path and identifier
	 *  \param[in] cert : certificate memory pointer to a certificate that is already
	 *             allocated and filled with the content of the
	 *             certificate.
	 *  \param[in] cert_size : certificate size.
	 *
	 *  \return S_OK on success, error code otherwise
	 *  \see artik_error artik_security_handle
	 */
	artik_error(*set_certificate) (artik_security_handle handle,
			const char *cert_name, const unsigned char *cert,
			unsigned int cert_size);
	/*!
	 *  \brief Get a certificate
	 *
	 *  \param[in] handle : Handle tied to a requested security
	 *             instance.
	 *             This handle is returned by the request
	 *             function.
	 *  \param[in] cert_name : Certificate identifier
	 *  \param[in] type : Certificate type of output
	 *  \param[out] cert : certificate area's pointer that will be allocated by this
	 *              function and filled with the content of the certificate.
	 *              This shall not be null.
	 *  \param[out] cert_size : certificate size information.
	 *
	 *  \return S_OK on success, error code otherwise
	 *  \see artik_error artik_security_handle
	 */
	artik_error(*get_certificate) (artik_security_handle handle,
			const char *cert_name, artik_security_cert_type_t type,
			unsigned char **cert, unsigned int *cert_size);
	/*!
	 *  \brief Remove a certificate.
	 *
	 * - Limitations
	 * <PRE>
	 *  1. type     : type parameter is working for only ARTIK_STORAGE.
	 * </PRE>
	 *
	 *  \param[in] handle : Handle tied to a requested security
	 *             instance.
	 *             This handle is returned by the request
	 *             function.
	 *  \param[in] cert_name : Certificate identifier
	 *
	 *  \return S_OK on success, error code otherwise
	 *  \see artik_error artik_security_handle
	 */
	artik_error(*remove_certificate) (artik_security_handle handle,
			const char *cert_name);
	/*!
	 * \brief Get the hash of the input message
	 *
	 * - Limitations
	 * <PRE>
	 *  1. Algorithm       : \ref see_hash_mode
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] hash_algo : Hash algorithm.
	 * \param[in] input : Input data.
	 * \param[in] input_size : The size of input data.
	 * \param[out] hash : Hashed data. This is double pointer and will be
	 *             allocated in this function with proper size. This pointer
	 *             must be freed by caller.
	 * \param[out] hash_size : Hashed data size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*get_hash) (artik_security_handle handle,
			see_hash_mode hash_algo,
			const unsigned char *input, unsigned int input_size,
			unsigned char **hash, unsigned int *hash_size);
	/*!
	 * \brief Get HMAC from input data
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 *  [ Common ]
	 *   1. HMAC with       : \ref see_hash_mode
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] hmac_algo : Hash algorithm.
	 * \param[in] key_name : HMAC key to use.
	 * \param[in] input : Input data.
	 * \param[in] input_size : The size of input data.
	 * \param[out] hmac : HMAC value. This is double pointer and will be
	 *             allocated in this function with proper size. This pointer
	 *             must be freed by caller.
	 * \param[out] hmac_size : HMAC value size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*get_hmac) (artik_security_handle handle,
			see_hash_mode hmac_algo, const char *key_name,
			const unsigned char *input, unsigned int input_size,
			unsigned char **hmac, unsigned int *hmac_size);
	/*!
	 * \brief Get rsa signature for input data
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] rsa_algo : RSA algorithm. This should be in \ref see_rsa_mode define
	 *            form.
	 * \param[in] key_name : RSA key to use.
	 * \param[in] hash : Hash value. User should calculate hash value from
	 *            a message. get_hash() might be used for it.
	 * \param[in] hash_size : The size of hash value.
	 * \param[out] sig : signature value. This is double pointer and will be
	 *             allocated in this function with proper size. This pointer
	 *             must be freed by caller.
	 * \param[out] sig_size : signature value size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle see_rsa_mode
	 */
	artik_error(*get_rsa_signature) (artik_security_handle handle,
			see_rsa_mode rsa_algo, const char *key_name,
			const unsigned char *hash, unsigned int hash_size,
			unsigned int salt_size,
			unsigned char **sig, unsigned int *sig_size);
	/*!
	 * \brief Verify rsa signature for input hash
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] rsa_algo : RSA algorithm. This should be in \ref see_rsa_mode define
	 *            form.
	 * \param[in] key_name : RSA key to use.
	 * \param[in] hash : Hash value. User should calculate hash value from
	 *            a message. get_hash() might be used for it.
	 * \param[in] hash_size : The size of hash value.
	 * \param[in] sig : signature value.
	 * \param[in] sig_size : signature value size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle see_rsa_mode
	 */
	artik_error(*verify_rsa_signature) (artik_security_handle handle,
			see_rsa_mode rsa_algo, const char *key_name,
			const unsigned char *hash, unsigned int hash_size,
			unsigned int salt_size,
			const unsigned char *sig, unsigned int sig_size);
	/*!
	 * \brief Get ecdsa signature for input data
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] ecdsa_algo : ECDSA algorithm.
	 * \param[in] key_name : ECC key to use.
	 * \param[in] hash : Hash value. User should calculate hash value from
	 *            a message. get_hash() might be used for it.
	 * \param[in] hash_size : The size of hash value.
	 * \param[out] sig : signature value. This is double pointer and will be
	 *             allocated in this function with proper size. This pointer
	 *             must be freed by caller.
	 * \param[out] sig_size : signature value size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*get_ecdsa_signature) (artik_security_handle handle,
			see_algorithm ecdsa_algo, const char *key_name,
			const unsigned char *hash, unsigned int hash_size,
			unsigned char **sig, unsigned int *sig_size);
	/*!
	 * \brief Verify ecdsa signature for input hash
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] ecdsa_algo : ECDSA algorithm.
	 * \param[in] key_name : ECC key to use.
	 * \param[in] hash : Hash value. User should calculate hash value from
	 *            a message. get_hash() might be used for it.
	 * \param[in] hash_size : The size of hash value.
	 * \param[in] sig : signature value.
	 * \param[in] sig_size : signature value size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*verify_ecdsa_signature) (artik_security_handle handle,
			see_algorithm ecdsa_algo, const char *key_name,
			const unsigned char *hash, unsigned int hash_size,
			const unsigned char *sig, unsigned int sig_size);
	/*!
	 * \brief Generate DH key pair and get public key.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] key_algo : Key algorithm.
	 * \param[in] key_name : Key path and identity.
	 * \param[out] pubkey : Public key value in DER form. This is double pointer
	 *             and will be allocated in this function with proper size. This
	 *             pointer must be freed by caller.
	 * \param[out] pubkey_size : Public key value size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*generate_dhm_params) (artik_security_handle handle,
			see_algorithm key_algo, const char *key_name,
			unsigned char **pubkey, unsigned int *pubkey_size);
	/*!
	 * \brief Generate DH key pair and get public key using user's dh parameter.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] key_name : Key path and identity.
	 * \param[in] params : DH parameter p and q in DER form.
	 * \param[in] params_size : DH parameter size.
	 * \param[out] pubkey : Public key value in DER form. This is double pointer
	 *             and will be allocated in this function with proper size. This
	 *             pointer must be freed by caller.
	 * \param[out] pubkey_size : Public key value size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*set_dhm_params) (artik_security_handle handle,
			const char *key_name,
			const unsigned char *params, unsigned int params_size,
			unsigned char **pubkey, unsigned int *pubkey_size);
	/*!
	 * \brief Compute secret key from DH key and public key.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] key_name : Key path and identity.
	 * \param[in] pubkey : Public key value.
	 * \param[in] pubkey_size : Public key value size.
	 * \param[out] secret : Secret key value. This is double pointer and will be
	 *             allocated in this function with proper size. This pointer
	 *             must be freed by caller.
	 * \param[out] secret_size : Secret key value size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*compute_dhm_params) (artik_security_handle handle,
			const char *key_name,
			const unsigned char *pubkey, unsigned int pubkey_size,
			unsigned char **secret, unsigned int *secret_size);
	/*!
	 * \brief Generate ECDH key.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] key_algo : ECDH algorithm.
	 * \param[out] pubkey : Public key value in DER form. This is double pointer
	 *             and will be allocated in this function with proper size. This
	 *             pointer must be freed by caller.
	 * \param[out] pubkey_size : Public key value size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*generate_ecdh_params)(artik_security_handle handle,
			see_algorithm key_algo, const char *key_name,
			unsigned char **pubkey, unsigned int *pubkey_size);

	/*!
	 * \brief Compute secret key from ECDH key and public key.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] key_name : ECDH key path and identity.
	 * \param[in] pubkey : Public key value in DER form.
	 * \param[in] pubkey_size : Public key value size.
	 * \param[out] secret : Secret key value. This is double pointer and will be
	 *             allocated in this function with proper size. This pointer
	 *             must be freed by caller.
	 * \param[out] secret_size : Secret key value size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*compute_ecdh_params)(artik_security_handle handle,
			const char *key_name, const unsigned char *pubkey,
			unsigned int pubkey_size, unsigned char **secret,
			unsigned int *secret_size);
	/*!
	 * \brief Set a key
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot for each key
	 *              AES : 0 ~ 15
	 *              HMAC, RSA, DH, ECC : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) SE Storage  : SE/0 ~ 14 for AES_256
	 *                           SE/15 ~ 30 for AES_128
	 *          3) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] key_algo : Key algorithm.
	 * \param[in] key_name : Key path and identity.
	 * \param[in] key : Allocated memory of key. Key form is in DER.
	 * \param[in] key_size : The size of key.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle ARTIK_STORAGE PROVISION_STORAGE
	 * \see SECURE_STORAGE MEMORY_STORAGE
	 */
	artik_error(*set_key) (artik_security_handle handle,
			see_algorithm key_algo, const char *key_name,
			const unsigned char *key, unsigned int key_size);
	/*!
	 * \brief Generate a key
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot for each key
	 *              AES : 0 ~ 15
	 *              HMAC, RSA, DH, ECC : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) SE Storage  : SE/0 ~ 14 for AES_256
	 *                           SE/15 ~ 30 for AES_128
	 *          3) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] key_algo : Key algorithm.
	 * \param[in] key_name : Key path and identity.
	 * \param[in] key_param : RSA has a parameter input for exponent. HMAC has
	 *            a parameter for key size. hmac_key_param or rsa_key_param
	 *            shall be a input here.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle hmac_key_param rsa_key_param
	 */
	artik_error(*generate_key) (artik_security_handle handle,
			see_algorithm key_algo, const char *key_name,
			const void *key_param);
	/*!
	 * \brief Get public key from an asymmetric key.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot for each key
	 *              AES : 0 ~ 15
	 *              HMAC, RSA, DH, ECC : 0 ~ 7
	 *   2. Key Path     : Key path shall be ARTIK_STORAGE,
	 *                     SECURE_STORAGE_DEFAULT, or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] key_algo : Key algorithm.
	 * \param[in] key_name : Key path and identity.
	 * \param[out] pubkey : Public key value. This is double pointer and will be
	 *             allocated in this function with proper size. This pointer
	 *             must be freed by caller.
	 * \param[out] pubkey_size : Public key value size.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*get_publickey) (artik_security_handle handle,
			see_algorithm key_algo, const char *key_name,
			unsigned char **pubkey, unsigned int *pubkey_size);
	/*!
	 * \brief Remove a key.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot for each key
	 *              AES : 0 ~ 15
	 *              HMAC, RSA, DH, ECC : 0 ~ 7
	 *   2. Key Path     : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) SE Storage  : SE/0 ~ 14 for AES_256
	 *                           SE/15 ~ 30 for AES_128
	 *          3) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] key_algo : Key algorithm.
	 * \param[in] key_name : Key path and identity.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*remove_key) (artik_security_handle handle,
			see_algorithm key_algo, const char *key_name);
	/*!
	 * \brief Write a small data into secure storage.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Data Name    :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot for each key
	 *              AES : 0 ~ 15
	 *              HMAC, RSA, DH, ECC : 0 ~ 7
	 *   2. Data Path    : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Data Name    :
	 *          1) TEE Storage : 20 characters max length
	 *          2) SE Storage  : SE/0 ~ 26
	 *          3) TEMP Storage: TMP/0 ~ 3
	 *   2. Data Size    :
	 *          1) TEE Storage : 32 KB
	 *          2) SE Storage  : 192 Bytes (SE Storage does not support offset.)
	 *          3) TEMP Storage: 32 KB
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] data_name : Data name in secure storage.
	 * \param[in] offset : Data offset.
	 * \param[in] data : Allocated memory of the data.
	 * \param[in] data_size : The size of the data.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*write_secure_storage) (artik_security_handle handle,
			const char *data_name, unsigned int offset,
			const unsigned char *data, unsigned int data_size);
	/*!
	 * \brief Read a data from secure storage.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Data Name    :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot for each key
	 *              AES : 0 ~ 15
	 *              HMAC, RSA, DH, ECC : 0 ~ 7
	 *   2. Data Path    : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Data Name    :
	 *          1) TEE Storage : 20 characters max length
	 *          2) SE Storage  : SE/0 ~ 26
	 *          3) TEMP Storage: TMP/0 ~ 3
	 *   2. Data Size    :
	 *          1) TEE Storage : 32 KB
	 *          2) SE Storage  : 192 Bytes (SE Storage does not support offset.)
	 *          3) TEMP Storage: 32 KB
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] data_name : Data name in secure storage.
	 * \param[in] offset : Data offset.
	 * \param[out] data : Data from secure storage. This is double pointer and
	 *             will be allocated in this function with proper size. This
	 *             pointer must be freed by caller.
	 * \param[out] data_size : The size of the data.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*read_secure_storage) (artik_security_handle handle,
			const char *data_name, unsigned int offset, unsigned int read_size,
			unsigned char **data, unsigned int *data_size);
	/*!
	 * \brief Remove a data from secure storage.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Data Name    :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot for each key
	 *              AES : 0 ~ 15
	 *              HMAC, RSA, DH, ECC : 0 ~ 7
	 *   2. Data Path    : Key path shall be SECURE_STORAGE_DEFAULT,
	 *                     or MEMORY_STORAGE.
	 *
	 *  [ Linux ]
	 *   1. Data Name    :
	 *          1) TEE Storage : 20 characters max length
	 *          2) SE Storage  : SE/0 ~ 26
	 *          3) TEMP Storage: TMP/0 ~ 3
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] data_name : Data name in secure storage.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle
	 */
	artik_error(*remove_secure_storage) (artik_security_handle handle,
			const char *data_name);
	/*!
	 * \brief Encrypt a input message using AES.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 15
	 *   2. Key Path     : Key path shall be ARTIK_STORAGE, PROVISION_STORAGE,
	 *                    SECURE_STORAGE_DEFAULT, or MEMORY_STORAGE.
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) SE Storage  : SE/0 ~ 14 for AES_256
	 *                           SE/15 ~ 30 for AES_128
	 *          3) TEMP Storage: TMP/0 ~ 3
	 *  [ Common ]
	 *   1. Mode           : \ref see_aes_mode
	 *   2. Initial Vector : 16 bytes size shall be used.
	 *   3. Input size     : If you use AES_ECB_NOPAD, AES_CBC_NOPAD, input size
	 *                       shall be in align of 16 bytes.
	 *   4. Input max size : Max size depends on the model.
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] aes_mode : AES algorithm.
	 * \param[in] key_name : AES key path and identity.
	 * \param[in] iv : Initial vector value.
	 * \param[in] iv_size : The size of initial vector value.
	 * \param[in] input : Input message to be encrypted
	 * \param[in] input_size : The size of input message
	 * \param[out] output : Encrypted result value.
	 * \param[out] output_size : The size of encrypted result value.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle see_aes_mode
	 * \see AES_ECB_NOPAD AES_ECB_PKCS7 AES_CBC_NOPAD AES_CBC_PKCS7
	 * \see AES_CTR_NOPAD PROVISION_STORAGE
	 */
	artik_error(*aes_encryption) (artik_security_handle handle,
			see_aes_mode aes_mode, const char *key_name,
			const unsigned char *iv, unsigned int iv_size,
			const unsigned char *input, unsigned int input_size,
			unsigned char **output, unsigned int *output_size);
	/*!
	 * \brief Decrypt a input message using AES.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 15
	 *   2. Key Path     : Key path shall be ARTIK_STORAGE, PROVISION_STORAGE,
	 *                     SECURE_STORAGE_DEFAULT, or MEMORY_STORAGE.
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) SE Storage  : SE/0 ~ 14 for AES_256
	 *                           SE/15 ~ 30 for AES_128
	 *          3) TEMP Storage: TMP/0 ~ 3
	 *  [ Common ]
	 *   1. Mode           : \ref see_aes_mode
	 *   2. Initial Vector : 16 bytes size shall be used.
	 *   3. Input size     : If you use AES_ECB_NOPAD, AES_CBC_NOPAD, input size
	 *                       shall be in align of 16 bytes.
	 *   4. Input max size : Max size depends on the model.
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] aes_mode : AES algorithm.
	 * \param[in] key_name : AES key path and identity.
	 * \param[in] iv : Initial vector value.
	 * \param[in] iv_size : The size of initial vector value.
	 * \param[in] input : Input message to be decrypted
	 * \param[in] input_size : The size of input message
	 * \param[out] output : Decrypted result value.
	 * \param[out] output_size : The size of decrypted result value.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle see_aes_mode
	 * \see AES_ECB_NOPAD AES_ECB_PKCS7 AES_CBC_NOPAD AES_CBC_PKCS7
	 * \see AES_CTR_NOPAD ARTIK_STORAGE PROVISION_STORAGE SECURE_STORAGE_DEFAULT
	 * \see SECURE_STORAGE_SE SECURE_STORAGE_MEMORY
	 */
	artik_error(*aes_decryption) (artik_security_handle handle,
			see_aes_mode aes_mode, const char *key_name,
			const unsigned char *iv, unsigned int iv_size,
			const unsigned char *input, unsigned int input_size,
			unsigned char **output, unsigned int *output_size);
	/*!
	 * \brief Encrypt a input message using RSAES.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 8
	 *   2. Key Path     : Key path shall be ARTIK_STORAGE, PROVISION_STORAGE,
	 *                     SECURE_STORAGE_DEFAULT, or MEMORY_STORAGE.
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 *  [ Common ]
	 *   1. Mode           : \ref see_rsa_mode
	 *   2. Initial Vector : 16 bytes size shall be used.
	 *   3. Input size     : If you use AES_ECB_NOPAD, AES_CBC_NOPAD, input size
	 *                       shall be in align of 16 bytes.
	 *   4. Input max size : Max size depends on the model.
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] rsa_mode : RSAES mode.
	 * \param[in] key_name : RSA key path and name.
	 * \param[in] input : Input message to be encrypted
	 * \param[in] input_size : The size of input message
	 * \param[out] output : Encrypted result value.
	 * \param[out] output_size : The size of encrypted result value.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle see_rsa_mode
	 * \see ARTIK_STORAGE PROVISION_STORAGE SECURE_STORAGE_DEFAULT
	 * \see SECURE_STORAGE_SE SECURE_STORAGE_MEMORY MEMORY_STORAGE
	 */
	artik_error(*rsa_encryption) (artik_security_handle handle,
			see_rsa_mode rsa_mode, const char *key_name,
			const unsigned char *input, unsigned int input_size,
			unsigned char **output, unsigned int *output_size);
	/*!
	 * \brief Decrypt a input message using RSAES.
	 *
	 * - Limitations
	 * <PRE>
	 *  [ RTOS ]
	 *   1. Key Name     :
	 *          Key identity length shall not exceed 4 bytes and
	 *          Key shall be in octet form in RTOS model.
	 *          1) Slot : 0 ~ 8
	 *   2. Key Path     : Key path shall be ARTIK_STORAGE, PROVISION_STORAGE,
	 *                     SECURE_STORAGE_DEFAULT, or MEMORY_STORAGE.
	 *  [ Linux ]
	 *   1. Key Name     :
	 *          1) TEE Storage : 20 characters max length
	 *          2) TEMP Storage: TMP/0 ~ 3
	 *  [ Common ]
	 *   1. Mode           : \ref see_rsa_mode
	 *   2. Initial Vector : 16 bytes size shall be used.
	 *   3. Input size     : If you use AES_ECB_NOPAD, AES_CBC_NOPAD, input size
	 *                       shall be in align of 16 bytes.
	 *   4. Input max size : Max size depends on the model.
	 * </PRE>
	 *
	 * \param[in] handle : handle Handle tied to a requested security instance.
	 *            This handle is returned by the request function.
	 * \param[in] rsa_mode : RSAES mode.
	 * \param[in] key_name : RSA key path and name.
	 * \param[in] input : Input message to be decrypted
	 * \param[in] input_size : The size of input message
	 * \param[out] output : Decrypted result value.
	 * \param[out] output_size : The size of decrypted result value.
	 *
	 * \return S_OK on success, other value on failure.
	 * \see artik_error artik_security_handle see_rsa_mode
	 * \see ARTIK_STORAGE PROVISION_STORAGE SECURE_STORAGE_DEFAULT
	 * \see SECURE_STORAGE_SE SECURE_STORAGE_MEMORY MEMORY_STORAGE
	 */
	artik_error(*rsa_decryption) (artik_security_handle handle,
			see_rsa_mode rsa_mode, const char *key_name,
			const unsigned char *input, unsigned int input_size,
			unsigned char **output, unsigned int *output_size);
	/*!
	 *  \brief Initialize verification of PKCS7 signature against a signed
	 *         binary.
	 *
	 *  \param[out] handle signing handle returned by the API. It must be passed
	 *                     to subsequent calls to \ref verify_signature_update
	 *                     and \ref verify_signature_final.
	 *  \param[in] signature_pem PKCS7 signature in a PEM encoded string.
	 *  \param[in] root_ca X509 certificate of the root CA against which to
	 *                     verify the signer certificate in a PEM encoded
	 *                     string.
	 *  \param[in] signing_time_in If provided, the verification function fails
	 *                             if the date occured before the signing time
	 *                             specified in the PKCS7 signature.
	 *  \param[out] signing_time_out If provided, this ate is filled up with the
	 *                               signing time extracted from the PKCS7 data.
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*verify_signature_init) (artik_security_handle * handle,
			const char *signature_pem, const char *root_ca,
			const artik_time * signing_time_in, artik_time * signing_time_out);
	/*!
	 *  \brief Feed data of the signed binary to the verification process.
	 *
	 *  Subsequent calls to this same function specifiying various data
	 *  lengths can be made to feed big amount of data to the verification
	 *  process.
	 *
	 *  \param[in] handle Handle returned by \ref verify_signature_init after
	 *                    initialization of the verification process.
	 *  \param[in] data Pointer to a buffer containing a portion of the data to
	 *                  feed.
	 *  \param[in] data_len Length of the buffer passed in the \ref data
	 *                      parameter.
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*verify_signature_update) (artik_security_handle handle,
			const unsigned char *data, unsigned int data_len);
	/*!
	 *  \brief Finalize signature verification process and return final result.
	 *
	 *  Calls to this function must be made after proper initialization of the
	 *  signature verification process (\ref verify_signature_init) and after
	 *  signed data has been fed using the \ref verify_signature_update
	 *  function.
	 *
	 *  \param[in] handle Handle returned by \ref verify_signature_init after
	 *                    initialization of the verification process.
	 *
	 *  \return S_OK on signature verification success, error code otherwise
	 *
	 *  Signature verification related errors are listed below:
	 *      E_SECURITY_ERROR                  (-7000)
	 *      E_SECURITY_INVALID_X509           (-7001)
	 *      E_SECURITY_INVALID_PKCS7          (-7002)
	 *      E_SECURITY_CA_VERIF_FAILED        (-7003)
	 *      E_SECURITY_DIGEST_MISMATCH        (-7004)
	 *      E_SECURITY_SIGNATURE_MISMATCH     (-7005)
	 *      E_SECURITY_SIGNING_TIME_ROLLBACK  (-7006)
	 */
	artik_error(*verify_signature_final) (artik_security_handle handle);
	/*!
	 *  \brief Convert a certificate or a key from PEM format to
	 *         DER format
	 *
	 *  Only x509 public certificates, EC public key and EC private key are
	 *  supported.
	 *
	 *  \param[in] pem_data Data in PEM format
	 *  \param[out] der_data Data from the conversion into DER format
	 *  \param[out] length Length of the data
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*convert_pem_to_der) (const char *pem_data,
			unsigned char **der_data, unsigned int *length);
	/*!
	 *  \brief Get EC public key from the certificate passed as parameter
	 *
	 *  \param[in] cert Pointer to a string containing the
	 *             certificate to retrieve the EC public key
	 *  \param[out] key Pointer to a string that will be allocated
	 *              by the function
	 *              and filled with the content of the key. This
	 *              string must
	 *              be freed by the calling function.
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*get_ec_pubkey_from_cert) (const char *cert, char **key);
	/*!
	 *  \brief Get the serial number from the certificate
	 *
	 *  \param[in] pem type certificate
	 *  \param[out] sn preallocated array provided by the user
	 *  \param[in,out] len size of the pointer preallocated and
	 *                 set after the pointer was filled.
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*get_certificate_sn) (const char *pem_cert, unsigned char *sn,
			unsigned int *len);
	/*!
	 *  \brief Get certificate PEM chain
	 *
	 *  \param[in] handle Handle tied to a requested security instance.
	 *             This handle is returned by the /def request function.
	 *  \param[in] cert_name Identifier of the certificate slot to get
	 *  \param[out] chain List of all certificates contained in the slot in
	 *              PEM formatted strings
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*get_certificate_pem_chain) (artik_security_handle handle,
			const char *cert_name, artik_list**chain);
	/*!
	 *  \brief Loads the openssl engine for the process
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*load_openssl_engine)(void);
	/*!
	 *  \brief Releases the openssl engine for the process
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*unload_openssl_engine)(void);
} artik_security_module;

extern const artik_security_module security_module;

#ifdef __cplusplus
}
#endif
#endif				/* __ARTIK_SECURITY_H__ */
