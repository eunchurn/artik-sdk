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

#ifndef	__LINUX_SECURITY_H__
#define	__LINUX_SECURITY_H__

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

/**
 * @brief Cryptography algorithm
 */
typedef enum {
	LINUX_AES_ALGORITHM = 0x0000,
	LINUX_AES_128 = LINUX_AES_ALGORITHM, /**< 128 bits aes algorithm */
	LINUX_AES_192, /**< 192 bits aes algorithm */
	LINUX_AES_256, /**< 256 bits aes algorithm */
	LINUX_RSA_ALGORITHM = 0x1000,
	LINUX_RSA_1024 = LINUX_RSA_ALGORITHM, /**< 1024 bits rsa algorithm */
	LINUX_RSA_2048, /**< 2048 bits rsa algorithm */
	LINUX_RSA_3072, /**< 3072 bits rsa algorithm */
	LINUX_ECC_ALGORITHM = 0x2000,
	LINUX_ECC_BRAINPOOL_P256R1 = LINUX_ECC_ALGORITHM, /**< ecc brainpool curve for p256r1 */
	LINUX_ECC_BRAINPOOL_P384R1, /**< ecc brainpool curve for p384r1 */
	LINUX_ECC_BRAINPOOL_P512R1, /**< ecc brainpool curve for p512r1 */
	LINUX_ECC_SEC_P256R1, /**< nist curve for p256r1 */
	LINUX_ECC_SEC_P384R1, /**< nist curve for p384r1 */
	LINUX_ECC_SEC_P521R1, /**< nist curve for p521r1 */
	LINUX_HASH_ALGORITHM = 0x3000,
	LINUX_HASH_MD5 = LINUX_HASH_ALGORITHM, /**< md5 hash algorithm */
	LINUX_HASH_SHA1, /**< sha1 hash algorithm */
	LINUX_HASH_SHA224, /**< sha224 hash algorithm */
	LINUX_HASH_SHA256, /**< sha256 hash algorithm */
	LINUX_HASH_SHA384, /**< sha384 hash algorithm */
	LINUX_HASH_SHA512, /**< sha512 hash algorithm */
	LINUX_HMAC_ALGORITHM = 0x4000,
	LINUX_HMAC_MD5 = LINUX_HMAC_ALGORITHM, /**< hmac with md5 */
	LINUX_HMAC_SHA1, /**< hmac with sha1 */
	LINUX_HMAC_SHA224, /**< hmac with sha224 */
	LINUX_HMAC_SHA256, /**< hmac with sha256 */
	LINUX_HMAC_SHA384, /**< hmac with sha384 */
	LINUX_HMAC_SHA512, /**< hmac with sha512 */
	LINUX_DH_ALGORITHM = 0x5000,
	LINUX_DH_1024 = DH_ALGORITHM, /**< dh 1024 */
	LINUX_DH_1024_5114, /**< dh 1024 rfc5114*/
	LINUX_DH_2048, /**< dh 2048 */
	LINUX_DH_2048_5114 /**< dh 2048 rfc5114*/
} linux_see_algorithm;

/**
 * @brief aes mode
 */
typedef enum {
	LINUX_AES_ECB_NOPAD = 0, /**< aes128 ecb nopad mode */
	LINUX_AES_ECB_ISO9797_M1 = 1, /**< aes128 ecb iso9797 m1 mode */
	LINUX_AES_ECB_ISO9797_M2 = 2, /**< aes128 ecb iso9797 m2 mode */
	LINUX_AES_ECB_PKCS5 = 3, /**< aes128 ecb pkcs5 mode */
	LINUX_AES_ECB_PKCS7 = 4, /**< aes128 ecb pkcs7 mode */
	LINUX_AES_CBC_NOPAD = 5, /**< aes128 cbc nopad mode */
	LINUX_AES_CBC_ISO9797_M1 = 6, /**< aes128 cbc iso9797 m1 mode */
	LINUX_AES_CBC_ISO9797_M2 = 7, /**< aes128 cbc iso9797 m2 mode */
	LINUX_AES_CBC_PKCS5 = 8, /**< aes128 cbc pkcs5 mode */
	LINUX_AES_CBC_PKCS7 = 9, /**< aes128 cbc pkcs7 mode */
	LINUX_AES_CTR = 10 /**< aes128 ctr nopad mode */
} linux_see_aes_mode;

/**
 * @brief rsa mode
 */
typedef enum {
	/**< rsaes pkcs1 v1_5 for enc/dec */
	LINUX_RSAES_PKCS1_V1_5 = 0,
	/**< rsaes pkcs1 oaep mgf1 sha1 for enc/dec */
	LINUX_RSAES_PKCS1_OAEP_MGF1_SHA1 = 1,
	/**< rsaes pkcs1 oaep mgf1 sha224 for enc/dec */
	LINUX_RSAES_PKCS1_OAEP_MGF1_SHA224 = 2,
	/**< rsaes pkcs1 oaep mgf1 sha256 for enc/dec */
	LINUX_RSAES_PKCS1_OAEP_MGF1_SHA256 = 3,
	/**< rsaes pkcs1 oaep mgf1 sha384 for enc/dec */
	LINUX_RSAES_PKCS1_OAEP_MGF1_SHA384 = 4,
	/**< rsaes pkcs1 oaep mgf1 sha512 for enc/dec, not support rsa1024 */
	LINUX_RSAES_PKCS1_OAEP_MGF1_SHA512 = 5,
	/**< rsassa pkcs1 v1_5 md5 for sign/verify */
	LINUX_RSASSA_PKCS1_V1_5_MD5 = 6,
	/**< rsassa pkcs1 v1_5 sha1 for sign/verify */
	LINUX_RSASSA_PKCS1_V1_5_SHA1 = 7,
	/**< rssssa pkcs1 v1_5 sha224 for sign/verify */
	LINUX_RSASSA_PKCS1_V1_5_SHA224 = 8,
	/**< rsassa pkcs1 v1_5 sha256 for sign/verify */
	LINUX_RSASSA_PKCS1_V1_5_SHA256 = 9,
	/**< rsassa pkcs1 v1_5 sha384 for sign/verify */
	LINUX_RSASSA_PKCS1_V1_5_SHA384 = 10,
	/**< rsassa pkcs1 v1_5 sha512 for sign/verify, not support rsa1024 */
	LINUX_RSASSA_PKCS1_V1_5_SHA512 = 11,
	/**< rsassa pkcs1 pss mgf1 sha1 for sign/verify */
	LINUX_RSASSA_PKCS1_PSS_MGF1_SHA1 = 12,
	/**< rsassa pkcs1 pss mgf1 sha224 for sign/verify */
	LINUX_RSASSA_PKCS1_PSS_MGF1_SHA224 = 13,
	/**< rsassa pkcs1 pss mgf1 sha256 for sign/verify */
	LINUX_RSASSA_PKCS1_PSS_MGF1_SHA256 = 14,
	/**< rsassa pkcs1 pss mgf1 sha384 for sign/verify */
	LINUX_RSASSA_PKCS1_PSS_MGF1_SHA384 = 15,
	/**< rsassa pkcs1 pss mgf1 sha512 for sign/verify, not support rsa1024*/
	LINUX_RSASSA_PKCS1_PSS_MGF1_SHA512 = 16,
} linux_see_rsa_mode;

/**
 * @brief ecdsa curve
 */
typedef enum {
	LINUX_ECDSA_BRAINPOOL_P256R1 = 0, /**< brainpool curve for P256 */
	LINUX_ECDSA_BRAINPOOL_P384R1 = 1, /**< brainpool curve for P384r1 */
	LINUX_ECDSA_BRAINPOOL_P512R1 = 2, /**< brainpool curve for P512r1 */
	LINUX_ECDSA_SEC_P256R1 = 3, /**< nist curve for P256r1 */
	LINUX_ECDSA_SEC_P384R1 = 4, /**< nist curve for P384r1 */
	LINUX_ECDSA_SEC_P521R1 = 5, /**< nist curve for P521r1 */
} linux_see_ecdsa_curve;

/**
 * @brief csr
 */
typedef struct {
	unsigned char issuer_country[128]; /**< issuer country */
	unsigned char issuer_organization[128]; /**< issuer organization */
	unsigned char issuer_cn[128]; /**< issuer cn */
	unsigned char issuer_keyname[20]; /**< issuer key name in secure storage */
	unsigned int issuer_algorithm; /**< algorithm of issuer key, refer to see_algorithm */
	unsigned char subject_country[128]; /**< subject country */
	unsigned char subject_organization[128]; /**< subject organization */
	unsigned char subject_cn[128]; /**< subject cn */
	unsigned char subject_keyname[20]; /**< subject key name in secure storage */
	unsigned int subject_algorithm; /**< algorithm of subject key, refer to see_algorithm */
	unsigned int serial; /**< certificate serial */
	unsigned int cert_years; /**< certificate expiration date */
} see_csr;

typedef struct {
	int (*generate_random)(unsigned int size, see_data *random);
	int (*generate_certificate)(const char *cert_name, see_csr *csr,
			see_data *cert);
	int (*set_certificate)(const char *cert_name, see_data *certificate);
	int (*get_certificate)(const char *cert_name, see_data *certificate);
	int (*remove_certificate)(const char *cert_name);
	int (*get_signature)(see_algorithm algo, unsigned int mode,
			const char *key_name, see_data *hash, see_data *sign);
	int (*verify_signature)(see_algorithm algo, unsigned int mode,
			const char *key_name, see_data *hash, see_data *sign);
	int (*get_hash)(see_algorithm algo, see_data *data, see_data *hash);
	int (*get_hmac)(see_algorithm algo, const char *key_name, see_data *data,
			see_data *hmac);
	int (*generate_dhparams)(see_algorithm algo, const char *name, see_data *public);
	int (*set_dhparams)(see_algorithm algo, const char *name, see_data *params, see_data *public);
	int (*compute_dhparams)(see_algorithm algo, const char *name, see_data *public, see_data *secret);
	int (*generate_ecdhkey)(see_algorithm algo, const char *name, see_data *public);
	int (*compute_ecdhkey)(see_algorithm algo, const char *name, see_data *public, see_data *secret);
	int (*read_secure_storage)(const char *name, unsigned int offset,
			unsigned int size, see_data *data);
	int (*write_secure_storage)(const char *name, unsigned int offset,
			see_data *data);
	int (*delete_secure_storage)(const char *name);
	int (*get_size_secure_storage)(const char *name, unsigned int *size);
	int (*get_list_secure_storage)(unsigned int *count, see_storage_list *list);
	int (*post_provision)(const char *admin_id, const char *admin_key,
			see_data *pp_data, unsigned int lock);
	int (*generate_key)(see_algorithm algo, const char *name, see_data *key);
	int (*set_key)(see_algorithm algo, const char *name, see_data *key);
	int (*get_pubkey)(see_algorithm algo, const char *name, see_data *key);
	int (*remove_key)(see_algorithm algo, const char *name);
	int (*encryption)(see_algorithm algo, unsigned int mode,
			const char *key_name, see_data *iv, see_data *input, see_data *output);
	int (*decryption)(see_algorithm algo, unsigned int mode,
			const char *key_name, see_data *iv, see_data *input, see_data *output);
	int (*process_provision)(unsigned int mode, see_algorithm algo, see_data *data);
	int (*provision_signature)(unsigned int algo, see_data *hash, see_data *sign);
	int (*get_hash_stream)(unsigned int proc, int *handle, see_algorithm algo, see_data *hash, see_data *sign);
	int (*get_hmac_stream)(unsigned int proc, int *handle, see_algorithm algo, const char *key_name, see_data *data,
			see_data *hmac);
	int (*encryption_stream)(unsigned int proc, int *handle, see_algorithm algo, unsigned int mode,
			const char *key_name, see_data *iv, see_data *input, see_data *output);
	int (*decryption_stream)(unsigned int proc, int *handle, see_algorithm algo, unsigned int mode,
			const char *key_name, see_data *iv, see_data *input, see_data *output);
	int (*generate_key_with_params)(see_algorithm algo, const char *name, see_data *params, see_data *key);
} see_dev;

#endif  /* __LINUX_SECURITY_H__ */
