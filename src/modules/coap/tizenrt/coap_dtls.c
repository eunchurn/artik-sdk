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

#include "coap_dtls.h"
#include "coap_mem.h"

#include <stdlib.h>

#include <artik_coap.h>
#include <artik_log.h>

#include <tls/easy_tls.h>

#define MAX_LENGTH_PSK 64

typedef struct psk_data {
	artik_coap_verify_psk_callback psk_callback;
	void *user_data;
} psk_data;

bool is_dtls_event_fatal(int result)
{
	switch (result) {
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		log_err("dtls: close notify");
		return true;
	case MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE:
		log_err("dtls: unexpected message");
		return true;
	case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
		log_err("dtls: fatal alert message");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC:
		log_err("dtls: bad record mac");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_RECORD_OVERFLOW:
		log_err("dtls: record overflow");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_DECOMPRESSION_FAILURE:
		log_err("dtls: decompression failure");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE:
		log_err("dtls: handshake failure");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER:
		log_err("dtls: illegal parameter");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA:
		log_err("dtls: unknown CA");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED:
		log_err("dtls: access denied");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR:
		log_err("dtls: decode error");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR:
		log_err("dtls: decrypt error");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION:
		log_err("dtls: protocol version");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_INSUFFICIENT_SECURITY:
		log_err("dtls: insufficient security");
		return true;
	case MBEDTLS_ERR_SSL_INTERNAL_ERROR:
		log_err("dtls: internal error");
		return true;
	case MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT:
		log_err("dtls: unsupported extension");
		return true;
	default:
		return false;
	}
}

int verify_psk_callback(void *parameter, mbedtls_ssl_context *ssl,
	const unsigned char *psk_identity, size_t identity_len)
{
	psk_data *data = (psk_data *)parameter;
	unsigned char *psk = NULL;
	int psk_len = 0;
	unsigned char *identity = NULL;

	psk = (unsigned char *)coap_malloc(MAX_LENGTH_PSK);

	if (!psk) {
		log_err("Memory problem");
		return -1;
	}

	identity = (unsigned char *)coap_malloc(identity_len);

	if (!identity) {
		log_err("Memory problem");
		if (psk)
			coap_free(psk);
		return -1;
	}

	memcpy((char *)identity, (char *)psk_identity, identity_len);


	psk_len = data->psk_callback(identity, &psk, MAX_LENGTH_PSK,
			data->user_data);

	if (psk_len > 0) {
		mbedtls_ssl_set_hs_psk(ssl, psk, psk_len);
		if (identity)
			coap_free(identity);
		if (psk)
			coap_free(psk);
		return 0;
	} else
		return -1;
}

void *coap_dtls_new_context(artik_ssl_config *ssl, artik_coap_psk_param *psk)
{
	log_dbg("");

	tls_cred cred;

	memset(&cred, 0, sizeof(tls_cred));

	if (ssl) {
		if (ssl->ca_cert.data) {
			cred.ca_cert = (unsigned char *)ssl->ca_cert.data;
			cred.ca_certlen = ssl->ca_cert.len;
		}
		if (ssl->client_cert.data) {
			cred.dev_cert = (unsigned char *)ssl->client_cert.data;
			cred.dev_certlen = ssl->client_cert.len;
		}
		if (ssl->client_key.data) {
			cred.dev_key = (unsigned char *)ssl->client_key.data;
			cred.dev_keylen = ssl->client_key.len;
		}
	}

	if (psk) {
		if (psk->identity)
			cred.psk_identity = (char *)psk->identity;

		if (psk->psk) {
			cred.psk = (unsigned char *)psk->psk;
			cred.psk_len = (size_t)psk->psk_len;
		}
	}

	return TLSCtx(&cred);
}


void *coap_dtls_new_client_session(coap_session_t *session)
{
	if (!session)
		return NULL;

	tls_opt opt;
	tls_ctx *ctx = (tls_ctx *)session->context->dtls_context;
	int fd = session->sock.fd;

	memset(&opt, 0, sizeof(tls_opt));

	opt.server = MBEDTLS_SSL_IS_CLIENT;
	opt.transport = MBEDTLS_SSL_TRANSPORT_DATAGRAM;

	if (session->psk_identity || session->psk_key) {
		opt.force_ciphersuites[0] = MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8;
		opt.client_rpk = 1;
		opt.server_rpk = 1;
	} else if (session->ecdsa_keys.priv_key || session->ecdsa_keys.pub_key_x ||
		session->ecdsa_keys.pub_key_y) {
		opt.force_ciphersuites[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		opt.force_curves[0] = MBEDTLS_ECP_DP_SECP256R1;
		opt.client_rpk = 1;
		opt.server_rpk = 1;
	}

	opt.hs_timeout_min = 1000;
	opt.hs_timeout_max = 3000;
	opt.auth_mode = 0;

	return TLSSession(fd, ctx, &opt);
}

void *coap_dtls_new_server_session(coap_session_t *session)
{

	if (!session)
		return NULL;

	tls_opt opt;
	tls_ctx *ctx = (tls_ctx *)session->context->dtls_context;
	tls_session *ssl_session;
	psk_data data;

	memset(&opt, 0, sizeof(tls_opt));

	opt.server = MBEDTLS_SSL_IS_SERVER;
	opt.transport = MBEDTLS_SSL_TRANSPORT_DATAGRAM;

	if (session->context->psk_hint || session->context->psk_key) {
		opt.force_ciphersuites[0] = MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8;

		if (session->context->verify_psk_callback) {
			data.psk_callback = session->context->verify_psk_callback;
			data.user_data = session->context->verify_data;
			opt.psk_callback = verify_psk_callback;
			opt.user_data = &data;
		}

		opt.client_rpk = 1;
		opt.server_rpk = 1;
	} else if (session->context->priv_key ||
			session->context->pub_key_x ||
			session->context->pub_key_y) {
		opt.force_ciphersuites[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		opt.client_rpk = 1;
		opt.server_rpk = 1;
	}

	opt.recv_timeout = 3000;
	opt.hs_timeout_min = 1000;
	opt.hs_timeout_max = 3000;

	ssl_session = TLSSession(session->endpoint->sock.fd, ctx, &opt);

	return ssl_session;
}

void coap_dtls_free_session(coap_session_t *session)
{
	if (!session)
		return;

	tls_session *s_session = (tls_session *)session->tls;

	if (!s_session)
		return;

	int ret = TLSSession_free(s_session);

	if (ret)
		log_err("Fail to free TLS session");
}

int coap_dtls_send(coap_session_t *session,
	const uint8_t *data,
	size_t data_len)
{
	tls_session *s_session = NULL;
	unsigned char *buf = (unsigned char *)data;
	int res;

	if (!session) {
		log_err("session is NULL");
		return -1;
	}

	s_session = (tls_session *)session->tls;

	log_dbg("");

	res = TLSSend(s_session, buf, data_len);

	if (res <= 0) {
		log_err("dtls: info in sending data: 0x%X", -res);

		if (is_dtls_event_fatal(res)) {

			if (session) {
				session->context->nack_handler(session->context,
					session, NULL, COAP_NACK_TLS_FAILED, 0);
				coap_session_free(session);
			}

			log_dbg("session freed");
		}
	}

	return res;
}

int coap_dtls_receive(coap_session_t *session,
	const uint8_t *data,
	size_t data_len)
{
	tls_session *s_session = NULL;
	unsigned char *buf = (unsigned char *)data;
	int res;

	if (!session) {
		log_err("session is NULL");
		return -1;
	}

	s_session = (tls_session *)session->tls;

	if (!session->endpoint) {
		if ((session->sock.flags & COAP_SOCKET_HAS_DATA) == 0)
			return -1;

		session->sock.flags &= ~COAP_SOCKET_HAS_DATA;
	}

	res = TLSRecv(s_session, buf, data_len);

	if (res <= 0) {
		log_err("dtls: info in receiving data: 0x%X", -res);

		if (is_dtls_event_fatal(res)) {

			if (session->context && session->context->nack_handler) {
				session->context->nack_handler(session->context,
					session, NULL, COAP_NACK_TLS_FAILED, 0);
			}

			coap_session_release(session);
		}
	}

	return res;
}

unsigned int coap_dtls_get_overhead(coap_session_t *session)
{
	(void)session;
	return 13 + 8 + 8;
}

uint32_t coap_dtls_get_timeout(coap_session_t *session)
{
	(void)session;
	return 0;
}

void coap_dtls_handle_timeout(coap_session_t *session)
{
	(void)session;
}

void coap_dtls_free_context(void *handle)
{
	if (handle) {
		tls_ctx *tls = (tls_ctx *)handle;

		TLSCtx_free(tls);
	}
}
