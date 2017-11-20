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

#ifndef COAP_DTLS_H_
#define COAP_DTLS_H_

#include <artik_ssl.h>
#include <artik_coap.h>

#include "coap.h"
#include "coap_session.h"

void *coap_dtls_new_context(artik_ssl_config *ssl, artik_coap_psk_param *psk);

void *coap_dtls_new_client_session(coap_session_t *session);

void *coap_dtls_new_server_session(coap_session_t *session);

void coap_dtls_free_session(coap_session_t *session);

int coap_dtls_send(coap_session_t *session,
	const uint8_t *data,
	size_t data_len);

int coap_dtls_receive(coap_session_t *session,
	const uint8_t *data,
	size_t data_len);

unsigned int coap_dtls_get_overhead(coap_session_t *session);

uint32_t coap_dtls_get_timeout(coap_session_t *session);

void coap_dtls_handle_timeout(coap_session_t *session);

void coap_dtls_free_context(void *handle);

#endif
