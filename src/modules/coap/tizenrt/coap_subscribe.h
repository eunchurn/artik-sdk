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

#ifndef COAP_SUBSCRIBE_H_
#define COAP_SUBSCRIBE_H_

#include "coap_address.h"
#include "coap_session.h"
#include "coap_socket.h"
#include "coap_uri.h"

#define COAP_OBSERVE_ESTABLISH 0

#define COAP_OBSERVE_CANCEL 1

#define COAP_OBS_MAX_NON 5

#define COAP_OBS_MAX_FAIL 3

typedef struct coap_subscription_t {
	struct coap_subscription_t *next;
	coap_session_t *session;

	unsigned int non_cnt:4;
	unsigned int fail_cnt:2;
	unsigned int dirty:1;

	size_t token_length;
	unsigned char token[8];
	coap_str *query;
} coap_subscription_t;

void coap_subscription_init(coap_subscription_t *s);

#endif /* COAP_SUBSCRIBE_H */
