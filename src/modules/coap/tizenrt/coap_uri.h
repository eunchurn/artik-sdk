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

#ifndef COAP_URI_H_
#define COAP_URI_H_

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>

#include "hashkey.h"

#define COAP_DEFAULT_SCHEME	"coap"

#define ISEQUAL_CI(a, b) \
	((a) == (b) || (islower(b) && ((a) == ((b) - 0x20))))

typedef struct {
	size_t length;
	unsigned char *s;
} coap_str;

typedef struct {
	coap_str host;
	unsigned short port;
	coap_str path;
	coap_str query;
	bool secure;
} coap_uri;

#define COAP_SET_STR(st, l, v) { (st)->length = (l), (st)->s = (v); }

int coap_split_uri(const unsigned char *uri, size_t len, coap_uri *u);

int coap_hash_path(const unsigned char *path, size_t len, coap_key_t key);

#endif
