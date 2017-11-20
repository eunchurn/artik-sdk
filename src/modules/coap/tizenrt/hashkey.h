/*
 * hashkey.h -- definition of hash key type and helper functions
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_HASHKEY_H_
#define COAP_HASHKEY_H_

#include <stdlib.h>

typedef unsigned char coap_key_t[4];

#ifndef coap_hash

void coap_hash_impl(const unsigned char *s, unsigned int len, coap_key_t h);

#define coap_hash(String, Length, Result) \
	coap_hash_impl((String), (Length), (Result))

#define __COAP_DEFAULT_HASH
#else
#undef __COAP_DEFAULT_HASH
#endif

#define coap_str_hash(Str, H) {				\
	memset((H), 0, sizeof(coap_key_t));		\
	coap_hash((Str)->s, (Str)->length, (H));	\
}

#endif
