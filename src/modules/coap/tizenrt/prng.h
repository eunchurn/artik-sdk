/*
 * prng.h -- Pseudo Random Numbers
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_PRNG_H_
#define COAP_PRNG_H_

#include <stdlib.h>

static int coap_prng_impl(unsigned char *buf, size_t len)
{
	while (len--)
		*buf++ = rand() & 0xFF;
	return 1;
}

#define prng(Buf, Length) coap_prng_impl((Buf), (Length))

#define prng_init(Value) srand((unsigned long)(Value))

#endif
