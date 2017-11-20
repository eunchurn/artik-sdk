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

#include "coap_time.h"

#include <sys/time.h>
#include <stdlib.h>

static uint32_t coap_clock_offset = 0;

void coap_clock_init(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	coap_clock_offset = tv.tv_sec;
}

/* creates a Qx.frac from fval */
#define Q(frac, fval) ((uint32_t)(((1 << (frac)) * (fval))))

/* number of frac bits for sub-seconds */
#define FRAC 10

/* rounds val up and right shifts by frac positions */
#define SHR_FP(val, frac) (((val) + (1 << ((frac) - 1))) >> (frac))

void coap_ticks(uint32_t *t)
{
	uint32_t tmp;

	struct timeval tv;

	gettimeofday(&tv, NULL);

	tmp = SHR_FP(tv.tv_usec * Q(FRAC, (COAP_TICKS_PER_SECOND/1000000.0)), FRAC);

	*t = tmp + (tv.tv_sec - coap_clock_offset) * COAP_TICKS_PER_SECOND;
}
