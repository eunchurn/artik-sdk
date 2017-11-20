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

#ifndef _COAP_BLOCK_H
#define _COAP_BLOCK_H

#include <er-coap-13.h>
#include <stdlib.h>

#define COAP_MAX_BLOCK_SZX 6

typedef struct {
	uint32_t num;
	uint8_t m;
	uint16_t szx;
} coap_block_t;

int coap_convert_to_block(unsigned int value, coap_block_t *block);

#endif
