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

#include "coap_block.h"
#include <artik_log.h>

int coap_convert_to_block(uint32_t value, coap_block_t *block)
{
	uint16_t size;

	if (!block) {
		log_dbg("block is NULL");
		return -1;
	}

	memset(block, 0, sizeof(coap_block_t));

	size = value & 0x07;
	size += 4;

	block->num = value/16;
	block->m = value & 0x08;
	block->szx = 1 << (unsigned int)size;

	return 0;
}
