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


#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include <artik_adc.h>

#include "os_adc.h"

#include <tinyara/analog/adc.h>
#include <tinyara/analog/ioctl.h>

#define MAX_SIZE 128
#define S5J_ADC_MAX_CHANNELS	4

artik_error os_adc_request(artik_adc_config *config)
{
	char *path = NULL;
	int fd = 0;

	if (!config)
		return E_BAD_ARGS;

	path = malloc(MAX_SIZE + 1);
	if (!path)
		return E_NO_MEM;

	snprintf(path, MAX_SIZE, "/dev/adc%d", config->pin_num);

	/* Try to open the device to check for proper pin number */
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		free(path);
		return E_BAD_ARGS;
	}

	close(fd);
	config->user_data = (void *)path;

	return S_OK;
}

artik_error os_adc_release(artik_adc_config *config)
{
	char *path = NULL;

	if (!config)
		return E_BAD_ARGS;

	path = (char *)config->user_data;
	if (path)
		free(path);

	return S_OK;
}

artik_error os_adc_get_value(artik_adc_config *config, int *value)
{
	void *path = NULL;
	struct adc_msg_s sample[S5J_ADC_MAX_CHANNELS];
	size_t readsize;
	ssize_t nbytes;
	int nsamples;
	int fd = 0;

	if (!config || !value)
		return E_BAD_ARGS;

	path = (char *)config->user_data;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return E_BUSY;

	if (ioctl(fd, ANIOC_TRIGGER, 0) < -1) {
		close(fd);
		return E_BUSY;
	}

	readsize = S5J_ADC_MAX_CHANNELS * sizeof(struct adc_msg_s);
	nbytes = read(fd, sample, readsize);

	if (nbytes < 0) {
		close(fd);
		return E_BUSY;
	}

	nsamples = nbytes / sizeof(struct adc_msg_s);

	if (nsamples * sizeof(struct adc_msg_s) == nbytes)
		*value = sample[config->pin_num].am_data;

	close(fd);

	return S_OK;
}
