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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <artik_loop.h>
#include <artik_module.h>
#include <artik_adc.h>

typedef struct {
	int count;
	artik_adc_handle *handle;
	artik_adc_module *adc;
} watch_adc_t;

static int quit_cb(void *user_data)
{
	artik_loop_module *loop = artik_request_api_module("loop");

	loop->quit();
	return 0;
}

static bool string_to_positive_integer(const char *buff, int *integer, const char *arg_name)
{
	if (buff == NULL || buff == '\0') {
		fprintf(stderr, "Error: Failed to parse argument '%s'.\n", arg_name);
		return false;
	}

	char *end = NULL;
	long val = strtol(buff, &end, 10);

	if (errno != 0 || buff == end || end == NULL || *end != '\0') {
		fprintf(stderr, "Error: Failed to parse argument '%s': '%s' is not a number.\n", arg_name, buff);
		return false;
	}

	if (val <= 0) {
		fprintf(stderr, "Error: Argument '%s' must be a positive number.\n", arg_name);
		return false;
	}

	*integer = (int) val;
	return true;
}

static int adc_periodic_callback(void *user_data)
{
	int val;
	artik_error ret;
	watch_adc_t *data = (watch_adc_t *)user_data;
	artik_loop_module *loop = NULL;

	ret = data->adc->get_value(*data->handle, &val);
	if (ret != S_OK) {
		loop = (artik_loop_module *) artik_request_api_module("loop");
		fprintf(stderr, "Error: Failed to get adc value (err=%d)\n", ret);
		loop->quit();
		return 0;
	}

	printf("Value = %d\n", val);

	if (--data->count < 1) {
		loop = (artik_loop_module *) artik_request_api_module("loop");
		loop->quit();
		return 0;
	}

	return 1;
}

static void adc_read_value(int interval, int count)
{
	int periodicid;
	int signalid;
	watch_adc_t watch_data;
	artik_adc_config config = { 0, "adc", NULL };
	artik_adc_handle handle;
	artik_error ret;
	artik_adc_module *adc = NULL;
	artik_loop_module *loop = NULL;

	adc = (artik_adc_module *) artik_request_api_module("adc");
	if (!adc) {
		fprintf(stderr, "Error: Failed to request ADC module\n");
		return;
	}

	loop = (artik_loop_module *) artik_request_api_module("loop");
	if (!loop) {
		fprintf(stderr, "Error: Failed to request Loop module\n");
		artik_release_api_module(adc);
		return;
	}

	ret = adc->request(&handle, &config);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to request adc (err=%d)\n", ret);
		goto exit;
	}

	watch_data.count = count;
	watch_data.handle = &handle;
	watch_data.adc = adc;
	ret = loop->add_periodic_callback(&periodicid, 1000*interval, adc_periodic_callback, &watch_data);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to setup periodic callback: %s\n", error_msg(ret));
		adc->release(handle);
		goto exit;
	}

	ret = loop->add_signal_watch(SIGINT, quit_cb, NULL, &signalid);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to setup signal handler: %s\n", error_msg(ret));
		adc->release(handle);
		goto exit;
	}
	loop->run();

	adc->release(handle);

exit:
	artik_release_api_module(loop);
	artik_release_api_module(adc);
}

static void usage(void)
{
	printf(
		"Usage:\n"
		" adc-example [options]\n"
		"\n"
		"Options:\n"
		"  -c <num>     Number of times the value is read. (default 5)\n"
		"  -n <sec>     Seconds to wait between readings. (default 1)\n"
		"  -h           Display this help and exit.\n");
}

int main(int argc, char **argv)
{
	int count = 5;
	int interval = 1;
	int c;

	while ((c = getopt(argc, argv, "c:n:h")) != -1) {
		switch (c) {
		case 'c':
			if (!string_to_positive_integer(optarg, &count, "count"))
				return -1;

			break;

		case 'n':
			if (!string_to_positive_integer(optarg, &interval, "interval"))
				return -1;

			break;
		case 'h':
			usage();
			return 0;

		case '?':
			if (optopt == 'c' || optopt == 'n')
				fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
			else
				fprintf(stderr, "Error: Unknow option '-%c'.\n", optopt);
			usage();
			return -1;

		default:
			abort();
		}
	}

	adc_read_value(interval, count);
}
