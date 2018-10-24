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

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <artik_module.h>
#include <artik_loop.h>
#include <artik_pwm.h>

static unsigned int string_to_positive_integer(const char * const buff, int *dst, const char * const option_name)
{
	char *nbuff = NULL;

	if (!buff) {
		fprintf(stderr,  "Invalid buffer which is empty for '%s'.\n", option_name);
		return 0;
	}

	errno = 0;
	*dst = strtol(buff, &nbuff, 10);
	if (nbuff[0] != 0 ||
		(errno != 0 && *dst == 0) ||
		(errno == ERANGE)) {
		printf("Invalid '%s' base definition, it should be an integer of base 10.\n", option_name);
		return 0;
	}
	return 1;
}

static void usage(void)
{
	printf("Usage: pwm-example [OPTIONS]\n\n");
	printf(" Options:\n");
	printf("  -delay <0-10>  Delay in seconds for enable or disable the module. (default 1)\n");
	printf("  -h             Display this help and exit.\n\n");
}

static int on_quit_cb(void *user_data)
{
	artik_loop_module *loop = (artik_loop_module *)
		artik_request_api_module("loop");

	printf("\rQuit PWM example\n\n");
	if (loop) {
		loop->quit();
		artik_release_api_module(loop);
	}
	return 1;
}


static int on_process_cb(void *user_data)
{
	artik_pwm_module *pwm = (artik_pwm_module *)((void **)user_data)[0];
	artik_pwm_handle handle = (artik_pwm_handle)((void **)user_data)[1];
	static int enable = 1;

	if (enable)
		pwm->enable(handle);
	else
		pwm->disable(handle);
	enable = (enable ? 0 : 1);
	return 0;
}

static artik_error init(int speed, int *periodicid,
						artik_loop_module **loop, artik_pwm_module **pwm,
						artik_pwm_handle *handle, artik_pwm_config *config)
{
	int			 signalid = 0;
	static void	*params[2] = { 0, 0};
	artik_error	res = S_OK;

	*loop = (artik_loop_module *)artik_request_api_module("loop");
	if (!(*loop))
		return E_BAD_ARGS;
	*pwm = (artik_pwm_module *)artik_request_api_module("pwm");
	if (!(*pwm))
		return E_BAD_ARGS;
	res = (*loop)->add_signal_watch(SIGINT, on_quit_cb, NULL, &signalid);
	if (res != S_OK)
		return res;
	res = (*pwm)->request(handle, config);
	params[0] = (void *)(*pwm);
	params[1] = (void *)(*handle);
	res = (*loop)->add_periodic_callback(periodicid, speed*1000, on_process_cb, (void *)params);
	return res;
}

static int parse_arguments(int argc, char **argv, int *speed)
{
	int c;

	while ((c = getopt(argc, argv, "s:h")) != -1) {
		switch (c) {
		case 's':
			if (!string_to_positive_integer(optarg, speed, "speed"))
				return -1;
			break;
		case 'h':
			usage();
			return 1;
		case '?':
			if (optopt == 's')
				fprintf(stderr, "Option '-%c' requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknow option '-%c'.\n", optopt);
			usage();
			return -1;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	artik_loop_module *loop = NULL;
	artik_pwm_module *pwm = NULL;
	artik_pwm_handle handle = NULL;
	int periodicid = -1;
	artik_error res = S_OK;
	int speed = 1;
	artik_pwm_config	config = {
		((0 << 8) | 2),
		"pwm",
		500000,
		300000,
		ARTIK_PWM_POLR_NORMAL,
		NULL
	};

	res = parse_arguments(argc, argv, &speed);
	if (res != S_OK)
		goto exit;
	res = init(speed, &periodicid, &loop, &pwm, &handle, &config);
	if (res != S_OK)
		goto exit;
	loop->run();
exit:
	if (res != S_OK)
		fprintf(stderr, "pwm: Failed due to error, %s\n", error_msg(res));
	if (pwm && handle) {
		pwm->disable(handle);
		pwm->release(handle);
	}
	if (pwm)
		artik_release_api_module(pwm);
	if (loop && periodicid != -1)
		loop->remove_periodic_callback(periodicid);
	if (loop)
		artik_release_api_module(loop);
	return 1;
}
