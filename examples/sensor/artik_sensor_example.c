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
#include <string.h>

#include <artik_module.h>
#include <artik_platform.h>
#include <artik_loop.h>
#include <artik_sensor.h>
#include <artik_gpio.h>

enum Color {
	R = 0,
	B
};

static unsigned int string_to_positive_integer(const char * const buff, int *dst, const char * const option_name)
{
	if (!buff) {
		fprintf(stdout, "Invalid buffer which is empty for '%s'.\n", option_name);
		return 0;
	}
	char *nbuff = NULL;

	*dst = strtol(buff, &nbuff, 10);
	if (nbuff[0] != 0 ||
		(errno != 0 && *dst == 0) ||
		(errno == ERANGE)) {
		fprintf(stdout, "Invalid '%s' base definition, it should be an integer of base 10.\n", option_name);
		return 0;
	}
	return 1;
}

static void usage(void)
{
	printf("Usage: sensor-example [options]\n\n"
		" Options:\n"
		"  -n <sec>\t Number of seconds for each interval. (default 1)\n"
		"  -h\t Display this help and exit.\n");
}

static int on_quit_cb(void *user_data)
{
	artik_loop_module *loop = (artik_loop_module *)user_data;

	printf("\rQuit SENSOR example\n");
	loop->quit();
	return -2;
}

static int on_process_cb(void *user_data)
{
	artik_gpio_handle **handle_gpio = (artik_gpio_handle **)((void **)user_data)[2];
	artik_sensor_temperature *sensor_envtemp = (artik_sensor_temperature *)((void **)user_data)[0];
	artik_gpio_module *gpio = (artik_gpio_module *)((void **)user_data)[1];
	artik_sensor_handle handle_envtemp = (artik_sensor_handle *)((void **)user_data)[3];
	int res = 0;

	sensor_envtemp->get_celsius(handle_envtemp, &res);
	if (res < 0) {
		gpio->write(handle_gpio[R], 0);
		gpio->write(handle_gpio[B], 1);
		printf("%d C°\n", res);
	}

	if (res >= 0 && res < 15) {
		gpio->write(handle_gpio[R], 0);
		gpio->write(handle_gpio[B], 1);
		printf("%d C°\n", res);
	}

	if (res >= 15 && res < 27) {
		gpio->write(handle_gpio[R], 0);
		gpio->write(handle_gpio[B], 1);
		printf("%d C°\n", res);
	}

	if (res > 26 && res < 30) {
		gpio->write(handle_gpio[R], 1);
		gpio->write(handle_gpio[B], 0);
		printf("%d C°\n", res);
	}

	if (res >= 30) {
		gpio->write(handle_gpio[R], 1);
		gpio->write(handle_gpio[B], 0);
		printf("%d C°\n", res);
	}
	return 1;
}

static artik_error init(artik_loop_module **loop, artik_gpio_module **gpio,
						artik_sensor_module **sensor, artik_gpio_handle *handle_gpio,
						artik_sensor_temperature **sensor_envtemp,
						artik_sensor_handle *handle_envtemp, int interval,
						int *signalid, int *periodicid)
{
	static void			*params[4] = {0, 0};
	artik_gpio_config		gpio_config = {28, NULL, GPIO_OUT, GPIO_EDGE_NONE, 0};
	artik_sensor_config	*sensor_envtemp_conf = NULL;
	artik_error			res = S_OK;

	handle_gpio[R] = 0;
	handle_gpio[B] = 0;
	(*gpio) = (artik_gpio_module *)artik_request_api_module("gpio");
	if (!(*gpio))
		return E_BUSY;
	(*loop) = (artik_loop_module *)artik_request_api_module("loop");
	if (!(*loop))
		return E_BUSY;
	(*sensor) = (artik_sensor_module *)artik_request_api_module("sensor");
	if (!(*sensor))
		return E_BUSY;
	sensor_envtemp_conf = (*sensor)->get_temperature_sensor(0);
	if (!sensor_envtemp_conf)
		return E_BAD_ARGS;
	res = (*gpio)->request(&handle_gpio[R], &gpio_config);
	if (res != S_OK)
		return res;
	gpio_config.id = 38;
	res = (*gpio)->request(&handle_gpio[B], &gpio_config);
	if (res != S_OK)
		return res;
	res = (*sensor)->request(sensor_envtemp_conf, handle_envtemp, (artik_sensor_ops *)sensor_envtemp);
	if (res == S_OK)
		res = (*loop)->add_signal_watch(SIGINT, on_quit_cb, (*loop), signalid);
	if (res == S_OK) {
		params[0] = (void *)(*sensor_envtemp);
		params[1] = (void *)(*gpio);
		params[2] = (void *)handle_gpio;
		params[3] = (*handle_envtemp);
		res = (*loop)->add_periodic_callback(periodicid, interval * 1000, on_process_cb, (void *)params);
	}
	return res;
}

static artik_error parse_arguments(int argc, char **argv, int *interval)
{
	int c;

	while ((c = getopt(argc, argv, "n:h")) != -1) {
		switch (c) {
		case 'h':
			usage();
			return 1;
		case 'n':
			if (!string_to_positive_integer(optarg, interval, "interval"))
				return -1;
			if ((*interval) <= 0)
				(*interval) = 1;
			break;
		case '?':
			if (optopt == 'n')
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
	artik_loop_module		*loop = NULL;
	artik_gpio_module		*gpio = NULL;
	artik_sensor_module	*sensor = NULL;
	artik_gpio_handle		handle_gpio[2] = {NULL, NULL};
	artik_sensor_temperature *sensor_envtemp = NULL;
	artik_sensor_handle	handle_envtemp = NULL;
	artik_error			res = S_OK;
	int signalid = -1, periodicid = -1, interval = 1;

	res = parse_arguments(argc, argv, &interval);
	if (res != S_OK)
		goto exit;
	res = init(&loop, &gpio, &sensor, handle_gpio, &sensor_envtemp,
			   &handle_envtemp, interval, &signalid, &periodicid);
	if (res != S_OK)
		goto exit;
	printf("SENSOR example start\n");
	loop->run();
 exit:
	if (res != S_OK)
		fprintf(stderr, "sensor: Failed due to error, %s\n", error_msg(res));
	if (gpio && handle_gpio[R])
		gpio->write(handle_gpio[R], 0);
	if (gpio && handle_gpio[B])
		gpio->write(handle_gpio[B], 0);
	if (sensor_envtemp && handle_envtemp)
		sensor_envtemp->release(handle_envtemp);
	if (gpio && handle_gpio[R])
		gpio->release(handle_gpio[R]);
	if (gpio && handle_gpio[B])
		gpio->release(handle_gpio[B]);
	if (loop && signalid != -1)
		loop->remove_signal_watch(signalid);
	if (loop && periodicid != -1)
		loop->remove_periodic_callback(periodicid);
	if (loop)
		artik_release_api_module(loop);
	if (sensor)
		artik_release_api_module(sensor);
	if (gpio)
		artik_release_api_module(gpio);
	return 1;
}
