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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <artik_module.h>
#include <artik_i2c.h>

static bool string_to_positive_integer(const char *buff, int *integer, const char *arg_name)
{
	if (buff == NULL || *buff == '\0') {
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

static bool string_to_unsigned_integer(const char *buff, unsigned int *uinteger, const char *arg_name)
{
	if (buff == NULL || *buff == '\0') {
		fprintf(stderr, "Error: Failed to parse argument '%s'.\n", arg_name);
		return false;
	}

	char *end = NULL;
	unsigned long val = strtoul(buff, &end, 16);

	if (errno != 0 || buff == end || end == NULL || *end != '\0') {
		fprintf(stderr, "Error: Failed to parse argument '%s': '%s' >%lu< is not a number.\n",
				arg_name, buff, val);
		return false;
	}

	*uinteger = (unsigned int) val;
	return true;
}

static void usage(void)
{
	printf("Usage:\n");
	printf(" Display the data localised to the 'read_addr' of the chip targeted by the 'chip_id' & 'chip_addr'.\n");
	printf(" i2c-example [options] <chip_id> <chip_addr> <read_addr>\n\n");
	printf(" Options:\n");
	printf("  -f\t Configure the frequency of the chip (1000 by default).\n");
	printf("  -w\t Configure the chip data format (8 or 16 bit and by default is 8).\n");
	printf("  -h\t Display this help and exit.\n");
}

static int i2c_command(artik_i2c_module *i2c, artik_i2c_handle i2c_handle, char **argv)
{
	artik_error res = S_OK;
	int   addr = 0;
	short data;

	string_to_unsigned_integer(argv[3], (unsigned int *)&addr, "");
	res = i2c->read_register(i2c_handle, addr, (char *)&data, 2);
	if (res == S_OK)
		fprintf(stdout, "Success: 0x%2x%2x at addr(%s).\n",
				((char *)&data)[0], ((char *)&data)[1], argv[3]);
	else
		fprintf(stdout, "Failed: %s (err=%d)\n", error_msg(res), res);
	return 1;
}

static int parse_arguments(int argc, char **argv, artik_i2c_config *i2c_config)
{
	int c;
	int value = 0;
	unsigned int uvalue = 0;

	i2c_config->id = 1;
	i2c_config->frequency = 1000;
	i2c_config->wordsize = I2C_8BIT;
	while ((c = getopt(argc, argv, "hf:w:")) != -1) {
		switch (c) {
		case 'f':
			if (!string_to_positive_integer(optarg, &(i2c_config->frequency), "[1...]")) {
				fprintf(stderr, "Error: Invalid value for the frequency selection,"
						" should be a positive integer.\n");
				goto exit;
			}
			break;
		case 'w':
			if (!string_to_positive_integer(optarg, &value, "[8|16]") || (value != 8 && value != 16)) {
				fprintf(stderr, "Error: Invalid value for the data format selection,"
						" should be 8 or 16.\n");
				goto exit;
			}
			i2c_config->wordsize = (value == 8 ? I2C_8BIT : I2C_16BIT);
			break;
		case 'h':
			usage();
			goto exit;
		case '?':
				if (optopt == 'f' || optopt == 'w')
					fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
				else
					fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);
			goto exit;
		default:
			abort();
		}
	}
	if (argc < 4) {
		fprintf(stderr, "Error: Invalid number of arguments."
				"The parameters 'chip_id', 'chip_addr' and 'read_addr' are mandatory.\n");
		goto exit;
	}
	if (!string_to_unsigned_integer(argv[1], &i2c_config->id, "chip_id")) {
		fprintf(stderr, "Error: Invalid argument 'chip_id' format, it should be a integer.\n");
		goto exit;
	}
	if (strncmp(argv[2], "0x", 2) != 0 ||
		!string_to_unsigned_integer(argv[2], (unsigned int *)&i2c_config->address, "chip_addr")) {
		fprintf(stderr, "Error: Invalid argument 'chip_addr' format, it should start with '0x'.\n");
		goto exit;
	}
	if (strncmp(argv[3], "0x", 2) != 0 ||
		!string_to_unsigned_integer(argv[3], &uvalue, "read_addr")) {
		fprintf(stderr, "Error: Invalid argument 'read_addr' format, it should start with '0x'.\n");
		goto exit;
	}
	return true;
exit:
	return false;
}

int main(int argc, char **argv)
{
	artik_i2c_module	*i2c = NULL;
	artik_i2c_config    i2c_config;
	artik_i2c_handle	handle_i2c = NULL;
	artik_error		ret = 0;

	if (!parse_arguments(argc, argv, &i2c_config))
		goto exit;
	i2c = (artik_i2c_module *) artik_request_api_module("i2c");
	if (!i2c) {
		fprintf(stderr, "Error: Failed to request i2c module.\n");
		goto exit;
	}
	ret = i2c->request(&handle_i2c, &i2c_config);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to request an i2c instance.\n");
		goto exit;
	}
	i2c_command(i2c, handle_i2c, argv);

exit:
	if (i2c && handle_i2c)
		i2c->release(handle_i2c);
	if (i2c)
		artik_release_api_module(i2c);
}
