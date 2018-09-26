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
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <artik_module.h>
#include <artik_cloud.h>
#include <artik_loop.h>

#define MAX_LONG        0x7FFFFFFF

typedef bool (*command_callback_t)(artik_ssl_config *ssl, int argc, char **argv, void *user_data);

typedef struct {
	const char *cmd;
	command_callback_t callback;
} command_t;

typedef struct {
	const char *token;
} user_cmd_data_t;

typedef struct {
	const char *did;
	const char *dtoken;
} device_cmd_data_t;

static const char akc_root_ca[] =
	"-----BEGIN CERTIFICATE-----\r\n"
	"MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB\r\n"
	"yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\r\n"
	"ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\r\n"
	"U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\r\n"
	"ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\r\n"
	"aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL\r\n"
	"MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\r\n"
	"ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln\r\n"
	"biwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp\r\n"
	"U2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y\r\n"
	"aXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1\r\n"
	"nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex\r\n"
	"t0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz\r\n"
	"SdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG\r\n"
	"BO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+\r\n"
	"rCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/\r\n"
	"NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E\r\n"
	"BAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH\r\n"
	"BgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy\r\n"
	"aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv\r\n"
	"MzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE\r\n"
	"p6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y\r\n"
	"5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK\r\n"
	"WE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ\r\n"
	"4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N\r\n"
	"hnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq\r\n"
	"-----END CERTIFICATE-----\r\n";

static void usage_options(void)
{
	printf("Options:\n");
	printf("  -k                                                Allow insecure connection.\n");
	printf("  -s [artik|manufacturer]                           Use SE for SSL (by default artik)\n");
	printf("  -d devercet=<devcert path>,devkey=<devkey path>   Client certificate and private key\n");
}

static void usage(void)
{
	printf("Usage: cloud-example [OPTIONS] COMMAND\n");
	printf("\n");
	usage_options();
	printf("  -h                                                Display this help and exit.\n");
	printf("\n");
	printf("Commands:\n");
	printf("  user\n");
	printf("  device\n");
	printf("\n");
	printf("Use 'cloud-example COMMAND -h' to get help on each command.\n");
}

static void usage_user(void)
{
	printf("Usage: cloud-example [OPTIONS] user [USER OPTIONS] <token> [USER COMMAND]\n");
	usage_options();
	printf("\n");
	printf("User options:\n");
	printf("  -h                                                Display this help and exit.\n");
	printf("\n");
	printf("User commands:\n");
	printf("  profile                              Get user profile\n");
	printf("  devices [-c|-o|-p|-u]                Get user's devices\n");
	printf("    -c <num>                           Number of devices returned (default 0)\n");
	printf("    -o <num>                           Offset (default 100)\n");
	printf("    -p                                 Include device properties\n");
	printf("    -u <uid>                           User ID (default current user)\n");
	printf("  device-types [-c|-o|-s|-u]           Get user's device types\n");
	printf("    -c <num>                           Number of devices returned (default 0)\n");
	printf("    -o <num>                           Offset (default 100)\n");
	printf("    -s                                 Return device types shared by all users\n");
	printf("    -u <uid>                           User ID (default current user)\n");
	printf("  application-properties [-u] <appid>  Get user's application properties\n");
	printf("    -u <uid>                           User ID (default current user)\n");
	printf("  device [DEVICE COMMANDS]             Add or delete device.\n");
	printf("    Device commands:\n");
	printf("      create [-u] <dtid> <name>        Create a new device\n");
	printf("        -u <uid>                       User ID (default current user)\n");
	printf("      delete <did>                     Delete a device\n");
	printf("      token [get|create|delete] <did>  Get, create or delete a acess token for a device.\n");
}

static void usage_device(void)
{
	printf("Usage: cloud-example [OPTIONS] device [DEVICE OPTIONS] <did> <dtoken> [DEVICE COMMAND]");
	usage_options();
	printf("Device options:\n");
	printf("  -h                                   Display this help and exit.\n");
	printf("Device commands:\n");
	printf("  get [-p]                             Get a device\n");
	printf("    -p                                 Include device properties\n");
	printf("  message <messsage>                   Send a message\n");
	printf("  action <action>                      Send an action\n");
	printf("  properties [PROPERTIES COMMAND]         Read or set device properties\n");
	printf("    Properties commands:\n");
	printf("      read [-t]                        Read device's properties\n");
	printf("         -t                            Include timestamp\n");
	printf("      set <property>                   Set a device's server property\n");
}

static bool fill_buffer_from_file(const char *file, char **pbuffer)
{
	FILE *stream = NULL;
	char *buffer = NULL;
	size_t size = 0;
	struct stat st;

	stream = fopen(file, "r");
	if (!stream) {
		fprintf(stderr, "Error: Cannot open '%s': %s\n", file, strerror(errno));
		goto error;
	}

	if (fstat(fileno(stream), &st)) {
		fprintf(stderr, "Error: Cannot access '%s': %s\n", file, strerror(errno));
		goto error;
	}

	if ((st.st_size < 0) || (st.st_size >= MAX_LONG)) {
		fprintf(stderr, "Error: Invalid size of file '%s'\n", file);
		goto error;
	}

	size = st.st_size + 1;

	if (fseek(stream, 0, SEEK_SET) != 0) {
		fprintf(stderr, "Error: Cannot seek '%s': %s\n", file, strerror(errno));
		goto error;
	}

	buffer = malloc((size + 1)*sizeof(char));
	if (!buffer) {
		fprintf(stderr, "Error: Cannot allocate %lu bytes\n", (unsigned long)size);
		goto error;
	}

	if (!fread(buffer, sizeof(char), size, stream)) {
		if (ferror(stream)) {
			fprintf(stderr, "Error: Failed to read %lu bytes\n", (unsigned long)size);
			goto error;
		}
	}
	fclose(stream);

	buffer[size] = '\0';
	*pbuffer = buffer;

	return true;

error:
	if (buffer)
		free(buffer);

	if (stream)
		fclose(stream);

	return false;
}


static bool parse_device_cert_opt(char *optarg, char **dev_cert, char **dev_key)
{
	char *subopts = optarg;
	char *value;
	char *const token[] = { "devcert", "devkey" };

	switch (getsubopt(&subopts, token, &value)) {
	case 0:
		if (value == NULL) {
			fprintf(stderr, "Error: Sub-option '%s' requires an argument", token[0]);
			return false;
		}

		if (!fill_buffer_from_file(value, dev_cert))
			return false;

		break;
	case 1:
		if (value == NULL) {
			fprintf(stderr, "Error: Sub-option '%s' requires an argument", token[1]);
			return false;
		}

		if (!fill_buffer_from_file(value, dev_key))
			return false;

		break;
	default:
		fprintf(stderr, "Error: Unknow sub-option '%s'\n", value);
		return false;
	}

	return true;
}

static bool execute_cmd(artik_ssl_config *ssl, void *user_data,
						command_t *cmd, int argc, char **argv,
						const char *name)
{
	int i = 0;

	if (argc < 2) {
		fprintf(stderr, "Error: %s not found.\n", name);
		return false;
	}

	while (cmd[i].cmd != NULL) {
		if (strcmp(argv[1], cmd[i].cmd) == 0)
			break;
		i++;
	}

	if (cmd[i].cmd == NULL) {
		fprintf(stderr, "Error: Unknow %s '%s'\n", name, argv[1]);
		return false;
	}

	return cmd[i].callback(ssl, argc - 1, argv + 1, user_data);
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
		fprintf(stderr, "Error: Failed to parse argument '%s': '%s' is not a number\n", arg_name, buff);
		return false;
	}

	if (val < 0) {
		fprintf(stderr, "Error: Argument '%s' must be a positive number\n", arg_name);
		return false;
	}

	*integer = (int) val;
	return true;
}

static char *parse_json_object(const char *data, const char *obj)
{
	char *res = NULL;
	char prefix[256];
	char *substr = NULL;

	snprintf(prefix, 256, "\"%s\":", obj);

	substr = strstr(data, prefix);
	if (substr != NULL) {
		int idx = 1;
		char end_token;

		/* Start after substring */
		substr += strlen(prefix);

		if (*substr == '{')
			end_token = '}';
		else
			end_token = '"';

		/* Count number of bytes to extract */
		while (substr[idx] != end_token)
			idx++;
		/* Copy the extracted string */
		res = strndup(substr+1, idx - 1);
	}

	return res;
}

static bool is_error(char *response, char *err)
{
	char *error = parse_json_object(response, "error");

	if (error) {
		char *message = parse_json_object(error, "message");

		if (message) {
			fprintf(stderr, "%s: %s\n", err, message);
			free(message);
		}
		free(error);
		return true;
	}

	return false;
}

static bool display_profile(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	artik_cloud_module *cloud =
		(artik_cloud_module *)artik_request_api_module("cloud");
	char *response = NULL;
	artik_error ret;
	user_cmd_data_t *data = (user_cmd_data_t *)user_data;
	const char *token = data->token;

	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		return false;
	}

	ret = cloud->get_current_user_profile(token, &response, ssl);
	artik_release_api_module(cloud);

	if (!response && ret != S_OK) {
		fprintf(stderr, "Error: Failed to get user profile (err %d)\n", ret);
		return false;
	}

	if (response && !is_error(response, "Error: Failed to get user profile"))
		fprintf(stdout, "User profile: %s\n", response);

	if (response)
		free(response);

	return true;
}

static char *get_current_user_id(const char *token, artik_ssl_config *ssl)
{
	artik_cloud_module *cloud =
		(artik_cloud_module *)artik_request_api_module("cloud");
	char *response = NULL;

	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		return NULL;
	}

	cloud->get_current_user_profile(token, &response, ssl);
	artik_release_api_module(cloud);

	char *id = NULL;

	if (response && !is_error(response, "Error: Failed to get user id"))
		id = parse_json_object(response, "id");

	if (response)
		free(response);

	return id;
}

static bool get_user_devices(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	bool ret = true;
	char *uid = NULL;
	int c;
	bool properties = false;
	int count = 100;
	int offset = 0;
	user_cmd_data_t *data = (user_cmd_data_t *)user_data;
	const char *token = data->token;
	artik_cloud_module *cloud = NULL;
	artik_error err = S_OK;
	char *response = NULL;

	optind = 1;
	while ((c = getopt(argc, argv, "u:pc:o:")) != -1) {
		switch (c) {
		case 'u':
			if (uid)
				free(uid);

			uid = strdup(optarg);
			break;
		case 'p':
			properties = true;
			break;
		case 'c':
			if (!string_to_positive_integer(optarg, &count, "<count>")) {
				ret = false;
				goto exit;
			}

			if (count <= 0) {
				fprintf(stderr, "Error: Argument '<count>' must be a positive integer.\n");
				ret = false;
				goto exit;
			}
			break;
		case 'o':
			if (!string_to_positive_integer(optarg, &offset, "<offset>")) {
				ret = false;
				goto exit;
			}
			break;
		case '?':
			if (optopt == 'u' || optopt == 'c' || optopt == 'o')
				fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
			else
				fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);

			ret = false;
			goto exit;
		default:
			abort();
		}
	}

	cloud = (artik_cloud_module *)artik_request_api_module("cloud");
	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		ret = false;
		goto exit;
	}

	if (!uid) {
		uid = get_current_user_id(token, ssl);
		if (!uid) {
			ret = false;
			goto exit;
		}
	}

	err = cloud->get_user_devices(token, count, properties, offset, uid, &response, ssl);
	if (!response && err != S_OK)
		fprintf(stderr, "Error: Failed to get user's devices (err=%d)\n", err);

	if (response && !is_error(response, "Error: Failed to get user's devices"))
		fprintf(stdout, "User's devices: %s\n", response);

	if (response)
		free(response);

exit:
	if (cloud)
		artik_release_api_module(cloud);
	if (uid)
		free(uid);

	return ret;
}

static bool get_device_types(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	bool ret = true;
	char *uid = NULL;
	int c;
	bool shared = false;
	int count = 100;
	int offset = 0;
	user_cmd_data_t *data = (user_cmd_data_t *)user_data;
	const char *token = data->token;
	artik_cloud_module *cloud = NULL;
	artik_error err = S_OK;
	char *response = NULL;

	optind = 1;
	while ((c = getopt(argc, argv, "u:sc:o:")) != -1) {
		switch (c) {
		case 'u':
			if (uid)
				free(uid);

			uid = strdup(optarg);
			break;
		case 's':
			shared = true;
			break;
		case 'c':
			if (!string_to_positive_integer(optarg, &count, "count")) {
				ret = false;
				goto exit;
			}

			if (count <= 0) {
				fprintf(stderr, "Error: Argument '<count>' must be a positive integer.\n");
				ret = false;
				goto exit;
			}
			break;
		case 'o':
			if (!string_to_positive_integer(optarg, &offset, "offset")) {
				ret = false;
				goto exit;
			}
			break;
		case '?':
			if (optopt == 'u' || optopt == 'c' || optopt == 'o')
				fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
			else
				fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);

			ret = false;
			goto exit;
		default:
			abort();
		}
	}

	cloud = (artik_cloud_module *)artik_request_api_module("cloud");
	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		ret = false;
		goto exit;
	}

	if (!uid) {
		uid = get_current_user_id(token, ssl);
		if (!uid) {
			ret = false;
			goto exit;
		}
	}

	err = cloud->get_user_device_types(token, count, shared, offset, uid, &response, ssl);
	if (!response && err != S_OK)
		fprintf(stdout, "Error: Failed to get user's device types (err=%d)\n", err);

	if (response && !is_error(response, "Error: Failed to get user's device types"))
		fprintf(stdout, "User's device types: %s\n", response);

	if (response)
		free(response);

exit:
	if (cloud)
		artik_release_api_module(cloud);
	if (uid)
		free(uid);

	return ret;
}

static bool get_application_properties(artik_ssl_config *ssl, int argc,
		char **argv, void *user_data)
{
	bool ret = true;
	char *uid = NULL;
	char *appid = NULL;
	int c;
	user_cmd_data_t *data = (user_cmd_data_t *)user_data;
	const char *token = data->token;
	artik_cloud_module *cloud = NULL;
	artik_error err = S_OK;
	char *response = NULL;

	optind = 1;
	while ((c = getopt(argc, argv, "u:")) != -1) {
		switch (c) {
		case 'u':
			if (uid)
				free(uid);

			uid = strdup(optarg);
			break;
		case '?':
			if (optopt == 'u')
				fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
			else
				fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);
			ret = false;
			goto exit;
		default:
			abort();
		}
	}

	if (optind == argc) {
		fprintf(stderr, "Error: 'application-properties': <appid> not found.\n");
		usage_user();
		ret = false;
		goto exit;
	}
	appid = argv[optind];

	if (!uid) {
		uid = get_current_user_id(token, ssl);
		if (!uid) {
			ret = false;
			goto exit;
		}
	}

	cloud = (artik_cloud_module *)artik_request_api_module("cloud");
	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		ret = false;
		goto exit;
	}

	err = cloud->get_user_application_properties(token, uid, appid, &response, ssl);
	if (!response && err != S_OK)
		fprintf(stderr, "Error: Failed to get user's application properties (err=%d)\n", err);

	if (response && !is_error(response, "Error: Failed to get user's application properties"))
		fprintf(stdout, "User's application properties: %s\n", response);

	if (response)
		free(response);

exit:
	if (cloud)
		artik_release_api_module(cloud);
	if (uid)
		free(uid);

	return ret;
}

static bool create_device(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	bool ret = true;
	artik_error err = S_OK;
	artik_cloud_module *cloud = NULL;
	char *response = NULL;
	char *uid = NULL;
	char *dtid = NULL;
	char *name = NULL;
	int c;
	user_cmd_data_t *data = (user_cmd_data_t *)user_data;
	const char *token = data->token;

	optind = 1;
	while ((c = getopt(argc, argv, "u:")) != -1) {
		switch (c) {
		case 'u':
			if (uid)
				free(uid);

			uid = strdup(optarg);
			break;
		case '?':
			if (optopt == 'u')
				fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
			else
				fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);
			usage_user();
			ret = false;
			goto exit;
		default:
			abort();
		}
	}

	if (argc == optind) {
		fprintf(stderr, "Error: 'device create': <dtid> not found.\n");
		usage_user();
		ret = false;
		goto exit;
	}

	if (argc == optind + 1) {
		fprintf(stderr, "Error: 'device create': <name> not found.\n");
		usage_user();
		ret = false;
		goto exit;
	}

	dtid = argv[optind];
	name = argv[optind + 1];

	if (!uid) {
		uid = get_current_user_id(token, ssl);
		if (!uid) {
			ret = false;
			goto exit;
		}
	}

	cloud = (artik_cloud_module *)artik_request_api_module("cloud");
	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		ret = false;
		goto exit;
	}

	err = cloud->add_device(token, uid, dtid, name, &response, ssl);
	if (!response && err != S_OK)
		fprintf(stderr, "Error: Failed to create device for <dtid %s> (err=%d)\n", dtid, err);

	if (response && !is_error(response, "Error: Failed to create device")) {
		char *device = NULL;
		char *did = NULL;

		device = parse_json_object(response, "data");
		if (device) {
			did = parse_json_object(device, "id");
			if (did) {
				fprintf(stdout, "Device <did %s> is created.\n", did);
				free(device);
				free(did);
			}
		}
	}

	if (response)
		free(response);

exit:
	if (cloud)
		artik_release_api_module(cloud);
	if (uid)
		free(uid);

	return ret;
}

static bool delete_device(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	char *did = NULL;
	artik_error ret = S_OK;
	char *response = NULL;
	artik_cloud_module *cloud;
	user_cmd_data_t *data = (user_cmd_data_t *)user_data;
	const char *token = data->token;

	if (argc < 2) {
		fprintf(stderr, "Error: 'device delete': <did> not found.\n");
		usage_user();
		return false;
	}
	did = argv[1];

	cloud = (artik_cloud_module *)artik_request_api_module("cloud");
	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		return false;
	}

	ret = cloud->delete_device(token, did, &response, ssl);
	artik_release_api_module(cloud);

	if (!response && ret != S_OK)
		fprintf(stderr, "Error: Failed to delete device <did %s> (err=%d)\n", did, ret);

	if (response && !is_error(response, "Error: Failed to delete device"))
		fprintf(stdout, "Device <did %s> is deleted.\n", did);

	if (response)
		free(response);

	return true;
}

static bool token_cmd(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	artik_error ret;
	char *response = NULL;
	char *did = NULL;
	user_cmd_data_t *data = (user_cmd_data_t *)user_data;
	const char *token = data->token;

	if (argc < 2) {
		fprintf(stderr, "Error: 'device token': '[get|create|delete]' not found\n");
		usage_user();
		return false;
	}

	if (argc < 3) {
		fprintf(stderr, "Error: 'device token': '<did>' not found\n");
		usage_user();
		return false;
	}

	did = argv[2];
	if (strcmp(argv[1], "get") == 0) {
		artik_cloud_module *cloud = (artik_cloud_module *)artik_request_api_module("cloud");

		if (!cloud) {
			fprintf(stderr, "Error: Failed to request cloud module\n");
			return false;
		}

		ret = cloud->get_device_token(token, did, &response, ssl);
		artik_release_api_module(cloud);

		if (!response && ret != S_OK)
			fprintf(stderr, "Error: Failed to get token for device <did %s> (err=%d)\n", did, ret);

		if (response && !is_error(response, "Error: Failed to get device token")) {
			char *data = NULL;
			char *dtoken = NULL;

			data = parse_json_object(response, "data");
			if (data) {
				dtoken = parse_json_object(data, "accessToken");
				if (dtoken) {
					fprintf(stdout, "Token for device <did %s> is %s\n", did, dtoken);
					free(data);
					free(dtoken);
				}
			}
		}

		if (response)
			free(response);
	} else if (strcmp(argv[1], "create") == 0) {
		artik_cloud_module *cloud = (artik_cloud_module *)artik_request_api_module("cloud");

		if (!cloud) {
			fprintf(stderr, "Error: Failed to request cloud module\n");
			return false;
		}

		ret = cloud->update_device_token(token, did, &response, ssl);
		artik_release_api_module(cloud);

		if (!response && ret != S_OK)
			fprintf(stderr, "Error: Failed to create token for device <did %s> (err=%d)\n", did, ret);

		if (response && !is_error(response, "Error: Failed to create device token")) {
			char *data = NULL;
			char *dtoken = NULL;

			data = parse_json_object(response, "data");
			if (data) {
				dtoken = parse_json_object(data, "accessToken");
				if (dtoken) {
					fprintf(stdout, "Token for device <did %s> is %s\n", did,  dtoken);
					free(data);
					free(dtoken);
				}
			}
		}

		if (response)
			free(response);

	} else if (strcmp(argv[1], "delete") == 0) {
		artik_cloud_module *cloud = (artik_cloud_module *)artik_request_api_module("cloud");

		if (!cloud) {
			fprintf(stderr, "Error: Failed to request cloud module\n");
			return false;
		}

		ret = cloud->delete_device_token(token, did, &response, ssl);
		artik_release_api_module(cloud);

		if (!response && ret != S_OK)
			fprintf(stderr, "Error: Failed to delete token for device <did %s> (err=%d)\n", did, ret);

		if (response && !is_error(response, "Error: Failed to delete device token"))
			fprintf(stdout, "Token for device <did %s> is deleted\n", did);

		if (response)
			free(response);

	} else {
		fprintf(stderr, "Error: 'device token': Unknow command '%s'\n", argv[1]);
		usage_user();
		return false;
	}

	return true;
}

static bool sub_device_cmd(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	command_t device_cmd[] = {
		{ "create", create_device },
		{ "delete", delete_device },
		{ "token", token_cmd },
		{ NULL, NULL }
	};

	if (!execute_cmd(ssl, user_data, device_cmd, argc, argv, "DEVICE COMMAND")) {
		usage_user();
		return false;
	}

	return true;
}

static bool user_cmd(artik_ssl_config *ssl, int argc, char **argv)
{

	int c;
	command_t user_cmd[] = {
		{ "profile", display_profile },
		{ "devices", get_user_devices },
		{ "device-types", get_device_types },
		{ "application-properties", get_application_properties },
		{ "device", sub_device_cmd },
		{ NULL, NULL }
	};

	optind = 1;
	while ((c = getopt(argc, argv, "+h")) != -1) {
		switch (c) {
		case 'h':
			usage_user();
			return false;
		case '?':
			fprintf(stderr, "Error: Unknow USER OPTION '-%c'\n", optopt);
			usage_user();
			return false;
		default:
			abort();
		}
	}

	if (optind == argc) {
		fprintf(stderr, "Error: '<token>' not found.\n");
		usage_user();
		return false;
	}

	user_cmd_data_t data = {
		.token = argv[optind]
	};

	if (!execute_cmd(ssl, &data, user_cmd, argc-optind, argv+optind, "USER COMMAND"))
		return false;

	return true;
}

static bool get_device(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	artik_error ret;
	int c;
	bool properties = true;
	char *response = NULL;
	device_cmd_data_t *data = (device_cmd_data_t *)user_data;
	const char *did = data->did;
	const char *dtoken = data->dtoken;
	artik_cloud_module *cloud = NULL;

	optind = 1;
	while ((c = getopt(argc, argv, "p")) != -1) {
		switch (c) {
		case 'p':
			properties = true;
			break;
		case '?':
			fprintf(stderr, "Error: 'device get': Unknow option '-%c'\n", optopt);
			usage_device();
			return false;
		default:
			abort();
		}
	}

	cloud = (artik_cloud_module *)artik_request_api_module("cloud");
	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		return false;
	}

	ret = cloud->get_device(dtoken, did, properties, &response, ssl);
	artik_release_api_module(cloud);

	if (!response && ret != S_OK)
		fprintf(stderr, "Error: Failed to get device <did %s> (err=%d)\n", did, ret);

	if (response && !is_error(response, "Error: Failed to get device"))
		fprintf(stdout, "Device <did %s>: %s\n", did, response);

	if (response)
		free(response);

	return true;
}

static bool send_message(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	artik_error ret;
	device_cmd_data_t *data = (device_cmd_data_t *)user_data;
	const char *did = data->did;
	const char *dtoken = data->dtoken;
	char *response;
	artik_cloud_module *cloud = NULL;
	const char *message = NULL;

	if (argc < 2) {
		fprintf(stderr, "Error: 'device message': Argument <message> not found\n");
		usage_device();
		return false;
	}

	message = argv[1];
	cloud = (artik_cloud_module *)artik_request_api_module("cloud");
	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		return false;
	}

	ret = cloud->send_message(dtoken, did, message, &response, ssl);
	artik_release_api_module(cloud);

	if (!response && ret != S_OK)
		fprintf(stderr, "Error: Failed to send message to the device <did %s> (err=%d)\n", did, ret);

	if (response && !is_error(response, "Error: Failed to send message"))
		fprintf(stdout, "Your message is sent to the device <did %s>\n", did);

	if (response)
		free(response);

	return true;
}

static bool send_action(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	device_cmd_data_t *data = (device_cmd_data_t *)user_data;
	char *response = NULL;
	artik_error ret;
	const char *did = data->did;
	const char *dtoken = data->dtoken;
	const char *action = NULL;
	artik_cloud_module *cloud = NULL;

	if (argc < 2) {
		fprintf(stderr, "Error: 'device action': Argument <action> not found\n");
		usage_device();
		return false;
	}

	action = argv[1];

	cloud = (artik_cloud_module *)artik_request_api_module("cloud");
	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		return false;
	}

	ret = cloud->send_action(dtoken, did, action, &response, ssl);
	if (!response && ret != S_OK)
		fprintf(stderr, "Error: Failed to send action to the device <did %s> (err=%d)\n", did, ret);

	if (response && !is_error(response, "Error: Failed to send action"))
		fprintf(stdout, "Your action is sent to the device <did %s>\n", did);

	if (response)
		free(response);

	return true;
}

static bool read_properties(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	int c;
	device_cmd_data_t *data = (device_cmd_data_t *)user_data;
	char *response = NULL;
	artik_error ret;
	const char *did = data->did;
	const char *dtoken = data->dtoken;
	bool timestamp = false;
	artik_cloud_module *cloud = NULL;

	optind = 1;
	while ((c = getopt(argc, argv, "t")) != -1) {
		switch (c) {
		case 't':
			timestamp = true;
			break;
		case '?':
			fprintf(stderr, "Error: 'device properties read': Unknow option '-%c'\n", optopt);
			usage_device();
			return false;
		default:
			abort();
		}
	}

	cloud = (artik_cloud_module *)artik_request_api_module("cloud");
	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		return false;
	}

	ret = cloud->get_device_properties(dtoken, did, timestamp, &response, ssl);
	if (!response && ret != S_OK)
		fprintf(stderr, "Error: Failed to read the device <did %s>'s properties (err=%d)\n", did, ret);

	if (response && !is_error(response, "Error: Failed to read device's properties"))
		fprintf(stdout, "The properties of device <did %s> are :%s\n", did, response);

	if (response)
		free(response);

	return true;
}

static bool set_property(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	device_cmd_data_t *data = (device_cmd_data_t *)user_data;
	char *response = NULL;
	char *properties;
	artik_error ret;
	const char *did = data->did;
	const char *dtoken = data->dtoken;
	artik_cloud_module *cloud = NULL;

	if (argc < 2) {
		fprintf(stderr, "Error: 'device properties set': Argument <properties> not found\n");
		usage_device();
		return false;
	}

	properties = argv[1];

	cloud = (artik_cloud_module *)artik_request_api_module("cloud");
	if (!cloud) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		return false;
	}

	ret = cloud->set_device_server_properties(dtoken, did, properties, &response, ssl);
	if (!response && ret != S_OK)
		fprintf(stderr, "Error: Failed to set device's properties (err=%d)\n", ret);


	if (response && !is_error(response, "Error: Failed to set device's properties"))
		fprintf(stdout, "The properties of device <did %s> is set\n", did);

	if (response)
		free(response);

	return true;
}

static bool properties_cmd(artik_ssl_config *ssl, int argc, char **argv, void *user_data)
{
	command_t props_cmd[] = {
		{ "read", read_properties },
		{ "set",  set_property},
		{ NULL, NULL }
	};

	if (!execute_cmd(ssl, user_data, props_cmd, argc, argv, "")) {
		usage_device();
		return false;
	}

	return true;
}

static bool device_cmd(artik_ssl_config *ssl, int argc, char **argv)
{
	command_t device_cmd[] = {
		{ "get", get_device },
		{ "message", send_message },
		{ "action", send_action },
		{ "properties", properties_cmd },
		{ NULL, NULL }
	};
	int c;

	optind = 1;
	while ((c = getopt(argc, argv, "+h")) != -1) {
		switch (c) {
		case 'h':
			usage_user();
			return false;
		case '?':
			fprintf(stderr, "Error: Unknow USER OPTION '-%c'\n", optopt);
			usage_device();
			return false;
		default:
			abort();
		}
	}

	if (optind == argc) {
		fprintf(stderr, "Error: '<did>' not found\n");
		usage_device();
		return false;
	}

	if (optind + 1 == argc) {
		fprintf(stderr, "Error: '<dtoken>' not found\n");
		usage_device();
		return false;
	}

	device_cmd_data_t data = {
		.did = argv[optind],
		.dtoken = argv[optind + 1]
	};

	if (!execute_cmd(ssl, &data, device_cmd, argc - optind - 1, argv + optind + 1, "DEVICE COMMAND")) {
		usage_device();
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	int c;
	bool verify = true;
	artik_ssl_config ssl;
	bool use_se = false;
	char *dev_cert = NULL;
	char *dev_key = NULL;
	char *cert_id = NULL;
	bool res = false;

	memset(&ssl, 0, sizeof(artik_ssl_config));

	while ((c = getopt(argc, argv, "+khs:d:")) != -1) {
		switch (c) {
		case 's':
			if (optarg) {
				use_se = true;
				cert_id = optarg;
			}
			break;
		case 'd':
			if (!parse_device_cert_opt(optarg, &dev_cert, &dev_key))
				goto exit;
			break;
		case 'k':
			verify = false;
			break;
		case 'h':
			usage();
			goto exit;
		case '?':
			if (optopt == 's') {
				use_se = true;
				break;
			}

			if (optopt == 'd')
				fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
			else
				fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);

			usage();
			goto exit;
		default:
			abort();
			break;
		}
	}

	if (dev_cert && use_se) {
		fprintf(stderr, "Error: Option '-s' and '-d' conflict");
		goto exit;
	}

	if (use_se) {
		ssl.se_config = malloc(sizeof(artik_secure_element_config));
		ssl.se_config->key_id = cert_id;
		ssl.se_config->key_algo = ECC_SEC_P256R1;
	}

	if (dev_cert) {
		ssl.client_cert.len = strlen(dev_cert);
		ssl.client_cert.data = dev_cert;
	}

	if (dev_key) {
		ssl.client_key.len = strlen(dev_key);
		ssl.client_key.data = dev_key;
	}

	if (verify)
		ssl.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;

	ssl.ca_cert.len = sizeof(akc_root_ca);
	ssl.ca_cert.data = (char *)akc_root_ca;

	if (optind == argc) {
		fprintf(stderr, "Error: COMMAND not found\n");
		usage();
		goto exit;
	}

	if (strcmp(argv[optind], "user") == 0) {
		res = user_cmd(&ssl, argc - optind, argv + optind);
	} else if (strcmp(argv[optind], "device") == 0) {
		res = device_cmd(&ssl, argc - optind, argv + optind);
	} else {
		fprintf(stderr, "Error: Unknow command '%s'\n", argv[optind]);
		usage();
		goto exit;
	}

exit:
	if (ssl.se_config)
		free(ssl.se_config);

	if (dev_cert)
		free(dev_cert);

	if (dev_key)
		free(dev_key);

	return res ? 0 : 1;
}
