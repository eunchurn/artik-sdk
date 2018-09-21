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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <artik_module.h>
#include <artik_loop.h>
#include <artik_coap.h>

#define MAX_SIZE 63
#define ADD_SPACES(x)				\
	do {					\
		fprintf(stdout, "\n");		\
		fprintf(stdout, "%*s", x, "");	\
	} while (0)

static bool started;
static bool connected;

static artik_coap_handle g_handle;
static artik_coap_handle f_handle;

static artik_coap_config g_config;

typedef struct {
	char data[256];
	int data_len;
} dataResource;

typedef struct {
	dataResource *dataRes;
	artik_coap_handle handle;
} serverInterface;

dataResource dataRes = {
	"Hello World",
	12
};

serverInterface interface;

static const char client_cert[] =
	"-----BEGIN CERTIFICATE-----\r\n"
	"MIIB4TCCAYegAwIBAgIJAJvNMfZLercmMAoGCCqGSM49BAMCME0xCzAJBgNVBAYT\r\n"
	"AkZSMQwwCgYDVQQIDANJZEYxDjAMBgNVBAcMBVBhcmlzMRAwDgYDVQQKDAdTYW1z\r\n"
	"dW5nMQ4wDAYDVQQLDAVBcnRpazAeFw0xODA0MjMxNTM0MjVaFw0xOTA0MjMxNTM0\r\n"
	"MjVaME0xCzAJBgNVBAYTAkZSMQwwCgYDVQQIDANJZEYxDjAMBgNVBAcMBVBhcmlz\r\n"
	"MRAwDgYDVQQKDAdTYW1zdW5nMQ4wDAYDVQQLDAVBcnRpazBZMBMGByqGSM49AgEG\r\n"
	"CCqGSM49AwEHA0IABKXl5NswY/mFN+kOslUjIJCMLMleTxu6cOZmphceJhtn+9a7\r\n"
	"0kukS38y3JivmUYQ1sD6lghw5pxUJlL4GIbczZmjUDBOMB0GA1UdDgQWBBTg5euL\r\n"
	"zcnBcY1SHoT+bq9lkOnPqDAfBgNVHSMEGDAWgBTg5euLzcnBcY1SHoT+bq9lkOnP\r\n"
	"qDAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIE0Y8P1HpQ05RmnLqW5+\r\n"
	"qVpvTzbQiQZALLvrPQLcwlSDAiEAiLYz3WTQeGjYmT/7F+c3vwWQp5XWjR8JGNjL\r\n"
	"oC39p5Q=\r\n"
	"-----END CERTIFICATE-----\n";

static const char client_key[] =
	"-----BEGIN EC PARAMETERS-----\r\n"
	"BggqhkjOPQMBBw==\r\n"
	"-----END EC PARAMETERS-----\r\n"
	"-----BEGIN EC PRIVATE KEY-----\r\n"
	"MHcCAQEEIIo1HWeuNp2tfYlrvEZo70rXvUJblFhkx0bizV/NLkieoAoGCCqGSM49\r\n"
	"AwEHoUQDQgAEpeXk2zBj+YU36Q6yVSMgkIwsyV5PG7pw5mamFx4mG2f71rvSS6RL\r\n"
	"fzLcmK+ZRhDWwPqWCHDmnFQmUvgYhtzNmQ==\r\n"
	"-----END EC PRIVATE KEY-----\n";

static int count_digits(unsigned int number)
{
	int count = 0;

	while (number != 0) {
		number /= 10;
		++count;
	}

	return count;
}

static void response_callback(const artik_coap_msg *msg,
			artik_coap_error error,
			void *user_data)
{
	int i;

	if (msg == NULL || error != ARTIK_COAP_ERROR_NONE) {
		fprintf(stderr, "Fail to receive message\n");
		if (error != ARTIK_COAP_ERROR_RST)
			connected = false;
		return;
	}

	fprintf(stdout, "==[ CoAP Response ]============================================\n");
	fprintf(stdout, "MID    : %d\n", msg->msg_id);
	fprintf(stdout, "Token  : ");

	if (msg->token && msg->token_len > 0) {
		for (i = 0; i < msg->token_len; i++)
			fprintf(stdout, "%02x", msg->token[i]);
	}
	fprintf(stdout, "\n");
	fprintf(stdout, "Type   : ");

	switch (msg->msg_type) {
	case ARTIK_COAP_MSG_CON:
		fprintf(stdout, "CON\n");
		break;
	case ARTIK_COAP_MSG_NON:
		fprintf(stdout, "NON\n");
		break;
	case ARTIK_COAP_MSG_ACK:
		fprintf(stdout, "ACK\n");
		break;
	case ARTIK_COAP_MSG_RST:
		fprintf(stdout, "RST\n");
		break;
	default:
		break;
	}

	fprintf(stdout, "Status : %u.%02u\n", msg->code >> 5, msg->code & 0x1f);

	if (msg->options && msg->num_options > 0) {
		int c = 0;

		fprintf(stdout, "Options: ");
		fprintf(stdout, "{");

		c = 10;
		for (i = 0; i < msg->num_options; i++) {
			switch (msg->options[i].key) {
			case ARTIK_COAP_OPTION_IF_MATCH: {
				int j;

				if (c + 11 + msg->options[i].data_len < MAX_SIZE)
					c += 11 + msg->options[i].data_len;
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"If-Match\":");

				for (j = 0; j < msg->options[i].data_len; j++)
					fprintf(stdout, "%02x", msg->options[i].data[j]);

				break;
			}
			case ARTIK_COAP_OPTION_URI_HOST:
				if (c + 11 + msg->options[i].data_len < MAX_SIZE)
					c += 11 + msg->options[i].data_len;
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Uri-Host\":%s",
					msg->options[i].data);

				break;
			case ARTIK_COAP_OPTION_ETAG: {
				int j;

				if (c + 7 + msg->options[i].data_len < MAX_SIZE)
					c += 7 + msg->options[i].data_len;
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Etag\":");

				for (j = 0; j < msg->options[i].data_len; j++)
					fprintf(stdout, "%02x", msg->options[i].data[j]);

				break;
			}
			case ARTIK_COAP_OPTION_IF_NONE_MATCH:
				if (c + 15 < MAX_SIZE)
					c += 15;
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"If-None-Match\"");

				break;
			case ARTIK_COAP_OPTION_OBSERVE: {
				unsigned int obs = 0;

				memcpy(&obs, msg->options[i].data,
					msg->options[i].data_len);

				if (c + 10 + count_digits(obs) < MAX_SIZE)
					c += 10 + count_digits(obs);
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Observe\":%d",
					obs);

				break;
			}
			case ARTIK_COAP_OPTION_URI_PORT: {
				unsigned int uri_port = 0;

				memcpy(&uri_port, msg->options[i].data,
					msg->options[i].data_len);

				if (c + 11 + count_digits(uri_port) < MAX_SIZE)
					c += 11 + count_digits(uri_port);
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Uri-Port\":%d",
					uri_port);

				break;
			}
			case ARTIK_COAP_OPTION_LOCATION_PATH:
				if (c + 16 + msg->options[i].data_len < MAX_SIZE)
					c += 16 + msg->options[i].data_len;
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Location-Path\":%s",
					msg->options[i].data);

				break;
			case ARTIK_COAP_OPTION_URI_PATH:
				if (c + 11 + msg->options[i].data_len < MAX_SIZE)
					c += 11 + msg->options[i].data_len;
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Uri-Path\":%s",
					msg->options[i].data);

				break;
			case ARTIK_COAP_OPTION_CONTENT_FORMAT: {
				unsigned int content_format = 0;

				memcpy(&content_format, msg->options[i].data,
					msg->options[i].data_len);

				if (c + 17 + count_digits(content_format) < MAX_SIZE)
					c += 17 + count_digits(content_format);
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Content-Format\":%d",
					content_format);

				break;
			}
			case ARTIK_COAP_OPTION_MAXAGE: {
				unsigned int max_age = 0;

				memcpy(&max_age, msg->options[i].data,
					msg->options[i].data_len);

				if (c + 17 + count_digits(max_age) < MAX_SIZE)
					c += 17 + count_digits(max_age);
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Max-Age\":%d",
					max_age);

				break;
			}
			case ARTIK_COAP_OPTION_URI_QUERY:
				if (c + 12 + msg->options[i].data_len < MAX_SIZE)
					c += 12 + msg->options[i].data_len;
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Uri-Query\":%s",
					msg->options[i].data);
				break;
			case ARTIK_COAP_OPTION_ACCEPT: {
				unsigned int accept = 0;

				memcpy(&accept, msg->options[i].data,
					msg->options[i].data_len);

				if (c + 9 + count_digits(accept) < MAX_SIZE)
					c += 9 + count_digits(accept);
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Accept\":%d",
					accept);
				break;
			}
			case ARTIK_COAP_OPTION_LOCATION_QUERY:
				if (c + 17 + msg->options[i].data_len < MAX_SIZE)
					c += 17 + msg->options[i].data_len;
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Location-Query\":%s",
					msg->options[i].data);
				break;
			case ARTIK_COAP_OPTION_BLOCK2: {
				uint32_t block2 = 0;
				uint16_t szx;
				uint32_t num;
				uint8_t more;
				uint16_t size;

				memcpy(&block2, msg->options[i].data,
					msg->options[i].data_len);

				szx = block2 & 0x07;
				szx += 4;

				num = block2/16;

				more = block2 & 0x08;
				more >>= 3;

				size = 1 << (uint16_t)szx;

				if (c + 9 + count_digits(num) + 1
						+ count_digits(more) + 1
						+ count_digits(size) < MAX_SIZE)
					c += 9 + count_digits(num) + 1
						+ count_digits(more) + 1
						+ count_digits(size);
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Block2\":%d/%d/%d",
					num, more, size);
				break;
			}
			case ARTIK_COAP_OPTION_PROXY_URI:
				if (c + 12 + msg->options[i].data_len < MAX_SIZE)
					c += 12 + msg->options[i].data_len;
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Proxy-Uri\":%s",
					msg->options[i].data);
				break;
			case ARTIK_COAP_OPTION_PROXY_SCHEME:
				if (c + 15 + msg->options[i].data_len < MAX_SIZE)
					c += 15 + msg->options[i].data_len;
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Proxy-Scheme\":%s",
					msg->options[i].data);
				break;
			case ARTIK_COAP_OPTION_SIZE1: {
				unsigned int size1 = 0;

				memcpy(&size1, msg->options[i].data,
					msg->options[i].data_len);

				if (c + 8 + count_digits(size1) < MAX_SIZE)
					c += 8 + count_digits(size1);
				else {
					c = 9;
					ADD_SPACES(c);
				}

				fprintf(stdout, "\"Size1\":%d",
					size1);
				break;
			}
			default:
				break;
			}
			if (i + 1 != msg->num_options)
				fprintf(stdout, ", ");
		}
		fprintf(stdout, "}\n");
	}

	fprintf(stdout, "Payload: %d Bytes\n", msg->data_len);

	if (msg->data && msg->data_len > 0) {
		fprintf(stdout, "---------------------------------------------------------------\n");
		fprintf(stdout, "%s\n", msg->data);
	}

	fprintf(stdout, "===============================================================\n");
}

static void get_test_callback(const artik_coap_msg *request,
				artik_coap_msg *response,
				void *user_data)
{
	serverInterface *iface = (serverInterface *)user_data;
	dataResource *data = iface->dataRes;
	unsigned int content_format = ARTIK_OPTION_CONTENT_FORMAT_PLAIN;

	response->code = ARTIK_COAP_RES_CONTENT;

	if (data->data_len > 0) {
		response->data = (unsigned char *)malloc(data->data_len);

		if (!response->data) {
			fprintf(stderr, "Memory problem for data\n");
			return;
		}

		memcpy(response->data, data->data, data->data_len);
		response->data_len = data->data_len - 1;
	}


	response->options = (artik_coap_option *)malloc(2*sizeof(artik_coap_option));

	if (!response->options) {
		fprintf(stderr, "Memory problem for options\n");
		return;
	}

	response->options[0].key = ARTIK_COAP_OPTION_CONTENT_FORMAT;
	response->options[0].data = (unsigned char *)malloc(1);

	if (!response->options[0].data) {
		fprintf(stderr, "Memory problem data option\n");
		return;
	}

	response->options[0].data_len = 1;

	memcpy(response->options[0].data, &content_format, response->options[0].data_len);

	response->num_options = 1;
}

static void post_test_callback(const artik_coap_msg *request,
				artik_coap_msg *response,
				void *user_data)
{
	serverInterface *iface = (serverInterface *)user_data;
	dataResource *data = iface->dataRes;
	artik_coap_handle *handle = iface->handle;

	artik_coap_module *coap = (artik_coap_module *)
					artik_request_api_module("coap");
	if (!coap) {
		fprintf(stderr, "CoAP module is not available\n");
		return;
	}

	if (request->data_len > 256) {
		response->code = ARTIK_COAP_RES_UNAUTHORIZED;
		response->data = (unsigned char *)malloc(34);

		if (!response->data) {
			fprintf(stderr, "Memory problem data response\n");
			return;
		}

		memcpy(response->data, "The length must be inferior to 256",
			34);
		response->data_len = 34;
		return;
	}

	if (data->data_len > 0) {
		response->code = ARTIK_COAP_RES_CHANGED;
		memcpy(data->data, request->data, request->data_len);
		data->data_len = request->data_len;
		if (coap->notify_resource_changed(handle, "test") != S_OK) {
			fprintf(stderr, "Fail to set the resource 'test' dirty\n");
			return;
		}
	} else {
		response->code = ARTIK_COAP_RES_CREATED;
		memcpy(data->data, request->data, request->data_len);
		data->data_len = request->data_len;
		if (coap->notify_resource_changed(handle, "test") != S_OK) {
			fprintf(stderr, "Fail to set the resource 'test' dirty\n");
			return;
		}
	}

	artik_release_api_module(coap);
}

static void put_test_callback(const artik_coap_msg *request,
				artik_coap_msg *response,
				void *user_data)
{
	serverInterface *iface = (serverInterface *)user_data;
	dataResource *data = iface->dataRes;
	artik_coap_handle *handle = iface->handle;

	artik_coap_module *coap = (artik_coap_module *)
					artik_request_api_module("coap");
	if (!coap) {
		fprintf(stderr, "CoAP module is not available\n");
		return;
	}

	if (request->data_len > 256) {
		response->code = ARTIK_COAP_RES_UNAUTHORIZED;
		response->data = (unsigned char *)malloc(34);
		memcpy(response->data, "The length must be inferior to 256",
			34);
		response->data_len = 34;
		return;
	}

	if (data->data_len > 0) {
		response->code = ARTIK_COAP_RES_CHANGED;
		memcpy(data->data, request->data, request->data_len);
		data->data_len = request->data_len;
		if (coap->notify_resource_changed(handle, "test") != S_OK) {
			fprintf(stderr, "Fail to set the resource 'test' dirty\n");
			return;
		}
	} else {
		response->code = ARTIK_COAP_RES_UNAUTHORIZED;
		response->data = (unsigned char *)malloc(44);

		if (!response->data) {
			fprintf(stderr, "Memory problem data response\n");
			return;
		}

		memcpy(response->data, "The resource is not created (do POST before)",
			44);
		response->data_len = 44;
	}

	artik_release_api_module(coap);
}

static void delete_test_callback(const artik_coap_msg *request,
					artik_coap_msg *response,
					void *user_data)
{
	serverInterface *iface = (serverInterface *)user_data;
	dataResource *data = iface->dataRes;
	artik_coap_handle *handle = iface->handle;

	artik_coap_module *coap = (artik_coap_module *)
					artik_request_api_module("coap");
	if (!coap) {
		fprintf(stderr, "CoAP module is not available\n");
		return;
	}

	response->code = ARTIK_COAP_RES_DELETED;

	memset(data, 0, sizeof(dataResource));

	if (coap->notify_resource_changed(handle, "test") != S_OK) {
		fprintf(stderr, "Fail to set the resource 'test' dirty\n");
		return;
	}

	artik_release_api_module(coap);
}

static void get_info_callback(const artik_coap_msg *request,
				artik_coap_msg *response,
				void *user_data)
{
	char info[35] = "Welcome from Artik CoAP Server Test";

	response->code = ARTIK_COAP_RES_CONTENT;

	response->data = (unsigned char *)malloc(35);

	if (!response->data) {
		fprintf(stderr, "Memory problem data response\n");
		return;
	}

	memcpy(response->data, info, 35);
	response->data_len = 35;

	response->options = (artik_coap_option *)malloc(1*sizeof(artik_coap_option));

	unsigned int content_format = ARTIK_OPTION_CONTENT_FORMAT_PLAIN;

	response->options[0].key = ARTIK_COAP_OPTION_CONTENT_FORMAT;
	response->options[0].data = (unsigned char *)malloc(1);
	memcpy(response->options[0].data, &content_format, 1);
	response->options[0].data_len = 1;

	response->num_options = 1;
}

#define MAX_PACKET_SIZE 1024

typedef void (*interactive_command_callback_t)(int argc, char **argv, artik_coap_module *coap);

typedef struct {
	const char *cmd;
	interactive_command_callback_t callback;
} interactive_command_t;

void usage(void)
{
	printf("Usage:\n");
	printf(" coap-example [options]\n");
	printf("Options:\n");
	printf("  -h                                                 Display this help and exit\n");
	printf("\n");
}

static void interactive_shell_usage(void)
{
	printf("  connect <uri> <psk/ecdsa> <identity> <psk>\t\t\t\t Connect to a CoAP server.\n");
	printf("  disconnect\t\t\t\t\t\t\t\t Disconnect from server.\n");
	printf("  request <GET/POST/PUT/DELETE/OBSERVE/STOP> <resource> <payload>\t Send a request to server.\n");
	printf("  start <psk/ecdsa>\t\t\t\t\t\t\t Start server.\n");
	printf("  stop\t\t\t\t\t\t\t\t\t Stop server.\n");
	printf("  exit\t\t\t\t\t\t\t\t\t Quit the program.\n");
	printf("  help\t\t\t\t\t\t\t\t\t Display the shell command usage.\n");
}

static void help_command(int argc, char **argv, artik_coap_module *coap)
{
	interactive_shell_usage();
}

static void connect_command(int argc, char **argv, artik_coap_module *coap)
{
	artik_error ret = S_OK;

	if (argc < 2) {
		fprintf(stderr, "Missing uri parameter\n");
		interactive_shell_usage();
		return;
	}

	if (connected) {
		fprintf(stderr, "Client already connected\n");
		return;
	}

	memset(&g_config, 0, sizeof(artik_coap_config));

	g_config.uri = argv[1];

	if (argc > 2 && !strcmp(argv[2], "psk")) {
		g_config.psk = malloc(sizeof(artik_coap_psk_param));

		if (!g_config.psk) {
			fprintf(stderr, "Memory problem\n");
			goto exit;
		}

		memset(g_config.psk, 0, sizeof(artik_coap_psk_param));

		if (argc > 3) {
			g_config.psk->identity = strdup(argv[3]);

			if (!g_config.psk->identity) {
				fprintf(stderr, "Memory problem\n");
				goto exit;
			}
		}

		if (argc > 4) {
			g_config.psk->psk = strdup(argv[4]);

			if (!g_config.psk->psk) {
				fprintf(stderr, "Memory problem\n");
				goto exit;
			}

			g_config.psk->psk_len = strlen(argv[4]);
		}
	} else if (argc > 2 && !strcmp(argv[2], "ecdsa")) {
		g_config.ssl = (artik_ssl_config *)malloc(sizeof(artik_ssl_config));

		if (!g_config.ssl) {
			fprintf(stderr, "Memory problem\n");
			goto exit;
		}

		memset(g_config.ssl, 0, sizeof(artik_ssl_config));

		g_config.ssl->client_cert.data = (char *)client_cert;
		g_config.ssl->client_cert.len = strlen(client_cert) + 1;

		g_config.ssl->client_key.data = (char *)client_key;
		g_config.ssl->client_key.len = strlen(client_key) + 1;
	} else if (argc > 2 && strcmp(argv[2], "psk") && strcmp(argv[2], "ecdsa")) {
		fprintf(stderr, "psk or ecdsa parameter only\n");
		ret = -1;
		goto exit;
	}

	ret = coap->create_client(&g_handle, &g_config);
	if (ret != S_OK) {
		fprintf(stderr, "Failed to create client\n");
		ret = -1;
		goto exit;
	}

	ret = coap->set_send_callback(g_handle, response_callback, NULL);
	if (ret != S_OK) {
		fprintf(stderr, "Fail to set send callback\n");
		ret = -1;
		goto exit;
	}

	ret = coap->connect(g_handle);
	if (ret != S_OK) {
		fprintf(stderr, "Failed to connect\n");
		coap->disconnect(g_handle);
		coap->destroy_client(g_handle);
		g_handle = NULL;
		ret = -1;
		goto exit;
	}

	connected = true;

exit:
	if (g_config.ssl)
		free(g_config.ssl);
	if (g_config.psk && g_config.psk->identity)
		free((void *)g_config.psk->identity);
	if (g_config.psk && g_config.psk->psk)
		free((void *)g_config.psk->psk);
	if (g_config.psk)
		free(g_config.psk);
}

static void disconnect_command(int argc, char **argv, artik_coap_module *coap)
{
	artik_error ret = S_OK;

	if (!g_handle) {
		fprintf(stderr, "Client not connected\n");
		return;
	}

	ret = coap->disconnect(g_handle);
	if (ret != S_OK) {
		fprintf(stderr, "Fail to disconnect\n");
		return;
	}

	ret = coap->destroy_client(g_handle);
	if (ret != S_OK) {
		fprintf(stderr, "Fail to destroy client\n");
		return;
	}

	g_handle = NULL;
	connected = false;
}

static void request_command(int argc, char **argv, artik_coap_module *coap)
{
	artik_error ret = S_OK;
	artik_coap_msg msg;
	bool observe = false;
	bool stop = false;

	if (argc < 3) {
		fprintf(stderr, "Missing parameters\n");
		interactive_shell_usage();
		return;
	}

	if (!g_handle) {
		fprintf(stderr, "Client not connected\n");
		return;
	}

	memset(&msg, 0, sizeof(artik_coap_msg));

	if (!strcmp(argv[1], "GET"))
		msg.code = ARTIK_COAP_REQ_GET;
	else if (!strcmp(argv[1], "POST"))
		msg.code = ARTIK_COAP_REQ_POST;
	else if (!strcmp(argv[1], "PUT"))
		msg.code = ARTIK_COAP_REQ_PUT;
	else if (!strcmp(argv[1], "DELETE"))
		msg.code = ARTIK_COAP_REQ_DELETE;
	else if (!strcmp(argv[1], "OBSERVE"))
		observe = true;
	else if (!strcmp(argv[1], "STOP"))
		stop = true;
	else {
		fprintf(stderr, "Unknown method (GET/POST/PUT/DELETE/OBSERVE/STOP accepted)\n");
		ret = -1;
		goto exit;
	}

	ret = coap->set_send_callback(g_handle, NULL, NULL);
	if (ret != S_OK) {
		fprintf(stderr, "Fail to unset send callback\n");
		ret = -1;
		goto exit;
	}

	if (observe) {
		ret = coap->set_observe_callback(g_handle, response_callback, NULL);
		if (ret != S_OK) {
			fprintf(stderr, "Fail to set observe callback\n");
			ret = -1;
			goto exit;
		}
	} else {
		ret = coap->set_send_callback(g_handle, response_callback, NULL);
		if (ret != S_OK) {
			fprintf(stderr, "Fail to set send callback\n");
			ret = -1;
			goto exit;
		}
	}

	if (argc == 4 && argv[3]) {
		msg.data = (unsigned char *)argv[3];
		msg.data_len = strlen(argv[3]);
	}

	msg.options = malloc(1*sizeof(artik_coap_option));

	if (!msg.options) {
		fprintf(stderr, "Memory problem\n");
		ret = -1;
		goto exit;
	}

	memset(msg.options, 0, 1*sizeof(artik_coap_option));

	msg.options[0].key = ARTIK_COAP_OPTION_CONTENT_FORMAT;
	msg.options[0].data = malloc(1);

	if (!msg.options[0].data) {
		fprintf(stderr, "Memory problem\n");
		ret = -1;
		goto exit;
	}

	msg.options[0].data[0] = 0;
	msg.options[0].data_len = 1;

	msg.num_options = 1;

	if (observe) {
		ret = coap->observe(g_handle, argv[2], ARTIK_COAP_MSG_CON,
			msg.options, msg.num_options, msg.token, msg.token_len);
		if (ret != S_OK) {
			fprintf(stderr, "Fail to observe\n");
			ret = -1;
			goto exit;
		}
	} else if (!stop) {
		ret = coap->send_message(g_handle, argv[2], &msg);
		if (ret != S_OK) {
			fprintf(stderr, "Failed to send message\n");
			ret = -1;
			goto exit;
		}
	} else {
		ret = coap->cancel_observe(g_handle, argv[2],
			msg.token, msg.token_len);
		if (ret != S_OK) {
			fprintf(stderr, "Failed to cancel observe\n");
			ret = -1;
			goto exit;
		}
		ret = coap->set_observe_callback(g_handle, NULL, NULL);
		if (ret != S_OK) {
			fprintf(stderr, "Fail to unset observe callback\n");
			ret = -1;
		}
	}

exit:
	if (msg.options && msg.options[0].data) {
		free(msg.options[0].data);
		msg.options[0].data = NULL;
	}
	if (msg.options) {
		free(msg.options);
		msg.options = NULL;
	}
}

static void start_command(int argc, char **argv, artik_coap_module *coap)
{
	artik_error ret = S_OK;
	artik_coap_resource resources[2];
	int num_resources;

	if (started) {
		fprintf(stderr, "The server is already started\n");
		return;
	}

	memset(&g_config, 0, sizeof(artik_coap_config));
	memset(resources, 0, 2*sizeof(artik_coap_resource));

	if (argc > 1 && !strcmp(argv[1], "psk")) {
		g_config.psk = malloc(sizeof(artik_coap_psk_param));

		if (!g_config.psk) {
			fprintf(stderr, "Memory problem\n");
			ret = -1;
			goto exit;
		}

		memset(g_config.psk, 0, sizeof(artik_coap_psk_param));

		if (argc > 2) {
			g_config.psk->identity = strdup(argv[2]);

			if (!g_config.psk->identity) {
				fprintf(stderr, "Memory problem\n");
				ret = -1;
				goto exit;
			}
		} else {
			fprintf(stderr, "Identity required\n");
			ret = -1;
			goto exit;
		}

		if (argc > 3) {
			g_config.psk->psk = strdup(argv[3]);

			if (!g_config.psk->psk) {
				fprintf(stderr, "Memory problem\n");
				ret = -1;
				goto exit;
			}

			g_config.psk->psk_len = strlen(argv[3]);
		} else {
			fprintf(stderr, "PSK required\n");
			ret = -1;
			goto exit;
		}
	} else if (argc > 1 && !strcmp(argv[1], "ecdsa")) {
		g_config.ssl = (artik_ssl_config *)malloc(sizeof(artik_ssl_config));

		if (!g_config.ssl) {
			fprintf(stderr, "Memory problem\n");
			ret = -1;
			goto exit;
		}

		memset(g_config.ssl, 0, sizeof(artik_ssl_config));

		g_config.ssl->client_cert.data = (char *)client_cert;
		g_config.ssl->client_cert.len = strlen(client_cert) + 1;

		g_config.ssl->client_key.data = (char *)client_key;
		g_config.ssl->client_key.len = strlen(client_key) + 1;
	} else if (argc > 1 && strcmp(argv[1], "psk") && strcmp(argv[1], "ecdsa")) {
		fprintf(stderr, "psk or ecdsa parameter only\n");
		ret = -1;
		goto exit;
	}

	ret = coap->create_server(&f_handle, &g_config);
	if (ret != S_OK) {
		fprintf(stderr, "Fail to create server\n");
		f_handle = NULL;
		ret = -1;
		goto exit;
	}

	interface.dataRes = &dataRes;
	interface.handle = f_handle;

	resources[0].path = "info";
	resources[0].path_len = 4;
	resources[0].default_notification_type = ARTIK_COAP_RESOURCE_NOTIFY_CON;
	resources[0].attributes = (artik_coap_attr *)malloc(2*sizeof(artik_coap_attr));

	if (!resources[0].attributes) {
		fprintf(stderr, "Memory problem\n");
		f_handle = NULL;
		ret = -1;
		goto exit;
	}

	memset(resources[0].attributes, 0, 2*sizeof(artik_coap_attr));

	resources[0].attributes[0].name = (unsigned char *)"ct";
	resources[0].attributes[0].name_len = 2;
	resources[0].attributes[0].val = (unsigned char *)"0";
	resources[0].attributes[0].val_len = 1;

	resources[0].attributes[1].name = (unsigned char *)"title";
	resources[0].attributes[1].name_len = 5;
	resources[0].attributes[1].val = (unsigned char *)"\"General Info\"";
	resources[0].attributes[1].val_len = 14;

	resources[0].resource_cb[0] = get_info_callback;
	resources[0].resource_data[0] = NULL;

	resources[0].num_attributes = 2;

	resources[1].path = "test";
	resources[1].path_len = 4;
	resources[1].default_notification_type = ARTIK_COAP_RESOURCE_NOTIFY_CON;
	resources[1].attributes = (artik_coap_attr *)malloc(4*sizeof(artik_coap_attr));

	if (!resources[1].attributes) {
		fprintf(stderr, "Memory problem\n");
		f_handle = NULL;
		ret = -1;
		goto exit;
	}

	memset(resources[1].attributes, 0, 4*sizeof(artik_coap_attr));

	resources[1].attributes[0].name = (unsigned char *)"ct";
	resources[1].attributes[0].name_len = 2;
	resources[1].attributes[0].val = (unsigned char *)"0";
	resources[1].attributes[0].val_len = 1;

	resources[1].attributes[1].name = (unsigned char *)"title";
	resources[1].attributes[1].name_len = 5;
	resources[1].attributes[1].val = (unsigned char *)"\"Internal Buffer\"";
	resources[1].attributes[1].val_len = 17;

	resources[1].attributes[2].name = (unsigned char *)"rt";
	resources[1].attributes[2].name_len = 2;
	resources[1].attributes[2].val = (unsigned char *)"\"Data\"";
	resources[1].attributes[2].val_len = 6;

	resources[1].attributes[3].name = (unsigned char *)"if";
	resources[1].attributes[3].name_len = 2;
	resources[1].attributes[3].val = (unsigned char *)"\"buffer\"";
	resources[1].attributes[3].val_len = 8;

	resources[1].num_attributes = 4;

	resources[1].resource_cb[0] = get_test_callback;
	resources[1].resource_data[0] = (void *)&interface;

	resources[1].resource_cb[1] = post_test_callback;
	resources[1].resource_data[1] = (void *)&interface;

	resources[1].resource_cb[2] = put_test_callback;
	resources[1].resource_data[2] = (void *)&interface;

	resources[1].resource_cb[3] = delete_test_callback;
	resources[1].resource_data[3] = (void *)&interface;

	resources[1].observable = true;

	num_resources = 2;

	ret = coap->init_resources(f_handle, resources, num_resources);
	if (ret != S_OK) {
		fprintf(stderr, "Fail to init resources\n");
		ret = -1;
		goto exit;
	}

	ret = coap->start_server(f_handle);
	if (ret != S_OK) {
		fprintf(stderr, "Fail to start server\n");
		ret = -1;
	}

	started = 1;

exit:
	if (resources[0].attributes)
		free(resources[0].attributes);
	if (resources[1].attributes)
		free(resources[1].attributes);
	if (g_config.psk && g_config.psk->identity)
		free((void *)g_config.psk->identity);
	if (g_config.psk && g_config.psk->psk)
		free((void *)g_config.psk->psk);
	if (g_config.psk)
		free(g_config.psk);
	if (g_config.ssl)
		free(g_config.ssl);
}

static void stop_command(int argc, char **argv, artik_coap_module *coap)
{
	artik_error ret = S_OK;

	if (!started) {
		fprintf(stderr, "The server is not started\n");
		return;
	}

	ret = coap->stop_server(f_handle);
	if (ret != S_OK) {
		fprintf(stderr, "Fail to stop server\n");
		ret = -1;
		return;
	}

	ret = coap->destroy_server(f_handle);
	if (ret != S_OK) {
		fprintf(stderr, "Fail to destroy server\n");
		return;
	}

	f_handle = NULL;

	started = false;
}

static void quit_command(int argc, char **argv, artik_coap_module *coap)
{
	artik_loop_module *loop = (artik_loop_module *) artik_request_api_module("loop");

	printf("\rQuit CoAP example\n");
	loop->quit();
}

static int coap_shell(int fd, enum watch_io io, void *user_data)
{
	interactive_command_t cmd[] = {
		{"help", help_command},
		{"connect", connect_command},
		{"disconnect", disconnect_command},
		{"request", request_command},
		{"start", start_command},
		{"stop", stop_command},
		{"exit", quit_command},
		{ NULL, NULL }
	};
	artik_coap_module *coap = (artik_coap_module *)user_data;
	char buffer[MAX_PACKET_SIZE];
	char **argv = NULL;
	int argc = 0;
	char *p = NULL;
	int i = 0;

	if (fgets(buffer, MAX_PACKET_SIZE, stdin) == NULL)
		return 1;
	p = strtok(buffer, " \t\n");
	while (p) {
		argv = realloc(argv, sizeof(char *) * ++argc);

		if (argv == NULL) {
			artik_loop_module *loop = (artik_loop_module *) artik_request_api_module("loop");

			fprintf(stderr, "Error: Not enough memory\n");
			loop->quit();
			return 0;
		}

		argv[argc - 1] = p;
		p = strtok(NULL, " \t\n");
	}

	if (argc < 1) {
		fprintf(stderr, "Error: Too few arguments\n");
		return 1;
	}

	while (cmd[i].cmd != NULL) {
		if (strcmp(cmd[i].cmd, argv[0]) == 0)
			break;
		++i;
	}

	if (cmd[i].cmd != NULL)
		cmd[i].callback(argc, argv, coap);
	else
		fprintf(stderr, "Error: Unknow command '%s'\n", argv[0]);
	write(1, ">", 1);
	return 1;
}

static int parse_arguments(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "h")) != -1) {
		switch (c) {
		case 'h':
			usage();
			goto exit;
		case '?':
			printf("Error: Unknow option '-%c'\n", optopt);
			goto exit;
		default:
			abort();
		}
	}
	return true;
 exit:
	return false;
}

int main(int argc, char **argv)
{
	artik_coap_module	*coap = NULL;
	artik_loop_module	*loop = NULL;
	artik_error		ret = 0;
	int			watchid = -1;

	if (!parse_arguments(argc, argv))
		goto exit;
	loop = (artik_loop_module *) artik_request_api_module("loop");
	if (!loop) {
		fprintf(stderr, "Error: Failed to request Loop module\n");
		goto exit;
	}
	coap = (artik_coap_module *) artik_request_api_module("coap");
	if (!coap) {
		fprintf(stderr, "Error: Failed to request bluetooth module.\n");
		goto exit;
	}
	ret = loop->add_fd_watch(STDIN_FILENO, (WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL),
							 coap_shell, coap, &watchid);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to create watcher for STDIN: %s\n", error_msg(ret));
		goto exit;
	}
	interactive_shell_usage();
	write(1, ">", 1);
	loop->run();

exit:
	if (loop && watchid != -1)
		loop->remove_fd_watch(watchid);
	if (loop)
		artik_release_api_module(loop);
	if (coap)
		artik_release_api_module(coap);
}
