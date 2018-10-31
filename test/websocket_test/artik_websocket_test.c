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
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <artik_module.h>
#include <artik_loop.h>
#include <artik_websocket.h>

static const char *echo_websocket_root_ca =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\n"
	"MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n"
	"DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\n"
	"PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\n"
	"Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
	"AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\n"
	"rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\n"
	"OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\n"
	"xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\n"
	"7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\n"
	"aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n"
	"HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\n"
	"SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\n"
	"ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\n"
	"AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\n"
	"R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\n"
	"JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\n"
	"Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n"
	"-----END CERTIFICATE-----\n";

static char *test_message = NULL;

static int quit_loop(void *user_data)
{
	artik_loop_module *loop = (artik_loop_module *)user_data;

	loop->quit();
	fprintf(stdout, "Loop quit!\n");

	return true;
}

static void connection_callback(void *user_data, void *result)
{
	intptr_t connected = (intptr_t)result;

	if (connected == ARTIK_WEBSOCKET_CONNECTED) {
		fprintf(stdout, "Websocket connected\n");

		artik_websocket_module *websocket = (artik_websocket_module *)
					artik_request_api_module("websocket");

		fprintf(stdout, "Writing: %s\n", test_message);

		websocket->websocket_write_stream((artik_websocket_handle)
						user_data, test_message);
		artik_release_api_module(websocket);
	} else if (connected == ARTIK_WEBSOCKET_CLOSED) {
		fprintf(stdout, "Websocket closed\n");

		artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
		loop->quit();
		artik_release_api_module(loop);
	} else if (connected == ARTIK_WEBSOCKET_CONNECTION_ERROR) {
		fprintf(stdout, "Websocket connection error\n");

		artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
		loop->quit();
		artik_release_api_module(loop);
	} else {
		fprintf(stderr, "TEST failed, handshake error\n");

		artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
		loop->quit();
		artik_release_api_module(loop);
	}
}

static void receive_callback(void *user_data, void *result)
{

	char *buffer = (char *)result;

	if (buffer == NULL) {
		fprintf(stdout, "Received failed\n");
		return;
	}

	artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");

	printf("Received: %s\n", (char *)result);
	free(result);

	loop->quit();
	artik_release_api_module(loop);
}

static artik_error test_websocket_write(char *uri, bool verify)
{
	artik_error ret = S_OK;
	artik_websocket_module *websocket = (artik_websocket_module *)
					artik_request_api_module("websocket");
	artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
	artik_websocket_handle handle;
	artik_websocket_config *config = NULL;

	config = (artik_websocket_config *)malloc(sizeof(
						artik_websocket_config));

	memset(config, 0, sizeof(artik_websocket_config));

	config->uri = uri;
	config->ssl_config.ca_cert.data = strdup(echo_websocket_root_ca);
	config->ssl_config.ca_cert.len = strlen(echo_websocket_root_ca);
	config->ping_period = 10000;
	config->pong_timeout = 5000;

	if (verify)
		config->ssl_config.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
	else
		config->ssl_config.verify_cert = ARTIK_SSL_VERIFY_NONE;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = websocket->websocket_request(&handle, config);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		goto exit;
	}

	ret = websocket->websocket_open_stream(handle);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		goto exit;
	}

	ret = websocket->websocket_set_connection_callback(handle,
					connection_callback, (void *)handle);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		goto exit;
	}

	ret = websocket->websocket_set_receive_callback(handle,
					receive_callback, (void *)handle);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		goto exit;
	}

	loop->add_signal_watch(SIGINT, quit_loop, (void *)loop, NULL);
	loop->run();

	websocket->websocket_close_stream(handle);
	websocket->websocket_release(handle);

	fprintf(stdout, "TEST: %s finished\n", __func__);

exit:
	artik_release_api_module(websocket);
	artik_release_api_module(loop);

	return ret;
}

int main(int argc, char *argv[])
{

	int opt;
	bool verify = false;
	artik_error ret = S_OK;
	char uri[26] = "ws://echo.websocket.org/";

	while ((opt = getopt(argc, argv, "tm:v")) != -1) {
		switch (opt) {
		case 't':
			snprintf(uri, 26, "%s", "wss://echo.websocket.org/");
			break;
		case 'm':
			test_message = strndup(optarg, strlen(optarg)+1);
			break;
		case 'v':
			verify = true;
			break;
		default:
			printf("Usage: websocket-test [-t for using TLS]\n"
			"[-m <message>] [-v for verifying CA certificate]\n");
			return 0;
		}
	}

	if (!test_message)
		test_message = strndup("ping", 5);

	ret = test_websocket_write(uri, verify);

	if (test_message)
		free(test_message);

	return (ret == S_OK) ? 0 : -1;
}

