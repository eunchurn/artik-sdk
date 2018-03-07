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
#include <artik_lwm2m.h>
#include <artik_network.h>

#define MAX_LONG        0x7FFFFFFF
#define MAX_PACKET_SIZE 1024

typedef void (*interactive_command_callback_t)(int argc, char **argv, void *user_data);

typedef struct {
	const char *cmd;
	interactive_command_callback_t callback;
} interactive_command_t;

void usage(void)
{
	printf("Usage:\n");
	printf(" lwm2m-example [options] URL\n");
	printf("URL\n");
	printf(" Only the two following URL syntax are supported:");
	printf("  coaps+tcp:\\\\server[:port]\n");
	printf("  coaps:\\\\server[:port]\n");
	printf("\n");
	printf("Options:\n");
	printf("  -i [id]                                            Device identity\n");
	printf("  -p [psk]                                           Pre-Shared-Key (needed "
		   "in DTLS/PSK, TLS/Cert and TLS/PSK)\n");
	printf("  -d devcert=<devcert path>,devkey=<devkey path>     Device certificate and private key\n");
	printf("  -c <root ca path>                                  CA certificate to verify "
		   "peer against. (Only used in TLS)\n");
	printf("  -e <server cert path>                              Server certificate (Only in DTLS/Cert)\n");
	printf("  -s [artik|manufacturer]                            Use SE for SSL (default: 'artik' devcert)\n");
	printf("  -k                                                 Allows insecure connection (Ignored in DTLS)\n");
	printf("  -h                                                 Display this help and exit\n");
	printf("\n");
}

static void interactive_help(void)
{
	printf("read <resource uri>                              Read the value of a resource\n");
	printf("change <resouce uri> <value>                     Change the value of a resource\n");
	printf("quit                                             Quit\n");
	printf("help                                             Display this help\n");
}

static void help_cmd(int argc, char **argv, void *user_data)
{
	interactive_help();
}

static void read_cmd(int argc, char **argv, void *user_data)
{
	artik_lwm2m_module *lwm2m = (artik_lwm2m_module *) artik_request_api_module("lwm2m");
	artik_lwm2m_handle handle = (artik_lwm2m_handle)user_data;
	artik_error ret;
	char *uri = NULL;
	char data[257];
	int len = 256;

	if (argc < 2) {
		fprintf(stderr, "Error: Too few arguments\n");
		interactive_help();
		return;
	}

	uri = argv[1];

	ret = lwm2m->client_read_resource(handle, uri, (unsigned char *)data, &len);
	if (ret != S_OK) {
		fprintf(stderr, "Read URI %s failed: %s", uri, error_msg(ret));
		return;
	}

	fprintf(stdout, "URI: %s - Value: %s\n", uri, data);
}

static void change_cmd(int argc, char **argv, void *user_data)
{
	artik_lwm2m_module *lwm2m = (artik_lwm2m_module *) artik_request_api_module("lwm2m");
	artik_lwm2m_handle handle = (artik_lwm2m_handle)user_data;
	artik_error ret;
	char *uri = NULL;
	char *value = NULL;

	if (argc < 3) {
		fprintf(stderr, "Error: Too few arguments");
		return;
	}
	uri = argv[1];
	value = argv[2];

	ret = lwm2m->client_write_resource(handle, uri, (unsigned char *)value, strlen(value));
	if (ret != S_OK)
		fprintf(stderr, "Error: Failed to change object %s: %s", uri, error_msg(ret));
}

static void quit_cmd(int argc, char **argv, void *user_data)
{
	artik_loop_module *loop = (artik_loop_module *) artik_request_api_module("loop");

	loop->quit();
}

static int lwm2m_shell(int fd, enum watch_io io, void *user_data)
{
	interactive_command_t cmd[] = {
		{"read", read_cmd},
		{"change", change_cmd},
		{"quit", quit_cmd},
		{"help", help_cmd},
		{NULL, NULL}
	};
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
			artik_loop_module *loop = (artik_loop_module *) artik_request_api_module("lwm2m");

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
		i++;
	}

	if (cmd[i].cmd != NULL)
		cmd[i].callback(argc, argv, user_data);
	else
		fprintf(stderr, "Error: Unknow command '%s'\n", argv[0]);

	if (argv)
		free(argv);

	write(1, ">", 1);

	return 1;
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
			fprintf(stderr, "Error: Sub-option '%s' requires an argument\n", token[0]);
			return false;
		}

		if (!fill_buffer_from_file(value, dev_cert))
			return false;

	case 1:
		if (value == NULL) {
			fprintf(stderr, "Error: Sub-option '%s' requires an argument\n", token[1]);
			return false;
		}

		if (!fill_buffer_from_file(value, dev_key))
			return false;

	default:
		fprintf(stderr, "Error: Unknow sub-option '%s'\n", value);
		return false;
	}

	return true;
}

static int parse_arguments(int argc, char **argv, artik_ssl_config *ssl, artik_lwm2m_config *lwm2m_config)
{
	int c;
	char *identity = NULL;
	char *psk = NULL;
	char *dev_cert = NULL;
	char *dev_key = NULL;
	char *root_ca = NULL;
	char *server_cert = NULL;
	char *cert_id = NULL;
	bool use_se = false;
	char *url = NULL;

	memset(ssl, 0, sizeof(artik_ssl_config));
	memset(lwm2m_config, 0, sizeof(artik_lwm2m_config));

	while ((c = getopt(argc, argv, "i:p:d:c:e:s::kh")) != -1) {
		switch (c) {
		case 'i':
			identity = optarg;
			break;
		case 'p':
			psk = optarg;
			break;
		case 'd':
			if (!parse_device_cert_opt(optarg, &dev_cert, &dev_key))
				goto exit;
			break;
		case 'c':
			if (!fill_buffer_from_file(optarg, &root_ca))
				goto exit;
			break;
		case 'e':
			if (!fill_buffer_from_file(optarg, &server_cert))
				goto exit;
			break;
		case 's':
			if (optarg) {
				use_se = true;
				cert_id = optarg;
			}
			break;
		case 'k':
			ssl->verify_cert = ARTIK_SSL_VERIFY_NONE;
			break;
		case 'h':
			usage();
			goto exit;
		case '?':
			if (optopt == 'i' || optopt == 'p' || optopt == 'd'
				|| optopt == 'c' || optopt == 'e')
				fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
			else if (optopt == 's')
				cert_id = "ARTIK/0";
			else
				fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);
			goto exit;
		default:
			abort();
		}
	}

	if (dev_cert && use_se) {
		fprintf(stderr, "Error: Option '-s' and '-d' conflict\n");
		goto exit;
	}

	if (root_ca && server_cert) {
		fprintf(stderr, "Error: Option '-c' and '-e' conflict\n");
		goto exit;
	}

	if (use_se) {
		ssl->se_config = malloc(sizeof(artik_secure_element_config));
		ssl->se_config->key_id = cert_id;
		ssl->se_config->key_algo = ECC_SEC_P256R1;
	}

	if (dev_cert) {
		ssl->client_cert.len = strlen(dev_cert);
		ssl->client_cert.data = dev_cert;
	}

	if (dev_key) {
		ssl->client_key.len = strlen(dev_key);
		ssl->client_key.data = dev_key;
	}

	if (root_ca) {
		ssl->ca_cert.len = strlen(root_ca);
		ssl->ca_cert.data = root_ca;
	}

	if (server_cert) {
		ssl->ca_cert.len = strlen(server_cert);
		ssl->ca_cert.data = server_cert;
	}

	if (optind == argc) {
		usage();
		fprintf(stderr, "Error: Too few arguments\n");
		goto exit;
	}
	url = argv[optind];

	lwm2m_config->server_id = 123;
	lwm2m_config->server_uri = url;
	lwm2m_config->name = identity;
	lwm2m_config->lifetime = 30;
	lwm2m_config->connect_timeout = 1000;
	lwm2m_config->tls_psk_identity = identity;
	lwm2m_config->tls_psk_key = psk;
	lwm2m_config->ssl_config = ssl;
	return true;
exit:
	if (ssl->se_config)
		free(ssl->se_config);

	if (dev_cert)
		free(dev_cert);

	if (dev_key)
		free(dev_key);

	if (root_ca)
		free(root_ca);

	if (server_cert)
		free(server_cert);
	return false;
}

static void on_error(void *data, void *user_data)
{
	artik_loop_module *loop = NULL;
	artik_error err = (artik_error)(intptr_t)data;

	loop = (artik_loop_module *) artik_request_api_module("loop");
	fprintf(stdout, "LWM2M error: %s\r\n", error_msg(err));
	loop->quit();
}

static void on_resource_execute(void *data, void *user_data)
{
	char *uri = (char *)(((artik_lwm2m_resource_t *)data)->uri);

	fprintf(stdout, "LWM2M resource execute: %s\r\n", uri);
}

static void on_resource_changed(void *data, void *user_data)
{
	artik_lwm2m_resource_t *res = (artik_lwm2m_resource_t *)data;
	char *uri = (char *)res->uri;

	fprintf(stdout, "LWM2M resource changed: %s", uri);
	if (res->length > 0) {
		char *buffer = strndup((char *)res->buffer, res->length);

		fprintf(stdout, " with buffer : %s\r\n", buffer);
	} else {
		fprintf(stdout, "\r\n");
	}
}

int main(int argc, char **argv)
{
	artik_ssl_config ssl;
	artik_lwm2m_module *lwm2m = NULL;
	artik_lwm2m_handle handle = NULL;
	artik_network_module *network = NULL;
	artik_loop_module *loop = NULL;
	artik_lwm2m_config lwm2m_config;
	char *ips[2] = {NULL, NULL};
	char *routes[2] = {NULL, NULL};
	artik_network_config net_config;
	artik_error ret = 0;
	int watchid = -1;

	memset(&lwm2m_config, 0, sizeof(artik_lwm2m_config));
	memset(&ssl, 0, sizeof(artik_ssl_config));

	if (!parse_arguments(argc, argv, &ssl, &lwm2m_config))
		goto exit;

	lwm2m = (artik_lwm2m_module *) artik_request_api_module("lwm2m");
	if (!lwm2m) {
		fprintf(stderr, "Error: Failed to request LWM2M module\n");
		goto exit;
	}

	network = (artik_network_module *) artik_request_api_module("network");
	if (!network) {
		fprintf(stderr, "Error: Failed to request Network module\n");
		goto exit;
	}

	loop = (artik_loop_module *) artik_request_api_module("loop");
	if (!loop) {
		fprintf(stderr, "Error: Failed to request Loop module\n");
		goto exit;
	}

	ret = network->get_network_config(&net_config, ARTIK_WIFI);
	ips[0] = net_config.ip_addr.address;
	routes[0] = net_config.gw_addr.address;

	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to get network configuration: %s\n", error_msg(ret));
		goto exit;
	}

	lwm2m_config.objects[ARTIK_LWM2M_OBJECT_FIRMWARE] =
		lwm2m->create_firmware_object(true, "artik-sdk-example", "1.0.0");
	lwm2m_config.objects[ARTIK_LWM2M_OBJECT_CONNECTIVITY_MONITORING] =
		lwm2m->create_connectivity_monitoring_object(0, 0, 0, 0,
										2, (const char **)ips,
										2, (const char **)routes,
										0, "ARTIK_5G", 2345, 189, 33);
	lwm2m_config.objects[ARTIK_LWM2M_OBJECT_DEVICE] =
		lwm2m->create_device_object("Samsung", "Artik", "1234567890",
									"1.0", "1.0", "1.0", "HUB", 0,
									5000, 1500, 100, 100000, 200000,
									"Europe/Paris", "+01:00", "U");

	if (!lwm2m_config.objects[ARTIK_LWM2M_OBJECT_FIRMWARE]) {
		fprintf(stderr, "Error: Failed to create lwm2m firmware object\n");
		goto exit;
	}

	if (!lwm2m_config.objects[ARTIK_LWM2M_OBJECT_CONNECTIVITY_MONITORING]) {
		fprintf(stderr, "Error: Failed to create LWM2M connectivity object\n");
		goto exit;
	}

	if (!lwm2m_config.objects[ARTIK_LWM2M_OBJECT_DEVICE]) {
		fprintf(stderr, "Error: Failed to create LWM2M device object\n");
		goto exit;
	}

	ret = lwm2m->client_request(&handle, &lwm2m_config);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to request client handle: %s\n", error_msg(ret));
		goto exit;
	}

	lwm2m->set_callback(handle, ARTIK_LWM2M_EVENT_ERROR, on_error, NULL);
	lwm2m->set_callback(handle, ARTIK_LWM2M_EVENT_RESOURCE_CHANGED, on_resource_changed, NULL);
	lwm2m->set_callback(handle, ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE, on_resource_execute, NULL);

	ret = loop->add_fd_watch(STDIN_FILENO, (WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL),
							 lwm2m_shell, handle, &watchid);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to create watcher for STDIN: %s\n", error_msg(ret));
		goto exit;
	}

	ret = lwm2m->client_connect(handle);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to connect to LWM2M server %s: %s\n",
				lwm2m_config.server_uri, error_msg(ret));
		goto exit;
	}

	interactive_help();
	write(1, ">", 1);
	loop->run();

exit:
	if (watchid != -1)
		loop->remove_fd_watch(watchid);

	if (handle)
		lwm2m->client_release(handle);

	if (lwm2m_config.objects[ARTIK_LWM2M_OBJECT_FIRMWARE])
		free(lwm2m_config.objects[ARTIK_LWM2M_OBJECT_FIRMWARE]);

	if (lwm2m_config.objects[ARTIK_LWM2M_OBJECT_CONNECTIVITY_MONITORING])
		free(lwm2m_config.objects[ARTIK_LWM2M_OBJECT_CONNECTIVITY_MONITORING]);

	if (lwm2m_config.objects[ARTIK_LWM2M_OBJECT_DEVICE])
		free(lwm2m_config.objects[ARTIK_LWM2M_OBJECT_DEVICE]);

	if (ssl.client_cert.data)
		free(ssl.client_cert.data);

	if (ssl.client_key.data)
		free(ssl.client_key.data);

	if (ssl.ca_cert.data)
		free(ssl.ca_cert.data);

	return 0;
}
