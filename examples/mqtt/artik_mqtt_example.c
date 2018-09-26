#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <artik_loop.h>
#include <artik_module.h>
#include <artik_mqtt.h>

#define MAX_UUID_LEN 128
#define BROKER_PORT 8883
#define MAX_LONG        0x7FFFFFFF
#define MAX_PACKET_SIZE 1024

typedef struct {
	artik_mqtt_module *mqtt;
	artik_ssl_config ssl;
	const char *did;
	const char *token;
	char sub_topic[MAX_UUID_LEN + 128];
	char pub_topic[MAX_UUID_LEN + 128];
	artik_mqtt_config config;
} mqtt_data_t;

typedef void (*interactive_command_callback_t)(int argc, char **argv, mqtt_data_t *data);

typedef struct {
	const char *cmd;
	interactive_command_callback_t callback;
} interactive_command_t;

static const char *akc_root_ca =
	"-----BEGIN CERTIFICATE-----\n"
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
	"-----END CERTIFICATE-----\n";

void usage(void)
{
	printf("Usage: mqtt-example [OPTIONS] <did> <token>\n");
	printf("Options:\n");
	printf("  -s [artik|manufacturer]                            Use SE for SSL (default: 'artik' devcert)\n");
	printf("  -d devcert=<devcert path>,devkey=<devkey path>     Device certificate and private key\n");
	printf("  -k                                                 Allows insecure connection\n");
	printf("  -h                                                 Display this help and exit\n");
}

void interactive_shell_usage(void)
{
	printf("publish <message>\n");
	printf("disconnect\n");
}

static void on_connect(artik_mqtt_config *client_config, void *user_data, artik_error result)
{
	artik_mqtt_handle handle = NULL;
	artik_mqtt_module *mqtt = NULL;
	mqtt_data_t *data = (mqtt_data_t *)user_data;
	artik_error ret;

	if (result != S_OK)
		fprintf(stderr, "Error: Connection failed: %s\n", error_msg(result));

	if (!client_config->handle)
		return;

	mqtt = (artik_mqtt_module *)artik_request_api_module("mqtt");
	handle = client_config->handle;
	ret = mqtt->subscribe(handle, 0, data->sub_topic);
	if (ret != S_OK) {
		artik_loop_module *loop = (artik_loop_module *)artik_request_api_module("loop");

		fprintf(stderr, "Error: Failed to subscibre to %s %s\n", data->sub_topic, error_msg(ret));
		loop->quit();
		artik_release_api_module(loop);
	}

	artik_release_api_module(mqtt);
}

static void on_message(artik_mqtt_config *client_config, void *user_data, artik_mqtt_msg *msg)
{
	mqtt_data_t *data = (mqtt_data_t *)user_data;

	if (strcmp(data->sub_topic, msg->topic) == 0)
		fprintf(stdout, "The device has recevied an action: %s\n", (char *)msg->payload);

}

static void on_disconnect(artik_mqtt_config *client_config, void *user_data, int result)
{
	mqtt_data_t *data = (mqtt_data_t *)user_data;
	artik_mqtt_handle handle = client_config->handle;
	artik_loop_module *loop = NULL;

	if (result != S_OK)
		return;

	data->mqtt->destroy_client(handle);
	loop = (artik_loop_module *)artik_request_api_module("loop");
	loop->quit();
	artik_release_api_module(loop);
}

static void publish_command(int argc, char **argv, mqtt_data_t *data)
{
	char *msg = NULL;
	artik_error ret;

	if (argc < 2) {
		fprintf(stderr, "Error: Too few arguments\n");
		return;
	}

	msg = argv[1];
	ret = data->mqtt->publish(data->config.handle, 0, false, data->pub_topic, strlen(msg), msg);
	if (ret != S_OK)
		fprintf(stderr, "Error: Publish the message '%s' failed: %s", msg, error_msg(ret));
}

static int mqtt_shell(int fd, enum watch_io io, void *user_data)
{
	interactive_command_t cmd[] = {
		{ "publish", publish_command },
		{ NULL, NULL }
	};
	char buffer[MAX_PACKET_SIZE];
	char **argv = NULL;
	int argc = 0;
	char *p = NULL;
	int i = 0;
	mqtt_data_t *data = (mqtt_data_t *)user_data;

	if (fgets(buffer, MAX_PACKET_SIZE, stdin) == NULL)
		return 1;

	p = strtok(buffer, "\n\t ");
	while (p) {
		argv = realloc(argv, sizeof(char *) * ++argc);

		if (argv == NULL) {
			artik_loop_module *loop = (artik_loop_module *) artik_request_api_module("lwm2m");

			fprintf(stderr, "Error: Not enough memory\n");
			loop->quit();
			return 0;
		}

		argv[argc - 1] = p;
		p = strtok(NULL, "\n\t ");
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
		cmd[i].callback(argc, argv, data);
	else
		fprintf(stderr, "Error: Unknow command '%s'\n", argv[0]);

	if (argv)
		free(argv);

	write(1, ">", 1);

	return 1;
}

static bool init_mqtt(mqtt_data_t *data)
{
	artik_mqtt_handle client;
	artik_mqtt_module *mqtt = data->mqtt;
	artik_mqtt_config *config = &data->config;
	artik_error ret;

	snprintf(data->sub_topic, MAX_UUID_LEN + 128, "/v1.1/actions/%s", data->did);
	snprintf(data->pub_topic, MAX_UUID_LEN + 128, "/v1.1/messages/%s", data->did);

	memset(config, 0, sizeof(artik_mqtt_config));
	config->client_id = "mqtt-example";
	config->block = true;
	config->user_name = data->did;
	config->pwd = data->token;
	config->tls = &data->ssl;

	mqtt->create_client(&client, config);
	mqtt->set_connect(client, on_connect, data);
	mqtt->set_disconnect(client, on_disconnect, NULL);
	mqtt->set_message(client, on_message, data);

	ret = mqtt->connect(client, "api.artik.cloud", BROKER_PORT);
	if (ret != S_OK) {
		fprintf(stdout, "Error: Failed to connect to 'api.artik.cloud': %s", error_msg(ret));
		return false;
	}
	return true;

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

int main(int argc, char **argv)
{
	artik_loop_module *loop = NULL;
	mqtt_data_t data;
	artik_error ret;
	int watchid;
	bool use_se = false;
	char *cert_id = NULL;
	char *dev_cert = NULL;
	char *dev_key = NULL;
	int c;

	memset(&data.ssl, 0, sizeof(artik_ssl_config));

	while ((c = getopt(argc, argv, "+hs:c:d:k")) != -1) {
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
			data.ssl.verify_cert = ARTIK_SSL_VERIFY_NONE;
			break;
		case 'h':
			usage();
			goto exit;
		case '?':
			if (optopt == 's' || optopt == 'c' || optopt == 'd')
				fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
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

	if (use_se) {
		data.ssl.se_config = malloc(sizeof(artik_secure_element_config));
		data.ssl.se_config->key_id = cert_id;
		data.ssl.se_config->key_algo = ECC_SEC_P256R1;
	}

	if (dev_cert) {
		data.ssl.client_cert.len = strlen(dev_cert);
		data.ssl.client_cert.data = dev_cert;
	}

	if (dev_key) {
		data.ssl.client_key.len = strlen(dev_key);
		data.ssl.client_key.data = dev_key;
	}

	if (argc < optind + 2) {
		fprintf(stderr, "Error: Too few arguments\n");
		usage();
		return -1;
	}

	loop = (artik_loop_module *)artik_request_api_module("loop");
	if (!loop) {
		fprintf(stderr, "Error: Failed to request Loop module\n");
		goto exit;
	}

	ret = loop->add_fd_watch(STDIN_FILENO, (WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL),
							 mqtt_shell, &data, &watchid);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to create watcher for STDIN: %s\n", error_msg(ret));
		goto exit;
	}

	data.ssl.ca_cert.data = strdup(akc_root_ca);
	data.ssl.ca_cert.len = strlen(akc_root_ca);
	data.ssl.verify_cert = ARTIK_SSL_VERIFY_NONE;
	data.did = argv[optind];
	data.token = argv[optind + 1];
	data.mqtt = (artik_mqtt_module *)artik_request_api_module("mqtt");
	if (!data.mqtt) {
		fprintf(stderr, "Error: Failed to request MQTT module\n");
		free(data.ssl.ca_cert.data);
		goto exit;
	}

	if (!init_mqtt(&data)) {
		free(data.ssl.ca_cert.data);
		goto exit;
	}

	interactive_shell_usage();
	write(1, ">", 1);
	loop->run();

	free(data.ssl.ca_cert.data);

exit:
	return 0;
}
