#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <artik_module.h>
#include <artik_loop.h>
#include <artik_platform.h>
#include <artik_http.h>

#define MAX_LONG        0x7FFFFFFF

void usage(void)
{
	printf("http-example [OPTIONS] COMMAND\n");
	printf("Options:\n");
	printf("  -H header                                          Pass custom header to server\n");
	printf("  -s [artik|manufacturer]                            Use SE for SSL (default: 'artik' devcert)\n");
	printf("  -c <root ca path>                                  CA certificate to verify peer against (SSL)\n");
	printf("  -d devcert=<devcert path>,devkey=<devkey path>     Device certificate and private key\n");
	printf("  -k                                                 Allows insecure connection\n");
	printf("  -h                                                 Display this help and exit\n");
	printf("\n");
	printf("Commands:\n");
	printf("  get <url>                                          Send an HTTP GET request to <url>\n");
	printf("  post <url> <body>                                  Send an HTTP POST request to <url>\n");
	printf("  put <url> <body>                                   Send an HTTP PUT request to <url>\n");
	printf("  del <url>                                          Send an HTTP DELETE request to <url>\n");
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

	case 1:
		if (value == NULL) {
			fprintf(stderr, "Error: Sub-option '%s' requires an argument", token[1]);
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

static bool get_cmd(artik_ssl_config *ssl, artik_http_headers *headers, int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Error: 'get': Too few arguments.\n");
		return false;
	}

	const char *url = argv[1];
	artik_http_module *http = (artik_http_module *)artik_request_api_module("http");
	artik_error ret;
	char *response = NULL;
	int status;

	if (!http) {
		fprintf(stderr, "Eroor: Failed to request HTTP module\n");
		return false;
	}

	ret = http->get(url, headers, &response, &status, ssl);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to GET '%s': %s.\n", url, error_msg(ret));
		artik_release_api_module(http);
		return false;
	}

	if (status >= 400) {
		fprintf(stderr, "Error: The requested URL returned error: %d\n", status);
		if (response) {
			fprintf(stderr, "%s", response);
			free(response);
		}
		artik_release_api_module(http);
		return false;
	}

	if (status >= 200) {
		fprintf(stdout, "The requested URL returned: %d\n", status);
		if (response) {
			fprintf(stdout, "%s\n", response);
			free(response);
		}

		artik_release_api_module(http);
		return true;
	}

	return false;
}

static bool put_cmd(artik_ssl_config *ssl, artik_http_headers *headers, int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "Error: 'put': Too few arguments.\n");
		return false;
	}

	const char *url = argv[1];
	const char *body = argv[2];
	artik_http_module *http = (artik_http_module *)artik_request_api_module("http");
	artik_error ret;
	char *response = NULL;
	int status;

	if (!http) {
		fprintf(stderr, "Eroor: Failed to request HTTP module\n");
		return false;
	}

	ret = http->put(url, headers, body, &response, &status, ssl);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to PUT '%s': %s.\n", url, error_msg(ret));
		artik_release_api_module(http);
		return false;
	}

	if (status >= 400) {
		fprintf(stderr, "Error: The requested URL returned error: %d\n", status);
		if (response) {
			fprintf(stderr, "%s", response);
			free(response);
		}
		artik_release_api_module(http);
		return false;
	}

	if (status >= 200) {
		fprintf(stdout, "The requested URL returned: %d", status);
		if (response) {
			fprintf(stdout, "%s\n", response);
			free(response);
		}

		artik_release_api_module(http);
		return true;
	}

	return false;
}

static bool post_cmd(artik_ssl_config *ssl, artik_http_headers *headers, int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "Error: 'post': Too few arguments.\n");
		return false;
	}

	const char *url = argv[1];
	const char *body = argv[2];
	artik_http_module *http = (artik_http_module *)artik_request_api_module("http");
	artik_error ret;
	char *response = NULL;
	int status;

	if (!http) {
		fprintf(stderr, "Eroor: Failed to request HTTP module\n");
		return false;
	}

	ret = http->post(url, headers, body, &response, &status, ssl);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to POST '%s': %s.\n", url, error_msg(ret));
		artik_release_api_module(http);
		return false;
	}

	if (status >= 400) {
		fprintf(stderr, "Error: The requested URL returned error: %d\n", status);
		if (response) {
			fprintf(stderr, "%s", response);
			free(response);
		}
		artik_release_api_module(http);
		return false;
	}

	if (status >= 200) {
		fprintf(stdout, "The requested URL returned: %d", status);
		if (response) {
			fprintf(stdout, "%s\n", response);
			free(response);
		}

		artik_release_api_module(http);
		return true;
	}

	return false;
}

static bool del_cmd(artik_ssl_config *ssl, artik_http_headers *headers, int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Error: 'del': Too few arguments.\n");
		return false;
	}

	const char *url = argv[1];
	artik_http_module *http = (artik_http_module *)artik_request_api_module("http");
	artik_error ret;
	char *response = NULL;
	int status;

	if (!http) {
		fprintf(stderr, "Eroor: Failed to request HTTP module\n");
		return false;
	}

	ret = http->del(url, headers, &response, &status, ssl);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to DELETE '%s': %s.\n", url, error_msg(ret));
		artik_release_api_module(http);
		return false;
	}

	if (status >= 400) {
		fprintf(stderr, "Error: The requested URL returned error: %d\n", status);
		if (response) {
			fprintf(stderr, "%s", response);
			free(response);
		}
		artik_release_api_module(http);
		return false;
	}

	if (status >= 200) {
		fprintf(stdout, "The requested URL returned: %d", status);
		if (response) {
			fprintf(stdout, "%s\n", response);
			free(response);
		}

		artik_release_api_module(http);
		return true;
	}

	return false;
}

int main(int argc, char **argv)
{
	bool res = false;
	artik_ssl_config ssl;
	artik_http_headers headers = { 0 };
	char *cmd = NULL;
	char *cert_id = NULL;
	bool use_se = false;
	char *ca_cert = NULL;
	char *dev_cert = NULL;
	char *dev_key = NULL;
	int c;

	memset(&ssl, 0, sizeof(artik_ssl_config));
	ssl.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;

	while ((c = getopt(argc, argv, "+hH:s::c:d:k")) != -1) {
		switch (c) {
		case 'H': {
			char *name = NULL;
			char *data = NULL;
			char *token = strtok(optarg, ":");

			if (!token) {
				fprintf(stderr, "Error: Invalid header\n");
				goto exit;
			}

			while (token) {
				name = token;
				token = strtok(NULL, ":");
				if (!token) {
					fprintf(stderr, "Error: Invalid header\n");
					goto exit;
				}
				data = token;
			}
			headers.fields =
				realloc(headers.fields, sizeof(artik_http_header_field) * ++headers.num_fields);
			headers.fields[headers.num_fields - 1].name = name;
			headers.fields[headers.num_fields - 1].data = data;
			break;
		}
		case 's':
			if (optarg) {
				use_se = true;
				cert_id = optarg;
			}
			break;
		case 'c':
			if (!fill_buffer_from_file(optarg, &ca_cert))
				goto exit;
			break;
		case 'd':
			if (!parse_device_cert_opt(optarg, &dev_cert, &dev_key))
				goto exit;
		case 'k':
			ssl.verify_cert = ARTIK_SSL_VERIFY_NONE;
			break;
		case 'h':
			usage();
			goto exit;
		case '?':
			if (optopt == 's' || optopt == 'H' ||
				optopt == 'c' || optopt == 'd')
				fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
			else
				fprintf(stderr, "Error: Unknow option '-%c'.\n", optopt);
			goto exit;
		}
	}

	if (optind == argc) {
		fprintf(stderr, "Error: Too few arguments\n");
		usage();
		goto exit;
	}

	if (dev_cert && use_se) {
		fprintf(stderr, "Error: Option '-s' and '-d' conflict\n");
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

	if (ca_cert) {
		ssl.ca_cert.len = strlen(ca_cert);
		ssl.ca_cert.data = ca_cert;
	}

	cmd = argv[optind];
	if (strcmp(cmd, "get") == 0)
		res = get_cmd(&ssl, &headers, argc - optind, argv + optind);
	else if (strcmp(cmd, "post") == 0)
		res = post_cmd(&ssl, &headers, argc - optind, argv + optind);
	else if (strcmp(cmd, "put") == 0)
		res = put_cmd(&ssl, &headers, argc - optind, argv + optind);
	else if (strcmp(cmd, "del") == 0)
		res = del_cmd(&ssl, &headers, argc - optind, argv + optind);
	else
		fprintf(stderr, "Error: Unknow COMMAND '%s'.\n", cmd);

exit:
	if (ssl.se_config)
		free(ssl.se_config);

	if (dev_cert)
		free(dev_cert);

	if (dev_key)
		free(dev_key);

	if (ca_cert)
		free(ca_cert);

	return res ? 0 : 1;
}
