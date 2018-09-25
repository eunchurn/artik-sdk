/*
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>

#include <artik_module.h>
#include <artik_security.h>

static void usage(void)
{
	printf("USAGE:\n");
	printf(" security-certificate --set <cert id> <cert path>\n");
	printf(" security-certificate --remove <cert id>\n");
	printf(" security-certificate --get <cert id> [cert path]\n");
	printf("\n");

	printf("OPTIONS:\n");
	printf("\t-set, --set <cert id> <cert path>\n");
	printf("\t\tSet certificate in file <cert path> in <cert id>\n");
	printf("\t-remove, --remove <cert id>\n");
	printf("\t\tRemove certificate stored in <cert id>\n");
	printf("\t-get, --get <cert id> [cert path]\n");
	printf("\t\tGet certificate stored in <cert id>.\n");
	printf("\t\tThe [cert path] argument is an optional\n");
	printf("\t\tpath to save the certificate in a file\n");
}

static bool set_cert(const char *cert_id, const char *path)
{
	artik_security_module *security = (artik_security_module *) artik_request_api_module("security");
	artik_security_handle handle = NULL;
	FILE *fp = NULL;
	bool res = false;
	unsigned int cert_len = 0;
	unsigned char *cert = NULL;
	artik_error err;
	long file_len;

	if (!path) {
		fprintf(stderr, "Error: <cert path> not provided.\n");
		return false;
	}

	if (security == INVALID_MODULE) {
		fprintf(stderr, "Unable to request security module\n");
		return false;
	}

	err = security->request(&handle);
	if (err != S_OK) {
		fprintf(stderr, "Error: Failed to create security instance\n");
		goto exit;
	}

	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "Error: Cannot open file '%s'.\n", path);
		goto exit;
	}

	if (fseek(fp, 0, SEEK_END) < 0) {
		fprintf(stderr, "Error: Cannot get the size of '%s'.\n", path);
		goto exit;
	}

	file_len = ftell(fp);
	if (file_len < 0) {
		fprintf(stderr, "Error: Cannot get the size of '%s'.\n", path);
		goto exit;
	}
	cert_len = file_len;

	rewind(fp);

	cert = malloc(cert_len);
	if (!cert) {
		fprintf(stderr, "Error: Not enough memory.\n");
		goto exit;
	}

	if (fread(cert, 1, cert_len, fp) <= 0) {
		fprintf(stderr, "Cannot read the file '%s'", path);
		goto exit;
	}

	err = security->set_certificate(handle, cert_id, cert, cert_len);
	if (err != S_OK) {
		fprintf(stderr, "Error: Cannot set certificate in '%s'.\n", cert_id);
		goto exit;
	}
	res = true;

exit:
	if (fp)
		fclose(fp);

	if (cert)
		free(cert);

	if (handle)
		security->release(handle);

	if (security != INVALID_MODULE)
		artik_release_api_module(security);

	return res;
}

static bool remove_cert(const char *cert_id)
{
	artik_security_module *security = (artik_security_module *) artik_request_api_module("security");
	artik_security_handle handle = NULL;
	bool res = false;
	artik_error err;

	if (security == INVALID_MODULE) {
		fprintf(stderr, "Unable to request security module\n");
		return false;
	}

	err = security->request(&handle);
	if (err != S_OK) {
		fprintf(stderr, "Error: Failed to create security instance\n");
		goto exit;
	}

	err = security->remove_certificate(handle, cert_id);
	if (err != S_OK) {
		fprintf(stderr, "Error: Failed to remove certificate.\n");
		goto exit;
	}

	fprintf(stdout, "Certificate '%s' removed.\n", cert_id);
	res = true;
exit:
	if (handle)
		security->release(handle);

	if (security != INVALID_MODULE)
		artik_release_api_module(security);

	return res;
}

static bool get_cert(const char *cert_id, const char *path)
{
	artik_security_module *security = (artik_security_module *) artik_request_api_module("security");
	artik_security_handle handle = NULL;
	bool res = false;
	unsigned char *cert = NULL;
	unsigned int cert_size = 0;
	artik_error err;

	if (security == INVALID_MODULE) {
		fprintf(stderr, "Unable to request security module\n");
		return false;
	}

	err = security->request(&handle);
	if (err != S_OK) {
		fprintf(stderr, "Error: Failed to create security instance\n");
		goto exit;
	}

	err = security->get_certificate(handle, cert_id, ARTIK_SECURITY_CERT_TYPE_PEM, &cert, &cert_size);
	if (err != S_OK) {
		fprintf(stderr, "Error: Failed to get certificate '%s'.\n", cert_id);
		goto exit;
	}

	if (path) {
		FILE *fp = fopen(path, "w");

		if (!fp) {
			fprintf(stderr, "Error: Failed to open file '%s'.\n", path);
			goto exit;
		}

		fprintf(stdout, "Save certificate in '%s'.\n", path);
		fwrite(cert, 1, cert_size, fp);
		fclose(fp);
	} else {
		fprintf(stdout, "Cert '%s' is :\n%s\n", cert_id, cert);
	}

	res = true;
exit:
	if (cert)
		free(cert);

	if (handle)
		security->release(handle);

	if (security != INVALID_MODULE)
		artik_release_api_module(security);

	return res;
}

#define CMD_SET_CERT 1
#define CMD_REMOVE_CERT 2
#define CMD_GET_CERT 3
#define CMD_GET_PUBKEY 4
#define CMD_HELP 5

const struct option longopts[] = {
	{
		.name = "set",
		.has_arg = required_argument,
		.flag = NULL,
		.val = CMD_SET_CERT
	},
	{
		.name = "remove",
		.has_arg = required_argument,
		.flag = NULL,
		.val = CMD_REMOVE_CERT
	},
	{
		.name = "get",
		.has_arg = required_argument,
		.flag = NULL,
		.val = CMD_GET_CERT
	},
	{
		.name = "getpubkey",
		.has_arg = required_argument,
		.flag = NULL,
		.val = CMD_GET_PUBKEY
	},
	{
		.name = "help",
		.has_arg = no_argument,
		.flag = NULL,
		.val = CMD_HELP
	},
	{ 0, 0, 0, 0}
};

int main(int argc, char **argv)
{
	int option_idx;
	int c;
	char *cert_id = NULL;
	char *path = NULL;
	int mode = -1;

	opterr = 0;
	while (1) {
		c = getopt_long_only(argc, argv, "", longopts, &option_idx);

		if (c == -1)
			break;

		if (mode != -1 && c != CMD_HELP) {
			fprintf(stderr, "Error: Options combinations are not supported.\n");
			return -1;
		}


		mode = c;
		switch (c) {
		case CMD_SET_CERT:
		case CMD_REMOVE_CERT:
		case CMD_GET_CERT:
		case CMD_GET_PUBKEY:
			cert_id = optarg;
			break;
		case CMD_HELP:
			usage();
			return 0;
		case '?':
			fprintf(stderr, "Error: Option '%s' requires an argument.\n", argv[optind - 1]);
			usage();
			return -1;
		default:
			abort();
		}
	}

	if (!cert_id) {
		usage();
		return -1;
	}

	if (optind + 1 == argc)
		path = argv[optind];

	switch (mode) {
	case CMD_SET_CERT:
		if (!set_cert(cert_id, path))
			return -1;

		break;
	case CMD_REMOVE_CERT:
		if (!remove_cert(cert_id))
			return -1;

		break;
	case CMD_GET_CERT:
		if (!get_cert(cert_id, path))
			return -1;

		break;
	default:
		fprintf(stderr, "Error: mode '%d' is not supported\n", mode);
		break;
	}

	return 0;

}
