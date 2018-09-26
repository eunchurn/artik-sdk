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
#include <artik_loop.h>
#include <artik_security.h>

#define MAX_PACKET_SIZE 1024

typedef void (*interactive_command_callback_t)
(int argc, char **argv, artik_security_module *security,
artik_security_handle handle, char *certid);

typedef struct {
	const char *cmd;
	interactive_command_callback_t callback;
} interactive_command_t;

static unsigned int string_to_positive_integer(const char * const buff,
		int *dst, const char * const option_name)
{
	char *nbuff = NULL;

	if (!buff) {
		fprintf(stderr, "Invalid buffer which is empty for '%s'.\n", option_name);
		return 0;
	}

	*dst = strtol(buff, &nbuff, 10);
	if (nbuff[0] != 0 ||
		(errno != 0 && *dst == 0) ||
		(errno == ERANGE)) {
		printf("Invalid '%s' base definition, it should be an integer of base 10.\n", option_name);
		return 0;
	}
	return 1;
}

static void interactive_shell_usage(void)
{
	printf("  certificate\t\t Display the secure element certificate.\n"
		   "  certificate_sn\t Display the secure element certificate Serial Number.\n"
		   "  certificate_ec_pubkey\t Display the secure element certificate EC Public Key.\n"
		   "  ca_chain\t\t Display the secure element certificate CA Chain.\n"
		   "  rand_bytes [size]\t Generate a random sequence.\n"
		   "  exit\t\t\t Quit the program.\n"
		   "  help\t\t\t Display the shell command usage.\n");
}

static void usage(void)
{
	printf("Usage: security-example [options]\n\n"
		" Options:\n"
		"  -h\t Display this help and exit.\n");
}

static void help_command(int argc, char **argv, artik_security_module *secu,
						 artik_security_handle handle_secu, char *certid)
{
	interactive_shell_usage();
}

static void quit_command(int argc, char **argv, artik_security_module *secu,
						 artik_security_handle handle_secu, char *certid)
{
	artik_loop_module *loop = (artik_loop_module *)artik_request_api_module("loop");

	printf("\rQuit SECURITY example\n");
	loop->quit();
}


static void certificate_command(int argc, char **argv, artik_security_module *secu,
								artik_security_handle handle_secu,
								char *certid)
{
	artik_error res = S_OK;
	char *cert = 0;
	unsigned int certlen = 0;

	res = secu->get_certificate(handle_secu, certid,
			ARTIK_SECURITY_CERT_TYPE_PEM, (unsigned char **)&cert, &certlen);
	if (res == S_OK) {
		printf("Certificate:\n%s\n\n", cert);
		free(cert);
	} else {
		fprintf(stderr, ": Failed, %s (err=%d)\n", error_msg(res), res);
	}
}

static void certificate_sn_command(int argc, char **argv, artik_security_module *secu,
								   artik_security_handle handle_secu,
								   char *certid)
{
	artik_error res = S_OK;
	unsigned char sn[32];
	unsigned int len = 32, i = 0;
	char *cert = 0;
	unsigned int certlen = 0;

	memset(sn, 0, sizeof(*sn) * len);

	res = secu->get_certificate(handle_secu, certid,
			ARTIK_SECURITY_CERT_TYPE_PEM, (unsigned char **)&cert, &certlen);
	if (res != S_OK) {
		fprintf(stderr, ": Failed, %s (err=%d)\n", error_msg(res), res);
		return;
	}
	res = secu->get_certificate_sn(cert, sn, &len);
	if (res == S_OK) {
		printf("Serial Number:\n");
		while (i < len) {
			printf("%u\n", sn[i]);
			++i;
		}
		printf("\n");
	} else {
		fprintf(stderr, ": Failed, %s (err=%d)\n", error_msg(res), res);
	}
}

static void certificate_ec_pubkey_command(int argc, char **argv,
		artik_security_module *secu, artik_security_handle handle_secu,
		char *certid)
{
	artik_error res = S_OK;
	char *cert = 0;
	char *key = 0;
	unsigned int certlen = 0;

	res = secu->get_certificate(handle_secu, certid,
		ARTIK_SECURITY_CERT_TYPE_PEM, (unsigned char **)&cert, &certlen);
	if (res != S_OK) {
		fprintf(stderr, "ca_chain: Failed, unable to get the certificate (%d).\n", res);
		return;
	}
	res = secu->get_ec_pubkey_from_cert(cert, &key);
	if (res == S_OK) {
		printf("EC Public key:\n%s\n\n", key);
		free(key);
	} else {
		fprintf(stderr, ": Failed, %s (err=%d)\n", error_msg(res), res);
	}
}

static void ca_chain_command(int argc, char **argv, artik_security_module *secu,
							 artik_security_handle handle_secu,
							 char *certid)
{
	artik_error res = S_OK;
	artik_list *chains = 0;
	struct artik_list *elem = NULL;

	res = secu->get_certificate_pem_chain(handle_secu, certid, &chains);
	if (res == S_OK) {
		elem = chains;
		while (elem != NULL) {
			printf("%s\n", (char *)elem->data);
			elem = elem->next;
		}
	} else {
		fprintf(stderr, ": Failed, %s (err=%d)\n", error_msg(res), res);
	}
}

static void rand_bytes_command(int argc, char **argv, artik_security_module *secu,
							   artik_security_handle handle_secu,
							   char *certid)
{
	artik_error res = S_OK;
	unsigned char *rand = 0;
	int len = 0, i = 0;

	if (!argv || !argv[1]) {
		fprintf(stderr, "rand_bytes: Failed, invalid parameters.\n");
		return;
	}
	if (!string_to_positive_integer(argv[1], &len, "rand_bytes_size"))
		return;
	if ((len <= 0) || (len > 1024)) {
		fprintf(stderr, "rand_bytes: Failed, invalid size value parameters (%d).\n", len);
		return;
	}

	rand = malloc(sizeof(*rand) * len);
	if (!rand) {
		fprintf(stderr, "rand_bytes: Failed to allocate memory.\n");
		return;
	}
	memset(rand, 0, sizeof(*rand) * len);
	res = secu->get_random_bytes(handle_secu, len, &rand);
	if (res == S_OK) {
		printf("Rand Bytes:\n");
		while (i < len) {
			printf("%u\n", rand[i]);
			++i;
		}
		printf("\n");
	} else {
		fprintf(stderr, ": Failed, %s (err=%d)\n", error_msg(res), res);
	}
	free(rand);
}

static int security_shell(int fd, enum watch_io io, void *user_data)
{
	interactive_command_t cmd[] = {
		{"help", help_command},
		{"certificate", certificate_command},
		{"certificate_sn", certificate_sn_command},
		{"certificate_ec_pubkey", certificate_ec_pubkey_command},
		{"ca_chain", ca_chain_command},
		{"rand_bytes", rand_bytes_command},
		{"exit", quit_command},
		{ NULL, NULL }
	};
	artik_security_module *secu = (artik_security_module *)((void **)user_data)[0];
	artik_security_handle *handle_secu = (artik_security_handle)((void **)user_data)[1];
	char *certid = *(char **)((void **)user_data)[2];
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
		cmd[i].callback(argc, argv, secu, handle_secu, certid);
	else
		fprintf(stderr, "Error: Unknow command '%s'\n", argv[0]);
	write(1, ">", 1);
	return 1;
}

static artik_error init(artik_loop_module **loop, artik_security_module **secu,
						artik_security_handle *handle_secu, int *signalid, int *watchid,
						char *certid)
{
	artik_error res = S_OK;
	static void *params[3] = { NULL, NULL, NULL};

	(*loop) = (artik_loop_module *)artik_request_api_module("loop");
	(*secu) = (artik_security_module *)artik_request_api_module("security");
	res = (*secu)->request(handle_secu);
	if (res == S_OK)
		res = (*loop)->add_signal_watch(SIGINT, (signal_callback)quit_command, NULL, signalid);
	if (res == S_OK) {
		params[0] = (void *)(*secu);
		params[1] = (void *)(*handle_secu);
		params[2] = (void *)&certid;
		res = (*loop)->add_fd_watch(1, WATCH_IO_IN, security_shell, (void *)params, watchid);
	}
	interactive_shell_usage();
	write(1, ">", 1);
	return res;
}

static artik_error parse_arguments(int argc, char **argv, char **certid)
{
	int c;

	while ((c = getopt(argc, argv, "hc:")) != -1) {
		switch (c) {
		case 'c':
			if (strncmp("true", optarg, 5) != 0 && strncmp("false", optarg, 5) != 0)
				return -1;
			if (strncmp("false", optarg, 5) == 0)
				printf(*certid, "%s/0", PROVISION_STORAGE);
			break;
		case 'h':
			usage();
			return 1;
		case '?':
			if (optopt == 'c')
				fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
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
	artik_security_module *secu = NULL;
	artik_security_handle handle_secu = NULL;
	char certid[SECU_LOCATION_STRLEN+2] = ARTIK_DEVICE_CERT_ID;
	artik_error res = S_OK;
	int watchid = -1, signalid = -1;

	res = parse_arguments(argc, argv, (char **)&certid);
	if (res != S_OK)
		goto exit;
	res = init(&loop, &secu, &handle_secu, &signalid, &watchid, (char *)certid);
	if (res != S_OK)
		goto exit;
	loop->run();
 exit:
	if (res != S_OK)
		fprintf(stderr, "security: Failed due to error, %s\n", error_msg(res));
	if (secu && handle_secu)
		secu->release(handle_secu);
	if (secu)
		artik_release_api_module(secu);
	if (loop && watchid != -1)
		loop->remove_fd_watch(watchid);
	if (loop && signalid != -1)
		loop->remove_signal_watch(signalid);
	if (loop)
		artik_release_api_module(loop);
	return 1;
}
