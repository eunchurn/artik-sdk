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
	printf(" security-key --generate KEY [public key]");
	printf(" security-key --getpubkey KEY <public key>\n");
	printf(" security-key --remove KEY\n");
	printf(" security-key --set KEY <key>\n");
	printf("\n");
	printf("OPTIONS:\n");
	printf("\t-generate, --generate KEY [public key]\n");
	printf("\t\tGenerate the new key described by KEY.\n");
	printf("\t\tThe [public key] argument is an optional path to save the public\n");
	printf("\t\tkey in a file. When [public key] is not provided and the public\n");
	printf("\t\tkey is available the public key is printed on stdout.\n");
	printf("\t-getpubkey, --getpubkey KEY [public key]\n");
	printf("\t\tGet the public key described by KEY and display this key on\n");
	printf("\t\tstdout.\n");
	printf("\t\tThe [public key] argument is an optional path to save the public\n\n");
	printf("\t\tkey in a file.\n");
	printf("\t-remove, --remove KEY\n");
	printf("\t\tRemove the key described by KEY from the SE.\n");
	printf("\t-set, --set KEY <key>\n");
	printf("\t\tSet a key in SE.\n");
	printf("\t\tThe <key> argument is a file containing the key.\n");
	printf("\t\tFor RSA, DH and ECDSA the key must be in DER format.\n");
	printf("\t\tFor AES the key is in raw format.\n");
	printf("\t-help, --help\n");
	printf("\t\tPrint this help message.\n");
	printf("\n");
	printf("KEY:\n");
	printf("\tKEY as the following format\n"
		   "\t\ttye=RSA|EC|DH|HMAC|AES,size=<size>,id=<key_id>,ec=brainpool|prime,dh_rfc5114\n\n");
	printf("\t* type=RSA|EC|DH|HMAC|AES\n");
	printf("\t\tThe type of the key. Only RSA, EC and AES are supported.\n");
	printf("\t* size=<size>\n");
	printf("\t\tThe size of the key\n");
	printf("\t* id=<key_id>\n");
	printf("\t\tThe key identifier in SE.\n");
	printf("\t* ec=brainpool|prime\n");
	printf("\t\tThe type of the curve for an EC key.\n");
	printf("\t* dh_rfc5114\n");
	printf("\t\tUse Diffie-Helman groups of RFC 5114\n");

}

static bool convert_to_see_algo(
	const char *key_algo, const char *curve_type, bool dh_5114, int key_size, see_algorithm *algo)
{
	bool res = true;

	if (strcmp(key_algo, "RSA") == 0) {
		switch (key_size) {
		case 1024:
			*algo = RSA_1024;
			break;
		case 2048:
			*algo = RSA_2048;
			break;
		default:
			res = false;
			fprintf(stderr, "Error: Value of 'size' must be 1024 or 2048 for RSA algorithm.\n");
			break;
		}
	} else if (strcmp(key_algo, "EC") == 0) {
		if (!curve_type) {
			fprintf(stderr, "Error: 'ec' must be set when 'type' is EC.\n");
			return false;
		}

		if (strcmp(curve_type, "brainpool") == 0) {
			switch (key_size) {
			case 256:
				*algo = ECC_BRAINPOOL_P256R1;
				break;
			default:
				res = false;
				fprintf(stderr, "Error: Value of 'size' must be 256 for ecc brainpool curve.\n");
				break;
			}
		} else if (strcmp(curve_type, "prime") == 0) {
			switch (key_size) {
			case 256:
				*algo = ECC_SEC_P256R1;
				break;
			case 384:
				*algo = ECC_SEC_P384R1;
				break;
			case 521:
				*algo = ECC_SEC_P521R1;
				break;
			default:
				res = false;
				fprintf(stderr, "Error: Value of 'size' must be 256, 384 or 521 for ecc nist curve.\n");
				break;
			}
		} else {
			res = false;
			fprintf(stderr, "Error: Value of 'ec' must be brainpool or prime.\n");
		}
	} else if (strcmp(key_algo, "AES") == 0) {
		switch (key_size) {
		case 128:
			*algo = AES_128;
			break;
		case 192:
			*algo = AES_192;
			break;
		case 256:
			*algo = AES_256;
			break;
		default:
			res = false;
			fprintf(stderr, "Error: Value of 'size' must be 128, 192 or 256 for AES algorithm.\n");
			break;
		}
	} else if (strcmp(key_algo, "HMAC") == 0) {
		*algo = HMAC_ALGORITHM;
	} else if (strcmp(key_algo, "DH")) {
		switch (key_size) {
		case 1024:
			if (dh_5114)
				*algo = DH_1024_5114;
			else
				*algo = DH_1024;
			break;
		case 2048:
			if (dh_5114)
				*algo = DH_2048_5114;
			else
				*algo = DH_2048;
			break;
		default:
			res = false;
			fprintf(stderr, "Error: Value of 'size' must be 1024 or 2048 for DH algorithm.\n");
		}
	} else {
		res = false;
		fprintf(stderr, "Error: Value of 'type' must be RSA, EC, AES, DH or HMAC.\n");
	}

	return res;
}

static bool string_to_positive_integer(const char *buff, int *integer, const char *arg_name)
{
	char *end = NULL;
	long val = 0;

	if (buff == NULL || *buff == '\0') {
		fprintf(stderr, "Error: Failed to parse argument '%s'.\n", arg_name);
		return false;
	}

	errno = 0;
	val = strtol(buff, &end, 10);

	if ((!val && errno != 0) || buff == end || end == NULL || *end != '\0') {
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

static bool parse_algorithm(
	see_algorithm *algo, char **key_id, unsigned int *pkey_size, char *subopts)
{
	enum {
		TYPE_OPT = 0,
		SIZE_OPT,
		KEY_ID_OPT,
		EC_TYPE_OPT,
		DH_5114
	};

	char *const token[] = {
		[TYPE_OPT] = "type",
		[SIZE_OPT] = "size",
		[KEY_ID_OPT] = "id",
		[EC_TYPE_OPT] = "ec",
		[DH_5114] = "dh_5114",
		NULL
	};

	char *value = NULL;

	char *key_algo = NULL;
	int key_size = -1;
	char *curve_type = NULL;
	bool dh_5114 = false;

	while (*subopts != '\0') {
		switch (getsubopt(&subopts, token, &value)) {
		case TYPE_OPT:
			if (value == NULL) {
				fprintf(stderr, "Error: Missing value for '%s'\n", token[TYPE_OPT]);
				return false;
			}

			key_algo = value;
			break;
		case SIZE_OPT:
			if (value == NULL) {
				fprintf(stderr, "Error: Missing value for '%s'\n", token[SIZE_OPT]);
				return false;
			}

			if (!string_to_positive_integer(value, &key_size, "size"))
				return false;

			if (pkey_size)
				*pkey_size = key_size;

			break;
		case KEY_ID_OPT:
			if (value == NULL) {
				fprintf(stderr, "Error: Missing value for '%s'\n", token[KEY_ID_OPT]);
				return false;
			}

			*key_id = value;
			break;
		case EC_TYPE_OPT:
			if (value == NULL) {
				fprintf(stderr, "Error: Missing value for '%s'\n", token[EC_TYPE_OPT]);
				return false;
			}

			curve_type = value;
			break;

		case DH_5114:
			dh_5114 = true;
			break;

		default:
			fprintf(stderr, "Error: Unknow sub-option '%s'\n", value);
			return false;
		}
	}

	if (!*key_id || !key_algo || key_size < 0) {
		fprintf(stderr, "Error: Missing sub-option 'id', 'type' or 'size'\n");
		return false;
	}

	if (!convert_to_see_algo(key_algo, curve_type, dh_5114, key_size, algo))
		return false;

	return true;
}

void output_buffer(unsigned char *buffer, int length)
{
	int i = 0;

	if (length == 0)
		fprintf(stdout, "\n");

	while (i < length) {
		unsigned char array[16];
		int j = 0;

		memcpy(array, buffer + i, 16);
		for (j = 0; j < 16 && i + j < length; j++) {
			fprintf(stdout, "%02X ", array[j]);
			if (j % 4 == 3)
				fprintf(stdout, " ");
		}
		if (length > 16) {
			while (j < 16) {
				fprintf(stdout, "   ");
				if (j % 4 == 3)
					fprintf(stdout, " ");
				j++;
			}
		}
		fprintf(stdout, " ");
		for (j = 0; j < 16 && i + j < length; j++) {
			if (isprint(array[j]))
				fprintf(stdout, "%c", array[j]);
			else
				fprintf(stdout, ".");
		}
		fprintf(stdout, "\n");
		i += 16;
	}
}

static bool get_pubkey(see_algorithm algo, char *key_id, char *public_key_path)
{
	artik_security_module *security = (artik_security_module *) artik_request_api_module("security");
	unsigned char *pubkey = NULL;
	unsigned int pubkey_size;
	artik_security_handle handle = NULL;
	artik_error ret;
	bool res = false;

	if (!(algo & RSA_ALGORITHM) && !(algo & ECC_ALGORITHM)) {
		fprintf(stderr, "Error: Only asymmetric cryptography algorithm (RSA or EC) has an public key\n");
		return false;
	}

	if (!security) {
		fprintf(stderr, "Error: Unable to request security module.\n");
		goto exit;
	}

	ret = security->request(&handle);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to request security instance (err=%s).\n", error_msg(ret));
		goto exit;
	}

	ret = security->get_publickey(handle, algo, key_id, &pubkey, &pubkey_size);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to get public key (err=%s).\n", error_msg(ret));
		goto exit;
	}

	if (public_key_path) {
		FILE *fp = fopen(public_key_path, "w");

		if (!fp) {
			fprintf(stderr, "Error: Failed to open %s\n", public_key_path);
			goto exit;
		}

		fprintf(stdout, "Save public key to %s\n", public_key_path);
		fwrite(pubkey, 1, pubkey_size, fp);
		fclose(fp);
	} else {
		fprintf(stdout, "Public key of %s:\n", key_id);
		output_buffer(pubkey, pubkey_size);
	}

	res = true;

exit:
	if (pubkey)
		free(pubkey);

	if (handle)
		security->release(handle);

	if (security)
		artik_release_api_module(security);

	return res;
}

static bool generate_key(
	see_algorithm algo, char *key_id, unsigned int key_size, char *public_key_path)
{
	artik_security_module *security = (artik_security_module *) artik_request_api_module("security");
	artik_security_handle handle = NULL;
	artik_error ret;
	bool res = false;
	struct hmac_key_param hmac_param;
	struct rsa_key_param rsa_param;
	/* This is the exponent used by OpenSSL for RSA (i.e. 65537) */
	unsigned char rsa_exponent[] = { 0x00, 0x01, 0x00, 0x01 };
	void *key_param = NULL;

	if (!security) {
		fprintf(stderr, "Error: Unable to request security module.\n");
		goto exit;
	}

	ret = security->request(&handle);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to request security instance (err=%s).\n", error_msg(ret));
		goto exit;
	}

	if (algo & RSA_ALGORITHM) {
		rsa_param.exponent_size = 4;
		rsa_param.exponent = rsa_exponent;
		key_param = &rsa_param;
	} else if (algo & HMAC_ALGORITHM) {
		hmac_param.key_size = key_size;
		key_param = &hmac_param;
	}

	ret = security->generate_key(handle, algo, key_id, key_param);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to generate key (err %s)\n", error_msg(ret));
		goto exit;
	}

	if ((algo & RSA_ALGORITHM) || (algo & ECC_ALGORITHM)) {
		if (!get_pubkey(algo, key_id, public_key_path))
			goto exit;

	}

	res = true;
exit:
	if (handle)
		security->release(handle);

	if (security)
		artik_release_api_module(security);

	return res;
}

static bool remove_key(see_algorithm algo, char *key_id)
{
	artik_security_module *security = (artik_security_module *) artik_request_api_module("security");
	artik_security_handle handle = NULL;
	artik_error ret;
	bool res = false;

	if (!security) {
		fprintf(stderr, "Error: Unable to request security module.\n");
		goto exit;
	}

	ret = security->request(&handle);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to request security instance (err=%s).\n", error_msg(ret));
		goto exit;
	}

	ret = security->remove_key(handle, algo, key_id);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to remove key '%s' from SE (err %s).\n", key_id, error_msg(ret));
		goto exit;
	}

	fprintf(stdout, "Key '%s' removed\n", key_id);
	res = true;

exit:
	if (handle)
		security->release(handle);

	if (security)
		artik_release_api_module(security);

	return res;
}

static bool set_key(see_algorithm algo, char *key_id, char *key_path)
{
	artik_security_module *security = (artik_security_module *) artik_request_api_module("security");
	artik_security_handle handle = NULL;
	bool res = false;
	FILE *fp = NULL;
	unsigned char *key = NULL;
	artik_error ret;
	unsigned int key_length;
	int err;
	long file_len;

	if (!security) {
		fprintf(stderr, "Error: Unable to request security module.\n");
		goto exit;
	}

	ret = security->request(&handle);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to request security instance (err=%s).\n", error_msg(ret));
		goto exit;
	}

	fp = fopen(key_path, "r");

	if (!fp) {
		fprintf(stderr, "Error: Unable to open file '%s'.\n", key_path);
		goto exit;
	}

	if (fseek(fp, 0, SEEK_END) < 0) {
		fprintf(stderr, "Error: Cannot get the size of '%s'.\n", key_path);
		goto exit;
	}

	file_len = ftell(fp);
	if (file_len < 0) {
		fprintf(stderr, "Error: Cannot get the size of '%s'.\n", key_path);
		goto exit;
	}
	key_length = file_len;

	rewind(fp);

	key = malloc(key_length);
	if (!key) {
		fprintf(stderr, "Error: Not enough memory.\n");
		goto exit;
	}

	err = fread(key, 1, key_length, fp);
	if (err <= 0) {
		fprintf(stderr, "Cannot read the file '%s'", key_path);
		goto exit;
	}

	ret = security->set_key(handle, algo, key_id, key, key_length);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to set key (err=%s)", error_msg(ret));
		goto exit;
	}

	fprintf(stderr, "Key '%s' created.\n", key_id);
	res = true;

exit:
	if (fp)
		fclose(fp);

	if (key)
		free(key);

	if (handle)
		security->release(handle);

	if (security)
		artik_release_api_module(security);

	return res;
}

#define CMD_GENERATE_KEY 1
#define CMD_GET_PUBKEY 2
#define CMD_REMOVE_KEY 3
#define CMD_SET_KEY 4
#define CMD_HELP 5

const struct option longopts[] = {
	{
		.name = "generate",
		.has_arg = required_argument,
		.flag = NULL,
		.val = CMD_GENERATE_KEY
	},
	{
		.name = "getpubkey",
		.has_arg = required_argument,
		.flag = NULL,
		.val = CMD_GET_PUBKEY
	},
	{
		.name = "remove",
		.has_arg = required_argument,
		.flag = NULL,
		.val = CMD_REMOVE_KEY
	},
	{
		.name = "set",
		.has_arg = required_argument,
		.flag = NULL,
		.val = CMD_SET_KEY
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
	see_algorithm algo = RSA_ALGORITHM;
	int option_idx;
	int c;
	char *key_id = NULL;
	char *key_path = NULL;
	int mode = -1;
	unsigned int key_size = 0;

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
		case CMD_GENERATE_KEY:
		case CMD_GET_PUBKEY:
		case CMD_REMOVE_KEY:
		case CMD_SET_KEY:
			if (!parse_algorithm(&algo, &key_id, &key_size, optarg))
				return -1;


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

	if (key_id == NULL) {
		usage();
		return -1;
	}

	if (optind + 1 == argc)
		key_path = argv[optind];

	switch (mode) {
	case CMD_GENERATE_KEY:
		if (!generate_key(algo, key_id, key_size, key_path))
			return -1;

		break;
	case CMD_GET_PUBKEY:
		if (!get_pubkey(algo, key_id, key_path))
			return -1;

		break;
	case CMD_SET_KEY:
		if (!set_key(algo, key_id, key_path))
			return -1;

		break;
	case CMD_REMOVE_KEY:
		if (!remove_key(algo, key_id))
			return -1;

		break;
	default:
		fprintf(stderr, "Error: mode '%d' is not supported\n", mode);
		break;
	}

	return 0;
}
