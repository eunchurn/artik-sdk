#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>

#include <artik_module.h>
#include <artik_security.h>

#define CMD_READ_STORAGE 1
#define CMD_WRITE_STORAGE 2
#define CMD_REMOVE_STORAGE 3
#define CMD_HELP 4

static void usage(void)
{
	printf("USAGE:\n");
	printf(" security-storage --read <data id> <size> [data path]\n");
	printf(" security-storage --write <data id> <data path>\n");
	printf(" security-storage --remove <data id>\n");
	printf("\n");

	printf("OPTIONS:\n");
	printf("\t-read, --read <data id> <size> [data path]\n");
	printf("\t\tRead <size> bytes from secure element storage\n");
	printf("\t\tidentified by <data id>.\n");
	printf("\t\tSave the read data in [data path] when [data path] is specified.\n");

	printf("\t-write, --write <data id> <data path>\n");
	printf("\t\tWrite the content of <data path> in the <data id> store\n");
	printf("\t\tof the secure element.\n");

	printf("\t-remove, --remove <data id>\n");
	printf("\t\tRemove the <data id> store of the secure storage.\n");
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

static bool write_secure_storage(const char *data_id, const char *path)
{
	artik_security_module *security = (artik_security_module *) artik_request_api_module("security");
	artik_security_handle handle = NULL;
	FILE *fp = NULL;
	bool res = false;
	unsigned int data_len = 0;
	unsigned char *data = NULL;
	artik_error err;
	long file_len;

	if (!path) {
		fprintf(stderr, "Error: <data path> not provided.\n");
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
	rewind(fp);
	data_len = file_len;

	data = malloc(data_len);
	if (!data) {
		fprintf(stderr, "Error: Not enough memory.\n");
		goto exit;
	}

	if (fread(data, 1, data_len, fp) <= 0) {
		fprintf(stderr, "Cannot read the file '%s'", path);
		goto exit;
	}

	err = security->write_secure_storage(handle, data_id, 0, data, data_len);
	if (err != S_OK) {
		fprintf(stderr, "Error: Cannot write data in '%s'.\n", data_id);
		goto exit;
	}
	res = true;

exit:
	if (fp)
		fclose(fp);

	if (data)
		free(data);

	if (handle)
		security->release(handle);

	if (security != INVALID_MODULE)
		artik_release_api_module(security);

	return res;
}

static bool read_secure_storage(const char *data_id, int read_size, const char *path)
{
	artik_security_module *security = (artik_security_module *) artik_request_api_module("security");
	artik_security_handle handle = NULL;
	bool res = false;
	unsigned char *data = NULL;
	unsigned int data_size = 0;
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

	err = security->read_secure_storage(handle, data_id, 0, read_size, &data, &data_size);
	if (err != S_OK) {
		fprintf(stderr, "Error: Failed to read in '%s'.\n", data_id);
		goto exit;
	}

	if (path) {
		FILE *fp = fopen(path, "w");

		if (!fp) {
			fprintf(stderr, "Error: Failed to open file '%s'.\n", path);
			goto exit;
		}

		fprintf(stdout, "Save data in '%s'.\n", path);
		fwrite(data, 1, data_size, fp);
		fclose(fp);
	} else {
		fprintf(stdout, "Read %d bytes from '%s':\n", data_size, data_id);
		output_buffer(data, data_size);
	}

	res = true;
exit:
	if (data)
		free(data);

	if (handle)
		security->release(handle);

	if (security != INVALID_MODULE)
		artik_release_api_module(security);

	return res;
}

static bool remove_secure_storage(const char *data_id)
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

	err = security->remove_secure_storage(handle, data_id);
	if (err != S_OK) {
		fprintf(stderr, "Error: Failed to remove data.\n");
		goto exit;
	}

	fprintf(stdout, "Data '%s' removed.\n", data_id);
	res = true;
exit:
	if (handle)
		security->release(handle);

	if (security != INVALID_MODULE)
		artik_release_api_module(security);

	return res;

}

static bool string_to_positive_integer(const char *buff, unsigned int *integer)
{
	char *end = NULL;
	long val = 0;

	if (buff == NULL || *buff == '\0')
		return false;

	errno = 0;
	val = strtol(buff, &end, 10);

	if ((!val && errno != 0) || buff == end || end == NULL || *end != '\0')
		return false;

	if (val < 0)
		return false;

	*integer = (unsigned int) val;
	return true;
}

const struct option longopts[] = {
	{
		.name = "read",
		.has_arg = required_argument,
		.flag = NULL,
		.val = CMD_READ_STORAGE
	},
	{
		.name = "write",
		.has_arg = required_argument,
		.flag = NULL,
		.val = CMD_WRITE_STORAGE
	},
	{
		.name = "remove",
		.has_arg = required_argument,
		.flag = NULL,
		.val = CMD_REMOVE_STORAGE
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
	char *data_id = NULL;
	char *path = NULL;
	int mode = -1;
	unsigned int read_size = 0;

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
		case CMD_READ_STORAGE:
			if (optind + 1 > argc) {
				fprintf(stderr, "Error: Too few arguments.\n");
				return -1;
			}

			data_id = optarg;

			if (!string_to_positive_integer(argv[optind], &read_size)) {
				fprintf(stderr, "Error: <size> in not a positive integer.\n");
				return -1;
			}


			if (optind + 2 == argc)
				path = argv[optind + 1];
			break;

		case CMD_WRITE_STORAGE:
		case CMD_REMOVE_STORAGE:
			data_id = optarg;
			if (optind + 1 == argc)
				path = argv[optind];

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

	if (!data_id) {
		usage();
		return -1;
	}

	switch (mode) {
	case CMD_READ_STORAGE:
		if (!read_secure_storage(data_id, read_size, path))
			return -1;

		break;
	case CMD_WRITE_STORAGE:
		if (!write_secure_storage(data_id, path))
			return -1;

		break;
	case CMD_REMOVE_STORAGE:
		if (!remove_secure_storage(data_id))
			return -1;

		break;
	default:
		fprintf(stderr, "Error: mode '%d' is not supported\n", mode);
		break;
	}

	return 0;

}
