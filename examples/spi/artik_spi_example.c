#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <artik_module.h>
#include <artik_spi.h>

typedef enum {
	COMMAND_READ,
	COMMAND_WRITE,
	COMMAND_READWRITE
} command_t;

typedef enum {
	DATA_FORMAT_HEX,
	DATA_FORMAT_STR
} data_format_t;

typedef struct {
	char *tx_buf;
	char *rx_buf;
	int len;
} spi_buffer_t;

void usage(void)
{
	printf("Usage: spi-example <bus> <cs> <COMMAND>\n");
	printf("\n");
	printf("Options:\n");
	printf("  -m <mode>                  Mode of the SPI controller "
		   "(must be 'mode0', 'mode1', 'mode2' or 'mode3')(default mode0)\n");
	printf("  -b <bits>                  Bits per word of the SPI controller (default 8)\n");
	printf("  -s <speed>                 Max speed of the SPI controller (default 500000)\n");
	printf("  -h                         Display this help and exit\n");
	printf("\n");
	printf("Command:\n");
	printf("  read <len>                 Read <len> bits from a SPI device with chipselect <cs> on bus <bus>\n");
	printf("  write [OPTIONS] <data>     Write <data> to a SPI device with chipselect <cs> on bus <bus>\n");
	printf("  Options:\n");
	printf("   -f <format>               Data format must be hex or string (default hex)\n");
	printf("  readwrite [OPTIONS] <data> Perform a read/write transaction over the SPI bus\n");
	printf("  Options:\n");
	printf("   -f <format>               Data format must be hex or string (default hex)\n");
}

static bool string_to_positive_integer(const char *buff, unsigned int *integer, const char *arg_name)
{
	char *end = NULL;
	long val = 0;

	if (buff == NULL || *buff == '\0') {
		fprintf(stderr, "Failed to parse argument '%s'.\n", arg_name);
		return false;
	}

	errno = 0;
	val = strtol(buff, &end, 10);

	if ((!val && errno != 0) || buff == end || end == NULL || *end != '\0') {
		fprintf(stderr, "Failed to parse argument '%s': '%s' is not a number.\n", arg_name, buff);
		return false;
	}

	if (val < 0) {
		fprintf(stderr, "Argument '%s' must be a positive number.\n", arg_name);
		return false;
	}

	*integer = (int) val;
	return true;
}

static bool hex_string_to_array(const char *str, char **buf, int *len)
{
	char *tmp = malloc(sizeof(char)*(strlen(str)+1));
	char *strhex = NULL;
	int count = 0;
	int i = 0;
	int j = 0;
	int str_len = 0;

	if (!tmp) {
		fprintf(stderr, "Error: not enough memory\n");
		return false;
	}

	/* Remove white-space characters */
	for (i = 0; str[i]; i++) {
		if (!isspace(str[i]))
			tmp[count++] = str[i];
	}
	tmp[count] = '\0';

	/* We need a even number of characters, because we convert two characters in one byte */
	if (count % 2 == 0) {
		strhex = tmp;
	} else {
		str_len = sizeof(char) * (count + 2);
		strhex = malloc(str_len);
		if (!strhex) {
			fprintf(stderr, "Error: not enough memory\n");
			free(tmp);
			return false;
		}

		strncpy(strhex, "0", str_len - 1);
		strncat(strhex, tmp, str_len - 1);
		strhex[str_len - 1] = '\0';
		free(tmp);
	}

	count = strlen(strhex);
	*buf = malloc(sizeof(char)*(count << 1));
	if (!*buf) {
		fprintf(stderr, "Error: not enough memory\n");
		free(strhex);
		return false;
	}

	*len = count >> 1;
	for (i = 0; i < count; i += 2) {
		char hex[3] = { 0 };

		if (!isxdigit(strhex[i]) || !isxdigit(strhex[i+1])) {
			fprintf(stderr, "Error: '%s' is not an hexadecimal value\n", str);
			free(*buf);
			*buf = NULL;
			free(strhex);
			return false;
		}

		hex[0] = strhex[i];
		hex[1] = strhex[i+1];

		(*buf)[j++] = strtol(hex, 0, 16);
	}

	free(strhex);

	return true;
}

static bool parse_buffer_arg(int argc, char **argv, spi_buffer_t *buf)
{
	int c;
	data_format_t format = DATA_FORMAT_HEX;

	while ((c = getopt(argc, argv, "+f:")) != -1) {
		switch (c) {
		case 'f':
			if (strcmp(optarg, "string") == 0) {
				format = DATA_FORMAT_STR;
			} else if (strcmp(optarg, "hex") == 0) {
				format = DATA_FORMAT_HEX;
			} else {
				fprintf(stderr, "Error: Unknow format '%s'", optarg);
				return false;
			}
			break;
		case '?':
			if (optopt == 'f')
				fprintf(stderr, "Error: Option '-%c' requires an argument\n", optopt);
			else
				fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);
			usage();
			return false;
		default:
			abort();
		}
	}

	if (optind > argc) {
		fprintf(stderr, "Error: Too few arguments\n");
		return false;
	}

	switch (format) {
	case DATA_FORMAT_STR:
		buf->tx_buf = strdup(argv[optind]);
		if (!buf->tx_buf)
			return false;
		buf->len = strlen(buf->tx_buf);
		break;
	case DATA_FORMAT_HEX:
		if (!hex_string_to_array(argv[optind], &buf->tx_buf, &buf->len))
			return false;
		break;
	}

	return true;
}

static void print_buffer(char *buffer, int length)
{
	int i = 0;

	while (i < length) {
		char array[16] = {0};
		int j;
		size_t size = 16;

		if (size > length - i)
			size = length - i;

		memcpy(array, buffer+i, size);
		for (j = 0 ; j < 16 && i+j < length; j++) {
			fprintf(stdout, "%02X ", array[j]);
			if (j%4 == 3)
				fprintf(stdout, " ");
		}
		if (length > 16) {
			while (j < 16) {
				fprintf(stdout, "   ");
				if (j%4 == 3)
					fprintf(stdout, " ");
				j++;
			}
		}

		fprintf(stdout, " ");
		for (j = 0 ; j < 16 && i+j < length; j++) {
			if (isprint(array[j]))
				fprintf(stdout, "%c", array[j]);
			else
				fprintf(stdout, ".");
		}
		fprintf(stdout, "\n");
		i += 16;
	}
}

static int spi_operation(command_t command, artik_spi_config *config, spi_buffer_t *buf)
{
	artik_spi_module *spi = NULL;
	artik_error ret;
	artik_spi_handle handle;

	spi = (artik_spi_module *)artik_request_api_module("spi");
	if (!spi) {
		fprintf(stderr, "Error: Failed to request SPI module\n");
		return -1;
	}

	ret = spi->request(&handle, config);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to request SPI (bus %d, cs %d): %s",
				config->bus, config->cs, error_msg(ret));
		artik_release_api_module(spi);
		return -1;
	}

	switch (command) {
	case COMMAND_READ:
		ret = spi->read(handle, buf->rx_buf, buf->len);
		if (ret != S_OK) {
			fprintf(stderr, "Error: Failed to read data from SPI controller: %s", error_msg(ret));
			spi->release(handle);
			artik_release_api_module(spi);
			return -1;
		}
		print_buffer(buf->rx_buf, buf->len);
		break;
	case COMMAND_WRITE:
		ret = spi->write(handle, buf->tx_buf, buf->len);
		if (ret != S_OK) {
			fprintf(stderr, "Error: Failed to write data from SPI controller: %s", error_msg(ret));
			spi->release(handle);
			artik_release_api_module(spi);
			return -1;
		}
		break;
	case COMMAND_READWRITE:
		ret = spi->read_write(handle, buf->tx_buf, buf->rx_buf, buf->len);
		if (ret != S_OK) {
			fprintf(stderr, "Error: Failed to read/write data from SPI controller: %s", error_msg(ret));
			spi->release(handle);
			artik_release_api_module(spi);

			return -1;
		}
		print_buffer(buf->rx_buf, buf->len);
		break;
	}

	spi->release(handle);
	artik_release_api_module(spi);

	return 0;
}

int main(int argc, char **argv)
{
	int c;
	command_t command;
	spi_buffer_t buf = { 0 };
	artik_spi_config config = {
		0,
		0,
		SPI_MODE0,
		8,
		500000
	};

	while ((c = getopt(argc, argv, "+hb:m:s:")) != -1) {
		switch (c) {
		case 'm':
			if (strcmp("mode0", optarg) == 0) {
				config.mode = SPI_MODE0;
			} else if (strcmp("mode1", optarg) == 0) {
				config.mode = SPI_MODE1;
			} else if (strcmp("mode2", optarg) == 0) {
				config.mode = SPI_MODE2;
			} else if (strcmp("mode3", optarg) == 0) {
				config.mode = SPI_MODE3;
			} else {
				fprintf(stderr, "Error: Unknow mode '%s'\n", optarg);
				return -1;
			}
			break;
		case 'b':
			if (!string_to_positive_integer(optarg, &config.bits_per_word, "<bits>"))
				return -1;

			break;
		case 's':
			if (!string_to_positive_integer(optarg, &config.max_speed, "<speed>"))
				return -1;

			break;
		case 'h':
			usage();
			return 0;
		case '?':
			if (optopt == 'm' || optopt == 'b' || optopt == 's')
				fprintf(stderr, "Error: Option '-%c' requires an argument\n", optopt);
			else
				fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);
			usage();
			return -1;
		default:
			abort();
		}
	}

	if (optind + 3 > argc) {
		fprintf(stderr, "Error: Too few arguments");
		usage();
		return -1;
	}

	if (!string_to_positive_integer(argv[optind], &config.bus, "<bus>"))
		return -1;

	if (!string_to_positive_integer(argv[optind + 1], &config.cs, "<cs>"))
		return -1;

	if (strcmp(argv[optind + 2], "read") == 0) {
		command = COMMAND_READ;
		if (optind + 4 > argc) {
			fprintf(stderr, "Error: Too few arguments");
			return -1;
		}

		if (!string_to_positive_integer(argv[optind + 3], (unsigned int *)&buf.len, "<len>"))
			return -1;

		if (buf.len > 1024) {
			fprintf(stderr, "Error: read length must be less than 1024\n");
			return -1;
		}

		buf.rx_buf = malloc(sizeof(char) * buf.len);
		if (!buf.rx_buf) {
			fprintf(stderr, "Error: Not enough memory\n");
			return -1;
		}
	} else if (strcmp(argv[optind + 2], "write") == 0) {
		command = COMMAND_WRITE;

		optind += 3;
		if (!parse_buffer_arg(argc, argv, &buf))
			return -1;

	} else if (strcmp(argv[optind + 2], "readwrite") == 0) {
		command = COMMAND_READWRITE;

		optind += 3;
		if (!parse_buffer_arg(argc, argv, &buf))
			return -1;

		if (buf.len > 1024) {
			fprintf(stderr, "Error: read/write length must be less than 1024\n");
			return -1;
		}

		buf.rx_buf = malloc(sizeof(char) * buf.len);
		if (!buf.rx_buf) {
			fprintf(stderr, "Error: Not enough memory\n");
			return -1;
		}
	} else {
		fprintf(stderr, "Error: Unknow command '%s'", argv[optind + 2]);
		return -1;
	}

	int ret = spi_operation(command, &config, &buf);

	if (buf.rx_buf)
		free(buf.rx_buf);

	if (buf.tx_buf)
		free(buf.tx_buf);

	return ret;
}
