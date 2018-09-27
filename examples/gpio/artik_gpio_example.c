#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <artik_module.h>
#include <artik_loop.h>
#include <artik_platform.h>
#include <artik_gpio.h>

static bool string_to_positive_integer(const char *buff, int *integer, const char *arg_name)
{
	if (buff == NULL || *buff == '\0') {
		fprintf(stderr, "Error: Failed to parse argument '%s'.\n", arg_name);
		return false;
	}

	char *end = NULL;
	long val = strtol(buff, &end, 10);

	if (errno != 0 || buff == end || end == NULL || *end != '\0') {
		fprintf(stderr, "Error: Failed to parse argument '%s': '%s' is not a number.\n", arg_name, buff);
		return false;
	}

	if (val < 0) {
		fprintf(stderr, "Error: Argument '%s' must be a positive number.\n", arg_name);
		return false;
	}

	*integer = (int) val;
	return true;
}

void usage(void)
{
	printf("Usage: gpio-example [COMMAND]\n");
	printf("Commands:\n");
	printf("  write <num> [0|1]\n");
	printf("  read <num>\n");
	printf("  watch [-t] <num>\n");
	printf("    -t <timeout>\n");
}

typedef enum {
	GPIO_ACTION_WRITE,
	GPIO_ACTION_READ,
	GPIO_ACTION_WATCH
} gpio_action_t;

static void gpio_callback(void *user_data, int value)
{
	unsigned int id = (unsigned int)(uintptr_t)user_data;

	fprintf(stdout, "The new value for GPIO %d is %d", id, value);
}

static void gpio_timeout(void *user_data)
{
	artik_loop_module *loop = (artik_loop_module *)artik_request_api_module("loop");

	loop->quit();
}

static int quit_cb(void *user_data)
{
	artik_loop_module *loop = artik_request_api_module("loop");

	loop->quit();
	return 0;
}

static void gpio_io(gpio_action_t action, int gpio_id, int value, int timeout)
{
	artik_gpio_module *gpio = (artik_gpio_module *)
		artik_request_api_module("gpio");
	artik_gpio_handle handle = NULL;
	char name[16];
	artik_gpio_config config = { gpio_id, name, GPIO_DIR_INVALID, GPIO_EDGE_INVALID, 0, NULL };
	artik_error ret;

	snprintf(name, 16, "gpio%d", config.id);

	switch (action) {
	case GPIO_ACTION_WRITE:
		config.dir = GPIO_OUT;
		config.edge = GPIO_EDGE_NONE;
		break;
	case GPIO_ACTION_READ:
	case GPIO_ACTION_WATCH:
		config.dir = GPIO_IN;
		config.edge = GPIO_EDGE_BOTH;
		break;
	}

	if (!gpio) {
		fprintf(stderr, "Error: Failed to request cloud module\n");
		exit(-1);
	}

	ret = gpio->request(&handle, &config);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to request GPIO %d: %s\n", gpio_id, error_msg(ret));
		artik_release_api_module(gpio);
		exit(-1);
	}

	switch (action) {
	case GPIO_ACTION_WRITE:
		ret = gpio->write(handle, value);
		if (ret != S_OK) {
			fprintf(stderr, "Error: Failed to write to GPIO %d: %s\n", gpio_id, error_msg(ret));
			goto exit;
		}
		fprintf(stdout, "Write %d to GPIO %d\n", value, gpio_id);
		gpio->release(handle);
		break;
	case GPIO_ACTION_READ:
		ret = gpio->read(handle);
		if (ret < 0) {
			fprintf(stderr, "Error: Failed to read form GPIO %d: %s\n", gpio_id, error_msg(ret));
			goto exit;
		}
		fprintf(stdout, "Read %d from GPIO %d\n", ret, gpio_id);

		break;
	case GPIO_ACTION_WATCH: {
		artik_loop_module *loop = (artik_loop_module *)artik_request_api_module("loop");
		int tid;
		int signalid;

		ret = gpio->set_change_callback(handle, gpio_callback, (void *)(uintptr_t)config.id);
		if (ret != S_OK) {
			fprintf(stderr, "Error: Failed to set change callback for GPIO %d: %s\n",
					gpio_id, error_msg(ret));
			artik_release_api_module(loop);
			goto exit;
		}

		ret = loop->add_signal_watch(SIGINT, quit_cb, NULL, &signalid);
		if (ret != S_OK) {
			fprintf(stderr, "Error: Failed to setup signal handler: %s\n", error_msg(ret));
			artik_release_api_module(loop);
			goto exit;
		}

		if (timeout > 0)
			loop->add_timeout_callback(&tid, timeout * 1000, gpio_timeout, handle);

		loop->run();

		artik_release_api_module(loop);
		break;
	}
	}

	gpio->release(handle);
	artik_release_api_module(gpio);
	return;

exit:
	gpio->release(handle);
	artik_release_api_module(gpio);
	exit(-1);
}

int main(int argc, char **argv)
{
	int gpio_id;
	int arg_gpio_id = 2;
	int timeout = 0;
	gpio_action_t action;
	int value = 0;

	if (argc < 3) {
		fprintf(stderr, "Error: Too few arguments.\n");
		usage();
		return -1;
	}

	if (strcmp(argv[1], "write") == 0) {
		action = GPIO_ACTION_WRITE;
		if (argc < 4) {
			fprintf(stderr, "Error: Too few arguments.\n");
			usage();
			return -1;
		}

		if (!string_to_positive_integer(argv[3], &value, "[0|1]"))
			return -1;

		if (value != 1 && value != 0) {
			fprintf(stderr, "Error: Argument [0|1] must be 0 or 1.\n");
			return -1;
		}
	} else if (strcmp(argv[1], "read") == 0) {
		action = GPIO_ACTION_READ;
	} else if (strcmp(argv[1], "watch") == 0) {
		int c;

		optind = 2;
		while ((c = getopt(argc, argv, "+t:")) != -1) {
			switch (c) {
			case 't':
				if (!string_to_positive_integer(optarg, &timeout, "timeout"))
					return -1;
				break;
			case '?':
				if (optopt == 't')
					fprintf(stderr, "Error: Option '-%c' requires an argument.\n", optopt);
				else
					fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);
				usage();
				break;
			default:
				abort();
			}
		}

		if (argc == optind) {
			fprintf(stderr, "Error: Too few arguments.");
			usage();
			return -1;
		}
		arg_gpio_id = optind;
		action = GPIO_ACTION_WATCH;
	} else {
		fprintf(stderr, "Error: Unknow operation '%s'\n", argv[1]);
		exit(-1);
	}

	if (!string_to_positive_integer(argv[arg_gpio_id], &gpio_id, "<num>"))
		exit(-1);

	gpio_io(action, gpio_id, value, timeout);
}
