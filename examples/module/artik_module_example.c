#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <artik_module.h>
#include <artik_platform.h>

typedef void (*command_callback_t)(int argc, char **argv);

typedef struct {
	const char *cmd;
	command_callback_t callback;
} command_t;

void usage(void)
{
	printf("Usage: module-example <COMMAND>\n");
	printf("\n");
	printf("Options:\n");
	printf("  -h                   Display this help and exit\n");
	printf("\n");
	printf("Command:\n");
	printf("  version              Show version number\n");
	printf("  platform             Show platform name\n");
	printf("  modules [<module>]   Show available modules\n");
}

static void execute_cmd(command_t *cmd, int argc, char **argv)
{
	int i = 0;

	if (argc < 2) {
		fprintf(stderr, "Error: Too few arguments.\n");
		usage();
		exit(-1);
	}

	while (cmd[i].cmd != NULL) {
		if (strcmp(argv[1], cmd[i].cmd) == 0)
			break;
		i++;
	}

	if (cmd[i].cmd == NULL) {
		fprintf(stderr, "Error: Unknow COMMAND '%s'\n", argv[1]);
		exit(-1);
	}

	cmd[i].callback(argc - 1, argv + 1);
}

static void version_cmd(int argc, char **argv)
{
	artik_api_version version;
	artik_error ret;

	ret = artik_get_api_version(&version);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to get ARTIK API version: %s\n", error_msg(ret));
		exit(-1);
	}

	fprintf(stdout, "ARTIK API version: %s\n", version.version);
}

static void platform_cmd(int argc, char **argv)
{
	char platname[MAX_PLATFORM_NAME];

	artik_get_platform_name(platname);
	fprintf(stdout, "Your platform is %s\n", platname);
}

static void modules_cmd(int argc, char **argv)
{
	char *module = NULL;
	artik_api_module *modules = NULL;
	artik_api_module *result = NULL;
	int i = 0;
	int num_modules = 0;

	if (argc > 1)
		module = argv[1];

	artik_get_available_modules(&modules, &num_modules);
	if (module) {
		for (i = 0; i < num_modules; i++) {
			if (strcmp(modules[i].name, module) == 0) {
				result = modules + i;
				break;
			}
		}

		if (result) {
			fprintf(stdout, "The module %s is available.\n", module);
		} else {
			fprintf(stdout, "Module %s not found.\n", module);
			exit(-1);
		}
	} else {
		fprintf(stdout, "Available modules are:\n");
		for (i = 0; i < num_modules; i++)
			fprintf(stdout, "  * %s\n", modules[i].name);
	}
}

int main(int argc, char **argv)
{
	command_t cmd[] = {
		{ "version", version_cmd },
		{ "platform", platform_cmd },
		{ "modules", modules_cmd },
		{ NULL, NULL }
	};
	int c;

	while ((c = getopt(argc, argv, "h")) != -1) {
		switch (c) {
		case 'h':
			usage();
			return 0;
		case '?':
			fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);
			return -1;
		default:
			abort();
		}
	}

	execute_cmd(cmd, argc - optind + 1, argv + optind - 1);
}
