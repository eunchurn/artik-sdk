#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <artik_loop.h>
#include <artik_module.h>
#include <artik_network.h>

#define MAX_PACKET_SIZE 1024

typedef bool (*command_callback_t)(void *user_data, int argc, char **argv);

typedef struct {
	const char *name;
	command_callback_t callback;
	bool is_only_interactive_mode;
	void *user_data;
} command_t;

typedef struct {
	artik_network_module *net;
	command_t *cmd;
} network_shell_t;

typedef struct {
	artik_network_module *net;
	artik_network_dhcp_client_handle handle;
} dhcp_client_t;

typedef enum {
	CLIENT_START,
	CLIENT_STOP
} dhcp_client_mode_t;

typedef struct {
	artik_network_module *net;
	artik_network_dhcp_server_handle handle;
} dhcp_server_t;

typedef enum {
	SERVER_START,
	SERVER_STOP
} dhcp_server_mode_t;

static bool string_to_uint(const char *buff, unsigned int *integer, const char *arg_name)
{
	if (buff == NULL || buff == '\0') {
		fprintf(stderr, "Failed to parse argument '%s'.\n", arg_name);
		return false;
	}

	char *end = NULL;
	long val = strtol(buff, &end, 10);

	if (errno != 0 || buff == end || end == NULL || *end != '\0') {
		fprintf(stderr, "Failed to parse argument '%s': '%s' is not a number.\n", arg_name, buff);
		return false;
	}

	if (val <= 0) {
		fprintf(stderr, "Argument '%s' must be a positive number.\n", arg_name);
		return false;
	}

	*integer = (unsigned int) val;
	return true;
}

static void usage(void)
{
	printf("Usage: network-example <COMMAND>\n");
	printf("Options:\n");
	printf("  -h\n");
	printf("Commands:\n");
	printf("  config <interface> [set <ip> <netmask> <gw> <dns>]\n");
	printf("  public-ip");
	printf("  ");
}

static void interactive_shell_network(void)
{
	printf("config <interface> [set <ip> <netmask> <gw> <dns>]\n");
	printf("dhcp start|stop\n");
	printf("dhcp-server start|stop\n");
	printf("public-ip\n");
}

static bool exec_cmd(command_t *cmd, int argc, char **argv, bool isInteractive)
{
	int i = 0;

	if (argc < 2) {
		fprintf(stderr, "Error: Too few arguments\n");
		if (isInteractive)
			interactive_shell_network();
		else
			usage();
		return false;
	}

	while (cmd[i].name != NULL) {
		if (strcmp(argv[0], cmd[i].name) == 0)
			break;
		i++;
	}

	if (cmd[i].name == NULL) {
		fprintf(stderr, "Error: Unknow command '%s'\n", argv[1]);
		if (isInteractive)
			interactive_shell_network();
		else
			usage();
		return false;
	}

	if (!cmd[i].is_only_interactive_mode || (cmd[i].is_only_interactive_mode && isInteractive))
		return cmd[i].callback(cmd[i].user_data, argc, argv);

	fprintf(stderr, "Error: The command '%s' is only available in interactive mode.", cmd[i].name);
	return false;
}


static int network_shell(int fd, enum watch_io io, void *user_data)
{
	char buffer[MAX_PACKET_SIZE];
	char **argv = NULL;
	int argc = 0;
	char *p = NULL;
	network_shell_t *net_shell = (network_shell_t *)user_data;
	artik_loop_module *loop = NULL;

	if (fgets(buffer, MAX_PACKET_SIZE, stdin) == NULL)
		return 1;

	p = strtok(buffer, "\n\t ");
	while (p) {
		argv = realloc(argv, sizeof(char *) * ++argc);

		if (argv == NULL) {
			fprintf(stderr, "Error: Not enough memory\n");
			loop = (artik_loop_module *) artik_request_api_module("loop");
			if (loop) {
				loop->quit();
				artik_release_api_module(loop);
			}
			return 0;
		}

		argv[argc - 1] = p;
		p = strtok(NULL, "\n\t ");
	}

	if (argc < 1) {
		fprintf(stderr, "Error: Too few arguments\n");
		write(1, ">", 1);
		return 1;
	}

	exec_cmd(net_shell->cmd, argc, argv, true);
	write(1, ">", 1);

	free(argv);
	return 1;
}

static bool config_cmd(void *user_data, int argc, char **argv)
{
	artik_network_module *net = (artik_network_module *)user_data;
	artik_network_interface_t intf;
	artik_network_config config;
	artik_error ret;

	if (argc < 2) {
		fprintf(stderr, "Error: Too few arguments");
		return false;
	}

	if (strcmp("wifi", argv[1]) == 0) {
		intf = ARTIK_WIFI;
	} else if (strcmp("ethernet", argv[1]) == 0) {
		intf = ARTIK_ETHERNET;
	} else {
		fprintf(stderr, "Error: Unknow interface '%s'\n", argv[2]);
		return false;
	}

	if (argc > 2) {
		if (argc < 6) {
			fprintf(stderr, "Error: Too few arguments\n");
			return false;
		}

		memset(&config, 0, sizeof(artik_network_config));
		strncpy(config.ip_addr.address, argv[2], MAX_IP_ADDRESS_LEN - 1);
		strncpy(config.netmask.address, argv[3], MAX_IP_ADDRESS_LEN - 1);
		strncpy(config.gw_addr.address, argv[4], MAX_IP_ADDRESS_LEN - 1);
		strncpy(config.dns_addr[0].address, argv[5], MAX_IP_ADDRESS_LEN - 1);

		config.ip_addr.type = ARTIK_IPV4;
		config.netmask.type = ARTIK_IPV4;
		config.gw_addr.type = ARTIK_IPV4;
		config.dns_addr[0].type = ARTIK_IPV4;
		ret = net->set_network_config(&config, intf);
		if (ret != S_OK) {
			fprintf(stderr, "Error: Failed to set network configuration: %s", error_msg(ret));
			return false;
		}
	} else {
		int i;

		ret = net->get_network_config(&config, intf);
		if (ret != S_OK) {
			fprintf(stderr, "Error: Failed to get network configuration: %s", error_msg(ret));
			return false;
		}

		fprintf(stdout, "HWaddr %s\n", config.mac_addr);
		fprintf(stdout, "addr %s\n", config.ip_addr.address);
		fprintf(stdout, "mask %s\n", config.netmask.address);
		fprintf(stdout, "gw %s\n", config.gw_addr.address);

		for (i = 0; i < MAX_DNS_ADDRESSES; i++)
			fprintf(stdout, "DNS%d addr %s\n", i, config.dns_addr[i].address);
	}
	return true;
}

static bool public_ip_cmd(void *user_data, int argc, char **argv)
{
	artik_network_module *net = (artik_network_module *)user_data;
	artik_network_ip public_ip;
	artik_error ret;

	ret = net->get_current_public_ip(&public_ip);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to get public IP address: %s", error_msg(ret));
		return false;
	}

	fprintf(stdout, "Our public IP is %s\n", public_ip.address);
	return true;
}

static bool dhcp_cmd(void *user_data, int argc, char **argv)
{
	dhcp_client_t *client = (dhcp_client_t *)user_data;
	artik_network_interface_t intf;
	artik_error ret;
	dhcp_client_mode_t mode;

	if (argc < 2) {
		fprintf(stderr, "Error: Too few arguments\n");
		return false;
	}

	if (strcmp("start", argv[1]) == 0) {
		mode = CLIENT_START;
		if (client->handle) {
			fprintf(stderr, "Error: DHCP client already started\n");
			return false;
		}

		if (argc < 3) {
			fprintf(stderr, "Error: Too few arguments\n");
			return false;
		}

		if (strcmp("wifi", argv[2]) == 0) {
			intf = ARTIK_WIFI;
		} else if (strcmp("ethernet", argv[2]) == 0) {
			intf = ARTIK_ETHERNET;
		} else {
			fprintf(stderr, "Error: Unknow interface '%s'\n", argv[2]);
			return false;
		}
	} else if (strcmp("stop", argv[1]) == 0) {
		mode = CLIENT_STOP;
		if (!client->handle) {
			fprintf(stderr, "Error: DHCP client is not launched\n");
			return false;
		}
	} else {
		fprintf(stderr, "Error: 'dhcp': Unknow command '%s'", argv[1]);
		return false;
	}

	switch (mode) {
	case CLIENT_START:
		ret = client->net->dhcp_client_start(client->handle, intf);
		break;
	case CLIENT_STOP:
		ret = client->net->dhcp_client_stop(client->handle);
		break;
	}

	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to start or stop dhcp client: %s", error_msg(ret));
		return false;
	}

	return true;
}

static bool dhcp_server_cmd(void *user_data, int argc, char **argv)
{
	dhcp_server_t *server = (dhcp_server_t *)user_data;
	dhcp_server_mode_t mode;
	artik_network_dhcp_server_config config;
	artik_error ret;

	if (argc < 2) {
		fprintf(stderr, "Error: Too few argument\n");
		return false;
	}

	if (strcmp("start", argv[1])) {
		mode = SERVER_START;
		if (server->handle) {
			fprintf(stderr, "Error: DHCP server already started\n");
			return false;
		}

		if (argc < 9) {
			fprintf(stderr, "Error: Too few arguments\n");
			return false;
		}

		memset(&config, 0, sizeof(artik_network_dhcp_server_config));
		if (strcmp("wifi", argv[2]) == 0) {
			config.interface = ARTIK_WIFI;
		} else if (strcmp("ethernet", argv[2]) == 0) {
			config.interface = ARTIK_ETHERNET;
		} else {
			fprintf(stderr, "Error: Unknow interface '%s'\n", argv[2]);
			return false;
		}

		strncpy(config.ip_addr.address, argv[3], MAX_IP_ADDRESS_LEN - 1);
		strncpy(config.netmask.address, argv[4], MAX_IP_ADDRESS_LEN - 1);
		strncpy(config.gw_addr.address, argv[5], MAX_IP_ADDRESS_LEN - 1);
		strncpy(config.dns_addr[0].address, argv[6], MAX_IP_ADDRESS_LEN - 1);
		config.ip_addr.type = ARTIK_IPV4;
		config.netmask.type = ARTIK_IPV4;
		config.gw_addr.type = ARTIK_IPV4;
		config.dns_addr[0].type = ARTIK_IPV4;
		strncpy(config.start_addr.address, argv[7], MAX_IP_ADDRESS_LEN - 1);

		if (!string_to_uint(argv[8], &config.num_leases, "<num_leases>"))
			return false;

	} else if (strcmp("stop", argv[1])) {
		mode = SERVER_STOP;
		if (!server->handle) {
			fprintf(stderr, "Error: The DHCP server is not launched\n");
			return false;
		}
	} else {
		fprintf(stderr, "Error: 'dhcp-server': Unknow command '%s'\n", argv[1]);
		return false;
	}

	switch (mode) {
	case SERVER_START:
		ret = server->net->dhcp_server_start(server->handle, &config);
		break;
	case SERVER_STOP:
		ret = server->net->dhcp_server_stop(server->handle);
		break;
	}

	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to start or stop DHCP server: %s\n", error_msg(ret));
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	artik_network_module *net = NULL;
	command_t cmd[] = {
		{ "config", config_cmd, false, NULL },
		{ "public-ip", public_ip_cmd, false, NULL },
		{ "dhcp", dhcp_cmd, true, NULL},
		{ "dhcp-server", dhcp_server_cmd, true, NULL},
		{ NULL, NULL, false, NULL }
	};
	dhcp_client_t dhcp_client;
	dhcp_server_t dhcp_server;
	int c;

	memset(&dhcp_client, 0, sizeof(dhcp_client_t));
	memset(&dhcp_server, 0, sizeof(dhcp_server_t));

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

	net = (artik_network_module *) artik_request_api_module("network");
	if (!net) {
		fprintf(stderr, "Error: Failed to request Network module\n");
		exit(-1);
	}

	dhcp_client.net = net;
	dhcp_server.net = net;
	cmd[0].user_data = net;
	cmd[1].user_data = net;
	cmd[2].user_data = &dhcp_client;
	cmd[3].user_data = &dhcp_server;

	if (argc < 2) {
		artik_loop_module *loop = NULL;
		network_shell_t net_shell = { net, cmd };
		int shellid;
		artik_error ret;

		loop = (artik_loop_module *)artik_request_api_module("loop");
		if (!loop) {
			fprintf(stderr, "Error: Failed to request Loop module\n");
			artik_release_api_module(net);
			return -1;
		}

		ret = loop->add_fd_watch(STDIN_FILENO,
						   (WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL),
						   &network_shell, &net_shell, &shellid);
		if (ret != S_OK) {
			fprintf(stderr, "Error: Failed to create watcher for STDIN: %s\n", error_msg(ret));
			artik_release_api_module(net);
			artik_release_api_module(loop);
			return -1;
		}

		interactive_shell_network();
		write(1, ">", 1);
		loop->run();

	} else if (!exec_cmd(cmd, argc - 1, argv + 1, false)) {
		artik_release_api_module(net);
		return -1;
	}

	artik_release_api_module(net);

	return 0;
}
