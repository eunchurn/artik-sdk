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

#include "os_network.h"

#include <artik_log.h>
#include <artik_list.h>

#include <apps/netutils/dhcpc.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netlib.h>
#include <net/if.h>
#include <net/lwip/prot/icmp.h>
#include <net/lwip/prot/ip4.h>
#include <pthread.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#define DHCPC_HANDLE	((artik_network_dhcp_client_handle)0x44484343)
#define DHCPS_HANDLE	((artik_network_dhcp_server_handle)0x44484353)
#define ICMP_HDR_SIZE (sizeof(struct ip_hdr) + sizeof(struct icmp_echo_hdr))
#define WATCH_ONLINE_STATUS_SCHED_PRI 100
#define WATCH_ONLINE_STATUS_SCHED_POLICY SCHED_RR
#define WATCH_ONLINE_STATUS_STACK_SIZE 2048
#define SOCK_ADDR_IN_ADDR(sa) (((struct sockaddr_in *)(sa))->sin_addr)

typedef struct {
	artik_list node;
	int delay;
	int timeout;
	char *addr;
	struct sockaddr *to;
	artik_watch_online_status_callback callback;
	void *user_data;

	bool resolved;
	bool force;
	int64_t last_echo;
	int64_t last_echo_response;
	bool online_status;
	u16_t seqno;
} echo_t;

typedef struct {
	pthread_t thread;
	pthread_mutex_t mutex;
	int sock;
	artik_list *monitored_servers;
	bool quit;
} watch_online_status_t;

typedef struct {
	size_t count;
	artik_network_ip *dns_addr;
} dns_addresses;

static watch_online_status_t *g_watch_data = NULL;
static const char *wifi_iface = "wl1";

artik_error os_dhcp_client_start(artik_network_dhcp_client_handle *handle,
		artik_network_interface_t interface)
{
	artik_error ret = S_OK;
	struct dhcpc_state state;
	void *dhcp_handle = NULL;
	int err = 0;

	log_dbg("");

	if (interface != ARTIK_WIFI)
		return E_NOT_SUPPORTED;

	dhcp_handle = dhcpc_open(wifi_iface);
	err = dhcpc_request(dhcp_handle, &state);
	dhcpc_close(dhcp_handle);

	if (err != OK) {
		log_err("Failed to request DHCP lease (err=%d)\n", err);
		switch (err) {
		case -100:
			ret = E_BAD_ARGS;
			break;
		case -2:
			ret = E_TIMEOUT;
			break;
		default:
			ret = E_NOT_CONNECTED;
			break;
		}
		goto exit;
	}

	netlib_set_ipv4addr(wifi_iface, &state.ipaddr);
	netlib_set_ipv4netmask(wifi_iface, &state.netmask);
	netlib_set_dripv4addr(wifi_iface, &state.default_router);

	*handle = DHCPC_HANDLE;

exit:
	return ret;
}

artik_error os_dhcp_client_stop(artik_network_dhcp_client_handle handle)
{
	struct in_addr zeroip;

	log_dbg("");

	if (handle != DHCPC_HANDLE)
		return E_BAD_ARGS;

	zeroip.s_addr = inet_addr("0.0.0.0");

	netlib_set_ipv4addr(wifi_iface, &zeroip);
	netlib_set_ipv4netmask(wifi_iface, &zeroip);
	netlib_set_dripv4addr(wifi_iface, &zeroip);

	return S_OK;
}

artik_error os_dhcp_server_start(artik_network_dhcp_server_handle *handle,
		artik_network_dhcp_server_config *config)
{
	struct in_addr ipaddr;

	log_dbg("");

	if (config->interface != ARTIK_WIFI)
		return E_NOT_SUPPORTED;

	if (dhcpd_start(wifi_iface)) {
		log_err("Failed to start DHCP server\n");
		ipaddr.s_addr = INADDR_ANY;
		netlib_set_ipv4addr(wifi_iface, &ipaddr);
		return E_NOT_CONNECTED;
	}

	*handle = DHCPS_HANDLE;

	return S_OK;
}

artik_error os_dhcp_server_stop(artik_network_dhcp_server_handle handle)
{
	struct in_addr ipaddr;

	log_dbg("");

	if (handle != DHCPS_HANDLE)
		return E_BAD_ARGS;

	dhcpd_stop();
	ipaddr.s_addr = INADDR_ANY;
	netlib_set_ipv4addr(wifi_iface, &ipaddr);

	return S_OK;
}

static int resolve(const char *addr, struct sockaddr_storage *to)
{
	struct addrinfo *result = NULL;
	struct addrinfo hints;
	int err;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_protocol = IPPROTO_ICMP;
	hints.ai_socktype = SOCK_RAW;

	err = getaddrinfo(addr, NULL, &hints, &result);
	if (err != 0) {
		log_dbg("getaddrinfo: Could not translate %s", addr);
		return err;
	}

	memcpy(to, result->ai_addr, result->ai_addrlen);

#ifndef CONFIG_RELEASE
	char host[INET6_ADDRSTRLEN];

	getnameinfo(result->ai_addr, result->ai_addrlen, host, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
	log_dbg("Translate address %s to %s", addr, host);
#endif

	freeaddrinfo(result);

	return 0;
}

bool os_send_echo(int sock, const struct sockaddr *to, u16_t seqno)
{

	struct icmp_echo_hdr iecho;
	int ret;
	pthread_t id = pthread_self();

	memset(&iecho, 0, sizeof(struct icmp_echo_hdr));
	ICMPH_CODE_SET(&iecho, 0);
	ICMPH_TYPE_SET(&iecho, ICMP_ECHO);
	iecho.id = (u16_t)id;
	iecho.seqno = seqno;
	iecho.chksum = ~chksum(&iecho, sizeof(struct icmp_echo_hdr));

	ret = sendto(sock, &iecho, sizeof(struct icmp_echo_hdr), 0, to, sizeof(struct sockaddr_in));
	if (ret <= 0) {
		log_dbg("sendto: unable to send ICMP request: %d - %s", errno, strerror(errno));
		return false;
	}

	return true;
}

bool os_check_echo_response(char *buf, ssize_t len, u16_t seqno)
{
	struct ip_hdr *iphdr = NULL;
	struct icmp_echo_hdr *iecho = NULL;
	pthread_t id = pthread_self();

	if (len >= ICMP_HDR_SIZE) {
		iphdr = (struct ip_hdr *)buf;
		iecho = (struct icmp_echo_hdr *)(buf + (IPH_HL(iphdr)*4));

		if (iecho->type == ICMP_ER && iecho->seqno == seqno && iecho->id == (u16_t)id)
			return true;
	}

	log_dbg("Bad echo response");
	return false;
}

static void notify_online_status_change(echo_t *node, bool status)
{
	node->resolved = status;

	if (status == node->online_status && !node->force)
		return;

	node->force = false;
	node->online_status = status;
	node->callback(status, node->addr, node->user_data);
}

static void send_echo_request(int sock, echo_t *node, int64_t now)
{

	if (!node->resolved)
		return;

	/* If echo request is already sent and timeout is not expired we can't resend an echo request */
	if (node->last_echo + node->timeout - now > 0)
		return;

	/* We start to send an echo request before the lifetime expires */
	if (node->last_echo_response + (node->delay / 2) - now > 0)
		return;

	if (!os_send_echo(sock, node->to, node->seqno))
		notify_online_status_change(node, false);

	node->seqno++;

	node->last_echo = now;
}

static int search_node_with_sockaddr(echo_t *node, struct sockaddr *sock_addr)
{
	if (node->to->sa_family != sock_addr->sa_family)
		return 0;

	if (node->to->sa_family != AF_INET)
		return 0;

	if (SOCK_ADDR_IN_ADDR(node->to).s_addr != SOCK_ADDR_IN_ADDR(sock_addr).s_addr)
		return 0;

	return 1;
}

static pthread_addr_t watch_online_status_cb(void *arg)
{
	watch_online_status_t *watch_data = (watch_online_status_t *)arg;
	struct timeval now;
	int64_t now_time;
	int ret;
	char buf[64];
	int sock = g_watch_data->sock;

	pthread_mutex_lock(&watch_data->mutex);

	gettimeofday(&now, NULL);
	now_time = now.tv_sec * 1000 + now.tv_usec / 1000;
	while (!watch_data->quit) {
		struct timeval timeout;
		echo_t *node = NULL;
		int min_timeout = INT_MAX;
		fd_set rfds;

		for (node = (echo_t *)watch_data->monitored_servers; node; node = (echo_t *)node->node.next) {
			int current_timeout = node->delay;

			if (!node->resolved) {
				int err = resolve(node->addr, (struct sockaddr_storage *)node->to);

				if (err == 0)
					node->resolved = true;
				else
					notify_online_status_change(node, false);
			}

			send_echo_request(watch_data->sock, node, now_time);

			/*
			 * Echo request are sent but echo response are not received
			 * therefore we need to wait node->echo_last + node->timeout - now
			 */
			if (node->last_echo > node->last_echo_response) {
				int t = node->last_echo + node->timeout - now_time;

				/*
				 * the time limit to receive echo response and
				 * the deadline have been exceed so we notify the user
				 */
				if (node->last_echo_response + node->delay - now_time < 0) {
					notify_online_status_change(node, false);
					t = node->timeout;
				}
				current_timeout = t;
			}

			if (min_timeout > current_timeout)
				min_timeout = current_timeout;
		}

		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		timeout.tv_sec = min_timeout / 1000;
		timeout.tv_usec = (min_timeout % 1000) * 1000;
		pthread_mutex_unlock(&watch_data->mutex);
		ret = select(sock + 1, &rfds, NULL, NULL, &timeout);
		gettimeofday(&now, NULL);
		now_time = now.tv_sec * 1000 + now.tv_usec / 1000;
		pthread_mutex_lock(&watch_data->mutex);

		if (ret == -1) {
			log_err("select: %s", strerror(errno));
			continue;
		} else if (ret) {
			socklen_t fromlen;
			struct sockaddr_storage from;
			ssize_t len;

			len = recvfrom(watch_data->sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
			if (len <= 0) {
				log_dbg("recvfrom: unable to receive data");
				continue;
			}

			node = (echo_t *)artik_list_get_by_check(
				watch_data->monitored_servers,
				(ARTIK_LIST_FUNCB)&search_node_with_sockaddr,
				&from);

			if (!node) {
#ifndef CONFIG_RELEASE
				char host[INET6_ADDRSTRLEN];

				getnameinfo((struct sockaddr *)&from, fromlen,
							host, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
				log_dbg("Node %s not found", host);
#endif
				continue;
			}

			if (!os_check_echo_response(buf, len, node->seqno - 1))
				continue;

			node->last_echo_response = now_time;
			notify_online_status_change(node, true);

		} else {
			log_dbg("select: timeout expired (%d)", min_timeout);
			continue;
		}

	}
	pthread_mutex_unlock(&watch_data->mutex);

	return NULL;
}

static bool init_watch_online_status(void)
{
	struct sched_param sparam;
	pthread_attr_t attr;
	pthread_mutexattr_t mutex_attr;
	int err;

	g_watch_data = malloc(sizeof(watch_online_status_t));

	memset(g_watch_data, 0, sizeof(watch_online_status_t));

	g_watch_data->sock = create_icmp_socket(0);
	if (g_watch_data->sock < 0)
		goto error;

	err = pthread_mutexattr_init(&mutex_attr);
	if (err != 0)
		goto error;

	err = pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
	if (err != 0) {
		pthread_mutexattr_destroy(&mutex_attr);
		goto error;
	}

	err = pthread_mutex_init(&g_watch_data->mutex, &mutex_attr);
	if (err != 0) {
		pthread_mutexattr_destroy(&mutex_attr);
		goto error;
	}
	pthread_mutexattr_destroy(&mutex_attr);

	err = pthread_attr_init(&attr);
	if (err != 0) {
		pthread_mutex_destroy(&g_watch_data->mutex);
		goto error;
	}

	sparam.sched_priority = WATCH_ONLINE_STATUS_SCHED_PRI;
	err = pthread_attr_setschedparam(&attr, &sparam);
	if (err != 0) {
		pthread_mutex_destroy(&g_watch_data->mutex);
		pthread_attr_destroy(&attr);
		goto error;
	}

	err = pthread_attr_setschedpolicy(&attr, WATCH_ONLINE_STATUS_SCHED_POLICY);
	if (err != 0) {
		pthread_mutex_destroy(&g_watch_data->mutex);
		pthread_attr_destroy(&attr);
		goto error;
	}

	err = pthread_attr_setstacksize(&attr, WATCH_ONLINE_STATUS_STACK_SIZE);
	if (err != 0) {
		pthread_mutex_destroy(&g_watch_data->mutex);
		pthread_attr_destroy(&attr);
		goto error;
	}

	err = pthread_mutex_lock(&g_watch_data->mutex);
	if (err != 0) {
		pthread_mutex_destroy(&g_watch_data->mutex);
		pthread_attr_destroy(&attr);
		goto error;
	}

	err = pthread_create(&g_watch_data->thread, &attr, watch_online_status_cb, g_watch_data);
	if (err != 0) {
		pthread_mutex_unlock(&g_watch_data->mutex);
		pthread_mutex_destroy(&g_watch_data->mutex);
		pthread_attr_destroy(&attr);
		goto error;
	}

	pthread_attr_destroy(&attr);
	pthread_setname_np(g_watch_data->thread, "Network connectivity monitoring");


	return true;

error:
	if (g_watch_data->sock > 0)
		close(g_watch_data->sock);

	free(g_watch_data);
	return false;
}

artik_error os_network_add_watch_online_status(
				artik_watch_online_status_handle * handle,
				const char *addr,
				int delay,
				int timeout,
				artik_watch_online_status_callback app_callback,
				void *user_data)
{
	struct sockaddr_storage *to = NULL;
	bool online_status = false;
	struct timeval now;
	int64_t now_time;
	echo_t *node = NULL;

	log_dbg("");

	if (!handle || !app_callback || delay <= 0 || timeout <= 0)
		return E_BAD_ARGS;

	if (timeout > delay)
		return E_BAD_ARGS;

	to = malloc(sizeof(struct sockaddr_storage));
	if (!to)
		return E_NO_MEM;

	/*
	 * The function init_watch_online_status takes the mutex
	 * g_watch_data->mutex.
	 * This allows to fill the list g_watch_data->monitored_servers
	 * before launching the thread loop
	 */

	if (g_watch_data)
		pthread_mutex_lock(&g_watch_data->mutex);
	else if (!init_watch_online_status())
		return E_NOT_INITIALIZED;

	node = (echo_t *)artik_list_add(&(g_watch_data->monitored_servers), 0, sizeof(echo_t));
	if (!node) {
		if (artik_list_size(g_watch_data->monitored_servers) == 0) {
			g_watch_data->quit = true;
			pthread_mutex_unlock(&g_watch_data->mutex);

			pthread_join(g_watch_data->thread, NULL);
		}

		log_dbg("Not enough memory");
		return E_NO_MEM;
	}

	node->node.handle = (ARTIK_LIST_HANDLE) node;
	node->addr = strdup(addr);
	node->to = (struct sockaddr *)to;
	node->timeout = timeout;
	node->delay = delay;
	node->callback = app_callback;
	node->online_status = online_status;
	node->user_data = user_data;
	node->resolved = false;
	node->force = true;
	node->seqno = 0;

	gettimeofday(&now, NULL);
	now_time = now.tv_sec * 1000 + now.tv_usec / 1000;
	node->last_echo = now_time;
	node->last_echo_response = now_time;
	*handle = (void *)node;
	pthread_mutex_unlock(&g_watch_data->mutex);

	return S_OK;
}

artik_error os_network_remove_watch_online_status(
					artik_watch_online_status_handle handle)
{
	echo_t *node = NULL;

	if (!handle)
		return E_BAD_ARGS;

	if (!g_watch_data)
		return E_NOT_INITIALIZED;

	pthread_mutex_lock(&g_watch_data->mutex);
	node = (echo_t *)artik_list_get_by_handle(g_watch_data->monitored_servers, (ARTIK_LIST_HANDLE) handle);

	if (!node)
		return E_BAD_ARGS;

	free(node->to);
	free(node->addr);

	artik_list_delete_node(&g_watch_data->monitored_servers, (ARTIK_LIST_HANDLE) handle);

	if (artik_list_size(g_watch_data->monitored_servers) == 0) {
		g_watch_data->quit = true;
		pthread_mutex_unlock(&g_watch_data->mutex);
		pthread_join(g_watch_data->thread, NULL);

		pthread_mutex_destroy(&g_watch_data->mutex);
		close(g_watch_data->sock);
		free(g_watch_data);
		g_watch_data = NULL;
		return S_OK;
	}
	pthread_mutex_unlock(&g_watch_data->mutex);

	return S_OK;
}

static bool add_nameserver(void *arg, struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_in *sin;
	dns_addresses *dns = arg;
	artik_network_ip *dns_addr = dns->dns_addr + dns->count;

	/* Ignore IPV6 address */
	if (addr->sa_family != AF_INET)
		return true;

	if (dns->count > MAX_DNS_ADDRESSES)
		return true;

	sin = (struct sockaddr_in *) addr;
	dns_addr->type = ARTIK_IPV4;

	dns->count++;
	if (!inet_ntop(AF_INET, &sin->sin_addr, dns_addr->address, MAX_IP_ADDRESS_LEN)) {
		log_dbg("Failed to convert DNS ip address into a character string.");
		return false;
	}

	return true;
}

artik_error os_get_network_config(
	artik_network_config * config,
	artik_network_interface_t interface
	)
{
	int sockfd;
	int ret;
	struct in_addr ipv4_host, ipv4_gw;
	struct sockaddr_in *ipv4_netmask, *sockaddr_in;
	struct ifreq req;
	dns_addresses dns;
	uint8_t macaddr[IFHWADDRLEN];

	if (!config) {
		log_dbg("config is NULL");
		return E_BAD_ARGS;
	}

	if (interface != ARTIK_WIFI) {
		log_dbg("Only ARTIK_WIFI is supported.");
		return E_BAD_ARGS;
	}

	sockfd = socket(PF_INET, NETLIB_SOCK_IOCTL, 0);
	if (sockfd < 0) {
		log_dbg("Failed to open the socket.");
		return E_NETWORK_ERROR;
	}

	memset(config, 0, sizeof(artik_network_config));
	memset(&req, 0, sizeof(struct ifreq));
	strncpy(req.ifr_name, "wl1", IFNAMSIZ);

	ret = ioctl(sockfd, SIOCGIFADDR, &req);
	if (ret) {
		log_dbg("Failed to get IP address. (err %d)", ret);
		close(sockfd);
		return E_NETWORK_ERROR;
	}

	sockaddr_in = (struct sockaddr_in *)&req.ifr_addr;
	memcpy(&ipv4_host, &sockaddr_in->sin_addr, sizeof(struct in_addr));

	ret = ioctl(sockfd, SIOCGIFDSTADDR, &req);
	if (ret) {
		log_dbg("Failed to get GW address.");
		close(sockfd);
		return E_NETWORK_ERROR;
	}

	sockaddr_in = (struct sockaddr_in *)&req.ifr_addr;
	memcpy(&ipv4_gw, &sockaddr_in->sin_addr, sizeof(struct in_addr));

	ret = ioctl(sockfd, SIOCGIFNETMASK, &req);
	if (ret) {
		log_dbg("Failed to get netmask");
		close(sockfd);
		return E_NETWORK_ERROR;
	}

	ipv4_netmask = (struct sockaddr_in *)&req.ifr_netmask;

	if (netlib_getmacaddr("wl1", macaddr) != OK) {
		log_dbg("Failed to get mac address");
		close(sockfd);
		return E_NETWORK_ERROR;
	}

	snprintf(config->mac_addr, MAX_MAC_ADDRESS_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
		macaddr[0], macaddr[1], macaddr[2],
		macaddr[3], macaddr[4], macaddr[5]);

	dns.count = 0;
	dns.dns_addr = config->dns_addr;
	if (!dns_foreach_nameserver(add_nameserver, &dns)) {
		log_dbg("Failed to get DNS servers.");
		close(sockfd);
		return E_NETWORK_ERROR;
	}

	if (!inet_ntop(AF_INET, &ipv4_host, config->ip_addr.address, MAX_IP_ADDRESS_LEN)) {
		log_dbg("Failed to convert host ip address into a character string.");
		close(sockfd);
		return E_NETWORK_ERROR;
	}

	if (!inet_ntop(AF_INET, &ipv4_gw, config->gw_addr.address, MAX_IP_ADDRESS_LEN)) {
		log_dbg("Failed to convert gw ip address into a character string.");
		close(sockfd);
		return E_NETWORK_ERROR;
	}

	if (!inet_ntop(AF_INET, &ipv4_netmask->sin_addr, config->netmask.address, MAX_IP_ADDRESS_LEN)) {
		log_dbg("Failed to convert netmask ip address into a character string.");
		close(sockfd);
		return E_NETWORK_ERROR;
	}

	config->ip_addr.type = ARTIK_IPV4;
	config->gw_addr.type = ARTIK_IPV4;
	config->netmask.type = ARTIK_IPV4;

	close(sockfd);

	return S_OK;
}

artik_error os_set_network_config(artik_network_config *config, artik_network_interface_t interface)
{
	struct in_addr host_addr, gw_addr, netmask_addr;
	struct in_addr dns[MAX_DNS_ADDRESSES];
	int i;
	size_t count = 0;

	if (!config) {
		log_dbg("config is NULL");
		return E_BAD_ARGS;
	}

	if (interface != ARTIK_WIFI) {
		log_dbg("Only ARTIK_WIFI is supported.");
		return E_BAD_ARGS;
	}

	if (!inet_pton(AF_INET, config->ip_addr.address, &host_addr)) {
		log_dbg("Failed to convert host ip address into a network address structure.");
		return E_BAD_ARGS;
	}

	if (!inet_pton(AF_INET, config->gw_addr.address, &gw_addr)) {
		log_dbg("Failed to convert gw ip address into a network address structure.");
		return E_BAD_ARGS;
	}

	if (!inet_pton(AF_INET, config->netmask.address, &netmask_addr)) {
		log_dbg("Failed to convert netmask address into a network address structure.");
		return E_BAD_ARGS;
	}

	for (i = 0; i < MAX_DNS_ADDRESSES; i++) {
		if (config->dns_addr[i].address[0] == '\0')
			continue;

		if (!inet_pton(AF_INET, config->dns_addr[i].address, &dns[count])) {
			log_dbg("Failed to convert dns address into a network address structure.");
			return E_BAD_ARGS;
		}

		dns_setserver(count++, NULL);
	}

	if (netlib_set_ipv4addr("wl1", &host_addr) != OK) {
		log_dbg("Failed to set ipv4 address");
		return E_NETWORK_ERROR;
	}

	if (netlib_set_dripv4addr("wl1", &gw_addr) != OK) {
		log_dbg("Failed to set gw address.");
		return E_NETWORK_ERROR;
	}

	if (netlib_set_ipv4netmask("wl1", &netmask_addr) != OK) {
		log_dbg("Failed to set netmask address.");
		return E_NETWORK_ERROR;
	}

	for (i = 0; i < count; i++) {
		struct sockaddr_in sockaddr_in;

		sockaddr_in.sin_family = AF_INET;
		sockaddr_in.sin_port = 0;
		sockaddr_in.sin_addr.s_addr = dns[i].s_addr;
		if (!dns_add_nameserver((struct sockaddr *)&sockaddr_in, sizeof(struct sockaddr_in))) {
			log_dbg("Failed to add new DNS.");
			return E_NETWORK_ERROR;
		}
	}

	return S_OK;
}
