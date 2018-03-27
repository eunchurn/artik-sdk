#include "common_network.h"
#include "os_network.h"

#include <artik_log.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

uint16_t chksum(void *dataptr, uint16_t len)
{
	uint32_t acc;
	uint16_t src;
	uint8_t *octetptr;

	acc = 0;
	/* dataptr may be at odd or even addresses */
	octetptr = (uint8_t *)dataptr;
	while (len > 1) {
		/*
		 * declare first octet as most significant
		 * thus assume network order, ignoring host order
		 */
		src = (*octetptr) << 8;
		octetptr++;
		/* declare second octet as least significant */
		src |= (*octetptr);
		octetptr++;
		acc += src;
		len -= 2;
	}

	if (len > 0) {
		/* accumulate remaining octet */
		src = (*octetptr) << 8;
		acc += src;
	}

	/* add deferred carry bits */
	acc = (acc >> 16) + (acc & 0x0000ffffUL);
	if ((acc & 0xffff0000UL) != 0)
		acc = (acc >> 16) + (acc & 0x0000ffffUL);

	/*
	 * This maybe a little confusing: reorder sum using htons()
	 * instead of ntohs() since it has a little less call overhead.
	 * The caller must invert bits for Internet sum !
	 */
	return htons((uint16_t)acc);
}

int resolve(const char *addr, struct sockaddr_storage *to)
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

int create_icmp_socket(int recv_timeout)
{
	int sock;
	struct timeval tv;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0) {
		log_dbg("socket: Failed to create socket");
		return -1;
	}

	if (recv_timeout <= 0)
		return sock;

	tv.tv_sec = recv_timeout / 1000;
	tv.tv_usec = (recv_timeout % 1000) * 1000;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) != 0) {
		log_dbg("setsockopt: unable to set timeout");
		close(sock);
		return -1;
	}


	return sock;
}
