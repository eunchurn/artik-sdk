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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/rtc.h>
#include <time.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <artik_module.h>
#include <artik_log.h>
#include <artik_time.h>
#include <artik_loop.h>
#include "os_time.h"

#define LEN_PACK 14
#define LEN_FORM 8
#define LEN_FDS 2

#define	POS_WDPACK 5
#define	POS_YPACK 6
#define	POS_MSPACK 10

#define EPOCH_DEF 1900
#define	MAX_EXPIRATION 1

#define	FORMAT_NULL ((uint64_t)506381209866536711LL)

#define NTP_PORT 123
#define EPOCH_BALANCE 2208988800U

#define MAX(a, b)	((a > b) ? a : b)

#define	GMT_MAX_LEN	30

typedef struct {
	char format_link[LEN_FORM];
	char *format_mod;
} artik_time_parser_t;

typedef struct {
	artik_time_zone gmt;
	alarm_callback func;
	artik_msecond date_alarm;
	artik_loop_module *loop;
	int alarm_id;
} artik_time_alarm_t;

static artik_error os_time_struct_empty(void *data, int len)
{
	int *addr = data;
	int size = 0;
	int check_set = 0;

	while (size < len) {
		check_set |= *addr;
		size += sizeof(*addr);
		addr = (void *)((intptr_t)data + size);
	}

	return check_set > 0 ? S_OK : E_BAD_ARGS;
}

static artik_error os_time_get_sys(struct tm *time, artik_time_zone gmt)
{
	struct tm *rtime = NULL;
	struct timeval tval;
	int res = gettimeofday(&tval, NULL);

	if (res < 0)
		return E_BAD_ARGS;

	rtime = gmtime(&tval.tv_sec);

	if (!rtime)
		return E_BAD_ARGS;

	rtime->tm_hour = (rtime->tm_hour+gmt)%24;
	rtime->tm_year += EPOCH_DEF;

	memcpy(time, rtime, sizeof(struct tm));

	return S_OK;
}

artik_error os_time_set_time(artik_time date, artik_time_zone gmt)
{
	char gmtname[GMT_MAX_LEN];

	if (gmt < ARTIK_TIME_UTC || gmt > ARTIK_TIME_GMT12)
		return E_BAD_ARGS;

	if ((int)date.second < 0 || (int)date.second > 59)
		return E_BAD_ARGS;

	if ((int)date.minute < 0 || (int)date.minute > 59)
		return E_BAD_ARGS;

	if ((int)date.hour < 0 || (int)date.hour > 23)
		return E_BAD_ARGS;

	if ((int)date.day < 1 || (int)date.day > 31)
		return E_BAD_ARGS;

	if ((int)date.month < 1 || (int)date.month > 12)
		return E_BAD_ARGS;

	if ((int)date.year < EPOCH_DEF)
		return E_BAD_ARGS;

	if ((int)date.day_of_week < 0 || (int)date.day_of_week > 6)
		return E_BAD_ARGS;

	if ((int)date.msecond < 0)
		return E_BAD_ARGS;

	struct tm str_time;
	time_t sec = 0;
	struct timespec time_spec;


	memset(&str_time, 0, sizeof(str_time));
	memset(&time_spec, 0, sizeof(time_spec));

	str_time.tm_sec = date.second;
	str_time.tm_min = date.minute;
	str_time.tm_hour = date.hour;
	str_time.tm_min = date.minute;
	str_time.tm_mday = date.day;
	str_time.tm_mon = date.month--;
	str_time.tm_year = date.year-EPOCH_DEF;
	str_time.tm_wday = date.day_of_week;

	snprintf(gmtname, GMT_MAX_LEN, "GMT-%d", gmt);
	setenv("TZ", gmtname, 1);
	tzset();

	sec = mktime(&str_time);

	if (sec < 0)
		return E_BAD_ARGS;

	time_spec.tv_sec = sec;
	time_spec.tv_nsec = 0;

	if (clock_settime(CLOCK_REALTIME, &time_spec) < 0) {
		perror(strerror(errno));
		return E_BAD_ARGS;
	}

	return S_OK;
}

artik_error os_time_get_time(artik_time_zone gmt, artik_time *date)
{
	if (!date)
		return E_BAD_ARGS;

	if (gmt < ARTIK_TIME_UTC || gmt > ARTIK_TIME_GMT12)
		return E_BAD_ARGS;

	struct tm *rtime = NULL;
	struct timeval tval;
	int res = gettimeofday(&tval, NULL);

	if (res < 0)
		return E_INVALID_VALUE;

	rtime = gmtime(&tval.tv_sec);

	if (!rtime)
		return E_INVALID_VALUE;

	rtime->tm_hour = (rtime->tm_hour+gmt)%24;
	rtime->tm_mon++;
	rtime->tm_year += EPOCH_DEF;

	date->second = (unsigned int)rtime->tm_sec;
	date->minute = (unsigned int)rtime->tm_min;
	date->hour = (unsigned int)rtime->tm_hour;
	date->day = (unsigned int)rtime->tm_mday;
	date->month = (unsigned int)rtime->tm_mon;
	date->year = (unsigned int)rtime->tm_year;
	date->day_of_week = (unsigned int)rtime->tm_wday;
	date->msecond = (unsigned int)(tval.tv_usec/1000);

	return S_OK;
}

artik_error os_time_get_time_str(char *date_str, int size, char *const format,
				 artik_time_zone gmt)
{
	if (!date_str)
		return E_BAD_ARGS;

	if (size <= 0)
		return E_BAD_ARGS;

	if (gmt < ARTIK_TIME_UTC || gmt > ARTIK_TIME_GMT12)
		return E_BAD_ARGS;

	struct tm rtime;

	memset(date_str, 0, size);
	memset(&rtime, 0, sizeof(rtime));

	os_time_get_sys(&rtime, gmt);

	rtime.tm_year -= EPOCH_DEF;

	if (strftime(date_str, size, format ? format : ARTIK_TIME_DFORMAT,
							&rtime) == 0)
		return E_BAD_ARGS;

	return S_OK;
}

artik_msecond os_time_get_tick(void)
{
	struct tm val_curr;
	time_t curr_in_sec = 0;
	time_t ms_current = 0;

	memset(&val_curr, 0, sizeof(val_curr));

	os_time_get_sys(&val_curr, ARTIK_TIME_UTC);

	ms_current = val_curr.tm_yday;

	val_curr.tm_yday = 0;
	val_curr.tm_year -= EPOCH_DEF;
	val_curr.tm_mon++;

	curr_in_sec = mktime(&val_curr);

	if (curr_in_sec == -1)
		return S_OK;

	curr_in_sec = (curr_in_sec * 1000L) + ((time_t) ms_current / 1000L);

	return curr_in_sec;
}

artik_error os_time_create_alarm_second(artik_time_zone gmt,
					artik_alarm_handle *handle,
					alarm_callback func,
					void *user_data,
					artik_msecond second)
{
	artik_time_alarm_t *alarm_data = NULL;
	struct tm curr_usr;
	time_t curr_in_sec;

	if (gmt < ARTIK_TIME_UTC || gmt > ARTIK_TIME_GMT12)
		return E_BAD_ARGS;

	if ((int)second < 0)
		return E_BAD_ARGS;

	if (!func)
		return E_BAD_ARGS;

	memset(&curr_usr, 0, sizeof(curr_usr));
	os_time_get_sys(&curr_usr, gmt);
	curr_usr.tm_yday = 0;
	curr_usr.tm_year -= EPOCH_DEF;
	curr_in_sec = mktime(&curr_usr);
	if (curr_in_sec < 0)
		return E_BAD_ARGS;

	curr_in_sec += (time_t) second;

	*handle = malloc(sizeof(artik_time_alarm_t));

	alarm_data = *handle;
	alarm_data->loop = (artik_loop_module *)
					artik_request_api_module("loop");
	alarm_data->func = func;
	alarm_data->gmt = gmt;
	alarm_data->date_alarm = curr_in_sec;

	if (!alarm_data->loop)
		return E_BUSY;

	return alarm_data->loop->add_timeout_callback(&alarm_data->alarm_id,
						(unsigned int)second*1000,
						func, user_data);
}

artik_error os_time_create_alarm_date(artik_time_zone gmt,
				      artik_alarm_handle *handle,
				      alarm_callback func,
				      void *user_data,
				      artik_time date)
{
	time_t date_in_sec = 0, curr_in_sec = 0;
	double diff_t;
	struct tm date_usr, curr_usr;

	if (gmt < ARTIK_TIME_UTC || gmt > ARTIK_TIME_GMT12)
		return E_BAD_ARGS;

	if (os_time_struct_empty(&date, sizeof(date)) != S_OK)
		return E_BAD_ARGS;

	if (!func)
		return E_BAD_ARGS;

	if ((int)date.second < 0 || (int)date.second > 59)
		return E_BAD_ARGS;

	if ((int)date.minute < 0 || (int)date.minute > 59)
		return E_BAD_ARGS;

	if ((int)date.hour < 0 || (int)date.hour > 23)
		return E_BAD_ARGS;

	if ((int)date.day < 1 || (int)date.day > 31)
		return E_BAD_ARGS;

	if ((int)date.month < 1 || (int)date.month > 12)
		return E_BAD_ARGS;

	if ((int)date.year < EPOCH_DEF)
		return E_BAD_ARGS;

	if ((int)date.day_of_week < 0 || (int)date.day_of_week > 6)
		return E_BAD_ARGS;

	if ((int)date.msecond < 0)
		return E_BAD_ARGS;

	memset(&curr_usr, 0, sizeof(curr_usr));
	os_time_get_sys(&curr_usr, gmt);

	curr_usr.tm_yday = 0;
	curr_usr.tm_year -= EPOCH_DEF;
	curr_in_sec = mktime(&curr_usr);

	if (curr_in_sec < 0)
		return E_INVALID_VALUE;

	memset(&date_usr, 0, sizeof(date_usr));
	date_usr.tm_sec = date.second;
	date_usr.tm_min = date.minute;
	date_usr.tm_hour = date.hour;
	date_usr.tm_min = date.minute;
	date_usr.tm_mday = date.day;
	date_usr.tm_mon = date.month--;
	date_usr.tm_year = date.year - EPOCH_DEF;
	date_usr.tm_wday = date.day_of_week;

	date_in_sec = mktime(&date_usr);
	if (date_in_sec < 0)
		return E_INVALID_VALUE;

	diff_t = difftime(date_in_sec, curr_in_sec);

	return os_time_create_alarm_second(gmt, handle, func, user_data,
		diff_t);
}

artik_error os_time_delete_alarm(artik_alarm_handle handle)
{
	artik_time_alarm_t *alarm_data = handle;

	if (alarm_data)
		free(handle);

	return S_OK;
}

artik_error os_time_get_delay_alarm(artik_alarm_handle handle,
				    artik_msecond *msecond)
{
	artik_time_alarm_t *alarm_data = handle;
	struct tm curr_usr;
	artik_msecond curr_in_sec = 0;
	int res = 0;
	artik_error ret = S_OK;

	if (!alarm_data)
		return E_BAD_ARGS;

	memset(&curr_usr, 0, sizeof(curr_usr));

	ret = os_time_get_sys(&curr_usr, alarm_data->gmt);
	if (ret != S_OK) {
		*msecond = 0;
		return ret;
	}

	curr_usr.tm_year -= EPOCH_DEF;
	curr_usr.tm_yday = 0;

	res = mktime(&curr_usr);
	if (res == 0)
		*msecond = 0;
	else if (res < 0) {
		*msecond = 0;
		return E_INVALID_VALUE;
	}

	curr_in_sec = res;
	*msecond = alarm_data->date_alarm <= curr_in_sec ?
		0 : (alarm_data->date_alarm - curr_in_sec);

	return S_OK;
}

artik_error os_time_sync_ntp(const char *hostname, unsigned int timeout)
{
	artik_error ret = S_OK;
	unsigned char msg[48] = { 0xe3, 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned long buf[1024];

	int sock;
	int res;

	struct protoent *proto;
	struct sockaddr_in server_addr;
	struct sockaddr saddr;
	socklen_t saddr_l;
	struct hostent *host_resolv;
	struct timeval time_struct = { timeout / 1000, ((timeout % 1000) * 1000) };

	log_dbg("");
	if (!hostname)
		return E_BAD_ARGS;
	proto = getprotobyname("udp");
	sock = socket(PF_INET, SOCK_DGRAM, proto->p_proto);
	if (sock < 0) {
		log_err("Failed to open socket");
		return E_BAD_ARGS;
	}

	if (timeout) {
		if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&time_struct,
				sizeof(time_struct)) < 0) {
			log_err("Failed to set socket options");
			ret = E_BAD_ARGS;
			goto exit;
		}
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	host_resolv = gethostbyname(hostname);
	if (!host_resolv) {
		log_err("Failed to resolve host name");
		ret = E_HTTP_ERROR;
		goto exit;
	}

	server_addr.sin_addr.s_addr =
	    inet_addr(inet_ntoa
		      (*(struct in_addr *)host_resolv->h_addr_list[0]));
	server_addr.sin_port = htons(NTP_PORT);

	res =
	    sendto(sock, msg, sizeof(msg), 0, (struct sockaddr *)&server_addr,
		   sizeof(server_addr));
	if (res != 48) {
		log_err("Failed to send request to socket");
		ret = E_BAD_ARGS;
		goto exit;
	}

	saddr_l = sizeof(saddr);
	res = recvfrom(sock, buf, 48, 0, &saddr, &saddr_l);
	if (res != 48) {
		log_err("Timeout on receiving response over the socket");
		ret = E_BAD_ARGS;
		goto exit;
	}

	time_struct.tv_sec = 0;
	time_struct.tv_usec = 0;

	time_struct.tv_sec = ntohl((time_t) buf[4]) - EPOCH_BALANCE;
	res = settimeofday(&time_struct, NULL);
	if (res != 0) {
		log_err("Failed to set new time");
		ret = E_BAD_ARGS;
		goto exit;
	}

exit:
	close(sock);

	return ret;
}

artik_error os_time_convert_timestamp_to_time(const int64_t timestamp,
					      artik_time *date)
{
	struct tm *rtime = NULL;
	time_t ts = (time_t)(timestamp & 0xFFFFFFFF);

	memset(date, 0, sizeof(*date));

	rtime = gmtime(&ts);

	if (!rtime)
		return E_INVALID_VALUE;

	rtime->tm_mon++;
	rtime->tm_year += EPOCH_DEF;

	date->second = (unsigned int)rtime->tm_sec;
	date->minute = (unsigned int)rtime->tm_min;
	date->hour = (unsigned int)rtime->tm_hour;
	date->day = (unsigned int)rtime->tm_mday;
	date->month = (unsigned int)rtime->tm_mon;
	date->year = (unsigned int)rtime->tm_year;
	date->day_of_week = (unsigned int)rtime->tm_wday;

	return S_OK;
}

artik_error os_time_convert_time_to_timestamp(const artik_time *date,
					      int64_t *timestamp)
{
	struct tm rtime;

	if ((int)date->second < 0 || (int)date->second > 59)
		return E_BAD_ARGS;

	if ((int)date->minute < 0 || (int)date->minute > 59)
		return E_BAD_ARGS;

	if ((int)date->hour < 0 || (int)date->hour > 23)
		return E_BAD_ARGS;

	if ((int)date->day < 1 || (int)date->day > 31)
		return E_BAD_ARGS;

	if ((int)date->month < 1 || (int)date->month > 12)
		return E_BAD_ARGS;

	if ((int)date->year < EPOCH_DEF)
		return E_BAD_ARGS;

	if ((int)date->day_of_week < 0 || (int)date->day_of_week > 6)
		return E_BAD_ARGS;

	if ((int)date->msecond < 0)
		return E_BAD_ARGS;

	memset(&rtime, 0, sizeof(rtime));

	rtime.tm_sec = (int)date->second;
	rtime.tm_min = (int)date->minute;
	rtime.tm_hour = (int)date->hour;
	rtime.tm_mday = (int)date->day;
	rtime.tm_mon = (int)date->month;
	rtime.tm_year = (int)date->year;
	rtime.tm_wday = (int)date->day_of_week;

	rtime.tm_year -= EPOCH_DEF;
	rtime.tm_mon--;

	*timestamp = (int64_t)timegm(&rtime);

	if (*timestamp < 0)
		return E_INVALID_VALUE;

	return S_OK;
}
