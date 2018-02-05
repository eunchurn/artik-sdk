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
#include <stdint.h>

#include <artik_module.h>
#include <artik_platform.h>
#include <artik_i2c.h>

/*
 * This test only works if the CW2015 Linux driver is unbound first:
 * artik520 : $ echo 1-0062 > /sys/bus/i2c/drivers/cw201x/unbind
 * artik1020: $ echo 0-0062 > /sys/bus/i2c/drivers/cw201x/unbind
 * artik710 : $ echo 8-0062 > /sys/bus/i2c/drivers/cw201x/unbind
 */

const char *cmd_artik520  = "echo 1-0062 > /sys/bus/i2c/drivers/cw201x/unbind";
const char *cmd_artik1020 = "echo 0-0062 > /sys/bus/i2c/drivers/cw201x/unbind";
const char *cmd_artik710  = "echo 8-0062 > /sys/bus/i2c/drivers/cw201x/unbind";
const char *cmd_artik530  = "echo 8-0062 > /sys/bus/i2c/drivers/cw201x/unbind";
const char *cmd_artik305  = "echo 8-0062 > /sys/bus/i2c/drivers/cw201x/unbind";
const char *cmd_evergreeen = "echo 6-001a > /sys/bus/i2c/drivers/rt5659/unbind";

static artik_i2c_config config = {
	1,
	2000,
	I2C_8BIT,
	0x62
};

#define CW201x_REG_VERSION	0x0
#define CW201x_REG_CONFIG	0x8

#define RT5659_REG_DEVICEID 0xff00
#define RT5659_REG_DUMMY    0xfb00

static artik_error i2c_test_cw2015(int platid)
{
	artik_i2c_module *i2c = (artik_i2c_module *)
						artik_request_api_module("i2c");
	artik_i2c_handle cw2015;
	char version, conf;
	artik_error ret;

	if (platid == ARTIK520)
		config.id = 1;
	else if (platid == ARTIK1020)
		config.id = 0;
	else
		config.id = 8;

	fprintf(stdout, "TEST: %s starting\n", __func__);
	ret = i2c->request(&cw2015, &config);
	if (ret != S_OK) {
		fprintf(stderr, "Failed to request I2C %d@0x%02x (%d)\n",
			config.id, config.address, ret);
		goto exit;
	}
	fprintf(stdout, "Reading version register...");
	ret = i2c->read_register(cw2015, CW201x_REG_VERSION, &version, 1);
	if (ret != S_OK) {
		fprintf(stderr,
			"FAILED\nFailed to read I2C %d@0x%02x\n"
			"register 0x%04x (%d)\n",
			config.id, config.address, CW201x_REG_VERSION, ret);
		goto exit;
	}
	fprintf(stdout, "OK - val=0x%02x\n", version);
	if (version != 0x6f) {
		fprintf(stderr,
			"%s: Wrong chip version read,\n"
			"expected 0x6f, got 0x%02x\n",
			__func__, version);
		goto exit;
	} else
		fprintf(stdout, "CW2015 version: 0x%02x\n", version);
	fprintf(stdout, "Reading configuration register...");
	ret = i2c->read_register(cw2015, CW201x_REG_CONFIG, &conf, 1);
	if (ret != S_OK) {
		fprintf(stderr,
			"FAILED\nFailed to read I2C %d@0x%02x\n"
			"register 0x%04x (%d)\n",
			config.id, config.address, CW201x_REG_CONFIG, ret);
		goto exit;
	}
	fprintf(stdout, "OK - val=0x%02x\n", conf);
	fprintf(stdout, "Writing configuration register...");
	conf = 0xff;
	ret = i2c->write_register(cw2015, CW201x_REG_CONFIG, &conf, 1);
	if (ret != S_OK) {
		fprintf(stderr,
			"FAILED\nFailed to write I2C %d@0x%02x\n"
			"register 0x%04x (%d)\n",
			config.id, config.address, CW201x_REG_CONFIG, ret);
		goto exit;
	}
	fprintf(stdout, "OK\n");
	fprintf(stdout, "Reading configuration register...");
	ret = i2c->read_register(cw2015, CW201x_REG_CONFIG, &conf, 1);
	if (ret != S_OK) {
		fprintf(stderr,
			"FAILED\nFailed to read I2C %d@0x%02x\n"
			"register 0x%04x (%d)\n",
			config.id, config.address, CW201x_REG_CONFIG, ret);
		goto exit;
	}
	fprintf(stdout, "OK - val=0x%02x\n", conf);
	ret = i2c->release(cw2015);
	if (ret != S_OK) {
		fprintf(stderr, "Failed to release I2C %d@0x%02x (%d)\n",
			config.id, config.address, ret);
		goto exit;
	}
exit:
	fprintf(stdout, "TEST: %s %s\n", __func__, (ret == S_OK) ? "succeeded" :
								"failed");

	artik_release_api_module(i2c);

	return ret;
}

static artik_error i2c_test_rt5659(int platid)
{
	artik_i2c_module *i2c = (artik_i2c_module *)
						artik_request_api_module("i2c");
	artik_i2c_handle rt5659;
	artik_error ret;
	uint16_t val;

	config.address = 0x1a;
	config.wordsize = I2C_16BIT;

	if (platid == EVERGREEEN)
		config.id = 6;

	fprintf(stdout, "TEST: %s starting\n", __func__);
	ret = i2c->request(&rt5659, &config);
	if (ret != S_OK) {
		fprintf(stderr, "Failed to request I2C %d@0x%02x (%d)\n",
			config.id, config.address, ret);
		goto exit;
	}

	fprintf(stdout, "Reading device ID...");
	ret = i2c->read_register(rt5659, RT5659_REG_DEVICEID, (char *)&val,
			sizeof(val));
	if (ret != S_OK) {
		fprintf(stderr,
			"FAILED\nFailed to read I2C %d@0x%02x\n"
			"register 0x%04x (%d)\n",
			config.id, config.address, RT5659_REG_DEVICEID, ret);
		goto exit;
	}

	fprintf(stdout, "OK - val=0x%04x\n", val);

	if (val != 0x1163) {
		fprintf(stderr, "%s: Wrong chip version read, expected 0x1163, got 0x%04x\n",
			__func__, val);
		goto exit;
	}

	fprintf(stdout, "Reading dummy register...");
	ret = i2c->read_register(rt5659, RT5659_REG_DUMMY, (char *)&val,
			sizeof(val));
	if (ret != S_OK) {
		fprintf(stderr,
			"FAILED\nFailed to read I2C %d@0x%02x\n"
			"register 0x%04x (%d)\n",
			config.id, config.address, RT5659_REG_DUMMY, ret);
		goto exit;
	}
	fprintf(stdout, "OK - val=0x%04x\n", val);

	fprintf(stdout, "Writing dummy register...");
	val = 0xaa55;
	ret = i2c->write_register(rt5659, RT5659_REG_DUMMY, (char *)&val, sizeof(val));
	if (ret != S_OK) {
		fprintf(stderr,
			"FAILED\nFailed to write I2C %d@0x%02x\n"
			"register 0x%04x (%d)\n",
			config.id, config.address, RT5659_REG_DUMMY, ret);
		goto exit;
	}
	fprintf(stdout, "OK\n");
	fprintf(stdout, "Reading back dummy register...");
	ret = i2c->read_register(rt5659, RT5659_REG_DUMMY, (char *)&val, sizeof(val));
	if (ret != S_OK) {
		fprintf(stderr,
			"FAILED\nFailed to read I2C %d@0x%02x\n"
			"register 0x%04x (%d)\n",
			config.id, config.address, RT5659_REG_DUMMY, ret);
		goto exit;
	}
	fprintf(stdout, "OK - val=0x%04x\n", val);

	if (val != 0xaa55) {
		fprintf(stderr, "%s: Failed to write dummy register, expected 0xaa55, got 0x%04x\n",
			__func__, val);
		goto exit;
	}

exit:
	if (i2c->release(rt5659) != S_OK) {
		fprintf(stderr, "Failed to release I2C %d@0x%02x\n",
			config.id, config.address);
	}

	fprintf(stdout, "TEST: %s %s\n", __func__, (ret == S_OK) ? "succeeded" :
								"failed");

	artik_release_api_module(i2c);

	return ret;
}

int main(void)
{
	artik_error ret = E_NOT_SUPPORTED;
	int platid = artik_get_platform();
	const char *cmd;

	if (platid == ARTIK520)
		cmd = cmd_artik520;
	else if (platid == ARTIK710)
		cmd = cmd_artik710;
	else if (platid == ARTIK530)
		cmd = cmd_artik530;
	else if (platid == ARTIK305)
		cmd = cmd_artik305;
	else if (platid == EVERGREEEN)
		cmd = cmd_evergreeen;
	else
		cmd = cmd_artik1020;

	/* Unbind the driver */
	if (system(cmd))
		fprintf(stdout, "Failed to unbind the driver\n");

	if ((platid == ARTIK520) || (platid == ARTIK1020) ||
			(platid == ARTIK710) || (platid == ARTIK530) ||
			(platid == ARTIK305)) {
		ret = i2c_test_cw2015(platid);
	} else if (platid == EVERGREEEN) {
		ret = i2c_test_rt5659(platid);
	} else {
		fprintf(stdout, "Test failed - Unsupported platform\n");
	}

	return (ret == S_OK) ? 0 : -1;
}
