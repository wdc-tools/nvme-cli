#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/fs.h>
#include <inttypes.h>
#include <asm/byteorder.h>

#include "linux/nvme_ioctl.h"

#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"
#include <sys/ioctl.h>
#define CREATE_CMD
#include "hgst-nvme.h"

/* Purge and Purge Monitor constants */
#define HGST_NVME_PURGE_CMD_OPCODE			0xDD
#define HGST_NVME_PURGE_MONITOR_OPCODE		0xDE
#define HGST_NVME_PUEGE_MONITOR_DATA_LEN	0x2F
#define HGST_NVME_PURGE_MONITOR_CMD_CDW10	0x0000000C
#define HGST_NVME_PURGE_MONITOR_TIMEOUT		0x7530
#define HGST_NVME_PURGE_CMD_SEQ_ERR			0x0C
#define HGST_NVME_PURGE_INT_DEV_ERR			0x06
#define HGST_NVME_PURGE_STATE_IDLE			0x00
#define HGST_NVME_PURGE_STATE_DONE			0x01
#define HGST_NVME_PURGE_STATE_BUSY			0x02
#define HGST_NVME_PURGE_STATE_REQ_PWR_CYC	0x03
#define HGST_NVME_PURGE_STATE_PWR_CYC_PURGE	0x04


/* Purge monitor response */
struct hgst_nvme_purge_monitor_data {
	__u16 rsvd1;
	__u16 rsvd2;
	__u16 first_erase_failure_cnt;
	__u16 second_erase_failure_cnt;
	__u16 rsvd3;
	__u16 programm_failure_cnt;
	__u32 rsvd4;
	__u32 rsvd5;
	__u32 entire_progress_total;
	__u32 entire_progress_current;
	__u8  rsvd6[14];
};

static const char* hgst_nvme_status_to_string(__u32 status)
{
	const char *str;

	switch (status) {
	case 0x00:
		str = "Purge State Idle.";
		break;
	case 0x01:
		str = "Purge State Done.";
		break;
	case 0x02:
	str = "Purge State Busy.";
		break;
	case 0x03:
		str = "Purge Operation resulted in an error that requires power cycle.";
		break;
	case 0x04:
		str = "The previous purge operation was interrupted by a power cycle\n"
			"or reset interruption. Other commands may be rejected until\n"
			"Purge Execute is issued and completed.";
		break;
	default:
		str = "Unknown.";
	}
	return str;
}

static int hgst_purge(int argc, char **argv,
				struct command *command, struct plugin *plugin)
{
	char *desc = "Send a Purge command";
	char *err_str;
	int fd;
	int rc;
	struct nvme_passthru_cmd admin_cmd;
	const struct argconfig_commandline_options command_line_options[] = {
		{   .option = NULL,
			.short_option = '\0',
			.meta = NULL,
			.config_type = CFG_NONE,
			.default_value = NULL,
			.argument_type = no_argument,
			.help = desc
		},
		{0}
	};

	err_str = "";
	memset(&admin_cmd, 0, sizeof(admin_cmd));
	admin_cmd.opcode = HGST_NVME_PURGE_CMD_OPCODE;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	rc = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (rc > 0) {
		switch (rc) {
		case HGST_NVME_PURGE_CMD_SEQ_ERR:
			err_str = "ERROR : Cannot execute purge, "
					"Purge operation is in progresss.\n";
			break;
		case HGST_NVME_PURGE_INT_DEV_ERR:
			err_str = "ERROR : Internal Device Error.\n";
			break;
		default:
			err_str = "ERROR\n";
		}
	}
	fprintf(stderr, "%s", err_str);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(rc), rc);
	return rc;
}

static int hgst_purge_monitor(int argc, char **argv,
				struct command *command, struct plugin *plugin)
{
	char *desc = "Send a Purge Monitor command";
	int fd;
	int rc;
	__u8 output[HGST_NVME_PUEGE_MONITOR_DATA_LEN];
	double progress_percent;
	struct nvme_admin_cmd admin_cmd;
	struct hgst_nvme_purge_monitor_data *mon;
	const struct argconfig_commandline_options command_line_options[] = {
		{
			.option = NULL,
			.short_option = '\0',
			.meta = NULL,
			.config_type = CFG_NONE,
			.default_value = NULL,
			.argument_type = no_argument,
			.help = desc
		},
		{0}
	};

	memset(output, 0, sizeof(output));
	memset(&admin_cmd, 0, sizeof(struct nvme_admin_cmd));
	admin_cmd.opcode = HGST_NVME_PURGE_MONITOR_OPCODE;
	admin_cmd.addr = (__u64) output;
	admin_cmd.data_len = HGST_NVME_PUEGE_MONITOR_DATA_LEN;
	admin_cmd.cdw10 = HGST_NVME_PURGE_MONITOR_CMD_CDW10;
	admin_cmd.timeout_ms = HGST_NVME_PURGE_MONITOR_TIMEOUT;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	rc = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (rc == 0) {
		mon = (struct hgst_nvme_purge_monitor_data *) output;
		printf("Purge state = 0x%0x \n%s\n", admin_cmd.result,
				hgst_nvme_status_to_string(admin_cmd.result));
		if (admin_cmd.result == HGST_NVME_PURGE_STATE_BUSY) {
			progress_percent = ((double)mon->entire_progress_current * 100) /
				mon->entire_progress_total;
			printf("Purge Progress = %f%%\n", progress_percent);
		}
	}
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(rc), rc);
	return rc;
}
