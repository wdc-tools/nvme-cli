#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>
#include <linux/limits.h>
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

/* Capture Diagnostics */
#define HGST_CAP_DIAGS_HEADER_TOC_SIZE	0x100
#define HGST_CAP_DIAGS_OPCODE			0xE6
#define HGST_NVME_CAP_DIAGS_CMD_OPCODE	0xC6

/* Drive Log */
#define HGST_NVME_GET_DRIVE_LOG_CMD				0x20
#define HGST_NVME_GET_DRIVE_LOG_STR_TBL_SUBCMD	0x02
#define HGST_NVME_GET_DRIVE_LOG_BIN_LOG_SUBCMD	0x00
#define HGST_NVME_GET_DRIVE_LOG_SIZE_SUBCMD		0x01
#define HGST_NVME_GET_DRIVE_LOG_SIZE_NDT		0x02
#define HGST_NVME_GET_DRIVE_LOG_SIZE_DATA_LEN	0x08
#define HGST_NVME_GET_DRIVE_LOG_CDW10			0x02
#define HGST_NVME_GET_DRIVE_LOG_CDW12			0x20

/* Purge and Purge Monitor constants */
#define HGST_NVME_PURGE_CMD_OPCODE			0xDD
#define HGST_NVME_PURGE_MONITOR_OPCODE		0xDE
#define HGST_NVME_PURGE_MONITOR_DATA_LEN	0x2F
#define HGST_NVME_PURGE_MONITOR_CMD_CDW10	0x0000000C
#define HGST_NVME_PURGE_MONITOR_TIMEOUT		0x7530
#define HGST_NVME_PURGE_CMD_SEQ_ERR			0x0C
#define HGST_NVME_PURGE_INT_DEV_ERR			0x06
#define HGST_NVME_PURGE_STATE_IDLE			0x00
#define HGST_NVME_PURGE_STATE_DONE			0x01
#define HGST_NVME_PURGE_STATE_BUSY			0x02
#define HGST_NVME_PURGE_STATE_REQ_PWR_CYC	0x03
#define HGST_NVME_PURGE_STATE_PWR_CYC_PURGE	0x04


/* Drive log data size */
static struct hgst_drive_log_size {
	__u32			drive_log_size;
};

/* Purge monitor response */
static struct hgst_nvme_purge_monitor_data {
	__u16			rsvd1;
	__u16			rsvd2;
	__u16			first_erase_failure_cnt;
	__u16			second_erase_failure_cnt;
	__u16			rsvd3;
	__u16			programm_failure_cnt;
	__u32			rsvd4;
	__u32			rsvd5;
	__u32			entire_progress_total;
	__u32			entire_progress_current;
	__u8			rsvd6[14];
};


static int hgst_get_serial_name(int fd, char *file)
{
	int i;
	int ret;
	struct nvme_id_ctrl ctrl;

	i = sizeof (ctrl.sn) - 1;
	ret = nvme_identify_ctrl(fd, &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR : HGST : nvme_identify_ctrl() failed 0x%x\n",
				ret);
		return -1;
	}
	/* Remove trailing spaces from the name */
	while (i && ctrl.sn[i] == ' ') {
		ctrl.sn[i] = '\0';
		i--;
	}
	sprintf(file, "%s.bin", ctrl.sn);
	return 0;
}

static int hgst_create_log_file(char *file, __u8 *drive_log_data,
		__u32 drive_log_length)
{
	FILE *bin_file;
	long PAGE_SIZE = sysconf(_SC_PAGESIZE);

	if (drive_log_length == 0) {
		fprintf(stderr, "ERROR : invalid log file lenth\n");
		return -1;
	}

	bin_file = fopen(file, "wb+");
	if (!bin_file) {
		fprintf(stderr, "ERROR : fopen : %s\n", strerror(errno));
		return -1;
	}

	while (drive_log_length > PAGE_SIZE) {
		fwrite(&drive_log_data, sizeof (__u8), PAGE_SIZE, bin_file);
		if (ferror(bin_file)) {
			fprintf (stderr, "ERROR : fwrite : %s\n", strerror(errno));
			return -1;
		}
		drive_log_length -= PAGE_SIZE;
	}

	fwrite(&drive_log_data, sizeof (__u8), drive_log_length, bin_file);
	if (ferror(bin_file)) {
		fprintf (stderr, "ERROR : fwrite : %s\n", strerror(errno));
		return -1;
	}

	if (fflush(bin_file) != 0) {
		fprintf(stderr, "ERROR : fsync : %s\n", strerror(errno));
		return -1;
	}
	fclose(bin_file);
	return 0;
}

static __u32 hgst_cap_diag_get_log_length(int fd, __u32 *cap_diag_length)
{
	int ret;
	__u32 total_length;
	__u8 header_toc[HGST_CAP_DIAGS_HEADER_TOC_SIZE];
	struct nvme_admin_cmd admin_cmd;

	memset(header_toc, 0, sizeof (header_toc));
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = HGST_CAP_DIAGS_OPCODE;
	admin_cmd.addr = (__u64) header_toc;
	admin_cmd.data_len = HGST_CAP_DIAGS_HEADER_TOC_SIZE;
	admin_cmd.cdw10 = HGST_CAP_DIAGS_HEADER_TOC_SIZE / 4;
	admin_cmd.cdw13 = 0x00;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret != 0) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret),
				ret);
		total_length = 0;
		ret = -1;
	} else {
		total_length = header_toc[0x04] << 24 |
						header_toc[0x05] << 16 |
						header_toc[0x06] << 8 |
						header_toc[0x07];
	}
	*cap_diag_length = total_length;
	return ret;
}

static int hgst_do_cap_diag(int fd, char *file)
{
	int ret;
	__u8 *cap_diag_data;
	__u32 cap_diag_length;
	struct nvme_admin_cmd admin_cmd;

	ret = hgst_cap_diag_get_log_length(fd, &cap_diag_length);
	if (ret != 0) {
		fprintf(stderr, "ERROR : failed to get the length of cap-diag log\n");
		return -1;
	}

	cap_diag_data = (__u8*) malloc(sizeof(__u8) * cap_diag_length);
	if (cap_diag_data == NULL) {
		fprintf(stderr, "ERROR : malloc : %s\n", strerror(errno));
		return -1;
	}

	memset(cap_diag_data, 0, cap_diag_length);
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));

	admin_cmd.opcode = HGST_CAP_DIAGS_OPCODE;
	admin_cmd.addr = (__u64) cap_diag_data;
	admin_cmd.data_len = cap_diag_length;
	admin_cmd.cdw10 = cap_diag_length / 4;
	admin_cmd.cdw13 = 0x00;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret == 0) {
		ret = hgst_create_log_file(file, cap_diag_data, cap_diag_length);
	}
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	free(cap_diag_data);

	return ret;
}

static int hgst_cap_diag(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Capture Diagnostics Log.";
	char *file = "Output file pathname.";
	char f[0x100];
	int fd;

	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"file", 'f', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (cfg.file == NULL) {
		cfg.file = f;
		if (hgst_get_serial_name(fd, cfg.file) == -1) {
			fprintf(stderr, "ERROR : failed to generate file name\n");
			return -1;
		}
	}
	return hgst_do_cap_diag(fd, cfg.file);
}

static __u32 hgst_drive_log_length(int fd, __u32 *drive_log_length)
{
	int ret;
	__u8 buf[HGST_NVME_GET_DRIVE_LOG_SIZE_DATA_LEN];
	struct hgst_drive_log_size *l;
	struct nvme_admin_cmd admin_cmd;

	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = HGST_NVME_CAP_DIAGS_CMD_OPCODE;
	admin_cmd.addr = (__u64) buf;
	admin_cmd.data_len = HGST_NVME_GET_DRIVE_LOG_SIZE_DATA_LEN;
	admin_cmd.cdw10 = HGST_NVME_GET_DRIVE_LOG_SIZE_NDT;
	admin_cmd.cdw12 = (HGST_NVME_GET_DRIVE_LOG_SIZE_SUBCMD << 8 |
						HGST_NVME_GET_DRIVE_LOG_CMD);

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret == 0) {
		l = (struct hgst_drive_log_size *) buf;
	} else {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret),
				ret);
		l->drive_log_size = 0;
		ret = -1;
	}

	*drive_log_length = l->drive_log_size;
	return ret;
}

static int hgst_do_drive_log(int fd, char *file)
{
	int ret;
	__u8 *drive_log_data;
	__u32 drive_log_length;
	struct nvme_admin_cmd admin_cmd;

	ret = hgst_drive_log_length(fd, &drive_log_length);
	if (ret != 0) {
		fprintf(stderr, "ERROR : failed to get the length of drive log\n");
		return -1;
	}

	drive_log_data = (__u8 *) malloc(sizeof (__u8) * drive_log_length);
	if (drive_log_data == NULL) {
		fprintf(stderr, "ERROR : malloc : %s\n", strerror(errno));
		return -1;
	}

	memset(drive_log_data, 0, sizeof (__u8) * drive_log_length);
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = HGST_NVME_CAP_DIAGS_CMD_OPCODE;
	admin_cmd.addr = (__u64) drive_log_data;
	admin_cmd.data_len = drive_log_length;
	admin_cmd.cdw10 = drive_log_length;
	admin_cmd.cdw12 = (HGST_NVME_GET_DRIVE_LOG_BIN_LOG_SUBCMD << 8 |
			HGST_NVME_GET_DRIVE_LOG_CMD);

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret == 0) {
		ret = hgst_create_log_file(file, drive_log_data, drive_log_length);
	}
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	free(drive_log_data);
	return ret;
}

static int hgst_drive_log(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Capture Drive Log.";
	char *file = "Output file pathname.";
	char f[0x100];
	int fd;
	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"file", 'f', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (cfg.file == NULL) {
		cfg.file = f;
		if (hgst_get_serial_name(fd, cfg.file) == -1) {
			fprintf(stderr, "ERROR : failed to generate file name\n");
			return -1;
		}
	}
	return hgst_do_drive_log(fd, cfg.file);
}

static const char* hgst_nvme_purge_mon_status_to_string(__u32 status)
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
	int ret;
	struct nvme_passthru_cmd admin_cmd;
	const struct argconfig_commandline_options command_line_options[] = {
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
		{0}
	};

	err_str = "";
	memset(&admin_cmd, 0, sizeof (admin_cmd));
	admin_cmd.opcode = HGST_NVME_PURGE_CMD_OPCODE;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret > 0) {
		switch (ret) {
		case HGST_NVME_PURGE_CMD_SEQ_ERR:
			err_str = "ERROR : Cannot execute purge, "
					"Purge operation is in progress.\n";
			break;
		case HGST_NVME_PURGE_INT_DEV_ERR:
			err_str = "ERROR : Internal Device Error.\n";
			break;
		default:
			err_str = "ERROR\n";
		}
	}
	fprintf(stderr, "%s", err_str);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	return ret;
}

static int hgst_purge_monitor(int argc, char **argv,
				struct command *command, struct plugin *plugin)
{
	char *desc = "Send a Purge Monitor command";
	int fd;
	int ret;
	__u8 output[HGST_NVME_PUEGE_MONITOR_DATA_LEN];
	double progress_peretent;
	struct nvme_passthru_cmd admin_cmd;
	struct hgst_nvme_purge_monitor_data *mon;
	const struct argconfig_commandline_options command_line_options[] = {
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
		{0}
	};

	memset(output, 0, sizeof (output));
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = HGST_NVME_PURGE_MONITOR_OPCODE;
	admin_cmd.addr = (__u64) output;
	admin_cmd.data_len = HGST_NVME_PUEGE_MONITOR_DATA_LEN;
	admin_cmd.cdw10 = HGST_NVME_PURGE_MONITOR_CMD_CDW10;
	admin_cmd.timeout_ms = HGST_NVME_PURGE_MONITOR_TIMEOUT;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret == 0) {
		mon = (struct hgst_nvme_purge_monitor_data *) output;
		printf("Purge state = 0x%0x \n%s\n", admin_cmd.result,
				hgst_nvme_purge_mon_status_to_string(admin_cmd.result));
		if (admin_cmd.result == HGST_NVME_PURGE_STATE_BUSY) {
			progress_peretent = ((double)mon->entire_progress_current * 100) /
				mon->entire_progress_total;
			printf("Purge Progress = %f%%\n", progress_peretent);
		}
	}
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	return ret;
}
