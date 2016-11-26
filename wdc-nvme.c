#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
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
#include "wdc-nvme.h"

#define WRITE_SIZE	(sizeof(__u8) * 4096)

#define WDC_NVME_SUBCMD_SHIFT	8

#define WDC_NVME_LOG_SIZE_DATA_LEN			0x08

/* Capture Diagnostics */
#define WDC_NVME_CAP_DIAG_HEADER_TOC_SIZE	WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_CAP_DIAG_OPCODE			0xE6
#define WDC_NVME_CAP_DIAG_CMD_OPCODE		0xC6
#define WDC_NVME_CAP_DIAG_SUBCMD			0x00
#define WDC_NVME_CAP_DIAG_CMD				0x00

/* Crash dump */
#define WDC_NVME_CRASH_DUMP_SIZE_OPCODE		WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_CRASH_DUMP_SIZE_DATA_LEN	WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_CRASH_DUMP_SIZE_NDT		0x02
#define WDC_NVME_CRASH_DUMP_SIZE_CMD		0x20
#define WDC_NVME_CRASH_DUMP_SIZE_SUBCMD		0x03

#define WDC_NVME_CRASH_DUMP_OPCODE			WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_CRASH_DUMP_CMD				0x20
#define WDC_NVME_CRASH_DUMP_SUBCMD			0x04

/* Drive Log */
#define WDC_NVME_DRIVE_LOG_SIZE_OPCODE		WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_DRIVE_LOG_SIZE_DATA_LEN	WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_DRIVE_LOG_SIZE_NDT			0x02
#define WDC_NVME_DRIVE_LOG_SIZE_CMD			0x20
#define WDC_NVME_DRIVE_LOG_SIZE_SUBCMD		0x01

#define WDC_NVME_DRIVE_LOG_OPCODE			WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_DRIVE_LOG_CMD				WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_DRIVE_LOG_SUBCMD			0x00

/* Pfail Crash dump */
#define WDC_NVME_PFAIL_DUMP_SIZE_OPCODE		WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_PFAIL_DUMP_SIZE_DATA_LEN	WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_PFAIL_DUMP_SIZE_NDT		0x02
#define WDC_NVME_PFAIL_DUMP_SIZE_CMD		0x20
#define WDC_NVME_PFAIL_DUMP_SIZE_SUBCMD		0x05

#define WDC_NVME_PFAIL_DUMP_OPCODE			WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_PFAIL_DUMP_CMD				0x20
#define WDC_NVME_PFAIL_DUMP_SUBCMD			0x06

/* Purge and Purge Monitor */
#define WDC_NVME_PURGE_CMD_OPCODE			0xDD
#define WDC_NVME_PURGE_MONITOR_OPCODE		0xDE
#define WDC_NVME_PURGE_MONITOR_DATA_LEN		0x2F
#define WDC_NVME_PURGE_MONITOR_CMD_CDW10	0x0000000C
#define WDC_NVME_PURGE_MONITOR_TIMEOUT		0x7530
#define WDC_NVME_PURGE_CMD_SEQ_ERR			0x0C
#define WDC_NVME_PURGE_INT_DEV_ERR			0x06

#define WDC_NVME_PURGE_STATE_IDLE			0x00
#define WDC_NVME_PURGE_STATE_DONE			0x01
#define WDC_NVME_PURGE_STATE_BUSY			0x02
#define WDC_NVME_PURGE_STATE_REQ_PWR_CYC	0x03
#define WDC_NVME_PURGE_STATE_PWR_CYC_PURGE	0x04

/* Clear dumps */
#define WDC_NVME_CLEAR_DUMP_OPCODE			0xFF
#define WDC_NVME_CLEAR_CRASH_DUMP_CMD		0x03
#define WDC_NVME_CLEAR_CRASH_DUMP_SUBCMD	0x05
#define WDC_NVME_CLEAR_PFAIL_DUMP_CMD		0x03

static int wdc_get_serial_name(int fd, char *file, size_t len);
static int wdc_create_log_file(char *file, __u8 *drive_log_data,
		__u32 drive_log_length);
static int wdc_do_clear_dump(int fd, __u8 opcode, __u32 cdw12);
static int wdc_do_dump(int fd, __u32 opcode,__u32 data_len, __u32 cdw10,
		__u32 cdw12, __u32 dump_length, char *file);
static int wdc_do_crash_dump(int fd, char *file);
static int wdc_crash_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static int wdc_do_pfail_dump(int fd, char *file);
static int wdc_pfail_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static int wdc_do_drive_log(int fd, char *file);
static int wdc_drive_log(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static const char* wdc_purge_mon_status_to_string(__u32 status);
static int wdc_purge(int argc, char **argv,
		struct command *command, struct plugin *plugin);
static int wdc_purge_monitor(int argc, char **argv,
		struct command *command, struct plugin *plugin);

/* Drive log data size */
struct wdc_log_size {
	__u32			log_size;
};

/* Purge monitor response */
struct wdc_nvme_purge_monitor_data {
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


static int wdc_get_serial_name(int fd, char *file, size_t len)
{
	int i;
	int ret;
	struct nvme_id_ctrl ctrl;

	i = sizeof (ctrl.sn) - 1;

	memset(&ctrl, 0, sizeof (struct nvme_id_ctrl));
	ret = nvme_identify_ctrl(fd, &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : nvme_identify_ctrl() failed "
				"0x%x\n", ret);
		return -1;
	}
	/* Remove trailing spaces from the name */
	while (i && ctrl.sn[i] == ' ') {
		ctrl.sn[i] = '\0';
		i--;
	}
	snprintf(file, len, "%s.bin", ctrl.sn);
	return 0;
}

static int wdc_create_log_file(char *file, __u8 *drive_log_data,
		__u32 drive_log_length)
{
	FILE *bin_file;

	if (drive_log_length == 0) {
		fprintf(stderr, "ERROR : invalid log file length\n");
		return -1;
	}

	bin_file = fopen(file, "wb+");
	if (!bin_file) {
		fprintf(stderr, "ERROR : fopen : %s\n", strerror(errno));
		return -1;
	}

	while (drive_log_length > WRITE_SIZE) {
		fwrite(drive_log_data, sizeof (__u8), WRITE_SIZE, bin_file);
		if (ferror(bin_file)) {
			fprintf (stderr, "ERROR : fwrite : %s\n", strerror(errno));
			return -1;
		}
		drive_log_data += WRITE_SIZE;
		drive_log_length -= WRITE_SIZE;
	}

	fwrite(drive_log_data, sizeof (__u8), drive_log_length, bin_file);
	if (ferror(bin_file)) {
		fprintf (stderr, "ERROR : fwrite : %s\n", strerror(errno));
		return -1;
	}

	if (fflush(bin_file) != 0) {
		fprintf(stderr, "ERROR : fflush : %s\n", strerror(errno));
		return -1;
	}
	fclose(bin_file);
	return 0;
}

static int wdc_do_clear_dump(int fd, __u8 opcode, __u32 cdw12)
{
	int ret;
	struct nvme_admin_cmd admin_cmd;

	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = opcode;
	admin_cmd.cdw12 = cdw12;
	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret != 0) {
		fprintf(stdout, "ERROR : Crash dump erase failed\n");
	}
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	return ret;
}

static __u32 wdc_dump_length(int fd, __u32 opcode, __u32 cdw10, __u32 cdw12, __u32 *dump_length)
{
	int ret;
	__u8 buf[WDC_NVME_LOG_SIZE_DATA_LEN] = {0};
	struct wdc_log_size *l;
	struct nvme_admin_cmd admin_cmd;

	l = (struct wdc_log_size *) buf;
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = opcode;
	admin_cmd.addr = (__u64) buf;
	admin_cmd.data_len = WDC_NVME_LOG_SIZE_DATA_LEN;
	admin_cmd.cdw10 = cdw10;
	admin_cmd.cdw12 = cdw12;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret != 0) {
		l->log_size = 0;
		ret = -1;
		fprintf(stderr, "ERROR : reading dump length failed\n");
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	}

	if (opcode == WDC_NVME_CAP_DIAG_OPCODE) {
		*dump_length = buf[0x04] << 24 | buf[0x05] << 16 | buf[0x06] << 8 | buf[0x07];
	} else {
		*dump_length = l->log_size;
	}
	return ret;
}

static int wdc_do_dump(int fd, __u32 opcode,__u32 data_len, __u32 cdw10,
		__u32 cdw12, __u32 dump_length, char *file)
{
	int ret;
	__u8 *dump_data;
	struct nvme_admin_cmd admin_cmd;

	dump_data = (__u8 *) malloc(sizeof (__u8) * dump_length);
	if (dump_data == NULL) {
		fprintf(stderr, "ERROR : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(dump_data, 0, sizeof (__u8) * dump_length);
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = opcode;
	admin_cmd.addr = (__u64) dump_data;
	admin_cmd.data_len = data_len;
	admin_cmd.cdw10 = cdw10;
	admin_cmd.cdw12 = cdw12;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	if (ret == 0) {
		ret = wdc_create_log_file(file, dump_data, dump_length);
	}
	free(dump_data);
	return ret;
}

static int wdc_do_cap_diag(int fd, char *file)
{
	int ret;
	__u32 cap_diag_length;

	ret = wdc_dump_length(fd, WDC_NVME_CAP_DIAG_OPCODE,
						WDC_NVME_CAP_DIAG_HEADER_TOC_SIZE,
						0x00,
						&cap_diag_length);
	if (ret == -1) {
		return -1;
	}
	printf("cap_diag_length %u\n", cap_diag_length);
	if (cap_diag_length == 0) {
		fprintf(stderr, "Capture Dignostics log is empty\n");
	} else {
		ret = wdc_do_dump(fd, WDC_NVME_CAP_DIAG_OPCODE, cap_diag_length,
				cap_diag_length,
				(WDC_NVME_CAP_DIAG_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
				 WDC_NVME_CAP_DIAG_CMD, cap_diag_length, file);

	}
	return ret;
}

static int wdc_cap_diag(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Capture Diagnostics Log.";
	char *file = "Output file pathname.";
	char f[PATH_MAX];
	int fd;

	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (cfg.file == NULL) {
		cfg.file = f;
		if (wdc_get_serial_name(fd, cfg.file, PATH_MAX) == -1) {
			fprintf(stderr, "ERROR : failed to generate file name\n");
			return -1;
		}
	}
	return wdc_do_cap_diag(fd, cfg.file);
}

static int wdc_do_crash_dump(int fd, char *file)
{
	int ret;
	__u32 crash_dump_length;

	ret = wdc_dump_length(fd, WDC_NVME_CRASH_DUMP_SIZE_OPCODE,
			WDC_NVME_CRASH_DUMP_SIZE_NDT,
			((WDC_NVME_CRASH_DUMP_SIZE_SUBCMD <<
			WDC_NVME_SUBCMD_SHIFT) | WDC_NVME_CRASH_DUMP_SIZE_CMD),
			&crash_dump_length);
	if (ret == -1) {
		return -1;
	}
	if (crash_dump_length == 0) {
		fprintf(stderr, "Crash dump is empty\n");
	} else {
		ret = wdc_do_dump(fd, WDC_NVME_CRASH_DUMP_OPCODE, crash_dump_length,
				crash_dump_length,
				(WDC_NVME_CRASH_DUMP_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
				 WDC_NVME_CRASH_DUMP_CMD, crash_dump_length, file);
	}
	return ret;
}

static int wdc_crash_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Crash Dump.";
	char *file = "Output file pathname.";
	char *clear = "Erases the Crash Dump.";
	char f[PATH_MAX] = {0};
	int fd;
	__u8 opcode = WDC_NVME_CLEAR_DUMP_OPCODE;
	__u32 cdw12 = ((WDC_NVME_CLEAR_CRASH_DUMP_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_CLEAR_CRASH_DUMP_CMD);
	struct config {
		char *file;
		int clear;
	};

	struct config cfg = {
		.file = NULL,
		.clear = 0
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{"clear", 'c', NULL, CFG_NONE, &cfg.clear, no_argument, clear},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);

	if (cfg.clear == 1) {
		return wdc_do_clear_dump(fd, opcode, cdw12);
	}

	if (cfg.file == NULL) {
		cfg.file = f;
		if (wdc_get_serial_name(fd, cfg.file, PATH_MAX) == -1) {
			fprintf(stderr, "ERROR : failed to generate file name\n");
			return -1;
		}
	}
	return wdc_do_crash_dump(fd, cfg.file);
}

static int wdc_do_drive_log(int fd, char *file)
{
	int ret;
	__u8 *drive_log_data;
	__u32 drive_log_length;
	struct nvme_admin_cmd admin_cmd;

	ret = wdc_dump_length(fd, WDC_NVME_DRIVE_LOG_SIZE_OPCODE,
			WDC_NVME_DRIVE_LOG_SIZE_NDT,
			(WDC_NVME_DRIVE_LOG_SIZE_SUBCMD <<
			WDC_NVME_SUBCMD_SHIFT | WDC_NVME_DRIVE_LOG_SIZE_CMD),
			&drive_log_length);
	if (ret == -1) {
		return -1;
	}

	drive_log_data = (__u8 *) malloc(sizeof (__u8) * drive_log_length);
	if (drive_log_data == NULL) {
		fprintf(stderr, "ERROR : malloc : %s\n", strerror(errno));
		return -1;
	}

	memset(drive_log_data, 0, sizeof (__u8) * drive_log_length);
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = WDC_NVME_DRIVE_LOG_OPCODE;
	admin_cmd.addr = (__u64) drive_log_data;
	admin_cmd.data_len = drive_log_length;
	admin_cmd.cdw10 = drive_log_length;
	admin_cmd.cdw12 = ((WDC_NVME_DRIVE_LOG_SUBCMD <<
				WDC_NVME_SUBCMD_SHIFT) | WDC_NVME_DRIVE_LOG_SIZE_CMD);

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret),
			ret);
	if (ret == 0) {
		ret = wdc_create_log_file(file, drive_log_data, drive_log_length);
	}
	free(drive_log_data);
	return ret;
}

static int wdc_drive_log(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Capture Drive Log.";
	char *file = "Output file pathname.";
	char f[PATH_MAX] = {0};
	int fd;
	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (cfg.file == NULL) {
		cfg.file = f;
		if (wdc_get_serial_name(fd, cfg.file, PATH_MAX) == -1) {
			fprintf(stderr, "ERROR : failed to generate file name\n");
			return -1;
		}
	}
	return wdc_do_drive_log(fd, cfg.file);
}

static int wdc_do_pfail_dump(int fd, char *file)
{
	int ret;
	__u32 pfail_dump_length;

	ret = wdc_dump_length(fd,WDC_NVME_PFAIL_DUMP_SIZE_OPCODE,
			WDC_NVME_PFAIL_DUMP_SIZE_NDT,
			((WDC_NVME_PFAIL_DUMP_SIZE_SUBCMD <<
			WDC_NVME_SUBCMD_SHIFT) | WDC_NVME_PFAIL_DUMP_SIZE_CMD),
			&pfail_dump_length);
	if (ret == -1) {
		fprintf(stderr, "ERROR : failed to get the length of drive log\n");
		return -1;
	}
	if (pfail_dump_length == 0) {
		fprintf(stderr, "PFail dump is empty\n");
	} else {
		ret = wdc_do_dump(fd, WDC_NVME_PFAIL_DUMP_OPCODE, pfail_dump_length,
				pfail_dump_length,
				(WDC_NVME_PFAIL_DUMP_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
				 WDC_NVME_PFAIL_DUMP_CMD, pfail_dump_length, file);
	}
	return ret;
}

static int wdc_pfail_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Power Fail Dump.";
	char *file = "Output file pathname.";
	char *clear = "Erases the pfail crash dump.";
	char f[PATH_MAX] = {0};
	int fd;
	__u8 opcode = WDC_NVME_CLEAR_DUMP_OPCODE;
	__u32 cdw12 = WDC_NVME_CLEAR_PFAIL_DUMP_CMD;
	struct config {
		char *file;
		int clear;
	};

	struct config cfg = {
		.file = NULL,
		.clear = 0
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{"clear", 'c', NULL, CFG_NONE, &cfg.clear, no_argument, clear},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);

	if (cfg.clear == 1) {
		return wdc_do_clear_dump(fd, opcode, cdw12);
	}

	if (cfg.file == NULL) {
		cfg.file = f;
		if (wdc_get_serial_name(fd, cfg.file, PATH_MAX) == -1) {
			fprintf(stderr, "ERROR : failed to generate file name\n");
			return -1;
		}
	}
	return wdc_do_pfail_dump(fd, cfg.file);
}
static const char* wdc_purge_mon_status_to_string(__u32 status)
{
	const char *str;

	switch (status) {
	case WDC_NVME_PURGE_STATE_IDLE:
		str = "Purge State Idle.";
		break;
	case WDC_NVME_PURGE_STATE_DONE:
		str = "Purge State Done.";
		break;
	case WDC_NVME_PURGE_STATE_BUSY:
		str = "Purge State Busy.";
		break;
	case WDC_NVME_PURGE_STATE_REQ_PWR_CYC:
		str = "Purge Operation resulted in an error that requires "
			"power cycle.";
		break;
	case WDC_NVME_PURGE_STATE_PWR_CYC_PURGE:
		str = "The previous purge operation was interrupted by a power "
			"cycle\nor reset interruption. Other commands may be "
			"rejected until\nPurge Execute is issued and "
			"completed.";
		break;
	default:
		str = "Unknown.";
	}
	return str;
}

static int wdc_purge(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	char *desc = "Send a Purge command.";
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
	admin_cmd.opcode = WDC_NVME_PURGE_CMD_OPCODE;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret > 0) {
		switch (ret) {
		case WDC_NVME_PURGE_CMD_SEQ_ERR:
			err_str = "ERROR : Cannot execute purge, "
					"Purge operation is in progress.\n";
			break;
		case WDC_NVME_PURGE_INT_DEV_ERR:
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

static int wdc_purge_monitor(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	char *desc = "Send a Purge Monitor command.";
	int fd;
	int ret;
	__u8 output[WDC_NVME_PURGE_MONITOR_DATA_LEN];
	double progress_percent;
	struct nvme_passthru_cmd admin_cmd;
	struct wdc_nvme_purge_monitor_data *mon;
	const struct argconfig_commandline_options command_line_options[] = {
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
		{0}
	};

	memset(output, 0, sizeof (output));
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = WDC_NVME_PURGE_MONITOR_OPCODE;
	admin_cmd.addr = (__u64) output;
	admin_cmd.data_len = WDC_NVME_PURGE_MONITOR_DATA_LEN;
	admin_cmd.cdw10 = WDC_NVME_PURGE_MONITOR_CMD_CDW10;
	admin_cmd.timeout_ms = WDC_NVME_PURGE_MONITOR_TIMEOUT;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret == 0) {
		mon = (struct wdc_nvme_purge_monitor_data *) output;
		printf("Purge state = 0x%0x\n", admin_cmd.result);
		printf("%s\n", wdc_purge_mon_status_to_string(admin_cmd.result));
		if (admin_cmd.result == WDC_NVME_PURGE_STATE_BUSY) {
			progress_percent =
				((double)mon->entire_progress_current * 100) /
				mon->entire_progress_total;
			printf("Purge Progress = %f%%\n", progress_percent);
		}
	}
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	return ret;
}
