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
#include "json.h"

#include "argconfig.h"
#include "suffix.h"
#include <sys/ioctl.h>
#define CREATE_CMD
#include "wdc-nvme.h"

#define safe_div_fp(numerator, denominator) \
	(denominator ? ((double)numerator/(double)denominator) : 0)

#define calc_percent(numerator, denominator) \
	(denominator ? (uint64_t)(((double)numerator/(double)denominator)*100) : 0)

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

/* LED Beacon Disable */
#define WDC_NVME_LED_BEACON_DISABLE_OPCODE	0xD4
#define WDC_NVME_LED_BEACON_DISABLE_CMD		0x08
#define WDC_NVME_LED_BEACON_DISABLE_SUBCMD	0x00

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

/* Additional Smart Log */
#define WDC_ADD_LOG_BUF_LEN							0x4000
#define WDC_NVME_ADD_LOG_OPCODE						0xC1
#define WDC_GET_LOG_PAGE_SSD_PERFORMANCE			0x37
#define WDC_NVME_GET_STAT_PERF_INTERVAL_LIFETIME	0x0F
static int wdc_get_serial_name(int fd, char *file, size_t len, char *suffix);
static int wdc_create_log_file(char *file, __u8 *drive_log_data,
		__u32 drive_log_length);
static int wdc_do_clear_dump(int fd, __u8 opcode, __u32 cdw12);
static int wdc_do_dump(int fd, __u32 opcode,__u32 data_len, __u32 cdw10,
		__u32 cdw12, __u32 dump_length, char *file);
static int wdc_do_crash_dump(int fd, char *file);
static int wdc_crash_dump(int fd, char *file);
static int wdc_get_crash_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static int wdc_do_drive_log(int fd, char *file);
static int wdc_drive_log(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static const char* wdc_purge_mon_status_to_string(__u32 status);
static int wdc_purge(int argc, char **argv,
		struct command *command, struct plugin *plugin);
static int wdc_purge_monitor(int argc, char **argv,
		struct command *command, struct plugin *plugin);
enum {
	WDC_HUMAN,
	WDC_JSON,
};

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

/* Additional Smart Log */
struct wdc_log_page_header
{
	uint8_t		num_subpages;
	uint8_t		reserved;
	uint16_t	total_log_size;
};

struct wdc_log_page_subpage_header
{
	uint8_t		spcode;
	uint8_t		pcset;
	uint16_t	subpage_length;
};

struct wdc_ssd_perf_stats
{
	uint64_t	hr_cmds;		/* Host Read Commands				*/
	uint64_t	hr_blks;		/* Host Read Blocks					*/
	uint64_t	hr_ch_cmds;		/* Host Read Cache Hit Commands		*/
	uint64_t	hr_ch_blks;		/* Host Read Cache Hit Blocks		*/
	uint64_t	hr_st_cmds;		/* Host Read Stalled Commands		*/
	uint64_t	hw_cmds;		/* Host Write Commands				*/
	uint64_t	hw_blks;		/* Host Write Blocks				*/
	uint64_t	hw_os_cmds;		/* Host Write Odd Start Commands	*/
	uint64_t	hw_oe_cmds;		/* Host Write Odd End Commands		*/
	uint64_t	hw_st_cmds;		/* Host Write Commands Stalled		*/
	uint64_t	nr_cmds;		/* NAND Read Commands				*/
	uint64_t	nr_blks;		/* NAND Read Blocks					*/
	uint64_t	nw_cmds;		/* NAND Write Commands				*/
	uint64_t	nw_blks;		/* NAND Write Blocks				*/
	uint64_t	nrbw;			/* NAND Read Before Write			*/
};

static int wdc_get_serial_name(int fd, char *file, size_t len, char *suffix)
{
	int i;
	int ret;
	char orig[PATH_MAX] = {0};
	struct nvme_id_ctrl ctrl;

	i = sizeof (ctrl.sn) - 1;
	strncpy(orig, file, PATH_MAX);
	memset(file, 0, len);
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
	snprintf(file, len, "%s%s%s.bin", orig, ctrl.sn, suffix);
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
	} else {
		if (opcode == WDC_NVME_CAP_DIAG_OPCODE) {
			l->log_size = buf[0x04] << 24 | buf[0x05] << 16 | buf[0x06] << 8 | buf[0x07];
		}
	}
	*dump_length = l->log_size;
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
	if (cfg.file != NULL) {
		strncpy(f, cfg.file, PATH_MAX);
	}
	if (wdc_get_serial_name(fd, f, PATH_MAX, "cap_diag") == -1) {
		fprintf(stderr, "ERROR : failed to generate file name\n");
		return -1;
	}
	return wdc_do_cap_diag(fd, f);
}

static int wdc_led_beacon_disable(int fd)
{
	int ret;
	struct nvme_admin_cmd admin_cmd;

	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = WDC_NVME_LED_BEACON_DISABLE_OPCODE;
	admin_cmd.cdw12 = ((WDC_NVME_LED_BEACON_DISABLE_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_LED_BEACON_DISABLE_CMD);

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	return ret;
}

static int wdc_do_crash_dump(int fd, char *file)
{
	int ret;
	__u32 crash_dump_length;
	__u8 opcode = WDC_NVME_CLEAR_DUMP_OPCODE;
	__u32 cdw12 = ((WDC_NVME_CLEAR_CRASH_DUMP_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_CLEAR_CRASH_DUMP_CMD);

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
		if (ret == 0)
			ret = wdc_do_clear_dump(fd, opcode, cdw12);
		wdc_led_beacon_disable(fd);
	}
	return ret;
}

static int wdc_crash_dump(int fd, char *file)
{
	char f[PATH_MAX] = {0};

	if (file != NULL) {
		strncpy(f, file, PATH_MAX);
	}
	if (wdc_get_serial_name(fd, f, PATH_MAX, "crash_dump") == -1) {
		fprintf(stderr, "ERROR : failed to generate file name\n");
		return -1;
	}
	return wdc_do_crash_dump(fd, f);
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
	if (cfg.file != NULL) {
		strncpy(f, cfg.file, PATH_MAX);
	}
	if (wdc_get_serial_name(fd, f, PATH_MAX, "drive_log") == -1) {
		fprintf(stderr, "ERROR : failed to generate file name\n");
		return -1;
	}
	return wdc_do_drive_log(fd, f);
}

static int wdc_get_crash_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Get Crash Dump.";
	char *file = "Output file pathname.";
	int fd;
	int ret;
	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);

	ret = wdc_crash_dump(fd, cfg.file);
	if (ret != 0) {
		fprintf(stderr, "ERROR : failed to read crash dump\n");
	}
	return ret;
}

static void wdc_do_id_ctrl(__u8 *vs)
{
	char vsn[24];
	int base = 3072;
	int vsn_start = 3081;

	memcpy(vsn, &vs[vsn_start - base], sizeof(vsn));
	printf("wdc vsn	: %s\n", vsn);
}

static int wdc_id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, wdc_do_id_ctrl);
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

static void wdc_print_log_human(struct wdc_ssd_perf_stats *perf)
{
	printf("  Performance Statistics :- \n");
	printf("  Host Read Commands                             %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hr_cmds));
	printf("  Host Read Blocks                               %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hr_blks));
	printf("  Average Read Size                              %20lf\n",
			safe_div_fp((le64_to_cpu(perf->hr_blks)), (le64_to_cpu(perf->hr_cmds))));
	printf("  Host Read Cache Hit Commands                   %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hr_ch_cmds));
	printf("  Host Read Cache Hit_Percentage                 %20"PRIu64"%%\n",
			(uint64_t) calc_percent(le64_to_cpu(perf->hr_ch_cmds), le64_to_cpu(perf->hr_cmds)));
	printf("  Host Read Cache Hit Blocks                     %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hr_ch_blks));
	printf("  Average Read Cache Hit Size                    %20f\n",
			safe_div_fp((le64_to_cpu(perf->hr_ch_blks)), (le64_to_cpu(perf->hr_ch_cmds))));
	printf("  Host Read Commands Stalled                     %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hr_st_cmds));
	printf("  Host Read Commands Stalled Percentage          %20"PRIu64"%%\n",
			(uint64_t)calc_percent((le64_to_cpu(perf->hr_st_cmds)), le64_to_cpu(perf->hr_cmds)));
	printf("  Host Write Commands                            %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hw_cmds));
	printf("  Host Write Blocks                              %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hw_blks));
	printf("  Average Write Size                             %20f\n",
			safe_div_fp((le64_to_cpu(perf->hw_blks)), (le64_to_cpu(perf->hw_cmds))));
	printf("  Host Write Odd Start Commands                  %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hw_os_cmds));
	printf("  Host Write Odd Start Commands Percentage       %20"PRIu64"%%\n",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_os_cmds)), (le64_to_cpu(perf->hw_cmds))));
	printf("  Host Write Odd End Commands                    %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hw_oe_cmds));
	printf("  Host Write Odd End Commands Percentage         %20"PRIu64"%%\n",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_oe_cmds)), (le64_to_cpu((perf->hw_cmds)))));
	printf("  Host Write Commands Stalled                    %20"PRIu64"\n",
		(uint64_t)le64_to_cpu(perf->hw_st_cmds));
	printf("  Host Write Commands Stalled Percentage         %20"PRIu64"%%\n",
		(uint64_t)calc_percent((le64_to_cpu(perf->hw_st_cmds)), (le64_to_cpu(perf->hw_cmds))));
	printf("  NAND Read Commands                             %20"PRIu64"\n",
		(uint64_t)le64_to_cpu(perf->nr_cmds));
	printf("  NAND Read Blocks Commands                      %20"PRIu64"\n",
		(uint64_t)le64_to_cpu(perf->nr_blks));
	printf("  Average NAND Read Size                         %20f\n",
		safe_div_fp((le64_to_cpu(perf->nr_blks)), (le64_to_cpu((perf->nr_cmds)))));
	printf("  Host Write Odd Start Commands                  %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hw_os_cmds));
	printf("  Nand Write Commands                            %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->nw_cmds));
	printf("  NAND Write Blocks                              %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->nw_blks));
	printf("  Average NAND Write Size                        %20f\n",
			safe_div_fp((le64_to_cpu(perf->nw_blks)), (le64_to_cpu(perf->nw_cmds))));
	printf("  NAND Read Before Write                         %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->nrbw));
}

static void wdc_print_log_json(struct wdc_ssd_perf_stats *perf)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_int(root, "Host Read Commands", le64_to_cpu(perf->hr_cmds));
	json_object_add_value_int(root, "Host Read Blocks", le64_to_cpu(perf->hr_blks));
	json_object_add_value_int(root, "Average Read Size",
			safe_div_fp((le64_to_cpu(perf->hr_blks)), (le64_to_cpu(perf->hr_cmds))));
	json_object_add_value_int(root, "Host Read Cache Hit Commands",
			(uint64_t)le64_to_cpu(perf->hr_ch_cmds));
	json_object_add_value_int(root, "Host Read Cache Hit Percentage",
			(uint64_t) calc_percent(le64_to_cpu(perf->hr_ch_cmds), le64_to_cpu(perf->hr_cmds)));
	json_object_add_value_int(root, "Host Read Cache Hit Blocks",
			(uint64_t)le64_to_cpu(perf->hr_ch_blks));
	json_object_add_value_int(root, "Average Read Cache Hit Size",
			safe_div_fp((le64_to_cpu(perf->hr_ch_blks)), (le64_to_cpu(perf->hr_ch_cmds))));
	json_object_add_value_int(root, "Host Read Commands Stalled",
			(uint64_t)le64_to_cpu(perf->hr_st_cmds));
	json_object_add_value_int(root, "Host Read Commands Stalled Percentage",
			(uint64_t)calc_percent((le64_to_cpu(perf->hr_st_cmds)), le64_to_cpu(perf->hr_cmds)));
	json_object_add_value_int(root, "Host Write Commands",
			(uint64_t)le64_to_cpu(perf->hw_cmds));
	json_object_add_value_int(root, "Host Write Blocks",
			(uint64_t)le64_to_cpu(perf->hw_blks));
	json_object_add_value_int(root, "Average Write Size",
			safe_div_fp((le64_to_cpu(perf->hw_blks)), (le64_to_cpu(perf->hw_cmds))));
	json_object_add_value_int(root, "Host Write Odd Start Commands",
			(uint64_t)le64_to_cpu(perf->hw_os_cmds));
	json_object_add_value_int(root, "Host Write Odd Start Commands Percentage",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_os_cmds)), (le64_to_cpu(perf->hw_cmds))));
	json_object_add_value_int(root, "Host Write Odd End Commands",
			(uint64_t)le64_to_cpu(perf->hw_oe_cmds));
	json_object_add_value_int(root, "Host Write Odd End Commands Percentage",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_oe_cmds)), (le64_to_cpu((perf->hw_cmds)))));
	json_object_add_value_int(root, "Host Write Commands Stalled",
		(uint64_t)le64_to_cpu(perf->hw_st_cmds));
	json_object_add_value_int(root, "Host Write Commands Stalled Percentage",
		(uint64_t)calc_percent((le64_to_cpu(perf->hw_st_cmds)), (le64_to_cpu(perf->hw_cmds))));
	json_object_add_value_int(root, "NAND Read Commands",
		(uint64_t)le64_to_cpu(perf->nr_cmds));
	json_object_add_value_int(root, "NAND Read Blocks Commands",
		(uint64_t)le64_to_cpu(perf->nr_blks));
	json_object_add_value_int(root, "Average NAND Read Size",
		safe_div_fp((le64_to_cpu(perf->nr_blks)), (le64_to_cpu((perf->nr_cmds)))));
	json_object_add_value_int(root, "Host Write Odd Start Commands",
			(uint64_t)le64_to_cpu(perf->hw_os_cmds));
	json_object_add_value_int(root, "Nand Write Commands",
			(uint64_t)le64_to_cpu(perf->nw_cmds));
	json_object_add_value_int(root, "NAND Write Blocks",
			(uint64_t)le64_to_cpu(perf->nw_blks));
	json_object_add_value_int(root, "Average NAND Write Size",
			safe_div_fp((le64_to_cpu(perf->nw_blks)), (le64_to_cpu(perf->nw_cmds))));
	json_object_add_value_int(root, "NAND Read Before Writen",
			(uint64_t)le64_to_cpu(perf->nrbw));
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int wdc_print_log(struct wdc_ssd_perf_stats *perf, int fmt)
{
	if (!perf) {
		fprintf(stderr, "Invalid buffer to read perf stats\n");
		return -1;
	}
	switch (fmt) {
	case WDC_HUMAN:
		wdc_print_log_human(perf);
		break;
	case WDC_JSON:
		wdc_print_log_json(perf);
		break;
	}
	return 0;
}

static int validate_output_format(char *format)
{
	if (!format)
		return -EINVAL;
	if (!strcmp(format, "human"))
		return WDC_HUMAN;
	if (!strcmp(format, "json"))
		return WDC_JSON;
	return -EINVAL;
}

static int wdc_smart_log_add(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Retrieve additional performance statistics.";
	char *interval = "Interval to read the statistics from [1, 15].";
	uint8_t *p;
	int i;
	int fd;
	int ret;
	int fmt = -1;
	int skip_cnt = 4;
	int total_subpages;
	__u8 *data;
	struct wdc_log_page_header *l;
	struct wdc_log_page_subpage_header *sph;
	struct wdc_ssd_perf_stats *perf;

	struct config {
		uint8_t interval;
		int   vendor_specific;
		char *output_format;
	};

	struct config cfg = {
		.interval = 14,
		.output_format = "human",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"interval", 'i', "NUM", CFG_POSITIVE, &cfg.interval, required_argument, interval},
		{"output-format", 'o', "FMT", CFG_STRING, &cfg.output_format, required_argument, "Output Format: human|json" },
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		fprintf(stderr, "ERROR : invalid output format\n");
		return fmt;
	}

	if (cfg.interval < 1 || cfg.interval > 15) {
		fprintf(stderr, "ERROR : interval out of range [1-15]\n");
		return -1;
	}

	if ((data = (__u8*) malloc(sizeof (__u8) * WDC_ADD_LOG_BUF_LEN)) == NULL) {
		fprintf(stderr, "ERROR : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof (__u8) * WDC_ADD_LOG_BUF_LEN);

	ret = nvme_get_log(fd, 0x01, WDC_NVME_ADD_LOG_OPCODE, WDC_ADD_LOG_BUF_LEN, data);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	if (ret == 0) {
		l = (struct wdc_log_page_header*)data;
		total_subpages = l->num_subpages + WDC_NVME_GET_STAT_PERF_INTERVAL_LIFETIME - 1;
		for (i = 0, p = data + skip_cnt; i < total_subpages; i++, p += skip_cnt) {
			sph = (struct wdc_log_page_subpage_header *) p;
			if (sph->spcode == WDC_GET_LOG_PAGE_SSD_PERFORMANCE) {
				if (sph->pcset == cfg.interval) {
					perf = (struct wdc_ssd_perf_stats *) (p + 4);
					ret = wdc_print_log(perf, fmt);
					break;
				}
			}
			skip_cnt = sph->subpage_length + 4;
		}
		if (ret) {
			fprintf(stderr, "ERROR : Unable to read data from buffer\n");
		}
	}
	free(data);
	return ret;
}
