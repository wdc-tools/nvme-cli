#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/fs.h>
#include <linux/limits.h>
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

/* Capture Diagnostics */
#define HGST_CAP_DIAGS_HEADER_TOC_SIZE	0x100
#define HGST_CAP_DIAGS_OPCODE			0xE6

/* Purge and Purge Monitor constants */
#define HGST_NVME_PURGE_CMD_OPCODE		0xDD
#define HGST_NVME_PURGE_MONITOR_OPCODE		0xDE
#define HGST_NVME_PURGE_MONITOR_DATA_LEN	0x2F
#define HGST_NVME_PURGE_MONITOR_CMD_CDW10	0x0000000C
#define HGST_NVME_PURGE_MONITOR_TIMEOUT		0x7530
#define HGST_NVME_PURGE_CMD_SEQ_ERR		0x0C
#define HGST_NVME_PURGE_INT_DEV_ERR		0x06
#define HGST_NVME_PURGE_STATE_IDLE		0x00
#define HGST_NVME_PURGE_STATE_DONE		0x01
#define HGST_NVME_PURGE_STATE_BUSY		0x02
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


static int hgst_get_serial_name(int fd, char *file)
{
	int i;
	int rc;
	struct nvme_id_ctrl ctrl;

	i = sizeof(ctrl.sn) - 1;
	rc = nvme_identify_ctrl(fd, &ctrl);
	if (rc) {
		fprintf(stderr, "ERROR : HGST : nvme_identify_ctrl() failed\n");
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

static __u32 hgst_cap_diag_get_log_length(int fd)
{
	__s32 rc;
	__u32 total_length;
	__u8 header_toc[HGST_CAP_DIAGS_HEADER_TOC_SIZE];
	struct nvme_admin_cmd admin_cmd;

	/* obtain main header and toc content */
	memset(header_toc, 0, sizeof(header_toc));
	memset(&admin_cmd, 0, sizeof(struct nvme_admin_cmd));
	admin_cmd.opcode = HGST_CAP_DIAGS_OPCODE;
	admin_cmd.addr = (__u64) header_toc;
	admin_cmd.data_len = HGST_CAP_DIAGS_HEADER_TOC_SIZE;
	/* NDT : how much bytes needs to be tranfered */
	admin_cmd.cdw10 = HGST_CAP_DIAGS_HEADER_TOC_SIZE / 4;
	/* offset = 0x00 : collect the data in snapshot image,
					not available accross resets
	*/
	admin_cmd.cdw13 = 0x00;
	rc = nvme_submit_passthru(fd,NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (rc != 0) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(rc), rc);
		return rc;
	}
	/* obtain total length of E6 log  */
	total_length = header_toc[0x04] << 24 |
					header_toc[0x05] << 16 |
					header_toc[0x06] <<  8 |
					header_toc[0x07];
	return total_length;
}


static int hgst_cap_diag_get_data(int fd, __u32 total_length,
		char *bin_filepath)
{
	int rc;
	__u8 *diag_data;
	FILE *bin_file;
	struct nvme_admin_cmd admin_cmd;

	if ((diag_data = malloc(total_length)) == NULL) {
		fprintf(stderr, "ERROR : malloc : %s\n", strerror(errno));
		return -1;
	}

	memset(diag_data, 0, total_length);
	memset(&admin_cmd, 0, sizeof(struct nvme_admin_cmd));

	admin_cmd.opcode = HGST_CAP_DIAGS_OPCODE;
	admin_cmd.addr = (__u64) diag_data;
	admin_cmd.data_len = total_length;
	/* NDT : how much bytes needs to be tranfered */
	admin_cmd.cdw10 = total_length / 4;
	/* offset = 0x00 : collect the data in snapshot image,
					not available accross resets
	*/
	admin_cmd.cdw13 = 0x00;

	rc = nvme_submit_passthru(fd,NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (rc != 0) {
		fprintf(stderr, "ERROR : failed to execute e6"
				" capture diagnostics command.\n");
	} else {
		if ((bin_file = fopen(bin_filepath, "wb+")) == NULL) {
			rc = errno;
			fprintf(stderr, "ERROR : fopen : %s\n",
				strerror(errno));
		} else {
			fwrite(diag_data, sizeof(__u8), total_length,
				bin_file);
			if (ferror(bin_file)) {
				rc = errno;
				fprintf (stderr, "ERROR : fwrite : %s\n",
					strerror(errno));
			}
		}
		fflush(bin_file);
		fclose(bin_file);
	}
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(rc), rc);
	free(diag_data);

	return rc;
}


static int hgst_cap_diag(int argc, char **argv,
				struct command *command, struct plugin *plugin)
{
	char *desc = "Capture diagnostics log.";
	char *file = "Output file pathname.";
	int fd;
	__u32 total_length;

	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"file",  'f', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if ((strcmp(cfg.file, "") == 0) &&
			(hgst_get_serial_name(fd, cfg.file) == -1)) {
		fprintf(stderr, "ERROR : failed to generate file "
				"pathname for cap-diag.\n");
		return -1;
	}
	total_length = hgst_cap_diag_get_log_length(fd);
	return hgst_cap_diag_get_data(fd, total_length, cfg.file);
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
	int rc;
	struct nvme_passthru_cmd admin_cmd;
	const struct argconfig_commandline_options command_line_options[] = {
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
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
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(rc), rc);
	return rc;
}

static int hgst_purge_monitor(int argc, char **argv,
				struct command *command, struct plugin *plugin)
{
	char *desc = "Send a Purge Monitor command";
	int fd;
	int rc;
	__u8 output[HGST_NVME_PURGE_MONITOR_DATA_LEN];
	double progress_percent;
	struct nvme_passthru_cmd admin_cmd;
	struct hgst_nvme_purge_monitor_data *mon;
	const struct argconfig_commandline_options command_line_options[] = {
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
		{0}
	};

	memset(output, 0, sizeof(output));
	memset(&admin_cmd, 0, sizeof(struct nvme_admin_cmd));
	admin_cmd.opcode = HGST_NVME_PURGE_MONITOR_OPCODE;
	admin_cmd.addr = (__u64) output;
	admin_cmd.data_len = HGST_NVME_PURGE_MONITOR_DATA_LEN;
	admin_cmd.cdw10 = HGST_NVME_PURGE_MONITOR_CMD_CDW10;
	admin_cmd.timeout_ms = HGST_NVME_PURGE_MONITOR_TIMEOUT;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	rc = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (rc == 0) {
		mon = (struct hgst_nvme_purge_monitor_data *) output;
		printf("Purge state = 0x%0x \n%s\n", admin_cmd.result,
				hgst_nvme_purge_mon_status_to_string(admin_cmd.result));
		if (admin_cmd.result == HGST_NVME_PURGE_STATE_BUSY) {
			progress_percent = ((double)mon->entire_progress_current * 100) /
				mon->entire_progress_total;
			printf("Purge Progress = %f%%\n", progress_percent);
		}
	}
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(rc), rc);
	return rc;
}
