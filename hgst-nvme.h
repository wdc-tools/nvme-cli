#undef CMD_INC_FILE
#define CMD_INC_FILE hgst-nvme

#if !defined(HGST_NVME) || defined(CMD_HEADER_MULTI_READ)
#define HGST_NVME

#include "cmd.h"

PLUGIN(NAME("hgst", "HGST vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("cap-diag", "HGST Capture-Diagnostics", hgst_cap_diag)
		ENTRY("drive-log", "HGST Drive Log", hgst_drive_log)
		ENTRY("purge", "HGST Purge", hgst_purge)
		ENTRY("purge-monitor", "HGST Purge Monitor", hgst_purge_monitor)
	)
);

#endif

#include "define_cmd.h"
