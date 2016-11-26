#undef CMD_INC_FILE
#define CMD_INC_FILE wdc-nvme

#if !defined(WDC_NVME) || defined(CMD_HEADER_MULTI_READ)
#define WDC_NVME

#include "cmd.h"

PLUGIN(NAME("wdc", "Western Digital vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("cap-diag", "WDC Capture-Diagnostics", wdc_cap_diag)
		ENTRY("crash-dump", "WDC Crash Dump", wdc_crash_dump)
		ENTRY("drive-log", "WDC Drive Log", wdc_drive_log)
		ENTRY("pfail-dump", "WDC Pfail Dump", wdc_pfail_dump)
		ENTRY("purge", "WDC Purge", wdc_purge)
		ENTRY("purge-monitor", "WDC Purge Monitor", wdc_purge_monitor)
	)
);

#endif

#include "define_cmd.h"
