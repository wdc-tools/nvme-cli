#undef CMD_INC_FILE
#define CMD_INC_FILE wdc-nvme

#if !defined(WDC_NVME) || defined(CMD_HEADER_MULTI_READ)
#define WDC_NVME

#include "cmd.h"

PLUGIN(NAME("wdc", "Western Digital vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("cap-diag", "WDC Capture-Diagnostics", wdc_cap_diag)
		ENTRY("drive-log", "WDC Drive Log", wdc_drive_log)
		ENTRY("get-crash-dump", "WDC Crash Dump", wdc_get_crash_dump)
		ENTRY("id-ctrl", "WDC identify controller", wdc_id_ctrl)
		ENTRY("purge", "WDC Purge", wdc_purge)
		ENTRY("purge-monitor", "WDC Purge Monitor", wdc_purge_monitor)
		ENTRY("smart-log-add", "WDC Additional Smart Log", wdc_smart_log_add)
		ENTRY("smart-log-add-c1", "WDC Additional Smart Log for C1 Log page", wdc_smart_log_add_c1)
		ENTRY("sanitize", "WDC Sanitize", wdc_sanitize)
		ENTRY("sanitize-monitor", "WDC Sanitize Monitor", wdc_sanitize_monitor)
	)
);

#endif

#include "define_cmd.h"
