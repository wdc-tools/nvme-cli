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
		ENTRY("get-pfail-dump", "WDC Pfail Dump", wdc_get_pfail_dump)
		ENTRY("id-ctrl", "WDC identify controller", wdc_id_ctrl)
		ENTRY("purge", "WDC Purge", wdc_purge)
		ENTRY("purge-monitor", "WDC Purge Monitor", wdc_purge_monitor)
		ENTRY("vs-internal-log", "WDC Internal Firmware Log", wdc_internal_fw_log)
		ENTRY("smart-add-log", "WDC Additional Smart Log", wdc_smart_add_log)
		ENTRY("smart-add-log-c1", "WDC Additional Smart Log for C1 Log page", wdc_smart_add_log_c1)
		ENTRY("smart-add-log-d0", "WDC Additional Smart Log for D0 Log page", wdc_smart_add_log_d0)
		ENTRY("clear-pcie-corr", "WDC Clear PCIe Correctable Error Count", wdc_clear_pcie_corr)
		ENTRY("drive-essentials", "WDC Drive Essentials", wdc_drive_essentials)
	)
);

#endif

#include "define_cmd.h"
