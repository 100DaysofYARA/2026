import "console"
import "lnk"

rule HELPER_get_lnk_info
{
    meta:
        description = "Extract useful information from LNK files. NOTE: For better output, run in a single thread."
        author = "@t3ft3lb"
        date = "2026-02-23"
    
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        console.log("Command Line Arguments: ", lnk.cmd_line_args) and
        console.log("Icon File Name: ", lnk.icon_location) and
        console.log("Machine ID: ", lnk.tracker_data.machine_id)
}