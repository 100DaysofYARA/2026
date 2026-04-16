rule SUSP_Abnormally_Large_LNK {
    meta:
        author = "M4nbat"
        description = "Detects LNK files that are unusually large, suggesting embedded payloads or junk data padding used for evasion."
        date = "2026-01-31"
        yarahub_uuid = "e4d3c2b1-5a6f-4721-89d3-c9e8f7a6b5d4"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.dropper"
        yarahub_reference_md5 = "N/A" // Generic hunting rule

    condition:
        uint32(0) == 0x0000004C and 
        uint32(4) == 0x00021401 and
        // Anything over 100KB is highly suspicious for a shortcut
        filesize > 100KB
}
