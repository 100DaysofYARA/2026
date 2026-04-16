rule ta_forbidden_hyena_blackout_locker
{
    meta:
        description = "Detects Forbidden Hyena (4BID) Blackout Locker"
        author = "@t3ft3lb"
        date = "2026-03-16"
        reference = "https://bi.zone/eng/expertise/blog/forbidden-hyena-atakuet-s-novym-troyanom-udalennogo-dostupa-blackreaperrat/"
        hash1 = "1fb2a010a9234de8a901ff910388dc538e410e9dd1e1382ec4ce28a05c754a02"
        hash2 = "3674f411cdb6d03b6f4e2d4b6bcff8d8907b415f47c536e531e04fde1ac68be1"
        hash3 = "71eba7b77838fffb0754852a9335555468dd161f87eb5ce048bceeb4d66ba64f"

    strings:
        $s0 = "T_SKIP_HIDDEN_FOLDERS" ascii fullword
        $s1 = "LT_KILL_DEFENDER" ascii fullword
        $s2 = "LT_KILL_PROCESSES_FLAG" ascii fullword
        $s3 = "LT_KILL_SERVICES_FLAG" ascii fullword
        $s4 = "LT_DELETE_EVENTLOGS" ascii fullword
        $s5 = "LT_DELETE_SHADOWS" ascii fullword
        $s6 = "T_ANTI_ANALYSIS" ascii fullword
        $s7 = "LT_PERSISTENCE" ascii fullword
        $s8 = "LT_NETWORK_SPREAD" ascii fullword
        $s9 = "LT_DISABLE_FS_REDIRECTION" ascii fullword
        $s10 = "LT_USE_RESTART_MANAGER" ascii fullword
        $s11 = "LT_SET_WALLPAPER" ascii fullword
        $s12 = "LT_SET_ICONS" ascii fullword
        $s13 = "LT_SELF_DESTRUCT" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 100KB and filesize < 500KB and
        7 of ($s*)
}