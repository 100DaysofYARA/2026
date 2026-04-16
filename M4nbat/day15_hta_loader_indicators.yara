rule APT36_HTA_Loader_Artifacts {
    meta:
        author = "M4nbat"
        description = "Detects APT36 HTA loader using specific variable names and decryption logic found in 2026 campaign."
        date = "2026-01-31"
        yarahub_uuid = "a1b2c3d4-e5f6-4721-b8d9-0123456789ab"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "ceb715db684199958aa5e6c05dc5c7f0" // MD5 of the LNK that drops this
        malpedia_family = "win.transparent_tribe"

    strings:
        $var1 = "ReadOnly" ascii wide
        $var2 = "WriteOnly" ascii wide
        $s1 = "Base64" ascii wide nocase
        $s2 = "XOR" ascii wide nocase
        $s3 = "mshta.exe" ascii wide nocase
        $script_start = "<script" ascii wide nocase
        $script_end = "</script>" ascii wide nocase

    condition:
        (filesize < 500KB) and
        $script_start and $script_end and
        all of ($var*) and 
        2 of ($s*)
}
