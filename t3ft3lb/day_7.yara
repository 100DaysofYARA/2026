import "lnk"

rule ta_squid_werewolf_malicious_lnk
{
    meta:
        description = "Detects Squid Werewolf (APT37) malicious LNK files"
        author = "@t3ft3lb"
        date = "2026-01-07"
        reference_1 = "https://bi.zone/eng/expertise/blog/sotni-tysyach-rubley-za-vashi-sekrety-kibershpiony-squid-werewolf-maskiruyutsya-pod-rekruterov/"
        reference_2 = "https://www.securonix.com/blog/shroudedsleep-a-deep-dive-into-north-koreas-ongoing-campaign-against-southeast-asia/"
        hash1 = "2b44d231bc3abb4891c13b14c3f42ac0a2c71b741eae41a04b1105e77b0154de"
        hash2 = "9d0807210b0615870545a18ab8eae8cecf324e89ab8d3b39a461d45cab9ef957"

    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        filesize > 30KB and filesize < 10MB and
        lnk.cmd_line_args contains "New-Object IO.FileStream ($env:temp" and
        lnk.cmd_line_args contains "'Open','Read','ReadWrite'" and
        lnk.cmd_line_args contains "Unicode.GetString([Convert]::FromBase64CharArray" and
        lnk.cmd_line_args contains "[IO.SeekOrigin]::Begin" and
        lnk.cmd_line_args contains "[Convert]::FromBase64\"\"String($" and
        lnk.tracker_data.machine_id startswith "UABEAD"
}