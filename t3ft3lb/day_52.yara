import "elf"

rule ta_snowbound_werewolf_snowlight_downloader
{
    meta:
        description = "Detects Snowbound Werewolf (Snowy Mogwai, UNC5174) SNOWLIGHT downloader"
        author = "@t3ft3lb"
        date = "2026-02-21"
        reference_1 = "https://www.sysdig.com/blog/unc5174-chinese-threat-actor-vshell"
        reference_2 = "https://cloud.google.com/blog/topics/threat-intelligence/initial-access-brokers-exploit-f5-screenconnect"
        hash = "e6db3de3a21debce119b16697ea2de5376f685567b284ef2dee32feb8d2d44f8"

    strings:
        $s0 = "/tmp/log_de.log" ascii fullword
        $s1 = "vs.gooogleasia.com" ascii fullword
        $s2 = "GET /?a=%s&h=%s&t=%s&p=%d HTTP/1.1" ascii fullword
        $s3 = "CWD\x00[kworker/0:2]" ascii fullword

        $h = { 48 C7 44 24 ?? 00 00 00 00 48 C7 44 24 ?? 00 00 00 00 66 C7 44 24 ?? 02 00 66 C7 44 24 ?? 20 FB }
        
    condition:
        uint32(0) == 0x464C457F and
        filesize > 5KB and filesize < 12KB and
        (
            (3 of ($s*) and $h) or
            elf.telfhash() == "T159B02B025470414C8FF221380C24CC831202C1A3C9415F608D40F740CA3F08D804CF4D"
        )
}