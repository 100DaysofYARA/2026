rule ta_clumsy_werewolf_msc_downloader
{
    meta:
        description = "Detects Clumsy Werewolf (Patchwork) MSC downloader"
        author = "@t3ft3lb"
        date = "2026-02-07"
        reference_1 = "https://www.ctfiot.com/269659.html"
        reference_2 = "https://gbhackers.com/darksamural-apt-group/"
        hash1 = "590879c567c6d95b18b34e46e9830ba7b807279d76d83abc066f013d4b6f693e"
        hash2 = "9f5b34ee5a5cd2eebc8923a961de8bc7b67c3048f7b6ebc1287fa8be613b9d83"

    strings:
        $x0 = "MMC_ConsoleFile" ascii fullword
        $x1 = "{2933BF90-7B36-11D2-B20E-00C04F983E60}" ascii fullword

        $s0 = "<String ID=\"14\" Refs=\"1\">http" ascii
        $s1 = ".html</String>" ascii
        $s2 = "{71E5B33E-1064-11D2-808F-0000F875A9CE}" ascii fullword
        $s3 = "AQAAABQAAAAAAAAABgAAAP////8=" ascii fullword

    condition:
        uint32(0) == 0x6D783F3C and
        filesize > 100KB and filesize < 3MB and
        all of ($x*) and 2 of ($s*)
}
