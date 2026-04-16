rule mlwr_batavia_downloader_vbe
{
    meta:
        description = "Detects Batavia VBE downloader"
        author = "@t3ft3lb"
        date = "2026-01-06"
        reference = "https://securelist.com/batavia-spyware-steals-data-from-russian-organizations/116866/"
        hash1 = "d6fc05b4a48ad310aba39f7f3df04ed6f7c4957afa1faf7f2120e85cb49a565b"
        hash2 = "d908001cfb2f0f8e2adb5c915194404871fbf47b7597357977ac5a14cac7250b"
        hash3 = "ea91b3ec95c7fbb810dc8c0c125c9a4522c6eea571638e2ec19a27e536eddc57"

    strings:
        $x = "@#@&" ascii

        $s0 = "N~q6" ascii
        $s1 = "AUN,q" ascii
        $s2 = "AVd+" ascii

    condition:
        uint32(0) == 0x5E7E4023 and uint32(filesize-5) == 0x407E235E and
        filesize > 1KB and filesize < 6KB and
        #x > 50 and all of ($s*)
}
