rule ta_rainbow_hyena_phantompxpigeon_backdoor
{
    meta:
        description = "Detects Rainbow Hyena (Head Mare, PhantomCore) PhantomPxPigeon backdoor"
        author = "@t3ft3lb"
        date = "2026-03-27"
        reference = "https://securelist.ru/head-mare-campaign-phantompxpigeon-backdoor-and-trueconf-software/114998/"
        hash1 = "2d5dbaad4590720b6117871ff0ecd7300d51f80aee8df7a11ec9e984a30d598a"
        hash2 = "42ba749a7b51f55bcf19bb425999c0848ad100c37e2494fb7ce44a18642ebf72"

    strings:
        $s0 = "BMSR" ascii
        $s1 = "Runner" ascii fullword
        $s2 = "GetSystemFirmwareTable" ascii fullword
        
        $h0 = { BE FF FF FF 7F BD DF B0 08 99 }
        $h1 = { C1 E8 1E 33 C1 69 C8 65 89 07 6C }
        $h2 = { C0 E1 03 48 B8 45 D5 B1 3B AF 05 AD FB 48 D3 E8 }
        $h3 = { C0 E1 03 48 B8 07 E1 57 25 2D D9 BF 13 48 D3 E8 }
        $h4 = { C0 E1 03 48 B8 77 3F B5 3D CB 01 B9 01 48 D3 E8 }
        $h5 = { 80 E1 07 C0 E1 03 48 B8 C1 8B FB 1B 7F 1F E3 09 }
        $h6 = { 80 E1 07 C0 E1 03 48 B8 19 A5 45 B1 67 9D 37 EF 48 D3 E8 }
        $h7 = { 48 B8 B3 94 D6 26 E8 0B 2E 11 48 F7 E9 48 C1 FA 1A 48 8B C2 48 C1 E8 3F }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 3MB and filesize < 8MB and
        2 of ($s*) and 3 of ($h*)
}