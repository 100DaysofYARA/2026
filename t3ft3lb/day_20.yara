rule ta_rainbow_hyena_phantomremote_backdoor
{
    meta:
        description = "Detects Rainbow Hyena (Head Mare, PhantomCore) PhantomRemote backdoor"
        author = "@t3ft3lb"
        date = "2026-01-20"
        reference = "https://bi.zone/eng/expertise/blog/rainbow-hyena-snova-atakuet-novyy-bekdor-i-smena-taktik/"
        hash1 = "ed9b24a77a74cd34c96b30f8de794fe85eb1d9f188f516bd7d6020cc81a86728"
        hash2 = "204544fc8a8cac64bb07825a7bd58c54cb3e605707e2d72206ac23a1657bfe1e"
        hash3 = "b683235791e3106971269259026e05fdc2a4008f703ff2a4d32642877e57429a"

    strings:
        $s0 = "&commandId=" ascii fullword
        $s1 = "&result=" ascii fullword
        $s2 = "cmd:" ascii fullword
        $s3 = "download:" ascii fullword
        $s4 = "Download successful: " ascii fullword
        $s5 = "Download failed: " ascii fullword
        $s6 = "&domain=" ascii wide fullword
        $s7 = "&hostname=" ascii wide fullword
        $s8 = "/poll?id=" wide fullword
        
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 200KB and filesize < 7MB and
        6 of ($s*)
}