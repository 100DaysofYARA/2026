rule mlwr_veletrix_loader
{
    meta:
        description = "Detects Veletrix loader"
        author = "@t3ft3lb"
        date = "2026-03-18"
        reference_1 = "https://www.seqrite.com/blog/operation-dragonclone-chinese-telecom-veletrix-vshell-malware/"
        reference_2 = "https://0x0d4y.blog/telecommunications-supply-chain-china-nexus-threat-technical-analysis-of-veletrix-loaders-strategic-infrastructure-positioning/"
        hash = "ac6e0ee1328cfb1b6ca0541e4dfe7ba6398ea79a300c4019253bd908ab6a3dc0"
        
    strings:
        $r = /(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)/ ascii fullword

        $s = "dr_data" ascii fullword

        $h0 = { 56 69 72 74 48 8B C8 C7 45 ?? 75 61 6C 41 48 8B
                D8 C7 45 ?? 6C 6C 6F 63 C7 45 ?? 45 78 4E 75 66
                C7 45 ?? 6D 61 C6 45 }
        $h1 = { 52 74 6C 49 48 8B C8 C7 45 ?? 70 76 34 53 C7 45
                ?? 74 72 69 6E C7 45 ?? 67 54 6F 41 C7 45 ?? 64
                64 72 65 C7 45 ?? 73 73 41 00 }
        $h2 = { F0 80 34 30 6F FF C3 81 FB 73 05 00 00 }
        $h3 = { 33 D2 48 FF C1 48 98 48 F7 F1 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 90KB and filesize < 120KB and
        #r > 200 and (#s > 5 or 3 of ($h*))
}