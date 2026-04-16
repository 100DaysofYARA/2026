import "pe"

rule ta_unsolicited_werewolf_luciload_loader
{
    meta:
        description = "Detects Unsolicited Werewolf (UnsolicitedBooker) LuciLoad loader"
        author = "@t3ft3lb"
        date = "2026-04-08"
        reference = "https://global.ptsecurity.com/en/research/pt-esc-threat-intelligence/poisonous-mars-or-how-lucidoor-knocks-on-the-doors-of-the-cis/"
        hash1 = "54c993140dd490bb44f4cfb31612dc2c13bbf8bfaac8a0ca2ffaa2e20d553074"
        hash2 = "469e1e62b324575950f3237d37f81567bc55476e48a2a1bd0d31d8b22ff09e9b"

    strings:
        $x = "OneDriveLaucher" wide fullword

        $f0 = "CreateWindowExW" ascii fullword
        $f1 = "FindResourceW" ascii fullword
        $f2 = "IsDebuggerPresent" ascii fullword
        $f3 = "IsProcessorFeaturePresent" ascii fullword
        $f4 = "QueryPerformanceCounter" ascii fullword
        $f5 = "GetTickCount64" ascii fullword
        
        $h0 = { 81 E7 FF 00 00 80 79 ?? 4F 81 CF 00 FF FF FF }
        $h1 = { C7 06 52 74 6C 44 C7 46 ?? 65 63 6F 6D C7 46 ??
                70 72 65 73 C7 46 ?? 73 42 75 66 66 C7 46 ?? 66
                65 C6 46 ?? 72 }
        $h2 = { 6A 6E AB AB AB 58 6A 74 66 89 01 58 6A 64 66 89
                41 ?? 58 6A 6C }
        $h3 = { 3D C0 06 01 00 74 ?? 3D 60 06 02 00 74 ?? 3D 70
                06 02 00 74 ?? 3D 50 06 03 00 74 ?? 3D 60 06 03
                00 74 ?? 3D 70 06 03 00 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 30KB and filesize < 80KB and
        (
         (($x or all of ($f*)) and 3 of ($h*)) or
         pe.imphash() == "edb74786cc7a6deb87728e9da6f2c89d"
        )
}