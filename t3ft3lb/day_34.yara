import "dotnet"

rule ta_paper_werewolf_csharp_downloader
{
    meta:
        description = "Detects Paper Werewolf (GOFFEE) C# downloader"
        author = "@t3ft3lb"
        date = "2026-02-03"
        reference_1 = "https://bi.zone/eng/expertise/blog/paper-werewolf-atakuet-rossiyu-s-ispolzovaniem-uyazvimosti-nulevogo-dnya-v-winrar/"
        reference_2 = "https://global.ptsecurity.com/en/research/pt-esc-threat-intelligence/fortune-telling-on-goffee-grounds/"
        hash1 = "2446f97c1884f70f97d68c2f22e8fc1b9b00e1559cd3ca540e8254749a693106"
        hash2 = "d519ef7bf4fce06b73ec109011bdf0b342e6f73eb603a160d69cecd6256a30bb"
        hash3 = "86f40d64d8b1fed9589c82b7a9924924c00fba8b4ebe8994673e266f05c9b661"

    strings:
        $s0 = "WinRunApp\\WinRunApp\\obj\\x64\\Release" ascii fullword
        $s1 = "StartLoading" ascii fullword
        $s2 = "Check" ascii fullword
        $s3 = "EscapeDataString" ascii fullword
        $s4 = "ParseAdd" ascii fullword
        
        $h = { 15 3F 00 68 00 6F 00 73 00 74 00 6E 00 61 00 6D
               00 65 00 3D 00 00 15 26 00 75 00 73 00 65 00 72
               00 6E 00 61 00 6D 00 65 00 3D 00 }
  
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 6KB and filesize < 1MB and
        dotnet.is_dotnet and dotnet.number_of_streams == 5 and
        3 of ($s*) and $h
}