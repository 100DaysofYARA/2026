rule ta_cavalry_werewolf_foalshell_csharp
{
    meta:
        description = "Detects Cavalry Werewolf (YoroTrooper, Tomiris) FoalShell C# reverse shell"
        author = "@t3ft3lb"
        date = "2026-02-17"
        reference_1 = "https://bi.zone/eng/expertise/blog/cavalry-werewolf-atakuet-rossiyu-cherez-doveritelnye-otnosheniya-mezhdu-gosudarstvami/"
        reference_2 = "https://news.drweb.com/show/?i=15078&lng=en&c=5"
        hash1 = "1dfe65e8dc80c59000d92457ff7053c07f272571a8920dbe8fc5c2e7037a6c98"
        hash2 = "ec80e96e3d15a215d59d1095134e7131114f669ebc406c6ea1a709003d3f6f17"

    strings:
        $dotnet = ".NETFramework" ascii fullword

        $s0 = "Documents\\reverseShells\\Reverse-Shell-CS\\Payload\\Real_cli\\obj\\Release" ascii fullword
        $s1 = "$8923c4d9-3fbf-4cf3-8a63-c5102293b774" ascii fullword
        $s2 = "Progra33v" ascii fullword

        $h = { (00 0D 73 00 68 00 65 00 6C 00 6C | 00 09 63 00 6D 00 64)
               00 3E 00 00 0B 65 00 78 00 69 00 74 00 0A 00 00 0F 63 00
               6D 00 64 00 2E 00 65 00 78 00 65 00 00 07 2F 00 63 00 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 80KB and filesize < 150KB and
        $dotnet and any of ($s*) and $h
}
