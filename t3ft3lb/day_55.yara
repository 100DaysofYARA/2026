rule ta_squid_werewolf_csharp_downloader
{
    meta:
        description = "Detects Squid Werewolf (APT37) C# downloader"
        author = "@t3ft3lb"
        date = "2026-02-24"
        reference = "https://bi.zone/eng/expertise/blog/sotni-tysyach-rubley-za-vashi-sekrety-kibershpiony-squid-werewolf-maskiruyutsya-pod-rekruterov/"
        hash1 = "0601426a6da40ec9b47bab54e4ec149ba69ee58f787eea0e32d1001cab1abd04" // DomainManager.dll
        hash2 = "62cee255eb34455d48a173c886075463337595e382f1fce2302dd82e1400db7c" // NetworkConfig.dll

    strings:
        $dotnet = ".NETFramework" ascii fullword

        $h0 = { 00 00 06 6F ?? 00 00 0A 25 7E ?? 00 00 04 6F ?? 00 00 0A 25 20 40 1F 00 00 }
        $h1 = { 02 19 73 ?? 00 00 0A 25 6F ?? 00 00 0A 69 0A 06 8D ?? 00 00 01 0B 25 07 16 06 6F }
        $h2 = { 7E ?? 00 00 04 16 9A 25 2D 0A 26 16 16 1F ?? 28 ?? 00 00 06 2A }
        $h3 = { 7E ?? 00 00 04 18 9A 25 2D 0B 26 18 1F }
        $h4 = { 06 91 06 61 20 ?? 00 00 00 61 D2 9C 06 17 58 0A 06 7E ?? 00 00 04 8E 69 FE 04 2D D9 2A}

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 5KB and filesize < 200KB and
        $dotnet and 4 of ($h*)
}