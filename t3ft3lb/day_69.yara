rule ta_sapphire_werewolf_amethyst_stealer_in_mem
{
    meta:
        description = "Detects Sapphire Werewolf Amethyst stealer in memory"
        author = "@t3ft3lb"
        date = "2026-03-10"
        reference = "https://bi.zone/eng/expertise/blog/kamen-ogranennyy-sapphire-werewolf-ispolzuet-novuyu-versiyu-amethyst-stealer-dlya-atak-na-tek/"
        hash1 = "9eb1254e6343e0184e0a81972e0860dba0da24fea387a0c05c0c8660442a69c1"
        hash2 = "7401dfd844664185aaa0ad7fe909c88eb10eb5e24080e0c17a676e4316d641af"
        hash3 = "29548fb375288b25a163b83932ac330f5154d3246fe310461f40f32b02bdfa61"

    strings:
        $dotnet = ".NETFramework" ascii fullword

        $x0 = "ngrok-free.app" wide fullword
        $x1 = "canarytokens.com" wide fullword
        $x2 = "api.telegram.org" wide fullword
        $x3 = "checkip.dyndns.org" wide fullword

        $s0 = "GetDrives" ascii fullword
        $s1 = "AppendAllText" ascii fullword
        $s2 = "DotNetZip.dll" ascii fullword
        $s3 = "EnumerateFiles" ascii fullword
        $s4 = "CreateDecryptor" ascii fullword
        $s5 = "CompressionLevel" ascii fullword
        $s6 = "EnumerateDirectories" ascii fullword
        $s7 = "TripleDESCryptoServiceProvider" ascii fullword
        $s8 = "Start sending files telegram" wide fullword
        
    condition:
        $dotnet and 2 of ($x*) and all of ($s*)
}