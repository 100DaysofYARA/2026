rule mlwr_blackhawk_loader
{
    meta:
        description = "Detects BlackHawk loader"
        author = "@t3ft3lb"
        date = "2026-04-05"
        reference_1 = "https://labs.k7computing.com/index.php/phantom-3-5-initial-vector-analysis-forensics/"
        reference_2 = "https://x.com/ESETresearch/status/2002023561859309830"
        hash1 = "122d9df1eea4f711fe7e1da9adee6bf254d39f3ff528687a4344831784db28ab"
        hash2 = "bb388854ce997acd7ad77e4af898d49cc71778d186d506f30ad73053359a1555"
        hash3 = "dc89ddbdef184c73aae943c46738d48e5586106954f2bf5e70135213bb310af2"

    strings:
        $dotnet = ".NETFramework" ascii fullword

        $x0 = "BLACKHAWK.pdb" ascii fullword
        $x1 = "BLACKHAWK.dll" ascii fullword 
        $x2 = "DOWN" ascii fullword
        $x3 = "SHOOT" ascii fullword
        
        $h0 = { 00 0F 00 28 ?? 00 00 06 0F 01 28 ?? 00 00 06 D0 01 00 00 1B }
        $h1 = { 04 02 7E ?? 00 00 0A 7E ?? 00 00 0A 7E ?? 00 00 0A 16 20 04 00 00 08 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 10KB and filesize < 70KB and
        $dotnet and (2 of ($x*) and all of ($h*))
}