rule ta_scaly_wolf_scalyloader
{
    meta:
        description = "Detects Scaly Wolf (Albino Ghouls) ScalyLoader malware"
        author = "@t3ft3lb"
        date = "2026-02-22"
        reference_1 = "https://bi.zone/upload/for_download/BI.ZONE_Threat_Zone_Research_2025_eng.pdf"
        reference_2 = "https://news.drweb.com/show/?i=15046&lng=en"
        hash1 = "fd36909cb4525f0195832763ecb68e1e8da8154f6db5db2e9075cb034b376c62"
        hash2 = "a29438bf54ebc8d7130824fa73732be20cb1c5e494339958c68986517e54dcef"
        hash3 = "a8fdb1c8c187b9ebce33c9e586c60b5067605010fc27586787efc0f102c26bea"

    strings:
        $x0 = "MyBoundary123456" ascii fullword
        $x1 = "SELECT * FROM AntivirusProduct" ascii fullword
        $x2 = "data:image/png;base64" ascii fullword

        $s0 = "Failed to allocate BSTR strings" ascii fullword
        $s1 = "Failed to open internet session" ascii fullword
        $s2 = "Failed to connect to server" ascii fullword
        $s3 = "Failed to open request" ascii fullword
        $s4 = "Failed to add headers" ascii fullword
        $s5 = "Failed to send request" ascii fullword
        $s6 = "Failed to open file." wide fullword
        $s7 = "Failed to get module file name." wide fullword
        $s8 = "Failed to get temp path." wide fullword
        $s9 = "Failed to open PDF file." wide fullword
        $s10 = "Failed to extract PDF resource." wide fullword

        $h0 = { C1 E? 1E 33 C? 69 ?? 65 89 07 6C }
        $h1 = { D1 E9 25 DF B0 08 99 33 82 }
        $h2 = { 25 AD 58 3A FF C1 E0 07 }
        $h3 = { 25 8C DF FF FF C1 E0 0F }
    
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 200KB and filesize < 4MB and
        ((all of ($x*) or all of ($h*)) and 6 of ($s*))
}