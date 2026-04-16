import "pe"

rule ta_paper_werewolf_echogather_backdoor
{
    meta:
        description = "Detects Paper Werewolf (GOFFEE) EchoGather backdoor"
        author = "@t3ft3lb"
        date = "2026-01-08"
        reference = "https://intezer.com/blog/tracing-a-paper-werewolf-campaign-through-ai-generated-decoys-and-excel-xlls/"
        hash1 = "c9c3841ef79625b5ae7588927cb77fa134560ba9154f9814550caee8e8ffac43"
        hash2 = "c3e04bb4f4d51bb1ae8e67ce72aff1c3abeca84523ea7137379f06eb347e1669"
        hash3 = "b2419afcfc24955b4439100706858d7e7fc9fdf8af0bb03b70e13d8eed52935c"

    strings:
        $s0 = "warp.exe" ascii fullword
        $s1 = "1.1.1.1" ascii fullword
        $s2 = "HARDWARE\\DESCRIPTION\\System\\BIOS" ascii fullword
        $s3 = "%ws:" wide fullword
        $s4 = "//%w" wide fullword
        $s5 = "s:%l" wide fullword
        $s6 = "u/%w" wide fullword
        $s7 = "https" wide fullword
        $s8 = "POST" wide fullword

        $x0 = "SystemManufacturer" xor ascii
        $x1 = "SystemProductName" xor ascii
        $x2 = "BIOSVendor" xor ascii
        $x3 = "cmd.exe" xor ascii

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 80KB and filesize < 400KB and
        (
         (7 of ($s*) and 2 of ($x*)) or
         pe.imphash() == "2f6b944b260e56e3b1602d5a94aa9bc1" or
         pe.imphash() == "7ac71b347c4ea4b4a7c80ea9d8b6bdf3"
        )
}