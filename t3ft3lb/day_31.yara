import "lnk"

rule ta_king_werewolf_lnk_base64_payload
{
    meta:
        description = "Detects King Werewolf (IAmTheKing, NGC6061) malicious LNK file containing a Base64-encoded payload"
        author = "@t3ft3lb"
        date = "2026-01-31"
        reference = "https://rt-solar.ru/solar-4rays/blog/6064/"
        hash1 = "9a770c320145c604feaea2b07af3dd5ddd729076bdaa55206499bac821b2985c"
        hash2 = "03446e7dc87a01a5eac65bc3d82b02a488393cd2d6bd213ab3d90ffca25d6456"

    strings:
        $s0 = "$TDESKEY" ascii fullword
        $s1 = "FromBase64String" ascii fullword

    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        filesize > 70KB and filesize < 4MB and
        lnk.icon_location == "C:\\Program Files\\Windows NT\\Accessories\\wordpad.exe" and
        lnk.cmd_line_args contains "[System.IO.File]::ReadAllBytes" and
        lnk.cmd_line_args contains "Get-ChildItem -Path $env:userprofile -Include" and
        lnk.cmd_line_args contains "powershell -exec bypass -w 1 -f c:\\windows\\temp\\" and
        $s0 and #s1 > 3
}