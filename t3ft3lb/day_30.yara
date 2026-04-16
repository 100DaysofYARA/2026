import "lnk"

rule ta_gremlin_wolf_lnk_webdav
{
    meta:
        description = "Detects Gremlin Wolf (OldGremlin) malicious LNK file that executes node.exe from WebDAV"
        author = "@t3ft3lb"
        date = "2026-01-30"
        reference_1 = "https://www.group-ib.com/resources/research-hub/oldgremlin/"
        reference_2 = "https://habr.com/ru/companies/F6/articles/836264/"
        hash1 = "86e9a1277bfdfcdc0d5b0d6d3e9aefebd699adb543de34cbc3a7d290b6fac1c9"
        hash2 = "0b5ff6ee2deb1014fab7cc45c84c7eb97b1739bd34b695fc524fc3dff06d9f2f"
        hash3 = "91834c3c11d6b48dab2938d347907d8ef8d0353092e0a32494875e50b100dc7d"

    strings:
        $x = "Web Client Network" ascii fullword

        $s0 = "DavWWWRoot" ascii wide fullword
        $s1 = "node.exe" ascii wide fullword

    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        filesize > 300 and filesize < 3KB and
        (lnk.icon_location contains "shell32.dll" or lnk.icon_location contains "SHELL32.DLL") and
        ($x or lnk.drive_type == lnk.DriveType.FIXED) and
        lnk.show_command == lnk.ShowCommand.MIN_NO_ACTIVE and
        #s0 > 1 and all of ($s*)
}