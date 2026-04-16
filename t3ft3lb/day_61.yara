rule tool_anydesk_win
{
    meta:
        description = "Detects AnyDesk remote desktop software"
        author = "@t3ft3lb"
        date = "2026-03-02"
        reference = "https://anydesk.com/"
        hash1 = "ac7f226bdf1c6750afa6a03da2b483eee2ef02cd9c2d6af71ea7c6a9a4eace2f"
        hash2 = "bfc1675ee1e358db8356f515aaded7962923e426aa0a0a1c0eddfc4dab053f89"

    strings:
        $x = "AnyDesk" ascii wide fullword

        $s0 = "win_loader\\AnyDesk.pdb" ascii fullword
        $s1 = "AnyDesk Software" ascii fullword
        $s2 = "screen sharing and remote control software." ascii fullword

        $h0 = { 69 D2 0D 66 19 00 81 C2 5F F3 6E 3C }
        $h1 = { C1 E9 18 80 E1 01 FE C9 F6 D1 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 5MB and filesize < 12MB and
        #x > 3 and (2 of ($s*) or any of ($h*))
}