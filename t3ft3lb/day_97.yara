rule ta_unsolicited_werewolf_marssnake_loader
{
    meta:
        description = "Detects Unsolicited Werewolf (UnsolicitedBooker) MarsSnake loader"
        author = "@t3ft3lb"
        date = "2026-04-07"
        reference = "https://global.ptsecurity.com/en/research/pt-esc-threat-intelligence/poisonous-mars-or-how-lucidoor-knocks-on-the-doors-of-the-cis/"
        hash1 = "01f28cefdcf3940c19efd7a0446aa0e56c56bc7c955774c94d6d469fca627a4e"
        hash2 = "87619f23611dda86bb58c845c7824f34c76e9d270f624e5bb2c1fd8ab96d750f"
        hash3 = "ea8cb5695b05372fa80f984b3a8ef2d1411a1d95b6b2be015107d0a19dc6dca8"

    strings:
        $x0 = "MarsSnake" ascii fullword
        $x1 = "OOkupFunction*71N" ascii

        $h0 = { 80 E1 07 C0 E1 03 }
        $h1 = { C1 E1 08 C1 E5 08 }
        $h2 = { 83 E1 01 41 D1 E9 }
        $h3 = { 8? E1 07 48 C1 EE 03 }
        $h4 = { D1 E8 03 C2 C1 E8 04 6B C0 1F }
        $h5 = { C1 EA 0F 69 C2 0F 00 FF FF 03 C8 B8 71 80 07 80 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 50KB and filesize < 100KB and
        any of ($x*) and 3 of ($h*)
}