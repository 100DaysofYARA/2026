rule ta_rare_werewolf_sim_dropper
{
    meta:
        description = "Detects Rare Werewolf (Librarian Likho (ex Ghouls), Rezet) Smart Install Maker (SIM) dropper"
        author = "@t3ft3lb"
        date = "2026-01-28"
        reference = "https://securelist.com/librarian-ghouls-apt-wakes-up-computers-to-steal-data-and-mine-crypto/116536/"
        hash1 = "c2c8e4e10e1440840068027baa346db0bc47c055b89aac9806d04280a60fc360"
        hash2 = "f18374fa790c5bbf7bc272c10a26f56db99b7d7eee08c986fa4bd20c3c455387"
        hash3 = "a4ca5e4eec5acbe7dc564eb3227fcd2e3022353e65b34258a4f76ef7d8df1ec8"

    strings:
        $sim = "Smart Install Maker" ascii fullword

        $x0 = "/c echo>>@$&%" ascii
        $x1 = "/c @$&%" ascii

        $s0 = "4t Niagara Software" ascii fullword
        $s1 = "Trays" ascii fullword
        $s2 = "AnyDesk" ascii fullword
        $s3 = "driver.exe" ascii fullword
        $s4 = "find.cmd" ascii fullword
        $s5 = "rezet.cmd" ascii fullword
        $s6 = "curl.exe" ascii fullword
        $s7 = "blat.exe" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 150KB and filesize < 50MB and
        $sim and (#x0 > 0 or #x1 > 5) and 4 of ($s*)
}