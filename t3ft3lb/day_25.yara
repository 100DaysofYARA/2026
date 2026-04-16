rule ta_magic_werewolf_commonmagic_loader
{
    meta:
        description = "Detects Magic Werewolf (RedStinger) CommonMagic loader"
        author = "@t3ft3lb"
        date = "2026-01-25"
        reference_1 = "https://www.threatdown.com/blog/uncovering-redstinger-undetected-apt-cyber-operations-in-eastern-europe-since-2020/"
        reference_2 = "https://securelist.com/bad-magic-apt/109087/"
        hash = "bc93ef8e20f2a9a8799934d629fe494d5d82ea49e06ed8fb00ea6cc2e96f407e"

    strings:
        $s0 = "\\CommonCommand\\Clean\\" wide fullword
        $s1 = "\\CommonCommand\\Overall\\" wide fullword
        $s2 = "\\CommonCommand\\Other\\" wide fullword
        $s3 = "*\x00\x00DAT" wide fullword

        $h0 = { 83 C1 23 2B C2 83 C0 FC 83 F8 1F }
        $h1 = { B8 AB AA AA 2A F7 E9 B8 AA AA AA 0A C1 FA 02 }
        $h2 = { C7 45 ?? 53 68 65 6C [0-1] C7 45 ?? 6C 33 32 2E C7 45 ?? 64 6C 6C 00 }
        $h3 = { C7 45 ?? 6B 65 72 6E C7 45 ?? 65 6C 33 32 C7 45 ?? 2E 64 6C 6C C6 45 ?? 00 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 40KB and filesize < 1MB and
        3 of ($s*) and 2 of ($h*)
}