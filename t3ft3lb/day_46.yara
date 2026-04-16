rule ta_arcane_werewolf_loki2_loader_module
{
    meta:
        description = "Detects Arcane Werewolf (Mythic Likho) Loki 2.0-2.1 loader module"
        author = "@t3ft3lb"
        date = "2026-02-15"
        reference_1 = "https://bi.zone/eng/expertise/blog/arcane-werewolf-vernulsya-s-obnovlennym-implantom-loki/"
        reference_2 = "https://securelist.com/loki-agent-for-mythic/113596/"
        hash1 = "7fbb29f8724fddfb32b29543e046cf4aceab8f10e5120150f58d7a119162c631" // loki 2.0
        hash2 = "551c0455a608edd88ecd6946c93ed2ac9a68a48148630975a17905205629f617" // loki 2.1

    strings:
        $s0 = "SHGetFolderPathW" ascii fullword
        $s1 = "Mingw-w64" ascii fullword

        $h0 = { 41 F6 C2 DF 75 ?? 41 80 E0 DF 41 80 C0 BF 41 80 F8 19 }
        $h1 = { 41 80 F8 1A 0F B6 D2 45 0F B6 C1 44 0F 43 C2 89 C2 C1 E2 05 }
        $h2 = { 44 8D 42 BF 41 89 D1 41 80 C9 20 41 80 F8 1A }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 70KB and filesize < 300KB and
        all of them
}
